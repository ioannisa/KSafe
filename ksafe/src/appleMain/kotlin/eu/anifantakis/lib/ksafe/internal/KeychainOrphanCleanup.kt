package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.*
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionarySetValue
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFAllocatorDefault
import platform.CoreFoundation.kCFBooleanTrue
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSArray
import platform.Foundation.NSData
import platform.Foundation.NSDictionary
import platform.Security.SecItemCopyMatching
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrApplicationTag
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeECSECPrimeRandom
import platform.Security.kSecAttrService
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecClassKey
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitAll
import platform.Security.kSecReturnAttributes
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.OsFamily
import kotlin.native.Platform

/**
 * Whether the Keychain orphan sweep is safe to run on [osFamily].
 *
 * The sweep enumerates every Keychain item under the library's hardcoded service and
 * deletes those with no surviving DataStore counterpart. That is only safe where the
 * Keychain is **app-private** — the iOS/tvOS/watchOS sandbox. On **macOS** items land in
 * the shared per-user *login* keychain with no app identity in the namespace (KSafe sets
 * no access group / data-protection keychain), so one KSafe-using app's sweep would
 * enumerate and DELETE another KSafe-using app's keys, permanently corrupting its data
 * every launch. Disable the sweep there: stale macOS Keychain entries are harmless
 * clutter, reclaimed by `clearAll()`.
 *
 * Pure + parameterized so it's unit-testable without a live Keychain.
 */
@OptIn(ExperimentalNativeApi::class)
internal fun keychainOrphanSweepEnabled(osFamily: OsFamily): Boolean =
    osFamily != OsFamily.MACOSX

/**
 * iOS-only Keychain orphan sweep. **Enforced** via [keychainOrphanSweepEnabled]: this is a
 * no-op on macOS, whose shared login keychain would otherwise let it delete other apps' keys.
 *
 * The Keychain is **not** wiped on app uninstall (unless the app opts out), so keys can
 * linger after DataStore has been cleared via Settings or `clearAll()`. This scans the
 * Keychain for items this library wrote, cross-references them against DataStore's
 * current key set, and deletes entries with no surviving DataStore counterpart. Two
 * item classes are covered:
 *
 *  1. **Generic-password items** — where both plain AES keys and
 *     Secure-Enclave-wrapped blobs live.
 *  2. **`kSecClassKey` EC private keys** — the SE-held ECIES keys used to
 *     wrap AES material for `HARDWARE_ISOLATED` writes. These are scanned
 *     independently so a crash between SE key creation and wrapped-key
 *     storage can still be cleaned up on the next run.
 *
 * Failures are swallowed by the caller — a locked device or a transient
 * Keychain error must never block `KSafe` initialization.
 *
 * [reservedKeyIds] lists key-id segments that are KSafe infrastructure rather than
 * per-value keys and must NEVER be swept — the shared master-key sentinels
 * (`__ksafe_master__` / `__ksafe_master_locked__`). A master key is referenced by every
 * `DEFAULT`-protected value collectively, not by any single user key, so it never appears
 * in [validKeys]; without this guard the sweep would classify it as an orphan and delete
 * it, rendering ALL `DEFAULT` ciphertext permanently undecryptable. A stale reserved key
 * is harmless clutter, reclaimed only by `clearAll()` (or reused by the next `DEFAULT`
 * write).
 */
@OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)
internal suspend fun cleanupOrphanedKeychainEntries(
    storage: KSafePlatformStorage,
    engine: KSafeEncryption,
    serviceName: String,
    keyPrefix: String,
    fileName: String?,
    legacyEncryptedPrefix: String,
    seKeyTagPrefix: String,
    reservedKeyIds: Set<String>,
    /** Live in-flight check (KSafeCore's dirty-key set): a key for a not-yet-committed write
     *  must not be reaped as an orphan. Default false for callers/tests that don't run
     *  concurrently with writes. */
    isInFlight: (String) -> Boolean = { false },
) {
    // Never sweep on macOS: the shared login keychain has no app-identity scoping, so we'd
    // delete other KSafe-using apps' keys. Bail before touching storage or the Keychain so
    // nothing else in this function can run there.
    if (!keychainOrphanSweepEnabled(Platform.osFamily)) return

    val snapshot = storage.snapshot()

    // Pass 1 — collect protection metadata from `__ksafe_meta_*__` and legacy
    // `__ksafe_prot_*__` entries.
    val protectionByKey = mutableMapOf<String, KSafeProtection>()
    for ((rawKey, storedValue) in snapshot) {
        val text = (storedValue as? StoredValue.Text)?.value ?: continue
        KeySafeMetadataManager.tryExtractCanonicalMetadataKey(rawKey)?.let { userKey ->
            KeySafeMetadataManager.parseProtection(text)?.let { protectionByKey[userKey] = it }
            return@let
        }
        KeySafeMetadataManager.tryExtractLegacyProtectionKey(rawKey)?.let { userKey ->
            if (!protectionByKey.containsKey(userKey)) {
                KeySafeMetadataManager.parseProtection(text)?.let { protectionByKey[userKey] = it }
            }
        }
    }

    // Pass 2 — derive the set of user-keys that still have a live DataStore
    // entry (either legacy `{fileName}_key` or canonical `__ksafe_value_key`
    // backed by protection metadata from pass 1).
    val validKeys = mutableSetOf<String>()
    for ((rawKey, _) in snapshot) {
        when {
            rawKey.startsWith(legacyEncryptedPrefix) ->
                validKeys.add(rawKey.removePrefix(legacyEncryptedPrefix))

            rawKey.startsWith(KeySafeMetadataManager.VALUE_PREFIX) -> {
                val userKey = rawKey.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
                if (protectionByKey[userKey] != null) validKeys.add(userKey)
            }
        }
    }

    val basePrefix = listOfNotNull(keyPrefix, fileName).joinToString(".")
    val prefixWithDelimiter = "$basePrefix."
    val sePrefixWithDelimiter = "$seKeyTagPrefix$prefixWithDelimiter"

    val orphanedKeyIds = mutableSetOf<String>()

    // --- Scan 1: generic-password items (plain keys + SE-wrapped keys) ---
    memScoped {
        val query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null).apply {
            CFDictionarySetValue(this, kSecClass, kSecClassGenericPassword)
            CFDictionarySetValue(this, kSecAttrService, CFBridgingRetain(serviceName))
            CFDictionarySetValue(this, kSecReturnAttributes, kCFBooleanTrue)
            CFDictionarySetValue(this, kSecMatchLimit, kSecMatchLimitAll)
        }
        val resultRef = alloc<CFTypeRefVar>()
        val status = SecItemCopyMatching(query, resultRef.ptr)
        CFRelease(query as CFTypeRef?)

        if (status == errSecSuccess) {
            (CFBridgingRelease(resultRef.value) as? NSArray)?.let { array ->
                for (i in 0 until array.count.toInt()) {
                    val dict = array.objectAtIndex(i.toULong()) as? NSDictionary ?: continue
                    val account = dict.objectForKey(kSecAttrAccount as Any) as? String ?: continue

                    // Plain keys: "{prefix}.{keyId}"; SE-wrapped keys:
                    // "se.{prefix}.{keyId}". The two prefixes are mutually
                    // exclusive, so at most one classifier matches.
                    // ownedKeyIds = validKeys: a named instance reaps only keys it can
                    // prove are its own, so it never destroys a root instance's dotted key
                    // that shares a byte-identical account (M-D). Root sweep is unaffected.
                    val orphan =
                        keychainOrphanKeyId(account, prefixWithDelimiter, fileName, validKeys, reservedKeyIds, isInFlight, ownedKeyIds = validKeys)
                            ?: keychainOrphanKeyId(account, sePrefixWithDelimiter, fileName, validKeys, reservedKeyIds, isInFlight, ownedKeyIds = validKeys)
                    if (orphan != null) orphanedKeyIds.add(orphan)
                }
            }
        }
    }

    // --- Scan 2: kSecClassKey EC private keys (SE-held) ---
    // Catches SE keys that exist without a matching generic-password item, e.g.
    // when a crash happened between SE key creation and wrapped-AES-key storage.
    memScoped {
        val query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null).apply {
            CFDictionarySetValue(this, kSecClass, kSecClassKey)
            CFDictionarySetValue(this, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
            CFDictionarySetValue(this, kSecReturnAttributes, kCFBooleanTrue)
            CFDictionarySetValue(this, kSecMatchLimit, kSecMatchLimitAll)
        }
        val resultRef = alloc<CFTypeRefVar>()
        val status = SecItemCopyMatching(query, resultRef.ptr)
        CFRelease(query as CFTypeRef?)

        if (status == errSecSuccess) {
            (CFBridgingRelease(resultRef.value) as? NSArray)?.let { array ->
                for (i in 0 until array.count.toInt()) {
                    val dict = array.objectAtIndex(i.toULong()) as? NSDictionary ?: continue
                    // SE EC keys use `applicationTag` (NSData) rather than `account` (NSString).
                    val tagData = dict.objectForKey(kSecAttrApplicationTag as Any) as? NSData ?: continue

                    val tagBytes = ByteArray(tagData.length.toInt())
                    if (tagBytes.isNotEmpty()) {
                        tagBytes.usePinned { pinned ->
                            platform.posix.memcpy(pinned.addressOf(0), tagData.bytes, tagData.length)
                        }
                    }
                    val tag = tagBytes.decodeToString()

                    // SE tags: "se.{prefix}.{keyId}". ownedKeyIds = validKeys (M-D, see above).
                    keychainOrphanKeyId(tag, sePrefixWithDelimiter, fileName, validKeys, reservedKeyIds, isInFlight, ownedKeyIds = validKeys)
                        ?.let { orphanedKeyIds.add(it) }
                }
            }
        }
    }

    // Guard: an EMPTY DataStore snapshot alongside Keychain entries scoped to *this*
    // service + key prefix almost certainly means a partial view of storage — a failed
    // 1.x → 2.0 path migration, a corrupt store reinitialised empty, or app data wiped
    // while the per-device Keychain survived — not a legitimate post-clearAll state.
    // Deleting here would destroy irrecoverable state: Secure Enclave EC private keys
    // are gone for good once removed. KSafeCore.startBackgroundCollector waits for the
    // first `snapshotFlow` emission before invoking this function, which covers the
    // common path; this guard catches the cases where the snapshot is *legitimately*
    // empty because the migration failed outright.
    if (snapshot.isEmpty() && orphanedKeyIds.isNotEmpty()) {
        println(
            "KSafe: Keychain orphan sweep skipped — DataStore is empty but " +
                "${orphanedKeyIds.size} scoped Keychain entries exist. " +
                "This usually indicates a 1.x → 2.0 migration where the " +
                "DataStore file failed to move; deleting the Keychain " +
                "entries would destroy data permanently. If you intended " +
                "to clear KSafe, call KSafe.clearAll() instead."
        )
        return
    }

    // engine.deleteKey unconditionally removes the plain key, the SE-wrapped
    // generic-password entry, and the SE EC private key for a given identifier.
    //
    // Re-check the live in-flight guard at DELETE time, not just at classify time
    // (FEEDBACK_4 H-B): the sweep runs on `collectorScope` while writes run on
    // `writeScope` (genuinely parallel on Native), so a `put` that committed
    // ciphertext and re-used a key AFTER we classified it but BEFORE this loop
    // would otherwise have its live key destroyed, orphaning the just-written
    // value. A write marks its key in-flight before its commit lands, so filtering
    // out now-in-flight ids here closes the window the classify-time check left open.
    for (keyId in keychainOrphansToDelete(orphanedKeyIds, isInFlight)) {
        engine.deleteKeySuspend("$prefixWithDelimiter$keyId")
    }
}
