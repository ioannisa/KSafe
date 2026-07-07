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
 * The sweep is only safe where the Keychain is app-private (iOS/tvOS/watchOS sandbox). On
 * macOS items share the per-user login keychain with no app identity in the namespace, so a
 * sweep would delete other KSafe-using apps' keys. Pure so it's testable without a Keychain.
 */
@OptIn(ExperimentalNativeApi::class)
internal fun keychainOrphanSweepEnabled(osFamily: OsFamily): Boolean =
    osFamily != OsFamily.MACOSX

/**
 * iOS-only Keychain orphan sweep (no-op on macOS via [keychainOrphanSweepEnabled]): the
 * Keychain survives app uninstall, so this deletes items the library wrote whose DataStore
 * counterpart no longer exists. Scans generic-password items AND SE-held `kSecClassKey` EC
 * keys, so a crash between SE key creation and wrapped-key storage is still cleaned up.
 *
 * [reservedKeyIds] holds the shared master-key sentinels: no single user key references
 * them, so they never appear in the valid-key set — without this guard the sweep would
 * delete the master and render ALL `DEFAULT` ciphertext permanently undecryptable.
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
    /** A key for a not-yet-committed write must not be reaped as an orphan. */
    isInFlight: (String) -> Boolean = { false },
) {
    // Bail before touching storage or the Keychain so nothing below can run on macOS.
    if (!keychainOrphanSweepEnabled(Platform.osFamily)) return

    val snapshot = storage.snapshot()

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

    // The user-keys that still have a live DataStore entry.
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

    // Scan generic-password items (plain keys + SE-wrapped keys).
    memScoped {
        // The dict's null value-callbacks mean it does not retain its values: hold the bridged
        // +1 across SecItemCopyMatching, then CFRelease, or every probe leaks a CFString.
        val serviceRef = CFBridgingRetain(serviceName)
        val query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null).apply {
            CFDictionarySetValue(this, kSecClass, kSecClassGenericPassword)
            CFDictionarySetValue(this, kSecAttrService, serviceRef)
            CFDictionarySetValue(this, kSecReturnAttributes, kCFBooleanTrue)
            CFDictionarySetValue(this, kSecMatchLimit, kSecMatchLimitAll)
        }
        val resultRef = alloc<CFTypeRefVar>()
        val status = SecItemCopyMatching(query, resultRef.ptr)
        CFRelease(query as CFTypeRef?)
        CFRelease(serviceRef)

        if (status == errSecSuccess) {
            (CFBridgingRelease(resultRef.value) as? NSArray)?.let { array ->
                for (i in 0 until array.count.toInt()) {
                    val dict = array.objectAtIndex(i.toULong()) as? NSDictionary ?: continue
                    val account = dict.objectForKey(kSecAttrAccount as Any) as? String ?: continue

                    // ownedKeyIds = validKeys: a named instance reaps only keys it can prove
                    // are its own, never a root key with a byte-identical dotted account.
                    val orphan =
                        keychainOrphanKeyId(account, prefixWithDelimiter, fileName, validKeys, reservedKeyIds, isInFlight, ownedKeyIds = validKeys)
                            ?: keychainOrphanKeyId(account, sePrefixWithDelimiter, fileName, validKeys, reservedKeyIds, isInFlight, ownedKeyIds = validKeys)
                    if (orphan != null) orphanedKeyIds.add(orphan)
                }
            }
        }
    }

    // Scan SE-held kSecClassKey EC keys — catches keys left without a matching generic-password
    // item by a crash between SE key creation and wrapped-key storage.
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

                    // SE tags: "se.{prefix}.{keyId}". ownedKeyIds = validKeys (see above).
                    keychainOrphanKeyId(tag, sePrefixWithDelimiter, fileName, validKeys, reservedKeyIds, isInFlight, ownedKeyIds = validKeys)
                        ?.let { orphanedKeyIds.add(it) }
                }
            }
        }
    }

    // An EMPTY DataStore snapshot alongside Keychain entries scoped to this service + prefix
    // almost certainly means a partial view of storage (a failed 1.x → 2.0 migration, a store
    // reinitialised empty, or app data wiped while the per-device Keychain survived), not a
    // legitimate post-clearAll state. Deleting here would destroy irrecoverable Secure Enclave
    // keys, so bail.
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

    // Re-check the in-flight guard at DELETE time, not just at classify time: the sweep and
    // writes run genuinely parallel on Native, so a `put` that committed ciphertext and
    // re-used a key AFTER classify but BEFORE this loop would otherwise have its live key
    // destroyed, orphaning the just-written value. A write marks its key in-flight before its
    // commit lands, so filtering now-in-flight ids here closes that window.
    for (keyId in keychainOrphansToDelete(orphanedKeyIds, isInFlight)) {
        engine.deleteKeySuspend("$prefixWithDelimiter$keyId")
    }
}
