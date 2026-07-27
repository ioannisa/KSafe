package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.*
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.autoreleasepool
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionarySetValue
import platform.CoreFoundation.CFMutableDictionaryRef
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
    fileName: String?,
    legacyEncryptedPrefix: String,
    seKeyTagPrefix: String,
    reservedKeyIds: Set<String>,
    /** A key for a not-yet-committed write must not be reaped as an orphan. */
    isInFlight: (String) -> Boolean = { false },
) {
    if (!keychainOrphanSweepEnabled(Platform.osFamily)) return

    val snapshot = storage.snapshot()

    val validKeys = keychainSweepValidKeys(snapshot, legacyEncryptedPrefix)

    // Same producer the factory's aliases come from — a sweep that derived the base itself would
    // reap live keys the moment the two spellings drifted.
    val prefixWithDelimiter = "${KSafeAliasFormat.dottedBase(fileName)}."
    val sePrefixWithDelimiter = "$seKeyTagPrefix$prefixWithDelimiter"

    val orphanedKeyIds = mutableSetOf<KeychainOrphan>()

    // Null value-callbacks: the dict won't retain values, so hold the bridged +1 across
    // SecItemCopyMatching then CFRelease, or every probe leaks a CFString.
    val serviceRef = CFBridgingRetain(serviceName)
    try {
        forEachKeychainAttributeDict({ query ->
            CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword)
            CFDictionarySetValue(query, kSecAttrService, serviceRef)
        }) { dict ->
            val account = dict.objectForKey(kSecAttrAccount as Any) as? String
            if (account != null) {
                // ownedKeyIds = validKeys: never reap a root key with a byte-identical dotted
                // account. Deliberate consequence: a NAMED store's orphans (whose owner is by
                // definition absent from validKeys) are never reaped — including strict-variant
                // orphans — and remain safe litter; only the root sweep reclaims orphans.
                val orphan =
                    keychainOrphanKeyId(account, prefixWithDelimiter, fileName, validKeys, reservedKeyIds, isInFlight, ownedKeyIds = validKeys)
                        ?: keychainOrphanKeyId(account, sePrefixWithDelimiter, fileName, validKeys, reservedKeyIds, isInFlight, ownedKeyIds = validKeys)
                if (orphan != null) orphanedKeyIds.add(orphan)
            }
        }
    } finally {
        CFRelease(serviceRef)
    }

    // Scan SE-held kSecClassKey EC keys: catches keys orphaned by a crash between SE key
    // creation and wrapped-key storage (no matching generic-password item).
    forEachKeychainAttributeDict({ query ->
        CFDictionarySetValue(query, kSecClass, kSecClassKey)
        CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
    }) { dict ->
        // SE EC keys use `applicationTag` (NSData) rather than `account` (NSString).
        val tagData = dict.objectForKey(kSecAttrApplicationTag as Any) as? NSData
        if (tagData != null) {
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

    if (keychainOrphanSweepBlocked(validKeys, orphanedKeyIds.size)) {
        println(
            "KSafe: Keychain orphan sweep skipped — the DataStore holds no encrypted " +
                "entry but ${orphanedKeyIds.size} scoped Keychain entries exist. " +
                "This usually indicates a partial storage view (a 1.x → 2.0 migration " +
                "where the DataStore file failed to move, a quarantined-corrupt store, " +
                "or a restore that recovered the Keychain but not the store); deleting " +
                "the Keychain entries would destroy data permanently. If you intended " +
                "to clear KSafe, call KSafe.clearAll() instead."
        )
        return
    }

    // Re-check the in-flight guard at DELETE time, not just at classify: sweep and writes run
    // parallel on Native, so a `put` that re-used a key after classify but before this loop
    // would lose its live key. Writes mark in-flight before commit, closing that window.
    for (keyId in keychainOrphansToDelete(orphanedKeyIds, isInFlight)) {
        engine.deleteKeySuspend("$prefixWithDelimiter$keyId")
    }
}

/**
 * Enumerates every Keychain item matching the query [configure] completes, handing each item's
 * attribute dictionary to [onItem]. Written once because the mechanics between the two scans are
 * manual CoreFoundation refcounting — the query's own +1 and the result array's — and that is
 * exactly where a duplicated release becomes a leak or a double free. The caller keeps ownership
 * of anything it bridges into the query inside [configure].
 */
@OptIn(ExperimentalForeignApi::class)
private inline fun forEachKeychainAttributeDict(
    configure: (CFMutableDictionaryRef?) -> Unit,
    onItem: (NSDictionary) -> Unit,
) {
    autoreleasepool {
        memScoped {
            val query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null).apply {
                configure(this)
                CFDictionarySetValue(this, kSecReturnAttributes, kCFBooleanTrue)
                CFDictionarySetValue(this, kSecMatchLimit, kSecMatchLimitAll)
            }
            val resultRef = alloc<CFTypeRefVar>()
            val status = SecItemCopyMatching(query, resultRef.ptr)
            CFRelease(query as CFTypeRef?)
            if (status != errSecSuccess) return@memScoped

            (CFBridgingRelease(resultRef.value) as? NSArray)?.let { array ->
                for (i in 0 until array.count.toInt()) {
                    val dict = array.objectAtIndex(i.toULong()) as? NSDictionary ?: continue
                    onItem(dict)
                }
            }
        }
    }
}
