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

/** Only safe where the Keychain is app-private; on macOS it is the shared login keychain, so a
 *  sweep there would reap other apps' keys. */
@OptIn(ExperimentalNativeApi::class)
internal fun keychainOrphanSweepEnabled(osFamily: OsFamily): Boolean =
    osFamily != OsFamily.MACOSX

/**
 * Deletes Keychain items whose DataStore counterpart is gone (the Keychain survives uninstall).
 * The [reservedKeyIds] master sentinels are skipped: reaping one leaves its entries undecryptable.
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

    // Same producer as the factory's aliases; two spellings drifting apart would reap live keys.
    val prefixWithDelimiter = "${KSafeAliasFormat.dottedBase(fileName)}."
    val sePrefixWithDelimiter = "$seKeyTagPrefix$prefixWithDelimiter"

    val orphanedKeyIds = mutableSetOf<KeychainOrphan>()

    // Null value-callbacks: the dict won't retain, so hold the bridged +1 until after the query.
    val serviceRef = CFBridgingRetain(serviceName)
    try {
        forEachKeychainAttributeDict({ query ->
            CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword)
            CFDictionarySetValue(query, kSecAttrService, serviceRef)
        }) { dict ->
            val account = dict.objectForKey(kSecAttrAccount as Any) as? String
            if (account != null) {
                // ownedKeyIds = validKeys: a root key with a byte-identical dotted account is never
                // reaped, so a named store's orphans are never reaped either and stay as litter.
                val orphan =
                    keychainOrphanKeyId(account, prefixWithDelimiter, fileName, validKeys, reservedKeyIds, isInFlight, ownedKeyIds = validKeys)
                        ?: keychainOrphanKeyId(account, sePrefixWithDelimiter, fileName, validKeys, reservedKeyIds, isInFlight, ownedKeyIds = validKeys)
                if (orphan != null) orphanedKeyIds.add(orphan)
            }
        }
    } finally {
        CFRelease(serviceRef)
    }

    // SE keys can be orphaned by a crash between key creation and wrapped-key storage.
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

    // Re-check in-flight at delete time: sweep and writes run in parallel on Native, so a `put`
    // that re-used a key after classify would otherwise lose its live key.
    for (keyId in keychainOrphansToDelete(orphanedKeyIds, isInFlight)) {
        engine.deleteKeySuspend("$prefixWithDelimiter$keyId")
    }
}

/** Enumerates Keychain items matching [configure]'s query; the caller keeps ownership of whatever it bridges in. */
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
