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

/**
 * iOS-only Keychain orphan sweep.
 *
 * DataStore's orphan-ciphertext cleanup (in [KSafeCore.cleanupOrphanedCiphertext])
 * handles the "Keystore wiped but DataStore restored from backup" case — the
 * common Android reinstall scenario. The reverse problem is iOS-specific:
 * the Keychain is **not** wiped on app uninstall (unless the app explicitly
 * opts out), so keys can linger after DataStore has been cleared by the user
 * via Settings or a `clearAll()` call.
 *
 * This function scans the Keychain for items this library wrote, cross-
 * references them against DataStore's current key set, and deletes Keychain
 * entries with no surviving DataStore counterpart. It covers two item
 * classes:
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
 */
@OptIn(ExperimentalForeignApi::class)
internal suspend fun cleanupOrphanedKeychainEntries(
    storage: KSafePlatformStorage,
    engine: KSafeEncryption,
    serviceName: String,
    keyPrefix: String,
    fileName: String?,
    legacyEncryptedPrefix: String,
    seKeyTagPrefix: String,
) {
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

                    // Plain keys: "{prefix}.{keyId}"
                    if (account.startsWith(prefixWithDelimiter)) {
                        val keyId = account.removePrefix(prefixWithDelimiter)
                        // When no fileName is set, prefix is "eu.anifantakis.ksafe." —
                        // be conservative and skip entries that look like they belong
                        // to a fileName-scoped instance (they contain a further ".").
                        if (fileName == null && keyId.contains('.')) continue
                        if (keyId !in validKeys) orphanedKeyIds.add(keyId)
                    }
                    // SE-wrapped keys: "se.{prefix}.{keyId}"
                    else if (account.startsWith(sePrefixWithDelimiter)) {
                        val keyId = account.removePrefix(sePrefixWithDelimiter)
                        if (fileName == null && keyId.contains('.')) continue
                        if (keyId !in validKeys) orphanedKeyIds.add(keyId)
                    }
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

                    // SE tags: "se.{prefix}.{keyId}"
                    if (tag.startsWith(sePrefixWithDelimiter)) {
                        val keyId = tag.removePrefix(sePrefixWithDelimiter)
                        if (fileName == null && keyId.contains('.')) continue
                        if (keyId !in validKeys) orphanedKeyIds.add(keyId)
                    }
                }
            }
        }
    }

    // engine.deleteKey unconditionally removes the plain key, the SE-wrapped
    // generic-password entry, and the SE EC private key for a given identifier.
    for (keyId in orphanedKeyIds) {
        engine.deleteKeySuspend("$prefixWithDelimiter$keyId")
    }
}
