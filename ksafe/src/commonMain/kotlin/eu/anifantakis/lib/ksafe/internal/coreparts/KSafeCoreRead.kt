package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.KSafeBase64
import eu.anifantakis.lib.ksafe.KSafeProtection
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeCore.CachedPlaintext
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.NULL_SENTINEL
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.isNullSentinel
import eu.anifantakis.lib.ksafe.internal.jsonDecode
import eu.anifantakis.lib.ksafe.internal.runBlockingOnPlatform
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.KSerializer

internal fun KSafeCore.resolveFromCache(
    key: String,
    defaultValue: Any?,
    protection: KSafeProtection?,
    serializer: KSerializer<*>,
): Any? {
    val cacheKey = if (protection != null) legacyEncryptedRawKey(key) else key
    val cachedValue = memoryCache[cacheKey] ?: return defaultValue

    return if (protection != null) {
        var jsonString: String? = null
        var deserialized: Any? = null
        var success = false

        val entryMeta = encMetaMap[key]
        val reqUnlocked = entryMeta?.requireUnlockedDevice == true

        // Strict entries always take the native-decrypt branch, even under a plaintext memory
        // policy, so a locked-device read never returns the secret straight from RAM.
        if (cacheHoldsCiphertext || reqUnlocked) {
            if (usesPlaintextSideCache && !reqUnlocked) {
                val cached = plaintextCache[cacheKey]
                if (cached != null && plaintextStillValid(cached)) {
                    if (cached.value == NULL_SENTINEL) return nullOrDefault(defaultValue, serializer)
                    try {
                        return jsonDecode(json, serializer, cached.value)
                    } catch (e: Throwable) {
                        if (e is CancellationException) throw e
                        // Corrupt side-cache entry: fall through to the native decrypt below.
                    }
                }
            }

            try {
                val encryptedString = cachedValue as? String
                if (encryptedString != null) {
                    val plainBytes = decryptEntryBlocking(
                        key, protection, KSafeBase64.decode(encryptedString), entryMeta,
                    )
                    val candidate = plainBytes.decodeToString()
                    deserialized = if (candidate == NULL_SENTINEL) nullOrDefault(defaultValue, serializer)
                    else jsonDecode(json, serializer, candidate)
                    success = true
                    // Write back only while the primary still holds the ciphertext we decrypted, then
                    // re-check and undo ours: a put may land between guard and store.
                    if (usesPlaintextSideCache && !reqUnlocked && memoryCache[cacheKey] == encryptedString) {
                        sideCacheWriteBackHook?.invoke()
                        val entry = CachedPlaintext(candidate, plaintextExpiry())
                        plaintextCache[cacheKey] = entry
                        if (memoryCache[cacheKey] != encryptedString) plaintextCache.removeIf(cacheKey, entry)
                    }
                }
            } catch (e: Throwable) {
                if (e is CancellationException) throw e
                // Transient keystore failures (locked device, hardware busy) must propagate so
                // callers can retry instead of getting silent defaults.
                if (isTransientDecryptFailure(e)) throw e
            }
        } else {
            jsonString = cachedValue as? String
        }

        if (success) return deserialized
        // A failed strict decrypt must not fall through to the cached value: during the
        // optimistic write window that slot transiently holds plaintext.
        if (reqUnlocked) return defaultValue
        if (jsonString == null) jsonString = cachedValue as? String
        if (jsonString == null) return defaultValue
        if (jsonString == NULL_SENTINEL) return nullOrDefault(defaultValue, serializer)
        try {
            jsonDecode(json, serializer, jsonString)
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
            defaultValue
        }
    } else {
        if (isNullSentinel(cachedValue)) return nullOrDefault(defaultValue, serializer)
        convertStoredValue(cachedValue, defaultValue, serializer)
    }
}

internal fun KSafeCore.ensureCacheReadyBlocking() {
    if (cacheInitialized.get()) return
    // Android/iOS/JVM block once to populate the cache; web can't block, so this throws and a
    // concurrent `getDirect` there returns its default until the background preload completes.
    try {
        runBlockingOnPlatform {
            if (!cacheInitialized.get()) {
                // Epoch read before the snapshot: the parameter default would read it after, and a
                // clearAll landing between the two would have its wiped secrets republished.
                val epoch = clearEpoch.get()
                updateCache(storage.snapshot(), epoch)
            }
        }
    } catch (e: Throwable) {
        if (e is CancellationException) throw e
    }
    // lazyLoad has no collector to run the one-time startup cleanup, so trigger it here.
    triggerLazyStartupCleanupOnce()
}
