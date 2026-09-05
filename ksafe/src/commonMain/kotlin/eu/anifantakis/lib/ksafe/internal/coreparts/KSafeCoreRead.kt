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

        // Strict (requireUnlockedDevice) entries ALWAYS take the native-decrypt branch, even
        // under a plaintext memory policy, so a locked-device read never returns the secret
        // straight from RAM. Their slot normally holds ciphertext, but TRANSIENTLY holds
        // plaintext during the optimistic write window — so the failure path below must also
        // refuse to fall through to that plaintext (the reqUnlocked guard on the fallback).
        if (cacheHoldsCiphertext || reqUnlocked) {
            if (usesPlaintextSideCache && !reqUnlocked) {
                val cached = plaintextCache[cacheKey]
                if (cached != null && plaintextStillValid(cached)) {
                    if (cached.value == NULL_SENTINEL) return nullOrDefault(defaultValue, serializer)
                    try {
                        return jsonDecode(json, serializer, cached.value)
                    } catch (e: Throwable) {
                        if (e is CancellationException) throw e
                        /* fall through */
                    }
                }
            }

            try {
                val encryptedString = cachedValue as? String
                if (encryptedString != null) {
                    // Future-format entries fail closed (non-transient → the default),
                    // never misread as v3.
                    val plainBytes = decryptEntryBlocking(
                        key, protection, KSafeBase64.decode(encryptedString), entryMeta,
                    )
                    val candidate = plainBytes.decodeToString()
                    deserialized = if (candidate == NULL_SENTINEL) nullOrDefault(defaultValue, serializer)
                    else jsonDecode(json, serializer, candidate)
                    success = true
                    // Guarded write-back: the decrypt is a slow round-trip during which a
                    // put/delete may have landed, so only repopulate the side cache when the
                    // primary still holds the exact ciphertext we decrypted (CAS discipline) —
                    // otherwise we'd serve stale plaintext, permanently under LAZY_PLAIN_TEXT.
                    // Store, re-check, undo our own entry: a put may land between guard and store.
                    if (usesPlaintextSideCache && !reqUnlocked && memoryCache[cacheKey] == encryptedString) {
                        sideCacheWriteBackHook?.invoke()
                        val entry = CachedPlaintext(candidate, plaintextExpiry())
                        plaintextCache[cacheKey] = entry
                        if (memoryCache[cacheKey] != encryptedString) plaintextCache.removeIf(cacheKey, entry)
                    }
                }
            } catch (e: Throwable) {
                if (e is CancellationException) throw e
                // Transient keystore failures (locked device, hardware busy) must
                // propagate so callers can retry instead of getting silent defaults.
                if (isTransientDecryptFailure(e)) throw e
                /* else fall through to plain-text fallback */
            }
        } else {
            jsonString = cachedValue as? String
        }

        if (success) return deserialized
        // A strict entry must NEVER fall through to the cached value when native-decrypt
        // didn't succeed: during the optimistic write window the slot transiently holds
        // plaintext, and serving it would return the secret from RAM on a locked device.
        // Return the default instead (a committed strict entry holds ciphertext here anyway).
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
    // Best-effort cold-start freshness. Android/iOS/JVM block once to
    // populate the cache; web can't block so the call throws and we fall
    // through — a concurrent `getDirect` there returns its default until
    // the background preload completes.
    try {
        runBlockingOnPlatform {
            if (!cacheInitialized.get()) {
                // Epoch BEFORE snapshot — the argument-order default would read it after.
                val epoch = clearEpoch.get()
                updateCache(storage.snapshot(), epoch)
            }
        }
    } catch (e: Throwable) {
        if (e is CancellationException) throw e
        /* web: no blocking available */
    }
    // lazyLoad has no collector to run the one-time startup cleanup — trigger it once
    // here, off the caller's thread, now that a first access has readied the cache.
    triggerLazyStartupCleanupOnce()
}
