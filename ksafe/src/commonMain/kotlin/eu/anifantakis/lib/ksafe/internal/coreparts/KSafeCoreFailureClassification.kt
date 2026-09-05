package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.internal.KSafeEngineMessage

// Rotation also retries an unreachable vault: plain reads treat that as definitive (the caller
// gets the default), but a rotation must pause and retry, not mark the entry failed.
internal fun isRotationRetryable(e: Throwable): Boolean =
    isTransientDecryptFailure(e) ||
        e.message?.contains(KSafeEngineMessage.VAULT_UNAVAILABLE, ignoreCase = true) == true

// Only a definitive key miss lets the orphan sweep reclaim ciphertext; anything else preserves it.
internal fun isOrphanProbeFailure(e: Throwable): Boolean =
    KSafeEngineMessage.isDefinitiveKeyMiss(e.message)

internal fun isTransientDecryptFailure(e: Throwable): Boolean {
    val msg = e.message ?: return false
    // Definitive results first: a store literally named "keystore" would otherwise have its
    // missing-key reads misclassified as retryable and throw instead of returning the default.
    if (KSafeEngineMessage.isDefinitiveKeyMiss(msg) ||
        msg.contains(KSafeEngineMessage.VAULT_UNAVAILABLE, ignoreCase = true)
    ) {
        return false
    }
    // A locked Android Keystore or iOS Keychain surfaces as these message strings; retryable so
    // callers can await unlock instead of silently getting the default.
    return msg.contains(KSafeEngineMessage.DEVICE_LOCKED, ignoreCase = true) ||
        msg.contains(KSafeEngineMessage.KEYSTORE, ignoreCase = true) ||
        msg.contains(KSafeEngineMessage.KEYCHAIN, ignoreCase = true)
}
