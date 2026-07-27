package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.internal.KSafeEngineMessage

/**
 * Rotation-scoped retry classification: everything [isTransientDecryptFailure] retries,
 * PLUS a temporarily unreachable key store ("vault unavailable" — locked OS keyring,
 * headless launch). For plain reads that signal is deliberately NOT retryable (the caller
 * gets the default rather than a throw), but a rotation must treat an outage as "pause
 * and retry next pass" — the entry stays readable under its recorded generation — never
 * as a failed entry, or an operator would read a transient outage as data damage.
 */
internal fun isRotationRetryable(e: Throwable): Boolean =
    isTransientDecryptFailure(e) ||
        e.message?.contains(KSafeEngineMessage.VAULT_UNAVAILABLE, ignoreCase = true) == true

internal fun isTransientDecryptFailure(e: Throwable): Boolean {
    val msg = e.message ?: return false
    // KSafe's OWN definitive results (key absent, vault unavailable) are never retryable —
    // exclude them first so a store literally named "keystore" doesn't get its missing-key
    // reads misclassified as a retryable hiccup and throw instead of returning the default.
    if (msg.contains(KSafeEngineMessage.NO_KEY, ignoreCase = true) ||
        msg.contains(KSafeEngineMessage.KEY_NOT_FOUND, ignoreCase = true) ||
        msg.contains(KSafeEngineMessage.VAULT_UNAVAILABLE, ignoreCase = true)
    ) {
        return false
    }
    // Android Keystore (device locked / Keystore crashed) and iOS Keychain (locked keychain /
    // Secure Enclave busy) surface as recognisable message strings; JVM software encryption
    // never produces these. Treated as retryable so callers can await unlock rather than
    // silently getting the default.
    return msg.contains(KSafeEngineMessage.DEVICE_LOCKED, ignoreCase = true) ||
        msg.contains(KSafeEngineMessage.KEYSTORE, ignoreCase = true) ||
        msg.contains(KSafeEngineMessage.KEYCHAIN, ignoreCase = true)
}
