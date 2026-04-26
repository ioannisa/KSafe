package eu.anifantakis.lib.ksafe.biometrics

/**
 * JVM implementation of [KSafeBiometrics] platform helpers — no-op.
 *
 * The JVM target has no biometric hardware. All calls return `true` so shared
 * KMP business logic can call into this module without branching. If you need
 * hard refusal behaviour on the JVM, gate the call in your own code.
 */

internal actual suspend fun platformVerifyBiometric(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
): Boolean = true

internal actual fun platformVerifyBiometricDirect(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    onResult: (Boolean) -> Unit,
) { onResult(true) }

internal actual fun platformClearBiometricAuth(scope: String?) { /* no-op */ }
