package eu.anifantakis.lib.ksafe.biometrics

/**
 * JVM implementation of [KSafeBiometrics] — no-op.
 *
 * The JVM target has no biometric hardware. All calls return `true` so shared
 * KMP business logic can call into this module without branching. If you need
 * hard refusal behaviour on the JVM, gate the call in your own code.
 */
@Suppress("unused")
actual class KSafeBiometrics {

    actual suspend fun verifyBiometric(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?,
    ): Boolean = true

    actual fun verifyBiometricDirect(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?,
        onResult: (Boolean) -> Unit,
    ) { onResult(true) }

    actual fun clearBiometricAuth(scope: String?) { /* no-op */ }
}
