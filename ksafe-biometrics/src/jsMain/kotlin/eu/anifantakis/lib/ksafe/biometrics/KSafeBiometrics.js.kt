package eu.anifantakis.lib.ksafe.biometrics

/**
 * Kotlin/JS implementation of [KSafeBiometrics] — no-op.
 *
 * Browsers have no standardised biometric API. All calls return `true` so shared
 * KMP business logic can call into this module without branching. If you need
 * hard refusal behaviour on the web, gate the call in your own code.
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
