package eu.anifantakis.lib.ksafe.biometrics

/**
 * Kotlin/Wasm implementation of [KSafeBiometrics] platform helpers — no-op.
 *
 * Browsers have no standardised biometric API. All calls return `true` so shared
 * KMP business logic can call into this module without branching. If you need
 * hard refusal behaviour on the web, gate the call in your own code.
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
