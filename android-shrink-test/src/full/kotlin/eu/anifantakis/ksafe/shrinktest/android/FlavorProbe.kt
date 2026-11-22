package eu.anifantakis.ksafe.shrinktest.android

import android.app.Instrumentation
import android.content.Intent
import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.biometrics.BiometricHelper
import eu.anifantakis.lib.ksafe.biometrics.KSafeBiometrics
import eu.anifantakis.lib.ksafe.compose.mutableStateOf
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout

// Not @Composable: the delegate works in any class, so the app needs no Compose compiler.
class ComposePrefs(ksafe: KSafe) {
    var nickname by ksafe.mutableStateOf("anon")
}

/** The part of the probe that needs ksafe-compose and ksafe-biometrics. */
object FlavorProbe {
    private const val NICKNAME = "neo"

    val KEYS = listOf("nickname")

    fun write(ksafe: KSafe) {
        ComposePrefs(ksafe).nickname = NICKNAME
    }

    fun verify(ksafe: KSafe, stage: String, check: (String, Any?, Any?) -> Unit) {
        check("$stage nickname (mutableStateOf)", ComposePrefs(ksafe).nickname, NICKNAME)
        check("$stage nickname (getDirect)", ksafe.getDirect("nickname", ""), NICKNAME)
    }

    // Nothing here may show a prompt that waits for input: the only verify is the strict one, and it
    // runs only where nothing is enrolled for it, so the OS refuses it at once.
    suspend fun describe(
        instrumentation: Instrumentation,
        fact: (String, Any?) -> Unit,
        check: (String, Any?, Any?) -> Unit,
    ) {
        val intent = Intent(instrumentation.targetContext, ProbeActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val activity = instrumentation.startActivitySync(intent)
        instrumentation.waitForIdleSync()
        try {
            // Set only by the lifecycle callbacks BiometricHelper.init registers. Asked first: the
            // availability calls can find the activity by reflection and would hide a missing init.
            val tracked = BiometricHelper.getCurrentActivity() != null
            fact("biometrics.tracksActivity", tracked)
            check("biometrics.tracksActivity", tracked, true)

            val strict = KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = false)
            fact("biometrics.available", strict)
            fact("biometrics.availableWithCredential", KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = true))
            val direct = CompletableDeferred<Boolean>()
            KSafeBiometrics.biometricsAvailableDirect(allowDeviceCredentialFallback = true) { direct.complete(it) }
            fact("biometrics.availableDirect", withTimeout(10_000) { direct.await() })
            fact("biometrics.hasUsableFragmentActivity", BiometricHelper.hasUsableFragmentActivity())

            if (tracked && !strict) {
                val verified = withTimeout(30_000) {
                    KSafeBiometrics.verifyBiometric("Shrink probe", allowDeviceCredentialFallback = false)
                }
                fact("biometrics.strictVerify", verified)
                check("biometrics.strictVerify", verified, false)
            } else {
                fact("biometrics.strictVerify", "skipped")
            }

            KSafeBiometrics.clearBiometricAuth()
            fact("biometrics.clearBiometricAuth", "ok")
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }
}
