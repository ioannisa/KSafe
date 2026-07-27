package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.browser.localStorage
import kotlinx.coroutines.await
import kotlin.js.Promise

/**
 * Kotlin/JS actuals for the WebAuthn interop surface (see `KSafeBiometrics.web.kt` for the
 * ceremony semantics and [WEBAUTHN_DISPATCHER_JS] for the dispatcher shared with Kotlin/Wasm).
 */
private val webAuthnDispatch: (String, String?) -> Promise<Any?> = js(WEBAUTHN_DISPATCHER_JS)

internal actual suspend fun webAuthnCall(op: String, arg: String?): String =
    webAuthnDispatch(op, arg).await() as String

internal actual fun webAuthnAbort() {
    // Synchronous inside the dispatcher; the returned (already-resolved) Promise is irrelevant.
    webAuthnDispatch("abort", null)
}

internal actual fun webBioLocalGet(key: String): String? = localStorage.getItem(key)

internal actual fun webBioLocalSet(key: String, value: String) {
    localStorage.setItem(key, value)
}

internal actual fun webBioLocalRemove(key: String) {
    localStorage.removeItem(key)
}

internal actual fun webBioMonotonicNowMs(): Double = jsPerformanceNow()

@Suppress("UNUSED_PARAMETER", "RedundantSuppression")
private fun jsPerformanceNow(): Double = js("performance.now()").unsafeCast<Double>()
