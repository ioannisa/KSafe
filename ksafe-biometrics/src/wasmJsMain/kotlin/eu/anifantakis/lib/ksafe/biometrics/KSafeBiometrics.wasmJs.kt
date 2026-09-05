@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.await
import kotlin.js.JsString
import kotlin.js.Promise

/** Kotlin/Wasm actuals for the WebAuthn interop; externals must be private, so the actuals delegate. */
@JsFun(
    "(op, arg) => {" +
        " var G = (typeof globalThis !== 'undefined') ? globalThis : self;" +
        // @JsFun takes one function expression, so the dispatcher's state is parked on the global.
        " if (!G.__ksafeWebAuthn) { G.__ksafeWebAuthn = " + WEBAUTHN_DISPATCHER_JS + "; }" +
        " return G.__ksafeWebAuthn(op, arg);" +
        "}"
)
private external fun _webAuthnCall(op: String, arg: String?): Promise<JsString>

internal actual suspend fun webAuthnCall(op: String, arg: String?): String =
    _webAuthnCall(op, arg).await<JsString>().toString()

internal actual fun webAuthnAbort() {
    // Synchronous inside the dispatcher; the resolved Promise is irrelevant.
    _webAuthnCall("abort", null)
}

@JsFun("(key) => { const v = window.localStorage.getItem(key); return v === null ? null : v; }")
private external fun _localGet(key: String): String?

@JsFun("(key, value) => { window.localStorage.setItem(key, value); }")
private external fun _localSet(key: String, value: String)

@JsFun("(key) => { window.localStorage.removeItem(key); }")
private external fun _localRemove(key: String)

@JsFun("() => performance.now()")
private external fun _performanceNow(): Double

internal actual fun webBioLocalGet(key: String): String? = _localGet(key)

internal actual fun webBioLocalSet(key: String, value: String) = _localSet(key, value)

internal actual fun webBioLocalRemove(key: String) = _localRemove(key)

internal actual fun webBioMonotonicNowMs(): Double = _performanceNow()
