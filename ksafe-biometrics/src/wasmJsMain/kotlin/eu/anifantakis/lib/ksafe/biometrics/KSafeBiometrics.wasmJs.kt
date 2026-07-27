@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.await
import kotlin.js.JsString
import kotlin.js.Promise

/**
 * Kotlin/Wasm actuals for the WebAuthn interop surface (see `KSafeBiometrics.web.kt` for the
 * ceremony semantics and [WEBAUTHN_DISPATCHER_JS] for the dispatcher shared with Kotlin/JS).
 * External functions are private (Kotlin/WASM requirement) and the internal `actual` functions
 * delegate to them.
 */
@JsFun(
    "(op, arg) => {" +
        " var G = (typeof globalThis !== 'undefined') ? globalThis : self;" +
        // @JsFun takes a single function expression, so the dispatcher's closure state has
        // nowhere to live between calls — instantiate it once and park it on the global object.
        " if (!G.__ksafeWebAuthn) { G.__ksafeWebAuthn = " + WEBAUTHN_DISPATCHER_JS + "; }" +
        " return G.__ksafeWebAuthn(op, arg);" +
        "}"
)
private external fun _webAuthnCall(op: String, arg: String?): Promise<JsString>

internal actual suspend fun webAuthnCall(op: String, arg: String?): String =
    _webAuthnCall(op, arg).await<JsString>().toString()

internal actual fun webAuthnAbort() {
    // Synchronous inside the dispatcher; the returned (already-resolved) Promise is irrelevant.
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
