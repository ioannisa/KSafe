package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.browser.localStorage
import kotlinx.coroutines.await
import kotlin.js.Promise

/**
 * Kotlin/JS actuals for the WebAuthn interop surface (see `KSafeBiometrics.web.kt` for
 * the ceremony semantics). The dispatcher is a self-contained JS IIFE — the `js(...)`
 * string references no Kotlin identifiers (the IR compiler renames parameters). Kept
 * behaviourally identical to the wasmJs `@JsFun` variant.
 */
private val webAuthnDispatch: (String, String?) -> Promise<Any?> = js(
    """
    (function() {
      var G = (typeof globalThis !== 'undefined') ? globalThis : self;
      function b64uToBuf(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '=';
        var bin = atob(s); var u = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u.buffer; }
      function bufToB64u(b) { var u = new Uint8Array(b); var s = ''; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+${'$'}/, ''); }
      function rnd(n) { var u = new Uint8Array(n); G.crypto.getRandomValues(u); return u; }
      function errName(e) { return (e && e.name) ? e.name : 'unknown'; }
      function outcomeOf(e) { return (errName(e) === 'NotAllowedError' ? 'denied:' : 'error:') + errName(e); }
      return function(op, arg) {
        try {
          if (op === 'available') {
            if (!G.isSecureContext) return Promise.resolve('no:insecure-context');
            if (typeof G.PublicKeyCredential === 'undefined') return Promise.resolve('no:no-webauthn');
            return G.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
              .then(function(ok) { return ok ? 'yes' : 'no:no-platform-authenticator'; })
              .catch(function(e) { return 'no:' + errName(e); });
          }
          if (op === 'register') {
            return G.navigator.credentials.create({ publicKey: {
              challenge: rnd(32),
              rp: { name: 'KSafe' },
              user: { id: rnd(16), name: 'ksafe', displayName: 'KSafe' },
              pubKeyCredParams: [ { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 } ],
              authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
              timeout: 120000,
              attestation: 'none'
            }}).then(function(cred) { return 'registered:' + bufToB64u(cred.rawId); })
              .catch(function(e) { return outcomeOf(e); });
          }
          if (op === 'verify') {
            return G.navigator.credentials.get({ publicKey: {
              challenge: rnd(32),
              allowCredentials: [ { type: 'public-key', id: b64uToBuf(arg) } ],
              userVerification: 'required',
              timeout: 120000
            }}).then(function() { return 'verified'; })
              .catch(function(e) { return outcomeOf(e); });
          }
          return Promise.resolve('error:unknown-op');
        } catch (e) { return Promise.resolve('error:' + errName(e)); }
      };
    })()
    """
)

internal actual suspend fun webAuthnCall(op: String, arg: String?): String =
    webAuthnDispatch(op, arg).await() as String

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
