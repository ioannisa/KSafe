@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.await
import kotlin.js.JsString
import kotlin.js.Promise

/**
 * Kotlin/Wasm actuals for the WebAuthn interop surface (see `KSafeBiometrics.web.kt` for
 * the ceremony semantics). The [_webAuthnCall] JS body is behaviourally identical to the
 * Kotlin/JS dispatcher in `KSafeBiometrics.js.kt`; only the binding (`@JsFun` vs `js()`)
 * differs. External functions are private (Kotlin/WASM requirement) and the internal
 * `actual` functions delegate to them.
 */
@JsFun(
    """
    (op, arg) => {
      var G = (typeof globalThis !== 'undefined') ? globalThis : self;
      if (!G.__ksafeWebAuthn) {
        var b64uToBuf = function(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '=';
          var bin = atob(s); var u = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u.buffer; };
        var bufToB64u = function(b) { var u = new Uint8Array(b); var s = ''; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
          return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
        var rnd = function(n) { var u = new Uint8Array(n); G.crypto.getRandomValues(u); return u; };
        var errName = function(e) { return (e && e.name) ? e.name : 'unknown'; };
        var outcomeOf = function(e) { return (errName(e) === 'NotAllowedError' ? 'denied:' : 'error:') + errName(e); };
        G.__ksafeWebAuthn = function(op, arg) {
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
      }
      return G.__ksafeWebAuthn(op, arg);
    }
    """
)
private external fun _webAuthnCall(op: String, arg: String?): Promise<JsString>

internal actual suspend fun webAuthnCall(op: String, arg: String?): String =
    _webAuthnCall(op, arg).await<JsString>().toString()

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
