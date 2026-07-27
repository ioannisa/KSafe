package eu.anifantakis.lib.ksafe.biometrics

/**
 * The WebAuthn ceremony dispatcher as JavaScript source, shared by both web targets: a
 * self-contained IIFE evaluating to `(op, arg) -> Promise<String>` with the outcome contract
 * documented on [webAuthnCall], keeping the in-flight ceremony's `AbortController` in its closure.
 *
 * It lives here as a `const val` because that is the one shape both interop primitives accept:
 * `js(...)` and `@JsFun(...)` each require a compile-time constant, and a constant may be
 * assembled from other constants. Only the wrapper is per-target — `@JsFun` takes a single
 * function expression and so has nowhere to keep the returned closure between calls, while
 * Kotlin/JS holds it in a module-level property.
 *
 * The program references no Kotlin identifiers: the JS IR compiler renames parameters.
 */
internal const val WEBAUTHN_DISPATCHER_JS = """
    (function() {
      var G = (typeof globalThis !== 'undefined') ? globalThis : self;
      function b64uToBuf(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '=';
        var bin = atob(s); var u = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u.buffer; }
      function bufToB64u(b) { var u = new Uint8Array(b); var s = ''; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
      function rnd(n) { var u = new Uint8Array(n); G.crypto.getRandomValues(u); return u; }
      function errName(e) { return (e && e.name) ? e.name : 'unknown'; }
      function outcomeOf(e) { return (errName(e) === 'NotAllowedError' ? 'denied:' : 'error:') + errName(e); }
      var currentAbort = null;
      function armAbort() { var c = (typeof G.AbortController !== 'undefined') ? new G.AbortController() : null; currentAbort = c; return c; }
      function disarm(c) { if (currentAbort === c) currentAbort = null; }
      return function(op, arg) {
        try {
          if (op === 'abort') {
            if (currentAbort) { currentAbort.abort(); currentAbort = null; }
            return Promise.resolve('aborted');
          }
          if (op === 'available') {
            if (!G.isSecureContext) return Promise.resolve('no:insecure-context');
            if (typeof G.PublicKeyCredential === 'undefined') return Promise.resolve('no:no-webauthn');
            return G.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
              .then(function(ok) { return ok ? 'yes' : 'no:no-platform-authenticator'; })
              .catch(function(e) { return 'no:' + errName(e); });
          }
          if (op === 'signalUnknown') {
            // Tell the passkey provider we no longer recognise this credential, so the orphan a
            // reset leaves behind can be dropped instead of sitting next to the new entry. Purely
            // best-effort: unsupported browsers and providers that ignore the signal simply keep
            // the passkey, which is exactly the behaviour before this call existed.
            if (!G.PublicKeyCredential || !G.PublicKeyCredential.signalUnknownCredential) {
              return Promise.resolve('signal:unsupported');
            }
            // rpId is the origin's effective domain: registration does not set rp.id, so the
            // browser defaulted it to exactly this.
            return G.PublicKeyCredential.signalUnknownCredential({ rpId: G.location.hostname, credentialId: arg })
              .then(function() { return 'signal:ok'; })
              .catch(function(e) { return 'signal:' + errName(e); });
          }
          if (op === 'register') {
            // The passkey's visible name; falls back to the library name when the app sets none.
            var pkName = (arg && arg.length) ? arg : 'KSafe';
            var rc = armAbort();
            return G.navigator.credentials.create({ publicKey: {
              challenge: rnd(32),
              rp: { name: pkName },
              user: { id: rnd(16), name: pkName, displayName: pkName },
              pubKeyCredParams: [ { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 } ],
              // residentKey 'discouraged': KSafe stores the id in localStorage and passes allowCredentials on
              // verify, so a non-discoverable credential suffices. 'preferred' made Windows Hello try to SAVE a
              // discoverable passkey (Microsoft Password Manager) and fail with 'problem saving your passkey'.
              authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'discouraged', requireResidentKey: false },
              timeout: 120000,
              attestation: 'none'
            }, signal: rc ? rc.signal : undefined }).then(function(cred) { disarm(rc); return 'registered:' + bufToB64u(cred.rawId); })
              .catch(function(e) { disarm(rc); return outcomeOf(e); });
          }
          if (op === 'verify') {
            var vc = armAbort();
            return G.navigator.credentials.get({ publicKey: {
              challenge: rnd(32),
              allowCredentials: [ { type: 'public-key', id: b64uToBuf(arg) } ],
              userVerification: 'required',
              timeout: 120000
            }, signal: vc ? vc.signal : undefined }).then(function() { disarm(vc); return 'verified'; })
              .catch(function(e) { disarm(vc); return outcomeOf(e); });
          }
          return Promise.resolve('error:unknown-op');
        } catch (e) { return Promise.resolve('error:' + errName(e)); }
      };
    })()
    """
