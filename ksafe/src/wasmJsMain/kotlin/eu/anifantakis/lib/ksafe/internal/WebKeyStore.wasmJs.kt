@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.await
import kotlin.js.JsAny
import kotlin.js.JsString
import kotlin.js.Promise

/**
 * Kotlin/Wasm actuals for [webKeyEnsure] et al.
 *
 * The JS body of [wkDispatch] is kept byte-identical to the Kotlin/JS variant
 * in `WebKeyStore.js.kt`; only the binding mechanism (`@JsFun` vs `js()`)
 * differs. enc/dec resolve to JS strings; ensure/del resolve to null.
 */
@JsFun(
    """
    (op, a, b) => {
      var G = (typeof globalThis !== 'undefined') ? globalThis : self;
      if (!G.__ksafeWK) {
        var DBN = 'ksafe-keys', STORE = 'keys';
        var open = function() { return new Promise(function(res, rej) {
          var rq = G.indexedDB.open(DBN, 1);
          rq.onupgradeneeded = function() { rq.result.createObjectStore(STORE); };
          rq.onsuccess = function() { res(rq.result); };
          rq.onerror = function() { rej(rq.error); };
        }); };
        var idbGet = function(n) { return open().then(function(db) { return new Promise(function(res, rej) {
          var r = db.transaction(STORE, 'readonly').objectStore(STORE).get(n);
          r.onsuccess = function() { res(r.result == null ? null : r.result); };
          r.onerror = function() { rej(r.error); };
        }); }); };
        var idbPut = function(n, v) { return open().then(function(db) { return new Promise(function(res, rej) {
          var r = db.transaction(STORE, 'readwrite').objectStore(STORE).put(v, n);
          r.onsuccess = function() { res(true); };
          r.onerror = function() { rej(r.error); };
        }); }); };
        var idbDel = function(n) { return open().then(function(db) { return new Promise(function(res, rej) {
          var r = db.transaction(STORE, 'readwrite').objectStore(STORE).delete(n);
          r.onsuccess = function() { res(true); };
          r.onerror = function() { rej(r.error); };
        }); }); };
        var b2u = function(b64) { var s = atob(b64); var u = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; };
        var u2b = function(buf) { var u = new Uint8Array(buf); var s = ''; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); };
        var mem = new Map();
        var subtle = G.crypto.subtle;
        // Legacy-first: a legacy localStorage raw key, WHEN PRESENT, is
        // authoritative — it provably encrypted the current ciphertext. Import
        // it and OVERWRITE any (possibly stale, from a prior lifecycle)
        // IndexedDB key under this name. Only fall back to an existing IDB key
        // when there is no legacy key. (Old code trusted an existing IDB key
        // first and ignored legacy → a stale IDB key shadowed the real key and
        // every encrypted value silently reset; see the 2.0.0→2.1.0 data-loss
        // regression — JVM had the identical flaw.)
        var ensure = function(name, legacy) {
          if (mem.has(name)) return Promise.resolve(null);
          if (legacy) { return subtle.importKey('raw', b2u(legacy), 'AES-GCM', false, ['encrypt', 'decrypt']).then(function(nk) { return idbPut(name, nk).then(function() { mem.set(name, nk); return null; }); }); }
          return idbGet(name).then(function(k) {
            if (k) { mem.set(name, k); return null; }
            return subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']).then(function(nk) { return idbPut(name, nk).then(function() { mem.set(name, nk); return null; }); });
          });
        };
        var keyOf = function(name) { if (mem.has(name)) return Promise.resolve(mem.get(name));
          return idbGet(name).then(function(k) { if (k) mem.set(name, k); return k; }); };
        var enc = function(name, dataB64) { return keyOf(name).then(function(k) {
          if (!k) throw new Error('KSafe: web key missing: ' + name);
          var iv = G.crypto.getRandomValues(new Uint8Array(12));
          return subtle.encrypt({ name: 'AES-GCM', iv: iv }, k, b2u(dataB64)).then(function(ctBuf) {
            var ct = new Uint8Array(ctBuf);
            var out = new Uint8Array(iv.length + ct.length);
            out.set(iv, 0); out.set(ct, iv.length);
            return u2b(out.buffer);
          });
        }); };
        var dec = function(name, dataB64) { return keyOf(name).then(function(k) {
          if (!k) throw new Error('KSafe: web key missing: ' + name);
          var all = b2u(dataB64); var iv = all.slice(0, 12); var ct = all.slice(12);
          return subtle.decrypt({ name: 'AES-GCM', iv: iv }, k, ct).then(function(ptBuf) { return u2b(ptBuf); });
        }); };
        var del = function(name) { mem['delete'](name); return idbDel(name).then(function() { return null; }); };
        G.__ksafeWK = { ensure: ensure, enc: enc, dec: dec, del: del };
      }
      var wk = G.__ksafeWK;
      if (op === 'ensure') return wk.ensure(a, b);
      if (op === 'enc') return wk.enc(a, b);
      if (op === 'dec') return wk.dec(a, b);
      if (op === 'delnw') return wk.del(a).catch(function() { return null; });
      return wk.del(a);
    }
    """
)
private external fun wkDispatch(op: String, a: String, b: String?): Promise<JsAny?>

@PublishedApi
internal actual suspend fun webKeyEnsure(idbName: String, legacyRawKeyB64: String?) {
    wkDispatch("ensure", idbName, legacyRawKeyB64).await<JsAny?>()
}

@PublishedApi
internal actual suspend fun webKeyEncrypt(idbName: String, plaintextB64: String): String =
    (wkDispatch("enc", idbName, plaintextB64).await() as JsString).toString()

@PublishedApi
internal actual suspend fun webKeyDecrypt(idbName: String, ivAndCipherB64: String): String =
    (wkDispatch("dec", idbName, ivAndCipherB64).await() as JsString).toString()

@PublishedApi
internal actual suspend fun webKeyDelete(idbName: String) {
    wkDispatch("del", idbName, null).await<JsAny?>()
}

@PublishedApi
internal actual fun webKeyDeleteNoWait(idbName: String) {
    // 'delnw' swallows rejection JS-side; dropping the Promise is safe.
    wkDispatch("delnw", idbName, null)
}
