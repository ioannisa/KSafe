package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.await
import kotlin.js.Promise

/**
 * Kotlin/JS actuals for [webKeyEnsure] et al.
 *
 * The whole WebCrypto + IndexedDB helper is defined once as a JS singleton on
 * `globalThis.__ksafeWK` (created lazily on first call) and driven through a
 * single dispatcher. The JS body is intentionally kept byte-identical to the
 * wasmJs `@JsFun` variant.
 */
private fun ksafeWkDispatch(op: String, a: String, b: String?): Promise<Any?> = js(
    """
    (function(op, a, b) {
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
        var ensure = function(name, legacy) { return idbGet(name).then(function(k) {
          if (mem.has(name)) return null;
          if (k) { mem.set(name, k); return null; }
          var mk = legacy
            ? subtle.importKey('raw', b2u(legacy), 'AES-GCM', false, ['encrypt', 'decrypt'])
            : subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
          return mk.then(function(nk) { return idbPut(name, nk).then(function() { mem.set(name, nk); return null; }); });
        }); };
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
    })(op, a, b)
    """
)

@PublishedApi
internal actual suspend fun webKeyEnsure(idbName: String, legacyRawKeyB64: String?) {
    ksafeWkDispatch("ensure", idbName, legacyRawKeyB64).await()
}

@PublishedApi
internal actual suspend fun webKeyEncrypt(idbName: String, plaintextB64: String): String =
    ksafeWkDispatch("enc", idbName, plaintextB64).await() as String

@PublishedApi
internal actual suspend fun webKeyDecrypt(idbName: String, ivAndCipherB64: String): String =
    ksafeWkDispatch("dec", idbName, ivAndCipherB64).await() as String

@PublishedApi
internal actual suspend fun webKeyDelete(idbName: String) {
    ksafeWkDispatch("del", idbName, null).await()
}

@PublishedApi
internal actual fun webKeyDeleteNoWait(idbName: String) {
    // Fire-and-forget: 'delnw' swallows rejection JS-side, so dropping the
    // returned Promise here cannot surface an unhandled rejection.
    ksafeWkDispatch("delnw", idbName, null)
}
