@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.await
import kotlin.js.JsAny
import kotlin.js.JsString
import kotlin.js.Promise

/**
 * Kotlin/Wasm actuals for [webKeyEnsure] et al. The [wkDispatch] JS body is behaviourally
 * identical to the Kotlin/JS variant in `WebKeyStore.js.kt`; only the binding (`@JsFun` vs
 * `js()`) differs.
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
        // Atomic create: 'add' (unlike 'put') fails with ConstraintError if the key
        // already exists. Resolves true on insert, false if another context won the race.
        var idbAdd = function(n, v) { return open().then(function(db) { return new Promise(function(res, rej) {
          var r = db.transaction(STORE, 'readwrite').objectStore(STORE).add(v, n);
          r.onsuccess = function() { res(true); };
          r.onerror = function(e) { if (r.error && r.error.name === 'ConstraintError') { if (e && e.preventDefault) e.preventDefault(); res(false); } else rej(r.error); };
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
        // Cross-tab key invalidation: a key deleted in another tab (clearAll / logout) leaves this
        // tab's page-local `mem` entry stale, so it would keep encrypting under a deleted key and
        // lose those writes. The deleting tab broadcasts an eviction to drop it from `mem`.
        var bc = (typeof BroadcastChannel !== 'undefined') ? new BroadcastChannel('ksafe-keys') : null;
        if (bc) bc.onmessage = function(e) { if (e && e.data && e.data.op === 'evict' && e.data.name) mem['delete'](e.data.name); };
        // Legacy-first: a legacy localStorage raw key, when present, is authoritative (it provably
        // encrypted the current ciphertext) — import it and overwrite any stale IDB key.
        var ensure = function(name, legacy, mint) {
          // Legacy import must precede the mem short-circuit: `mem` can hold a stale entry too.
          if (legacy) { return subtle.importKey('raw', b2u(legacy), 'AES-GCM', false, ['encrypt', 'decrypt']).then(function(nk) { return idbPut(name, nk).then(function() { mem.set(name, nk); return null; }); }); }
          if (mem.has(name)) return Promise.resolve(null);
          return idbGet(name).then(function(k) {
            if (k) { mem.set(name, k); return null; }
            // Read path (mint=false): never create a key. An absent key stays absent so decrypt
            // fails recoverably ('web key missing') rather than minting one that can't decrypt.
            if (!mint) return null;
            // Create via atomic 'add', not 'put': if two same-origin tabs race on first launch,
            // only one 'add' wins and the loser adopts the winner's key.
            return subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']).then(function(nk) {
              return idbAdd(name, nk).then(function(added) {
                if (added) { mem.set(name, nk); return null; }
                return idbGet(name).then(function(existing) { if (existing) mem.set(name, existing); return null; });
              });
            });
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
        var del = function(name) { mem['delete'](name); if (bc) bc.postMessage({ op: 'evict', name: name }); return idbDel(name).then(function() { return null; }); };
        // Migrate a pre-appNamespace key record to its namespaced name, non-destructively (copy
        // only if destination absent + source exists; source left in place).
        var copyIfAbsent = function(from, to) {
          return idbGet(to).then(function(existing) {
            if (existing) { mem.set(to, existing); return null; }
            return idbGet(from).then(function(k) {
              if (!k) return null;
              return idbAdd(to, k).then(function(added) { if (added) mem.set(to, k); return null; });
            });
          });
        };
        G.__ksafeWK = { ensure: ensure, enc: enc, dec: dec, del: del, copyIfAbsent: copyIfAbsent };
      }
      var wk = G.__ksafeWK;
      if (op === 'ensure') return wk.ensure(a, b, true);
      if (op === 'ensureNoMint') return wk.ensure(a, b, false);
      if (op === 'enc') return wk.enc(a, b);
      if (op === 'dec') return wk.dec(a, b);
      if (op === 'copyKey') return wk.copyIfAbsent(a, b);
      if (op === 'delnw') return wk.del(a).catch(function() { return null; });
      return wk.del(a);
    }
    """
)
private external fun wkDispatch(op: String, a: String, b: String?): Promise<JsAny?>

@PublishedApi
internal actual suspend fun webKeyEnsure(idbName: String, legacyRawKeyB64: String?, mintIfAbsent: Boolean) {
    wkDispatch(if (mintIfAbsent) "ensure" else "ensureNoMint", idbName, legacyRawKeyB64).await<JsAny?>()
}

@PublishedApi
internal actual suspend fun webKeyEncrypt(idbName: String, plaintextB64: String): String =
    (wkDispatch("enc", idbName, plaintextB64).await() as JsString).toString()

@PublishedApi
internal actual suspend fun webKeyDecrypt(idbName: String, ivAndCipherB64: String): String =
    (wkDispatch("dec", idbName, ivAndCipherB64).await() as JsString).toString()

@PublishedApi
internal actual suspend fun webKeyCopyIfAbsent(fromIdbName: String, toIdbName: String) {
    wkDispatch("copyKey", fromIdbName, toIdbName).await<JsAny?>()
}

@PublishedApi
internal actual suspend fun webKeyDelete(idbName: String) {
    wkDispatch("del", idbName, null).await<JsAny?>()
}

@PublishedApi
internal actual fun webKeyDeleteNoWait(idbName: String) {
    // 'delnw' swallows rejection JS-side; dropping the Promise is safe.
    wkDispatch("delnw", idbName, null)
}
