package eu.anifantakis.lib.ksafe.internal

/**
 * The one JS source of the web key store: the js and wasmJs bindings reach IndexedDB and WebCrypto
 * through different interop, so it stays JS text, and `const val` so both can inline it.
 */
internal object WebKeyStoreJsSource {

    /** Op dispatch, written against a store the caller bound to `wk` and the arguments `op, a, b, c`. */
    const val OP_ROUTING: String = """
      if (op === '${WebKeyStoreOps.ENSURE}') return wk.ensure(a, b, true, c);
      if (op === '${WebKeyStoreOps.ENSURE_NO_MINT}') return wk.ensure(a, b, false, c);
      if (op === '${WebKeyStoreOps.ENCRYPT}') return wk.enc(a, b, c);
      if (op === '${WebKeyStoreOps.DECRYPT}') return wk.dec(a, b, c);
      if (op === '${WebKeyStoreOps.COPY_KEY}') return wk.copyIfAbsent(a, b);
      if (op === '${WebKeyStoreOps.DELETE_NO_WAIT}') return wk.del(a).catch(function() { return null; });
      // Fallthrough, deliberately arm-less: '${WebKeyStoreOps.DELETE}' and anything unrecognised.
      return wk.del(a);
    """

    /**
     * Zero-argument factory returning `{ ensure, enc, dec, del, copyIfAbsent }`; callers cache the
     * built object. Property access is written `mem['delete'](…)` so both toolchains parse it.
     */
    const val FACTORY: String = """
    (function() {
      var G = (typeof globalThis !== 'undefined') ? globalThis : self;
      var DBN = 'ksafe-keys', STORE = 'keys';
      // One cached connection per page: per-op opens churn, and a never-closed connection
      // with no onversionchange would block any future deleteDatabase/schema upgrade.
      // versionchange/close drop the cache so the next op reopens cleanly.
      var dbP = null;
      var open = function() {
        if (dbP) return dbP;
        var p = new Promise(function(res, rej) {
          var rq = G.indexedDB.open(DBN, 1);
          rq.onupgradeneeded = function() { rq.result.createObjectStore(STORE); };
          rq.onsuccess = function() {
            var db = rq.result;
            db.onversionchange = function() { db.close(); if (dbP === p) dbP = null; };
            db.onclose = function() { if (dbP === p) dbP = null; };
            res(db);
          };
          rq.onerror = function() { if (dbP === p) dbP = null; rej(rq.error); };
        });
        dbP = p;
        return p;
      };
      var idbGet = function(n) { return open().then(function(db) { return new Promise(function(res, rej) {
        var r = db.transaction(STORE, 'readonly').objectStore(STORE).get(n);
        r.onsuccess = function() { res(r.result == null ? null : r.result); };
        r.onerror = function() { rej(r.error); };
      }); }); };
      // Durable only at TRANSACTION COMMIT: request.onsuccess fires before the commit and a
      // late abort (quota/IO) can still discard the write — resolving early let ciphertext
      // commit against a key record that never persisted.
      var idbPut = function(n, v) { return open().then(function(db) { return new Promise(function(res, rej) {
        var tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).put(v, n);
        tx.oncomplete = function() { res(true); };
        tx.onabort = tx.onerror = function() { rej(tx.error || new Error('idb tx aborted')); };
      }); }); };
      // Atomic create: 'add' (unlike 'put') fails with ConstraintError if the key
      // already exists. Resolves true on insert, false if another context won the race.
      var idbAdd = function(n, v) { return open().then(function(db) { return new Promise(function(res, rej) {
        var tx = db.transaction(STORE, 'readwrite');
        var dup = false;
        var r = tx.objectStore(STORE).add(v, n);
        r.onerror = function(e) { if (r.error && r.error.name === 'ConstraintError') { dup = true; if (e && e.preventDefault) e.preventDefault(); } };
        // Reject ONLY from onabort: a request error bubbles to the transaction, and
        // preventDefault() above stops the ABORT but not the propagation — rejecting from
        // tx.onerror would beat oncomplete and turn the documented "loser adopts the winner's
        // key" outcome into a thrown error. Any error we do NOT preventDefault still aborts,
        // so onabort covers every genuine failure.
        tx.oncomplete = function() { res(!dup); };
        tx.onabort = function() { rej(tx.error || (r && r.error) || new Error('idb tx aborted')); };
      }); }); };
      var idbDel = function(n) { return open().then(function(db) { return new Promise(function(res, rej) {
        var tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).delete(n);
        tx.oncomplete = function() { res(true); };
        tx.onabort = tx.onerror = function() { rej(tx.error || new Error('idb tx aborted')); };
      }); }); };
      var b2u = function(b64) { var s = atob(b64); var u = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; };
      var u2b = function(buf) { var u = new Uint8Array(buf); var s = ''; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); };
      var mem = new Map();
      // crypto.subtle is exposed ONLY in a SECURE CONTEXT (HTTPS, or a localhost/127.0.0.1
      // origin). On a plain-http non-localhost origin it is undefined; surface a clear, actionable
      // error the moment a crypto op needs it instead of a cryptic 'undefined.generateKey'.
      // Plain-mode / IDB-only paths (copyIfAbsent, del) keep working without it.
      var subtle = (G.crypto && G.crypto.subtle) || null;
      var requireSubtle = function() {
        if (!subtle) throw new Error('KSafe: WebCrypto (crypto.subtle) is unavailable — this page is not a secure context. Encrypted storage requires HTTPS, or a localhost / 127.0.0.1 origin (some browsers also allow file://). Serve the app over HTTPS to enable encryption.');
        return subtle;
      };
      // Cross-tab key invalidation: a key deleted in another tab (clearAll / logout) leaves this
      // tab's page-local `mem` entry stale, so it would keep encrypting under a deleted key and
      // lose those writes. The deleting tab broadcasts an eviction to drop it from `mem`.
      var bc = (typeof BroadcastChannel !== 'undefined') ? new BroadcastChannel('ksafe-keys') : null;
      if (bc) bc.onmessage = function(e) { if (e && e.data && e.data.op === 'evict' && e.data.name) mem['delete'](e.data.name); };
      // Fallback for browsers without BroadcastChannel (e.g. Safari < 15.4): a `storage` event
      // fires in OTHER same-origin tabs when localStorage changes, so it carries the eviction the
      // same way — without it a deleted key would linger in a surviving tab's `mem` and later
      // writes there would encrypt under a key already gone from IndexedDB (lost on reload).
      var evictKey = 'ksafe-keys-evict';
      if (!bc && G.localStorage && typeof G.addEventListener !== 'undefined') {
        G.addEventListener('storage', function(e) {
          if (e && e.key === evictKey && e.newValue) { try { var d = JSON.parse(e.newValue); if (d && d.name) mem['delete'](d.name); } catch (x) {} }
        });
      }
      // Legacy-first: a legacy localStorage raw key, when present, is authoritative (it provably
      // encrypted the current ciphertext) — import it and overwrite any stale IDB key.
      var ensure = function(name, legacy, mint, keyBitsRaw) {
        var keyBits = Number(keyBitsRaw);
        if (keyBits !== 128 && keyBits !== 256) throw new Error('KSafe: AES-GCM key size must be 128 or 256 bits');
        // Legacy import must precede the mem short-circuit: `mem` can hold a stale entry too.
        if (legacy) { return requireSubtle().importKey('raw', b2u(legacy), 'AES-GCM', false, ['encrypt', 'decrypt']).then(function(nk) { return idbPut(name, nk).then(function() { mem.set(name, nk); return null; }); }); }
        // No mem short-circuit: `mem` can hold a stale entry whose IDB record a concurrent
        // delete removed — trusting it here would mark the alias ensured and every later
        // encrypt would use a RAM-only key (unreadable after reload). ensure() runs once per
        // alias per session (engine-side ensured set), so always verifying IDB is cheap.
        return idbGet(name).then(function(k) {
          if (k) { mem.set(name, k); return null; }
          // Read path (mint=false): never create a key. An absent key stays absent so decrypt
          // fails recoverably ('web key missing') rather than minting one that can't decrypt.
          if (!mint) { mem['delete'](name); return null; }
          // Create via atomic 'add', not 'put': if two same-origin tabs race on first launch,
          // only one 'add' wins and the loser adopts the winner's key.
          return requireSubtle().generateKey({ name: 'AES-GCM', length: keyBits }, false, ['encrypt', 'decrypt']).then(function(nk) {
            return idbAdd(name, nk).then(function(added) {
              if (added) { mem.set(name, nk); return null; }
              return idbGet(name).then(function(existing) { if (existing) mem.set(name, existing); return null; });
            });
          });
        });
      };
      var keyOf = function(name) { if (mem.has(name)) return Promise.resolve(mem.get(name));
        return idbGet(name).then(function(k) { if (k) mem.set(name, k); return k; }); };
      var enc = function(name, dataB64, aadB64) { return keyOf(name).then(function(k) {
        if (!k) throw new Error('${KSafeEngineMessage.WEB_KEY_MISSING_PREFIX}' + name);
        var iv = G.crypto.getRandomValues(new Uint8Array(12));
        var params = aadB64 ? { name: 'AES-GCM', iv: iv, additionalData: b2u(aadB64) } : { name: 'AES-GCM', iv: iv };
        return requireSubtle().encrypt(params, k, b2u(dataB64)).then(function(ctBuf) {
          // A CryptoKey handle outlives its IDB record, so a cross-tab delete racing this write
          // would otherwise commit ciphertext no key survives reload to decrypt. Re-check the
          // record and fail recoverably ('web key missing' -> caller re-ensures and retries).
          // Residual window: a delete landing between this check and the caller's storage commit
          // still orphans that one write (reclaimed by the startup orphan sweep); closing it
          // fully needs Web Locks held across delete vs encrypt+commit.
          return idbGet(name).then(function(live) {
            if (!live) { mem['delete'](name); throw new Error('${KSafeEngineMessage.WEB_KEY_MISSING_PREFIX}' + name); }
            var ct = new Uint8Array(ctBuf);
            var out = new Uint8Array(iv.length + ct.length);
            out.set(iv, 0); out.set(ct, iv.length);
            return u2b(out.buffer);
          });
        });
      }); };
      var dec = function(name, dataB64, aadB64) { return keyOf(name).then(function(k) {
        if (!k) throw new Error('${KSafeEngineMessage.WEB_KEY_MISSING_PREFIX}' + name);
        var all = b2u(dataB64); var iv = all.slice(0, 12); var ct = all.slice(12);
        var params = aadB64 ? { name: 'AES-GCM', iv: iv, additionalData: b2u(aadB64) } : { name: 'AES-GCM', iv: iv };
        return requireSubtle().decrypt(params, k, ct).then(function(ptBuf) { return u2b(ptBuf); });
      }); };
      // Evict siblings only AFTER the IDB delete commits: an early broadcast lets another tab
      // re-read the doomed record via keyOf->idbGet and re-cache it, re-opening the very window
      // the eviction exists to close. Local mem is still dropped immediately.
      var del = function(name) { mem['delete'](name);
        return idbDel(name).then(function() {
          mem['delete'](name);
          if (bc) bc.postMessage({ op: 'evict', name: name });
          else if (G.localStorage) { try { G.localStorage.setItem(evictKey, JSON.stringify({ name: name, t: Date.now() })); } catch (x) {} }
          return null;
        }); };
      // Migrate a pre-appNamespace key record to its namespaced name, non-destructively: copy
      // only if the destination is absent (atomic 'add' won't clobber a live key) and source exists.
      var copyIfAbsent = function(from, to) {
        return idbGet(to).then(function(existing) {
          if (existing) { mem.set(to, existing); return null; }
          return idbGet(from).then(function(k) {
            if (!k) return null;
            return idbAdd(to, k).then(function(added) { if (added) mem.set(to, k); return null; });
          });
        });
      };
      return { ensure: ensure, enc: enc, dec: dec, del: del, copyIfAbsent: copyIfAbsent };
    })
    """
}
