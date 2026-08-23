package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.await
import kotlin.js.Promise

private val readStoredAesKeySize: (String) -> Promise<Any?> = js(
    """
    (function(name) {
      return new Promise(function(resolve, reject) {
        var request = indexedDB.open('ksafe-keys', 1);
        request.onupgradeneeded = function() {
          if (!request.result.objectStoreNames.contains('keys')) {
            request.result.createObjectStore('keys');
          }
        };
        request.onerror = function() { reject(request.error); };
        request.onsuccess = function() {
          var db = request.result;
          var get = db.transaction('keys', 'readonly').objectStore('keys').get(name);
          get.onerror = function() { db.close(); reject(get.error); };
          get.onsuccess = function() {
            var key = get.result;
            db.close();
            resolve(key && key.algorithm ? String(key.algorithm.length) : null);
          };
        };
      });
    })
    """
)

internal actual suspend fun storedWebAesKeySizeBits(idbName: String): Int? =
    (readStoredAesKeySize(idbName).await() as String?)?.toInt()
