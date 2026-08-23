@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.await
import kotlin.js.JsAny
import kotlin.js.JsString
import kotlin.js.Promise

@JsFun(
    """
    (name) => new Promise((resolve, reject) => {
      var request = indexedDB.open('ksafe-keys', 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains('keys')) {
          request.result.createObjectStore('keys');
        }
      };
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        var db = request.result;
        var get = db.transaction('keys', 'readonly').objectStore('keys').get(name);
        get.onerror = () => { db.close(); reject(get.error); };
        get.onsuccess = () => {
          var key = get.result;
          db.close();
          resolve(key && key.algorithm ? String(key.algorithm.length) : null);
        };
      };
    })
    """
)
private external fun readStoredAesKeySize(idbName: String): Promise<JsAny?>

internal actual suspend fun storedWebAesKeySizeBits(idbName: String): Int? {
    val result = readStoredAesKeySize(idbName).await<JsAny?>() ?: return null
    return (result as JsString).toString().toInt()
}
