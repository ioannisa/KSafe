@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.await
import kotlin.js.JsAny
import kotlin.js.JsString
import kotlin.js.Promise

// The factory and op routing are shared with the Kotlin/JS twin. `@JsFun` bodies keep no state
// between calls, so the built store is cached on the global object.
private const val DISPATCH_JS: String = """
    (op, a, b, c) => {
      var G = (typeof globalThis !== 'undefined') ? globalThis : self;
      if (!G.__ksafeWK) G.__ksafeWK = (${WebKeyStoreJsSource.FACTORY})();
      var wk = G.__ksafeWK;
      ${WebKeyStoreJsSource.OP_ROUTING}
    }
    """

@JsFun(DISPATCH_JS)
private external fun wkDispatch(op: String, a: String, b: String?, c: String? = definedExternally): Promise<JsAny?>

@PublishedApi
internal actual suspend fun webKeyEnsure(
    idbName: String,
    legacyRawKeyB64: String?,
    mintIfAbsent: Boolean,
    keySizeBits: Int,
) {
    wkDispatch(
        if (mintIfAbsent) WebKeyStoreOps.ENSURE else WebKeyStoreOps.ENSURE_NO_MINT,
        idbName,
        legacyRawKeyB64,
        keySizeBits.toString(),
    ).await<JsAny?>()
}

@PublishedApi
internal actual suspend fun webKeyEncrypt(idbName: String, plaintextB64: String, aadB64: String?): String =
    (wkDispatch(WebKeyStoreOps.ENCRYPT, idbName, plaintextB64, aadB64).await() as JsString).toString()

@PublishedApi
internal actual suspend fun webKeyDecrypt(idbName: String, ivAndCipherB64: String, aadB64: String?): String =
    (wkDispatch(WebKeyStoreOps.DECRYPT, idbName, ivAndCipherB64, aadB64).await() as JsString).toString()

@PublishedApi
internal actual suspend fun webKeyCopyIfAbsent(fromIdbName: String, toIdbName: String) {
    wkDispatch(WebKeyStoreOps.COPY_KEY, fromIdbName, toIdbName).await<JsAny?>()
}

@PublishedApi
internal actual suspend fun webKeyDelete(idbName: String) {
    wkDispatch(WebKeyStoreOps.DELETE, idbName, null).await<JsAny?>()
}

@PublishedApi
internal actual fun webKeyDeleteNoWait(idbName: String) {
    wkDispatch(WebKeyStoreOps.DELETE_NO_WAIT, idbName, null)
}
