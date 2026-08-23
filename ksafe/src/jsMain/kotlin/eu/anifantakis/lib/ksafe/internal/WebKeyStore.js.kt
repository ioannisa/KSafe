package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.await
import kotlin.js.Promise

/**
 * Kotlin/JS actuals for [webKeyEnsure] et al. The store is [WebKeyStoreJsSource.FACTORY] and the
 * op dispatch is [WebKeyStoreJsSource.OP_ROUTING], both shared with the wasmJs twin; only the
 * binding and where the built store is cached are per-target. The `js(...)` string must reference
 * no Kotlin identifiers — the IR compiler renames parameters, so referencing them inside `js(...)`
 * fails at runtime — hence the closure-returning-a-dispatcher shape, which also keeps the built
 * store in module scope rather than a page global shared with any other loaded copy.
 */
private const val DISPATCH_JS: String = """
    (function() {
      var wk = null;
      var init = ${WebKeyStoreJsSource.FACTORY};
      return function(op, a, b, c) {
        if (!wk) wk = init();
        ${WebKeyStoreJsSource.OP_ROUTING}
      };
    })()
    """

private val dispatch: (String, String, String?, String?) -> Promise<Any?> = js(DISPATCH_JS)

@PublishedApi
internal actual suspend fun webKeyEnsure(
    idbName: String,
    legacyRawKeyB64: String?,
    mintIfAbsent: Boolean,
    keySizeBits: Int,
) {
    dispatch(
        if (mintIfAbsent) WebKeyStoreOps.ENSURE else WebKeyStoreOps.ENSURE_NO_MINT,
        idbName,
        legacyRawKeyB64,
        keySizeBits.toString(),
    ).await()
}

@PublishedApi
internal actual suspend fun webKeyEncrypt(idbName: String, plaintextB64: String, aadB64: String?): String =
    dispatch(WebKeyStoreOps.ENCRYPT, idbName, plaintextB64, aadB64).await() as String

@PublishedApi
internal actual suspend fun webKeyDecrypt(idbName: String, ivAndCipherB64: String, aadB64: String?): String =
    dispatch(WebKeyStoreOps.DECRYPT, idbName, ivAndCipherB64, aadB64).await() as String

@PublishedApi
internal actual suspend fun webKeyCopyIfAbsent(fromIdbName: String, toIdbName: String) {
    dispatch(WebKeyStoreOps.COPY_KEY, fromIdbName, toIdbName, null).await()
}

@PublishedApi
internal actual suspend fun webKeyDelete(idbName: String) {
    dispatch(WebKeyStoreOps.DELETE, idbName, null, null).await()
}

@PublishedApi
internal actual fun webKeyDeleteNoWait(idbName: String) {
    dispatch(WebKeyStoreOps.DELETE_NO_WAIT, idbName, null, null)
}
