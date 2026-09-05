@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package eu.anifantakis.lib.ksafe.internal

// The external functions are private because Kotlin/Wasm forbids internal ones (name mangling);
// the internal actuals below delegate to them.

@JsFun("(key) => { const v = window.localStorage.getItem(key); return v === null ? null : v; }")
private external fun _localStorageGet(key: String): String?

@JsFun("(key, value) => { window.localStorage.setItem(key, value); }")
private external fun _localStorageSet(key: String, value: String)

@JsFun("(key) => { window.localStorage.removeItem(key); }")
private external fun _localStorageRemove(key: String)

@JsFun("() => { return window.localStorage.length; }")
private external fun _localStorageLength(): Int

@JsFun("(index) => { const k = window.localStorage.key(index); return k === null ? null : k; }")
private external fun _localStorageKey(index: Int): String?

// Kotlin/Wasm marshals Long as BigInt.
@JsFun("() => { return BigInt(Date.now()); }")
private external fun _currentTimeMillis(): Long

private const val SUBTLE_AVAILABLE_FN_JS: String = "() => { return $WEB_SUBTLE_AVAILABLE_JS; }"

@JsFun(SUBTLE_AVAILABLE_FN_JS)
private external fun _webCryptoSubtleAvailable(): Boolean

@PublishedApi
internal actual fun localStorageGet(key: String): String? = _localStorageGet(key)

@PublishedApi
internal actual fun localStorageSet(key: String, value: String) = _localStorageSet(key, value)

@PublishedApi
internal actual fun localStorageRemove(key: String) = _localStorageRemove(key)

@PublishedApi
internal actual fun localStorageLength(): Int = _localStorageLength()

@PublishedApi
internal actual fun localStorageKey(index: Int): String? = _localStorageKey(index)

@PublishedApi
internal actual fun currentTimeMillisWeb(): Long = _currentTimeMillis()

@PublishedApi
internal actual fun webCryptoSubtleAvailable(): Boolean = _webCryptoSubtleAvailable()
