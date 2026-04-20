@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package eu.anifantakis.lib.ksafe

/**
 * wasmJs actual implementations of the web-interop surface.
 *
 * External functions are private (Kotlin/WASM requirement: external functions
 * cannot be internal due to name mangling). The internal `actual` functions
 * below delegate to them.
 */

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

@JsFun("() => { return BigInt(Date.now()); }")
private external fun _currentTimeMillis(): Long

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
