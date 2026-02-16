@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package eu.anifantakis.lib.ksafe

/**
 * Browser localStorage access via Kotlin/WASM JS interop.
 *
 * These functions provide synchronous access to the browser's localStorage API.
 * localStorage is scoped per origin and persists across browser sessions.
 *
 * External functions are private (Kotlin/WASM requirement: external functions
 * cannot be internal due to name mangling). Internal delegating functions are
 * marked `@PublishedApi` so they can be called from public inline functions in KSafe.
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

@PublishedApi
internal fun localStorageGet(key: String): String? = _localStorageGet(key)

@PublishedApi
internal fun localStorageSet(key: String, value: String) = _localStorageSet(key, value)

@PublishedApi
internal fun localStorageRemove(key: String) = _localStorageRemove(key)

@PublishedApi
internal fun localStorageLength(): Int = _localStorageLength()

@PublishedApi
internal fun localStorageKey(index: Int): String? = _localStorageKey(index)
