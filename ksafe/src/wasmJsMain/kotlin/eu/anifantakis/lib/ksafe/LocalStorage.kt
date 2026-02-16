@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package eu.anifantakis.lib.ksafe

/**
 * Browser localStorage access via Kotlin/WASM JS interop.
 *
 * These functions provide synchronous access to the browser's localStorage API.
 * localStorage is scoped per origin and persists across browser sessions.
 *
 * Marked `@PublishedApi` so they can be called from public inline functions in KSafe.
 */

@JsFun("(key) => { const v = window.localStorage.getItem(key); return v === null ? null : v; }")
@PublishedApi
internal external fun localStorageGet(key: String): String?

@JsFun("(key, value) => { window.localStorage.setItem(key, value); }")
@PublishedApi
internal external fun localStorageSet(key: String, value: String)

@JsFun("(key) => { window.localStorage.removeItem(key); }")
@PublishedApi
internal external fun localStorageRemove(key: String)

@JsFun("() => { return window.localStorage.length; }")
@PublishedApi
internal external fun localStorageLength(): Int

@JsFun("(index) => { const k = window.localStorage.key(index); return k === null ? null : k; }")
@PublishedApi
internal external fun localStorageKey(index: Int): String?
