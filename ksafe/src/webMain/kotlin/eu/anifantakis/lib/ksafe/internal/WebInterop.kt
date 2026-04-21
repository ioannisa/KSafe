package eu.anifantakis.lib.ksafe.internal

/**
 * Browser localStorage + time-of-day interop declarations, shared between
 * the wasmJs and js targets. Each target provides its own `actual` bindings
 * in `WebInterop.wasmJs.kt` / `WebInterop.js.kt` because the underlying
 * JS-interop mechanisms (`@JsFun` for Kotlin/WASM vs. `external` for
 * Kotlin/JS) are different.
 *
 * All declarations are `@PublishedApi internal` so they can be referenced
 * from `public inline` KSafe members when needed.
 */

@PublishedApi
internal expect fun localStorageGet(key: String): String?

@PublishedApi
internal expect fun localStorageSet(key: String, value: String)

@PublishedApi
internal expect fun localStorageRemove(key: String)

@PublishedApi
internal expect fun localStorageLength(): Int

@PublishedApi
internal expect fun localStorageKey(index: Int): String?

/**
 * Returns the current epoch time in milliseconds.
 *
 * On wasmJs this goes through a `@JsFun` with `BigInt` conversion.
 * On js this is simply `kotlin.js.Date.now().toLong()`.
 */
@PublishedApi
internal expect fun currentTimeMillisWeb(): Long
