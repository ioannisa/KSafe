package eu.anifantakis.lib.ksafe.internal

/**
 * Browser localStorage + time-of-day interop `expect`s, shared by the wasmJs and js targets
 * (each provides its own `actual` because `@JsFun` and `external` bindings differ).
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

/** Current epoch time in milliseconds. */
@PublishedApi
internal expect fun currentTimeMillisWeb(): Long
