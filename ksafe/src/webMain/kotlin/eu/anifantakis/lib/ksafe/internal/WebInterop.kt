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

/**
 * Whether `crypto.subtle` (WebCrypto) is exposed on this page. Browsers withhold it outside a
 * SECURE CONTEXT (HTTPS, or a localhost/127.0.0.1 origin), where every encrypted operation fails.
 */
@PublishedApi
internal expect fun webCryptoSubtleAvailable(): Boolean

/** The secure-context probe itself, so both bindings evaluate the same predicate. */
internal const val WEB_SUBTLE_AVAILABLE_JS: String = "!!(globalThis.crypto && globalThis.crypto.subtle)"
