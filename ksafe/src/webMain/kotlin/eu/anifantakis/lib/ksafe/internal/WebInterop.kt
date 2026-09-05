package eu.anifantakis.lib.ksafe.internal

// Browser localStorage and clock expects; wasmJs and js each bind them their own way.

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

/** Browsers withhold `crypto.subtle` outside a secure context (HTTPS or localhost); encrypted ops then fail. */
@PublishedApi
internal expect fun webCryptoSubtleAvailable(): Boolean

internal const val WEB_SUBTLE_AVAILABLE_JS: String = "!!(globalThis.crypto && globalThis.crypto.subtle)"
