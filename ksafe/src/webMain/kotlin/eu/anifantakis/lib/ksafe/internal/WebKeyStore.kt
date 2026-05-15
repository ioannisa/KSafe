package eu.anifantakis.lib.ksafe.internal

/**
 * Non-extractable AES-GCM key storage for the web (wasmJs + js), backed by
 * **WebCrypto + IndexedDB**.
 *
 * The previous web engine generated an *extractable* key, exported its raw
 * bytes and Base64'd them into `localStorage` — recoverable by any XSS, any
 * extension with storage access, or anyone reading the browser profile. This
 * replacement instead:
 *
 * - generates (or imports) the AES-GCM key with `extractable = false`,
 * - persists the live `CryptoKey` object in IndexedDB via structured clone,
 *   so the raw key material is never exposed to JS again, and
 * - migrates a legacy `localStorage` raw key by importing it as a
 *   non-extractable key, then deleting the `localStorage` entry.
 *
 * The AES-GCM framing (12-byte random IV prepended to `ciphertext‖tag`)
 * matches the default layout produced by the prior `cryptography-kotlin`
 * WebCrypto AES.GCM engine, so data written by older versions still decrypts
 * once its key has migrated.
 *
 * All payloads cross the JS-interop boundary as Base64 strings so the
 * js (`external`) and wasmJs (`@JsFun`) bindings stay primitive-only. The
 * actual implementations bridge the underlying Promises to `suspend` via
 * `kotlinx.coroutines.await`.
 */

/** Ensures a non-extractable key exists for [idbName], migrating [legacyRawKeyB64] if provided. */
@PublishedApi
internal expect suspend fun webKeyEnsure(idbName: String, legacyRawKeyB64: String?)

/** Encrypts [plaintextB64]; returns Base64 of `IV ‖ ciphertext ‖ tag`. */
@PublishedApi
internal expect suspend fun webKeyEncrypt(idbName: String, plaintextB64: String): String

/** Decrypts Base64 [ivAndCipherB64] (`IV ‖ ciphertext ‖ tag`); returns Base64 plaintext. */
@PublishedApi
internal expect suspend fun webKeyDecrypt(idbName: String, ivAndCipherB64: String): String

/** Awaitable removal of the key for [idbName] from IndexedDB. */
@PublishedApi
internal expect suspend fun webKeyDelete(idbName: String)

/** Fire-and-forget removal (the blocking `deleteKey` path can't await). */
@PublishedApi
internal expect fun webKeyDeleteNoWait(idbName: String)
