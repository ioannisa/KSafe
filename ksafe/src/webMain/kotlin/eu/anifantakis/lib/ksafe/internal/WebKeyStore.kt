package eu.anifantakis.lib.ksafe.internal

/**
 * Non-extractable AES-GCM key storage for the web (wasmJs + js), backed by
 * WebCrypto + IndexedDB.
 *
 * - Keys are generated/imported with `extractable = false` and persisted as live
 *   `CryptoKey` objects in IndexedDB (structured clone), so raw key material is
 *   never exposed to JS.
 * - A legacy raw key found in `localStorage` is migrated: imported as a
 *   non-extractable key, then the `localStorage` entry is deleted.
 * - Framing is a 12-byte random IV prepended to `ciphertext‖tag`, matching the
 *   layout older versions wrote, so existing data still decrypts after migration.
 *
 * All payloads cross the JS-interop boundary as Base64 strings so the js
 * (`external`) and wasmJs (`@JsFun`) bindings stay primitive-only; the actuals
 * bridge the underlying Promises to `suspend`.
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
