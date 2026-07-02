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

/**
 * Ensures the key state for [idbName], migrating [legacyRawKeyB64] into IndexedDB if provided.
 *
 * When [mintIfAbsent] is `true` (the write path) a fresh non-extractable key is generated and
 * persisted if none exists. When `false` (the read path) no key is ever created — a genuinely
 * absent key is left absent so the subsequent decrypt fails recoverably with "web key missing"
 * instead of minting a key that can never decrypt the surviving ciphertext (FEEDBACK_4 H-A).
 * A legacy `localStorage` key is still migrated regardless, since it provably decrypts existing data.
 */
@PublishedApi
internal expect suspend fun webKeyEnsure(idbName: String, legacyRawKeyB64: String?, mintIfAbsent: Boolean)

/** Encrypts [plaintextB64]; returns Base64 of `IV ‖ ciphertext ‖ tag`. */
@PublishedApi
internal expect suspend fun webKeyEncrypt(idbName: String, plaintextB64: String): String

/** Decrypts Base64 [ivAndCipherB64] (`IV ‖ ciphertext ‖ tag`); returns Base64 plaintext. */
@PublishedApi
internal expect suspend fun webKeyDecrypt(idbName: String, ivAndCipherB64: String): String

/**
 * Copies the CryptoKey record from [fromIdbName] to [toIdbName] **only if** [toIdbName] is
 * absent and [fromIdbName] exists (atomic `add`, so a concurrent writer is never clobbered).
 * Used to migrate a pre-`appNamespace` key to its namespaced record name when `appNamespace`
 * is added on upgrade, so existing encrypted data stays readable (FEEDBACK_4 FB3-H1). The
 * source record is left in place (migrate-forward, non-destructive).
 */
@PublishedApi
internal expect suspend fun webKeyCopyIfAbsent(fromIdbName: String, toIdbName: String)

/** Awaitable removal of the key for [idbName] from IndexedDB. */
@PublishedApi
internal expect suspend fun webKeyDelete(idbName: String)

/** Fire-and-forget removal (the blocking `deleteKey` path can't await). */
@PublishedApi
internal expect fun webKeyDeleteNoWait(idbName: String)
