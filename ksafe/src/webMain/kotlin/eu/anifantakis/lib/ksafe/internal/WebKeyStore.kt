package eu.anifantakis.lib.ksafe.internal

/**
 * Non-extractable AES-GCM key storage for the web (wasmJs + js) over WebCrypto + IndexedDB. Keys
 * are generated/imported with `extractable = false` and persisted as live `CryptoKey` objects in
 * IndexedDB, so raw key material never reaches JS. Framing is a 12-byte random IV prepended to
 * `ciphertext‖tag` — the layout older versions wrote — so existing data still decrypts. Payloads
 * cross the interop boundary as Base64 so the js (`external`) / wasmJs (`@JsFun`) bindings stay
 * primitive-only.
 */

/**
 * Ensures key state for [idbName], migrating [legacyRawKeyB64] into IndexedDB if provided. With
 * [mintIfAbsent] true (write path) a fresh non-extractable key is minted if none exists; false
 * (read path) never mints — an absent key is left absent so decrypt fails recoverably ("web key
 * missing") rather than minting one that can't decrypt the surviving ciphertext.
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
 * Copies the CryptoKey from [fromIdbName] to [toIdbName] only if [toIdbName] is absent and
 * [fromIdbName] exists (atomic `add`, never clobbering a concurrent writer). Migrates a
 * pre-`appNamespace` key to its namespaced name so data stays readable on upgrade; the source
 * is left in place (non-destructive).
 */
@PublishedApi
internal expect suspend fun webKeyCopyIfAbsent(fromIdbName: String, toIdbName: String)

/** Awaitable removal of the key for [idbName] from IndexedDB. */
@PublishedApi
internal expect suspend fun webKeyDelete(idbName: String)

/** Fire-and-forget removal (the blocking `deleteKey` path can't await). */
@PublishedApi
internal expect fun webKeyDeleteNoWait(idbName: String)
