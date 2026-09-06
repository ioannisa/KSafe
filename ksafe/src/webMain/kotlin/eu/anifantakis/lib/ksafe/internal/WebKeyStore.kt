package eu.anifantakis.lib.ksafe.internal

// Non-extractable AES-GCM key storage for the web (WebCrypto + IndexedDB): raw key material never
// reaches JS. Framing is a 12-byte random IV before `ciphertext‖tag` — frozen, shipped data uses it.

/**
 * Ensures key state for [idbName], migrating [legacyRawKeyB64] if given. [mintIfAbsent] false
 * (read path) never mints: a fresh key could not decrypt surviving ciphertext.
 */
@PublishedApi
internal expect suspend fun webKeyEnsure(
    idbName: String,
    legacyRawKeyB64: String?,
    mintIfAbsent: Boolean,
    keySizeBits: Int,
)

/**
 * Encrypts [plaintextB64] to Base64 `IV ‖ ciphertext ‖ tag`. The key record is re-read afterwards,
 * so a cross-tab delete racing this write fails recoverably instead of persisting dead ciphertext.
 * A delete landing after that check still orphans one write; the startup sweep reclaims it.
 */
@PublishedApi
internal expect suspend fun webKeyEncrypt(idbName: String, plaintextB64: String, aadB64: String? = null): String

/** Decrypts Base64 [ivAndCipherB64] (`IV ‖ ciphertext ‖ tag`); returns Base64 plaintext. */
@PublishedApi
internal expect suspend fun webKeyDecrypt(idbName: String, ivAndCipherB64: String, aadB64: String? = null): String

/**
 * Copies the CryptoKey from [fromIdbName] to [toIdbName] only if the target is absent (atomic
 * `add`, so a concurrent writer is never clobbered); the source is left in place.
 */
@PublishedApi
internal expect suspend fun webKeyCopyIfAbsent(fromIdbName: String, toIdbName: String)

/** Awaitable removal of the key for [idbName] from IndexedDB. */
@PublishedApi
internal expect suspend fun webKeyDelete(idbName: String)

/** Fire-and-forget removal (the blocking `deleteKey` path can't await). */
@PublishedApi
internal expect fun webKeyDeleteNoWait(idbName: String)
