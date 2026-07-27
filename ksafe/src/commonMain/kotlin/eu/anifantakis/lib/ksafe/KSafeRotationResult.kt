package eu.anifantakis.lib.ksafe

/**
 * Outcome of a [KSafe.rotateKeys] pass.
 *
 * Rotation is resumable: a [skipped] or [failed] entry keeps decrypting under the key
 * generation recorded in its own metadata (that key is retained until nothing references
 * it), and the next [KSafe.rotateKeys] call picks it up again.
 *
 * @property rotated Entries successfully re-encrypted under the new key generation.
 * @property skipped Entries left on their previous generation this pass: a strict
 *   (`requireUnlockedDevice`) entry while the device is locked, or an entry a concurrent
 *   write superseded mid-rotation (the newer write wins).
 * @property failed Entries whose decrypt or re-encrypt failed outright.
 * @property keyGeneration The store's key generation after this pass; new writes encrypt
 *   under it.
 */
data class KSafeRotationResult(
    val rotated: Int,
    val skipped: Int,
    val failed: Int,
    val keyGeneration: Int,
)
