package eu.anifantakis.lib.ksafe

/**
 * Outcome of a [KSafe.rotateKeys] pass.
 *
 * Rotation is resumable: a [skipped] entry keeps decrypting under the key generation recorded
 * in its own metadata (that key is retained until nothing references it). Since 3.1.0, a
 * normally completed pass with [skipped] entries can persist the bounded budget configured by
 * [KSafeConfig.keyRotationRetryAttempts]. Each next KSafe instance consumes at most one attempt
 * against that same generation, unless its MaxAge policy is already due and starts the normal
 * fresh generation instead. A [failed] entry is also left untouched, but its
 * definitive failure may mean it is no longer readable and does not by itself schedule
 * automatic retries.
 *
 * Process death is handled separately: a pass carrying the explicit in-progress lifecycle
 * state is resumed automatically at the same generation when the next KSafe instance starts.
 * Marker-less records written by 3.0.0 are conservatively adopted as completed instead.
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
