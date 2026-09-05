package eu.anifantakis.lib.ksafe

/**
 * Outcome of a [KSafe.rotateKeys] pass. Skipped entries are retried by later instances per
 * [KSafeConfig.keyRotationRetryAttempts]; failed ones are not.
 *
 * @property rotated Entries re-encrypted under the new key generation.
 * @property skipped Entries left on their previous generation (a strict entry while the device is
 *   locked, or one a concurrent write superseded); they still decrypt under the retained old key.
 * @property failed Entries whose decrypt or re-encrypt failed outright.
 * @property keyGeneration The store's key generation after this pass; new writes use it.
 */
data class KSafeRotationResult(
    val rotated: Int,
    val skipped: Int,
    val failed: Int,
    val keyGeneration: Int,
)
