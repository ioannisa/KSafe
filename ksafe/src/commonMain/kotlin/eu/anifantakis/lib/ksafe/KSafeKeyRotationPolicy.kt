package eu.anifantakis.lib.ksafe

import kotlin.time.Duration

/**
 * When KSafe starts a fresh key generation on its own, set via [KSafeConfig.keyRotationPolicy].
 * The default is [Never], since key material is hardware- or OS-protected and does not expire;
 * on-demand rotation is always available via [KSafe.rotateKeys].
 */
sealed interface KSafeKeyRotationPolicy {

    /**
     * No scheduled rotation. A pass interrupted mid-way still resumes on the next instance, and
     * one that left retryable entries gets up to [KSafeConfig.keyRotationRetryAttempts] more
     * tries, one per instance; neither starts a new generation.
     */
    data object Never : KSafeKeyRotationPolicy

    /**
     * Rotates in the background shortly after startup once the generation is older than [maxAge],
     * measured from the last rotation or, for a store that never rotated, from the first launch
     * under this policy. Never blocks startup or reads. Entries a pass cannot reach (a strict
     * entry on a locked device) are retried on a later instance, unless a fresh pass is due by then.
     *
     * @property maxAge Must be positive; the constructor throws [IllegalArgumentException] otherwise.
     */
    data class MaxAge(val maxAge: Duration) : KSafeKeyRotationPolicy {
        init {
            require(maxAge.isPositive()) { "maxAge must be positive. Got: $maxAge" }
        }
    }
}
