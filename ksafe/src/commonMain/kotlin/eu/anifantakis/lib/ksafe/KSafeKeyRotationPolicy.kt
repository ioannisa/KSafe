package eu.anifantakis.lib.ksafe

import kotlin.time.Duration

/**
 * When KSafe starts a fresh key generation on its own; the default is [Never], since key material
 * is hardware- or OS-protected and does not expire. On-demand rotation is always available via
 * [KSafe.rotateKeys].
 */
sealed interface KSafeKeyRotationPolicy {

    /** No automatic new generation; an interrupted or partial pass still resumes on the next instance. */
    data object Never : KSafeKeyRotationPolicy

    /**
     * Rotates in the background shortly after startup once the generation is older than [maxAge],
     * measured from the last rotation or from first launch under this policy. Entries it cannot
     * reach (a strict entry on a locked device) are retried on a later instance. Never blocks reads.
     */
    data class MaxAge(val maxAge: Duration) : KSafeKeyRotationPolicy {
        init {
            require(maxAge.isPositive()) { "maxAge must be positive. Got: $maxAge" }
        }
    }
}
