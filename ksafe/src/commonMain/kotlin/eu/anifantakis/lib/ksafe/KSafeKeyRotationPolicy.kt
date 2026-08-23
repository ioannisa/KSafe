package eu.anifantakis.lib.ksafe

import kotlin.time.Duration

/**
 * When KSafe starts a fresh key generation automatically. The default is [Never]: key material
 * on every KSafe platform is hardware- or OS-protected and does not expire, so scheduled
 * rotation is an opt-in hygiene/compliance policy, not a security necessity. Since 3.1.0,
 * recovery of a pass carrying the explicit in-progress lifecycle state is independent of this
 * policy and runs after restart under [Never] too. Marker-less 3.0.0 records are instead
 * adopted as completed. A normally completed pass that leaves retryable skipped entries can
 * arm a bounded same-generation retry budget configured by
 * [KSafeConfig.keyRotationRetryAttempts]. Under [MaxAge], a fresh rotation takes precedence
 * if the generation is already due on that next run.
 * On-demand rotation is always available via [KSafe.rotateKeys].
 */
sealed interface KSafeKeyRotationPolicy {

    /**
     * No automatic new generation (the default). Rotate on demand with [KSafe.rotateKeys].
     * A 3.1.0+ generation marked in progress is still resumed automatically on the next KSafe
     * instance, and a normally completed generation with retryable skipped entries consumes
     * at most one configured retry attempt per next KSafe instance. Neither path creates a
     * fresh generation.
     */
    data object Never : KSafeKeyRotationPolicy

    /**
     * Rotates in the background shortly after startup whenever the current key generation is
     * older than [maxAge] (measured from the last rotation — or, for a store that has never
     * rotated, from the first launch under this policy). The rotation never blocks startup or
     * reads. A normally completed pass may leave entries behind (e.g. a strict entry on a
     * locked device); since 3.1.0 those can receive a bounded next-instance retry budget. If
     * [maxAge] is already due then, the normal fresh-generation pass supersedes the
     * same-generation retry. This is separate from a pass marked in progress, which always
     * resumes the same generation.
     */
    data class MaxAge(val maxAge: Duration) : KSafeKeyRotationPolicy {
        init {
            require(maxAge.isPositive()) { "maxAge must be positive. Got: $maxAge" }
        }
    }
}
