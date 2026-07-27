package eu.anifantakis.lib.ksafe

import kotlin.time.Duration

/**
 * When KSafe rotates its encryption keys automatically. The default is [Never]: key material
 * on every KSafe platform is hardware- or OS-protected and does not expire, so automatic
 * rotation is an opt-in hygiene/compliance policy, not a security necessity. On-demand
 * rotation is always available via [KSafe.rotateKeys].
 */
sealed interface KSafeKeyRotationPolicy {

    /** No automatic rotation (the default). Rotate on demand with [KSafe.rotateKeys]. */
    data object Never : KSafeKeyRotationPolicy

    /**
     * Rotates in the background shortly after startup whenever the current key generation is
     * older than [maxAge] (measured from the last rotation — or, for a store that has never
     * rotated, from the first launch under this policy). The rotation never blocks startup or
     * reads; entries it cannot rotate yet (e.g. strict entries on a locked device) are picked
     * up on a later launch.
     */
    data class MaxAge(val maxAge: Duration) : KSafeKeyRotationPolicy {
        init {
            require(maxAge.isPositive()) { "maxAge must be positive. Got: $maxAge" }
        }
    }
}
