package eu.anifantakis.lib.ksafe.compose

import androidx.compose.runtime.Immutable
import eu.anifantakis.lib.ksafe.SecurityViolation

/**
 * A UI-specific wrapper around [SecurityViolation] that guarantees immutability for Jetpack Compose.
 *
 * The original [SecurityViolation] class resides in an external, non-Compose library, which causes the
 * Compose compiler to treat it as "unstable." This prevents performance optimizations like skipping
 * recomposition.
 *
 * By wrapping it in this class and explicitly marking it as [Immutable], we satisfy the stability
 * contract, allowing collections (e.g., `ImmutableList<UiSecurityViolation>`) to be stable.
 *
 * @property violation The underlying domain model representing the security issue.
 */
@Immutable
data class UiSecurityViolation(
    val violation: SecurityViolation
)