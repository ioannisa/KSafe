package eu.anifantakis.lib.ksafe.compose

import androidx.compose.runtime.Immutable
import eu.anifantakis.lib.ksafe.SecurityViolation

/**
 * Compose-stable [Immutable] wrapper around [SecurityViolation], which lives in a
 * non-Compose library and is otherwise treated as unstable — blocking recomposition
 * skipping and stable collections like `ImmutableList<UiSecurityViolation>`.
 */
@Immutable
data class UiSecurityViolation(
    val violation: SecurityViolation
)