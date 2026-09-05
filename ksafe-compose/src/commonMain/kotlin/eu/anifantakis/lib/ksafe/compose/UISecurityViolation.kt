package eu.anifantakis.lib.ksafe.compose

import androidx.compose.runtime.Immutable
import eu.anifantakis.lib.ksafe.SecurityViolation

/**
 * [SecurityViolation] as an explicitly [Immutable] Compose value, so violation lists in UI state
 * stay skippable without relying on stability inference for a type from a non-Compose module.
 * Wrap each violation reported by `KSafeSecurityPolicy.onViolation`; read it back via [violation].
 */
@Immutable
data class UiSecurityViolation(
    val violation: SecurityViolation
)