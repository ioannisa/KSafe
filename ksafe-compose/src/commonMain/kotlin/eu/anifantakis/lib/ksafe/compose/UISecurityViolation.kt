package eu.anifantakis.lib.ksafe.compose

import androidx.compose.runtime.Immutable
import eu.anifantakis.lib.ksafe.SecurityViolation

/**
 * [SecurityViolation] in an [Immutable] data class. Compose already treats the enum as stable, so
 * the wrapper does not change skipping. Wrap each violation reported by
 * `KSafeSecurityPolicy.onViolation`; read it back via [violation].
 */
@Immutable
data class UiSecurityViolation(
    val violation: SecurityViolation
)