package eu.anifantakis.lib.ksafe.compose

import androidx.compose.runtime.Immutable
import eu.anifantakis.lib.ksafe.SecurityViolation

/** Compose-stable wrapper around [SecurityViolation], which Compose otherwise treats as unstable. */
@Immutable
data class UiSecurityViolation(
    val violation: SecurityViolation
)