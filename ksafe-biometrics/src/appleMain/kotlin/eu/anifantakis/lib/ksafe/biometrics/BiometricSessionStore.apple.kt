package eu.anifantakis.lib.ksafe.biometrics

import kotlin.time.TimeSource

private val biometricClockOrigin = TimeSource.Monotonic.markNow()

internal actual fun biometricMonotonicNowMs(): Double =
    biometricClockOrigin.elapsedNow().inWholeMilliseconds.toDouble()
