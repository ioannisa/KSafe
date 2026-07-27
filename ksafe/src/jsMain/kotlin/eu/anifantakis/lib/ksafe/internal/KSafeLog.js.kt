package eu.anifantakis.lib.ksafe.internal

// `console` (kotlin.js.console) is a default import on Kotlin/JS. warn/error surface at the correct
// DevTools severity level instead of console.log.
internal actual fun ksafeLogWarning(message: String) { console.warn(message) }

internal actual fun ksafeLogError(message: String) { console.error(message) }
