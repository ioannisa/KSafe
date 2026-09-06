package eu.anifantakis.lib.ksafe.internal

// `console` needs no import on Kotlin/JS (kotlin.js.console).
internal actual fun ksafeLogWarning(message: String) { console.warn(message) }

internal actual fun ksafeLogError(message: String) { console.error(message) }
