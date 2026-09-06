package eu.anifantakis.lib.ksafe.internal

// datastoreMain is exactly the non-web target set (Android + JVM + Apple), and all three log with
// `println`, so the actual lives here once.

internal actual fun ksafeLogWarning(message: String) { println(message) }

internal actual fun ksafeLogError(message: String) { println(message) }
