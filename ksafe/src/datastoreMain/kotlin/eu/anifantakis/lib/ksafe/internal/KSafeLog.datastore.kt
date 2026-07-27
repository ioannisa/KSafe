package eu.anifantakis.lib.ksafe.internal

// datastoreMain is exactly the non-web target set (Android + JVM + Apple), which is also exactly
// the set whose native log sink is `println` — so the actual lives here once.

internal actual fun ksafeLogWarning(message: String) { println(message) }

internal actual fun ksafeLogError(message: String) { println(message) }
