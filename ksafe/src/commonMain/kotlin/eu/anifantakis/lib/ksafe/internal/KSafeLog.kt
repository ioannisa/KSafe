package eu.anifantakis.lib.ksafe.internal

// Native severity per platform: on web a plain `println` hides under the default DevTools filter.
internal expect fun ksafeLogWarning(message: String)

internal expect fun ksafeLogError(message: String)
