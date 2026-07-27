package eu.anifantakis.lib.ksafe.internal

/**
 * Diagnostic logging routed to the platform's native severity level. This matters on the web:
 * a plain `println` maps to `console.log`, which hides under the DevTools default "Errors/Warnings"
 * filter — so a failure diagnostic a developer is actively hunting stays invisible. Warnings go to
 * `console.warn` and errors to `console.error`; every other platform keeps `println`.
 */
internal expect fun ksafeLogWarning(message: String)

internal expect fun ksafeLogError(message: String)
