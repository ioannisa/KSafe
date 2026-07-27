@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package eu.anifantakis.lib.ksafe.internal

@JsFun("(m) => { console.warn(m); }")
private external fun _consoleWarn(m: String)

@JsFun("(m) => { console.error(m); }")
private external fun _consoleError(m: String)

internal actual fun ksafeLogWarning(message: String) { _consoleWarn(message) }

internal actual fun ksafeLogError(message: String) { _consoleError(message) }
