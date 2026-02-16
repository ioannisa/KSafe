package eu.anifantakis.lib.ksafe

/**
 * WASM/JS security checker implementation.
 * Security checks are not applicable in browser environments.
 */
internal actual object SecurityChecker {
    actual fun isDeviceRooted(): Boolean = false
    actual fun isDebuggerAttached(): Boolean = false
    actual fun isDebugBuild(): Boolean = false
    actual fun isEmulator(): Boolean = false
}
