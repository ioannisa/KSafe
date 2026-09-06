package eu.anifantakis.lib.ksafe.internal

/** A browser exposes no root, debugger or emulator signal, so every check reports clean. */
internal actual object SecurityChecker {
    actual fun isDeviceRooted(): Boolean = false
    actual fun isDebuggerAttached(): Boolean = false
    actual fun isDebugBuild(): Boolean = false
    actual fun isEmulator(): Boolean = false
}
