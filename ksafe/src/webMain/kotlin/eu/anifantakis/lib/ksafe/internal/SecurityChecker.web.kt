package eu.anifantakis.lib.ksafe.internal

/** None of these checks apply in a browser. */
internal actual object SecurityChecker {
    actual fun isDeviceRooted(): Boolean = false
    actual fun isDebuggerAttached(): Boolean = false
    actual fun isDebugBuild(): Boolean = false
    actual fun isEmulator(): Boolean = false
}
