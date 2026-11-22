# Keep rules for the KSafe biometrics JVM jar. R8 reads them from the jar; a ProGuard build, a
# Compose Desktop release build among them, has to list this file in its configuration.

# Touch ID and Windows Hello go through JNA. Without the rules below a shrunk app cannot reach
# them, and a verifyBiometric that allows the device-credential fallback returns true without
# showing a prompt.

# Looked up by name from JNA's native library.
-keep class com.sun.jna.* { *; }

# Created by JNA through their no-argument constructor.
-keepclassmembers class * implements com.sun.jna.NativeMapped {
    <init>();
}

# The Touch ID reply block: only native code calls it, through JNA's reflection.
-keep interface eu.anifantakis.lib.ksafe.biometrics.** extends com.sun.jna.Callback { *; }
