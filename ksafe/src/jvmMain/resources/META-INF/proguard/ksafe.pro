# Keep rules for the KSafe JVM jar. R8 reads them from the jar; a ProGuard build, a Compose Desktop
# release build among them, has to list this file in its configuration.

# A compile-only annotation, absent from apps without Compose.
-dontwarn androidx.compose.runtime.Stable

# DataStore's own rule, which ProGuard does not read from its jar: its protobuf finds these fields
# by name, so an obfuscating ProGuard build could neither read nor write the store without it.
-keepclassmembers class * extends androidx.datastore.preferences.protobuf.GeneratedMessageLite {
    <fields>;
}

# The OS key vaults go through JNA. Without the rules below a shrunk app quietly keeps its keys in
# the DataStore file instead.

# Looked up by name from JNA's native library.
-keep class com.sun.jna.* { *; }

# Created by JNA through their no-argument constructor.
-keepclassmembers class * implements com.sun.jna.NativeMapped {
    <init>();
}

# Implemented by a JNA proxy that binds each method by its name.
-keep interface eu.anifantakis.lib.ksafe.internal.keyvault.** extends com.sun.jna.Library { *; }

# Fields read by the names in @Structure.FieldOrder. R8 and Compose Desktop builds keep annotations
# through kotlinx-serialization's or Compose's rules too; a plain ProGuard build gets it only here.
-keep class eu.anifantakis.lib.ksafe.internal.keyvault.** extends com.sun.jna.Structure { *; }
-keepattributes RuntimeVisibleAnnotations

# Windows DPAPI goes through jna-platform's Crypt32Util: its proxy interfaces and the names of the
# methods it calls, and DATA_BLOB's fields. KSafe always passes a null prompt struct.
-keep interface com.sun.jna.platform.win32.Crypt32
-keep interface com.sun.jna.platform.win32.Kernel32
-keepclassmembernames interface com.sun.jna.platform.win32.Crypt32 { <methods>; }
-keepclassmembernames interface com.sun.jna.platform.win32.Kernel32 { <methods>; }
-keep class com.sun.jna.platform.win32.WinCrypt$DATA_BLOB { *; }
