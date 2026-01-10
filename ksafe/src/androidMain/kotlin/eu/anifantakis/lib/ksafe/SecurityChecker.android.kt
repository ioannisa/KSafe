package eu.anifantakis.lib.ksafe

import android.os.Build
import android.os.Debug
import java.io.File

/**
 * Android-specific security checker implementation.
 *
 * IMPORTANT DISCLAIMER: Root detection is a cat-and-mouse game. Sophisticated
 * root-hiding tools (e.g., Magisk DenyList/Hide, Shamiko) can bypass most or all
 * of these checks. This implementation provides reasonable detection for casual
 * rooting but cannot guarantee detection against determined users with advanced
 * hiding tools. For high-security applications, consider additional measures
 * like Google Play Integrity API.
 */
internal actual object SecurityChecker {

    // Common paths where su binary is found on rooted devices
    private val suPaths = listOf(
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/su/bin",
        "/system/xbin/daemonsu"
    )

    // Magisk-specific paths (may be hidden by Magisk DenyList)
    private val magiskPaths = listOf(
        "/sbin/.magisk",
        "/data/adb/magisk",
        "/data/adb/magisk.img",
        "/data/adb/magisk.db",
        "/data/adb/modules",
        "/data/user_de/0/com.topjohnwu.magisk",
        "/cache/.disable_magisk"
    )

    // BusyBox paths (commonly installed on rooted devices)
    private val busyBoxPaths = listOf(
        "/system/xbin/busybox",
        "/system/bin/busybox",
        "/sbin/busybox",
        "/data/local/busybox",
        "/data/local/bin/busybox",
        "/data/local/xbin/busybox"
    )

    // Xposed Framework paths
    private val xposedPaths = listOf(
        "/system/framework/XposedBridge.jar",
        "/system/bin/app_process.orig",
        "/system/bin/app_process32_original",
        "/system/bin/app_process64_original",
        "/data/data/de.robv.android.xposed.installer",
        "/data/user_de/0/de.robv.android.xposed.installer"
    )

    // Root management and hiding app packages
    private val rootPackages = listOf(
        // Magisk variants (may use random package names)
        "com.topjohnwu.magisk",
        // SuperUser apps
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.yellowes.su",
        // Root tools
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global",
        // Xposed
        "de.robv.android.xposed.installer",
        "org.lsposed.manager",
        // Root checkers (having these may indicate user is root-aware)
        "com.joeykrim.rootcheck"
    )

    // Dangerous props that indicate rooting
    private val dangerousProps = mapOf(
        "ro.debuggable" to "1",
        "ro.secure" to "0"
    )

    /**
     * Check if the device is rooted.
     * Uses multiple detection methods for better accuracy.
     *
     * Note: Sophisticated hiding tools (Magisk DenyList, Shamiko) may bypass these checks.
     */
    actual fun isDeviceRooted(): Boolean {
        return checkRootPaths() ||
                checkMagiskPaths() ||
                checkBusyBox() ||
                checkXposed() ||
                checkRootPackages() ||
                checkBuildTags() ||
                checkDangerousProps()
    }

    /**
     * Check if a debugger is attached.
     */
    actual fun isDebuggerAttached(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }

    // Store application context for debug build detection
    internal var applicationContext: android.content.Context? = null

    /**
     * Check if this is a debug build.
     * Note: This checks Android's debuggable flag, not BuildConfig.DEBUG
     * since we don't have access to the app's BuildConfig.
     */
    actual fun isDebugBuild(): Boolean {
        return try {
            val appInfo = applicationContext?.applicationInfo
            appInfo?.let {
                (it.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
            } ?: false
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check if running on an emulator.
     */
    actual fun isEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.startsWith("unknown") ||
                Build.MODEL.contains("google_sdk") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK built for x86") ||
                Build.MANUFACTURER.contains("Genymotion") ||
                Build.BRAND.startsWith("generic") ||
                Build.DEVICE.startsWith("generic") ||
                Build.PRODUCT.contains("sdk") ||
                Build.PRODUCT.contains("emulator") ||
                Build.HARDWARE.contains("goldfish") ||
                Build.HARDWARE.contains("ranchu") ||
                Build.BOARD.contains("unknown") ||
                Build.ID.contains("FRF91") ||
                Build.MANUFACTURER.contains("unknown") ||
                Build.TAGS.contains("test-keys") ||
                Build.TYPE.contains("userdebug"))
    }

    // --- Private helper methods ---

    private fun checkRootPaths(): Boolean {
        return suPaths.any { path ->
            try {
                File(path).exists()
            } catch (_: Exception) {
                false
            }
        }
    }

    private fun checkMagiskPaths(): Boolean {
        return magiskPaths.any { path ->
            try {
                File(path).exists()
            } catch (_: Exception) {
                false
            }
        }
    }

    private fun checkBusyBox(): Boolean {
        return busyBoxPaths.any { path ->
            try {
                File(path).exists()
            } catch (_: Exception) {
                false
            }
        }
    }

    private fun checkXposed(): Boolean {
        // Check for Xposed files
        val xposedFilesExist = xposedPaths.any { path ->
            try {
                File(path).exists()
            } catch (_: Exception) {
                false
            }
        }

        // Check for Xposed in stack traces (Xposed hooks leave traces)
        val xposedInStack = try {
            throw Exception("Xposed check")
        } catch (e: Exception) {
            e.stackTrace.any { element ->
                element.className.contains("xposed", ignoreCase = true) ||
                        element.className.contains("lsposed", ignoreCase = true)
            }
        }

        return xposedFilesExist || xposedInStack
    }

    private fun checkRootPackages(): Boolean {
        val context = applicationContext ?: return false
        val pm = context.packageManager

        return rootPackages.any { packageName ->
            try {
                pm.getPackageInfo(packageName, 0)
                true
            } catch (_: Exception) {
                false
            }
        }
    }

    private fun checkBuildTags(): Boolean {
        val tags = Build.TAGS
        return tags != null && tags.contains("test-keys")
    }

    private fun checkDangerousProps(): Boolean {
        return try {
            dangerousProps.any { (prop, dangerousValue) ->
                val process = Runtime.getRuntime().exec("getprop $prop")
                val value = process.inputStream.bufferedReader().readLine()
                value == dangerousValue
            }
        } catch (_: Exception) {
            false
        }
    }
}
