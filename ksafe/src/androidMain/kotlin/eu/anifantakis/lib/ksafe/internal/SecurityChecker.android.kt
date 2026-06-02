package eu.anifantakis.lib.ksafe.internal

import android.annotation.SuppressLint
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
 *
 * In addition to the file/package probes (which modern Android's app sandbox
 * frequently defeats — `File.exists("/system/xbin/su")` returns false even when
 * the binary is present, because SELinux denies the `untrusted_app` domain access
 * to `su_exec`), this checker treats `userdebug`/`eng` builds and
 * `test-keys`/`dev-keys` signing as rooted. Such images — including Google-APIs
 * emulator system images and engineering devices — ship `su` and permit
 * `adb root` by construction. These build signals are read from the public
 * [Build] fields and `android.os.SystemProperties` (not a `getprop` subprocess),
 * so they survive the app sandbox where the path probes do not.
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
                checkRootIndicatingBuild() ||
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

    /**
     * Treats `userdebug`/`eng` builds and `test-keys`/`dev-keys` signing as a
     * rooted-capable environment. Reads only the public [Build.TYPE]/[Build.TAGS]
     * fields, so — unlike the file probes — it is unaffected by the app sandbox.
     * Delegates to the pure [isRootIndicatingBuild] for deterministic testing.
     */
    private fun checkRootIndicatingBuild(): Boolean =
        isRootIndicatingBuild(Build.TYPE, Build.TAGS)

    private fun checkDangerousProps(): Boolean {
        return dangerousProps.any { (prop, dangerousValue) ->
            readSystemProperty(prop) == dangerousValue
        }
    }

    /**
     * Reads a system property via `android.os.SystemProperties.get` through
     * reflection. This reads the native property area directly and therefore
     * works from the app sandbox, unlike `Runtime.exec("getprop")`, which modern
     * SELinux policy denies to the `untrusted_app` domain. Returns `null` on any
     * failure (missing/empty/blocked) so callers fail safe.
     */
    @SuppressLint("PrivateApi", "DiscouragedPrivateApi")
    private fun readSystemProperty(name: String): String? = try {
        val clazz = Class.forName("android.os.SystemProperties")
        val getter = clazz.getMethod("get", String::class.java)
        (getter.invoke(null, name) as? String)?.takeIf { it.isNotEmpty() }
    } catch (_: Throwable) {
        null
    }
}

/**
 * Pure predicate: do this build's type/tags indicate a rooted-capable image?
 *
 * `userdebug`/`eng` system builds and `test-keys`/`dev-keys` signing ship `su`,
 * allow `adb root`, and expose writable system partitions by construction — this
 * is true of Google-APIs emulator system images and engineering devices.
 * Extracted as a top-level function over the public [Build] fields so it is
 * deterministically unit-testable without depending on the host image.
 *
 * Note: `dev-keys` is the signing used by modern Google emulator system images;
 * matching only `test-keys` (the older AOSP convention) let rooted emulators slip
 * through as "not rooted".
 */
internal fun isRootIndicatingBuild(buildType: String?, buildTags: String?): Boolean {
    val dangerousType = buildType == "userdebug" || buildType == "eng"
    val dangerousTags = buildTags != null &&
            (buildTags.contains("test-keys") || buildTags.contains("dev-keys"))
    return dangerousType || dangerousTags
}
