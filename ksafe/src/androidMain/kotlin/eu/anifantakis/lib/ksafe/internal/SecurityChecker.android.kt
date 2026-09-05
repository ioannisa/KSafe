package eu.anifantakis.lib.ksafe.internal

import android.annotation.SuppressLint
import android.os.Build
import android.os.Debug
import java.io.File

/**
 * Best-effort: hiding tools bypass it, and the app sandbox hides `su` from the file probes
 * (`File.exists` reads false under SELinux); the build-signal checks survive that. Use Play
 * Integrity where it matters.
 */
internal actual object SecurityChecker {

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

    private val magiskPaths = listOf(
        "/sbin/.magisk",
        "/data/adb/magisk",
        "/data/adb/magisk.img",
        "/data/adb/magisk.db",
        "/data/adb/modules",
        "/data/user_de/0/com.topjohnwu.magisk",
        "/cache/.disable_magisk"
    )

    private val busyBoxPaths = listOf(
        "/system/xbin/busybox",
        "/system/bin/busybox",
        "/sbin/busybox",
        "/data/local/busybox",
        "/data/local/bin/busybox",
        "/data/local/xbin/busybox"
    )

    private val xposedPaths = listOf(
        "/system/framework/XposedBridge.jar",
        "/system/bin/app_process.orig",
        "/system/bin/app_process32_original",
        "/system/bin/app_process64_original",
        "/data/data/de.robv.android.xposed.installer",
        "/data/user_de/0/de.robv.android.xposed.installer"
    )

    // Root providers only; detection-only apps sit on stock devices and prove nothing. Must stay
    // in sync with the <queries> list in androidMain/AndroidManifest.xml.
    private val rootPackages = listOf(
        "com.topjohnwu.magisk",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.yellowes.su",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global",
        "de.robv.android.xposed.installer",
        "org.lsposed.manager"
    )

    private val dangerousProps = mapOf(
        "ro.debuggable" to "1",
        "ro.secure" to "0"
    )

    actual fun isDeviceRooted(): Boolean {
        return checkRootPaths() ||
                checkMagiskPaths() ||
                checkBusyBox() ||
                checkXposed() ||
                checkRootPackages() ||
                checkRootIndicatingBuild() ||
                checkDangerousProps()
    }

    actual fun isDebuggerAttached(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }

    internal var applicationContext: android.content.Context? = null

    // Reads Android's debuggable flag (the app's BuildConfig.DEBUG isn't reachable here).
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

    actual fun isEmulator(): Boolean = isEmulatorBuild(
        fingerprint = Build.FINGERPRINT,
        model = Build.MODEL,
        manufacturer = Build.MANUFACTURER,
        brand = Build.BRAND,
        device = Build.DEVICE,
        product = Build.PRODUCT,
        hardware = Build.HARDWARE,
        board = Build.BOARD,
        id = Build.ID,
    )

    /** Whether any of [paths] is present; an unreadable path is not evidence, so it reads false. */
    private fun anyPathExists(paths: List<String>): Boolean = paths.any { path ->
        try {
            File(path).exists()
        } catch (_: Exception) {
            false
        }
    }

    private fun checkRootPaths(): Boolean = anyPathExists(suPaths)

    private fun checkMagiskPaths(): Boolean = anyPathExists(magiskPaths)

    private fun checkBusyBox(): Boolean = anyPathExists(busyBoxPaths)

    private fun checkXposed(): Boolean {
        val xposedFilesExist = anyPathExists(xposedPaths)

        // Xposed hooks leave frames in stack traces.
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

    private fun checkRootIndicatingBuild(): Boolean =
        isRootIndicatingBuild(Build.TYPE, Build.TAGS)

    private fun checkDangerousProps(): Boolean {
        return dangerousProps.any { (prop, dangerousValue) ->
            readSystemProperty(prop) == dangerousValue
        }
    }

    // Reflection reads the property area directly; `getprop` is SELinux-denied to `untrusted_app`.
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
 * `userdebug`/`eng` ship `su`; `dev-keys` is ignored, since Google emulator images sign
 * `user` builds with it.
 */
internal fun isRootIndicatingBuild(buildType: String?, buildTags: String?): Boolean {
    val dangerousType = buildType == "userdebug" || buildType == "eng"
    val dangerousTags = buildTags != null && buildTags.contains("test-keys")
    return dangerousType || dangerousTags
}

/**
 * Hardware/product signals only; build type and tags belong to [isRootIndicatingBuild] — an
 * engineering device carrying them is not an emulator.
 */
internal fun isEmulatorBuild(
    fingerprint: String?,
    model: String?,
    manufacturer: String?,
    brand: String?,
    device: String?,
    product: String?,
    hardware: String?,
    board: String?,
    id: String?,
): Boolean {
    return (fingerprint?.startsWith("generic") == true ||
            fingerprint?.startsWith("unknown") == true ||
            model?.contains("google_sdk") == true ||
            model?.contains("Emulator") == true ||
            model?.contains("Android SDK built for x86") == true ||
            manufacturer?.contains("Genymotion") == true ||
            brand?.startsWith("generic") == true ||
            device?.startsWith("generic") == true ||
            product?.contains("sdk") == true ||
            product?.contains("emulator") == true ||
            hardware?.contains("goldfish") == true ||
            hardware?.contains("ranchu") == true ||
            board?.contains("unknown") == true ||
            id?.contains("FRF91") == true ||
            manufacturer?.contains("unknown") == true)
}
