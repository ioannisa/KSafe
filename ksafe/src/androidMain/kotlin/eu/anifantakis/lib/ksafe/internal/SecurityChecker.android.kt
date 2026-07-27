package eu.anifantakis.lib.ksafe.internal

import android.annotation.SuppressLint
import android.os.Build
import android.os.Debug
import java.io.File

/**
 * Android root detection, best-effort — hiding tools (Magisk DenyList, Shamiko) can bypass it;
 * use Play Integrity for high-security needs. The app sandbox defeats file/package probes
 * (SELinux denies `untrusted_app` access to `su`, so `File.exists` reads false even when
 * present); the build-signal checks survive it. The build *type* (`userdebug`/`eng`), not the
 * signing tag, is decisive — `user`-build emulators are `dev-keys`-signed yet not rooted.
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

    // Magisk paths (may be hidden by DenyList).
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

    // Root PROVIDERS/managers and root-requiring frameworks only. Detection-only apps
    // (e.g. Root Checker) are deliberately excluded: they sit on plenty of stock devices
    // and prove nothing — flagging them is a pure false positive. Must stay in sync with
    // the <queries> list in androidMain/AndroidManifest.xml.
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

    // Reads only public [Build] fields, so — unlike the file probes — it survives the app sandbox.
    private fun checkRootIndicatingBuild(): Boolean =
        isRootIndicatingBuild(Build.TYPE, Build.TAGS)

    private fun checkDangerousProps(): Boolean {
        return dangerousProps.any { (prop, dangerousValue) ->
            readSystemProperty(prop) == dangerousValue
        }
    }

    // Reflected `SystemProperties.get` hits the native property area directly and works from the
    // sandbox, unlike `Runtime.exec("getprop")` which SELinux denies to `untrusted_app`. Null on failure.
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
 * The reliable root signal is the build *type*: `userdebug`/`eng` ship `su` by construction;
 * `test-keys` signing is secondary. Deliberately ignores `dev-keys` — modern Google emulator
 * images are `dev-keys`-signed for both `user` and `userdebug`, so a `user`-build emulator must
 * not be flagged.
 */
internal fun isRootIndicatingBuild(buildType: String?, buildTags: String?): Boolean {
    val dangerousType = buildType == "userdebug" || buildType == "eng"
    val dangerousTags = buildTags != null && buildTags.contains("test-keys")
    return dangerousType || dangerousTags
}

/**
 * Emulator detection from hardware/product/fingerprint signals ONLY. Build type and signing
 * tags (`userdebug`/`test-keys`) deliberately do NOT count: they mark a root-capable image —
 * [isRootIndicatingBuild]'s job — and a physical engineering device carrying them is not an
 * emulator; flagging it here would trip an emulator-BLOCK policy for the wrong violation.
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
