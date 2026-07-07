package eu.anifantakis.lib.ksafe.internal

import android.annotation.SuppressLint
import android.os.Build
import android.os.Debug
import java.io.File

/**
 * Android security checks. Root detection is best-effort — hiding tools (Magisk
 * DenyList, Shamiko) can bypass it; use Play Integrity for high-security needs.
 *
 * The app sandbox often defeats the file/package probes (SELinux denies `untrusted_app`
 * access to `su`, so `File.exists` reads false even when present). The build-signal checks
 * survive the sandbox: a `userdebug`/`eng` type or `test-keys` signing indicates an image
 * that ships `su` by construction. The build *type*, not the signing tag, is decisive —
 * `user`-build emulators are `dev-keys`-signed yet not rooted.
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
        "org.lsposed.manager",
        "com.joeykrim.rootcheck"
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
        val xposedFilesExist = xposedPaths.any { path ->
            try {
                File(path).exists()
            } catch (_: Exception) {
                false
            }
        }

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

    // Treats `userdebug`/`eng` builds (and `test-keys` signing) as rooted-capable. Reads only
    // the public [Build] fields, so — unlike the file probes — it survives the app sandbox.
    private fun checkRootIndicatingBuild(): Boolean =
        isRootIndicatingBuild(Build.TYPE, Build.TAGS)

    private fun checkDangerousProps(): Boolean {
        return dangerousProps.any { (prop, dangerousValue) ->
            readSystemProperty(prop) == dangerousValue
        }
    }

    // Reads a system property via reflected `android.os.SystemProperties.get`, which hits the
    // native property area directly and works from the sandbox (unlike `Runtime.exec("getprop")`,
    // which SELinux denies to `untrusted_app`). Returns null on any failure so callers fail safe.
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
 * Does this build's type/tags indicate a rooted-capable image? The reliable signal is the
 * build *type*: `userdebug`/`eng` ship `su` and allow `adb root` by construction; `test-keys`
 * signing is a secondary indicator. Deliberately ignores `dev-keys` — modern Google emulator
 * images are `dev-keys`-signed for both `user` and `userdebug`, so the tag says nothing about
 * root and a `user`-build emulator must not be flagged.
 */
internal fun isRootIndicatingBuild(buildType: String?, buildTags: String?): Boolean {
    val dangerousType = buildType == "userdebug" || buildType == "eng"
    val dangerousTags = buildTags != null && buildTags.contains("test-keys")
    return dangerousType || dangerousTags
}
