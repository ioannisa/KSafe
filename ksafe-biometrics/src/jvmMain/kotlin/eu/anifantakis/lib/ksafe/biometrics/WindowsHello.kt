package eu.anifantakis.lib.ksafe.biometrics

import com.sun.jna.Function
import com.sun.jna.Memory
import com.sun.jna.NativeLibrary
import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.PointerByReference
import java.security.MessageDigest

/**
 * Computes WinRT *parameterized interface* (pinterface) IIDs at runtime with the
 * documented algorithm: an RFC 4122 name-based (v5, SHA-1) UUID over the WinRT
 * pinterface namespace GUID + the type's signature string. C++/WinRT does the same
 * at compile time via `guid_of<>`; these GUIDs are never published as constants, so
 * computing them is the only dependency-free way to get one. The implementation is
 * locked in by unit tests against published reference GUIDs (`IIterable<String>`,
 * `IVector<String>`).
 */
internal object WinRtGuid {

    /** WinRT pinterface namespace GUID: {11f47ad5-7b73-42c0-abae-878b1e16adee}. */
    private val PINTERFACE_NAMESPACE = byteArrayOf(
        0x11, 0xf4.toByte(), 0x7a, 0xd5.toByte(), 0x7b, 0x73, 0x42, 0xc0.toByte(),
        0xab.toByte(), 0xae.toByte(), 0x87.toByte(), 0x8b.toByte(), 0x1e, 0x16, 0xad.toByte(), 0xee.toByte(),
    )

    /** Canonical-string GUID of the v5 UUID for [signature] under the WinRT namespace. */
    fun pinterfaceGuid(signature: String): String {
        val sha1 = MessageDigest.getInstance("SHA-1")
        sha1.update(PINTERFACE_NAMESPACE)
        sha1.update(signature.toByteArray(Charsets.UTF_8))
        val hash = sha1.digest()
        val bytes = hash.copyOf(16)
        bytes[6] = ((bytes[6].toInt() and 0x0F) or 0x50).toByte() // version 5
        bytes[8] = ((bytes[8].toInt() and 0x3F) or 0x80).toByte() // RFC 4122 variant
        fun hex(from: Int, to: Int) = (from until to).joinToString("") { "%02x".format(bytes[it]) }
        return "${hex(0, 4)}-${hex(4, 6)}-${hex(6, 8)}-${hex(8, 10)}-${hex(10, 16)}"
    }

    /**
     * `IAsyncOperation<Windows.Security.Credentials.UI.UserConsentVerificationResult>`.
     * The enum's WinRT signature is `i4` (signed Int32): `UserConsentVerificationResult`
     * is a non-`[Flags]` enum, and those have Int32 underlying type. `u4` (UInt32, used only
     * for `[Flags]` enums) computes a *different* GUID, which `RequestVerificationForWindowAsync`
     * rejects with `E_NOINTERFACE` (0x80004002) — the bug that made the prompt silently
     * pass through instead of gating. Locked in by [DesktopBiometricsTest].
     */
    val ASYNC_OP_USER_CONSENT: String = pinterfaceGuid(
        "pinterface({9fc2b0bb-e446-44e2-aa61-9cab8f636af2};" +
            "enum(Windows.Security.Credentials.UI.UserConsentVerificationResult;i4))"
    )

    /** A canonical-string GUID as the 16-byte little-endian Windows layout JNA can pass as REFIID. */
    fun toWindowsBytes(guid: String): Memory {
        val hex = guid.replace("-", "")
        require(hex.length == 32) { "bad GUID: $guid" }
        val b = ByteArray(16) { i -> ((hex[i * 2].digitToInt(16) shl 4) or hex[i * 2 + 1].digitToInt(16)).toByte() }
        return Memory(16).apply {
            // data1 (LE int), data2 (LE short), data3 (LE short), data4 (as-is)
            setByte(0, b[3]); setByte(1, b[2]); setByte(2, b[1]); setByte(3, b[0])
            setByte(4, b[5]); setByte(5, b[4])
            setByte(6, b[7]); setByte(7, b[6])
            for (i in 8..15) setByte(i.toLong(), b[i])
        }
    }
}

/**
 * Windows Hello consent prompt for the JVM, via the documented Win32 interop route:
 * `RoGetActivationFactory` → [IUserConsentVerifierInterop] →
 * `RequestVerificationForWindowAsync` (classic COM, no WinRT projection needed).
 *
 * Windows treats the Hello PIN as part of Hello itself, and `UserConsentVerifier`
 * cannot exclude it — so `allowDeviceCredentialFallback = false` cannot enforce
 * biometrics-only here (platform limitation, documented). The flag still keys the
 * authorization cache strictly and controls the unavailable-fallback behavior.
 */
internal object WindowsHello {

    private const val RUNTIME_CLASS = "Windows.Security.Credentials.UI.UserConsentVerifier"
    private const val IID_USER_CONSENT_VERIFIER_INTEROP = "39e050c3-4e74-441a-8dc0-b81104df949c"
    // From the winmd metadata (windows-rs bindings publish it verbatim).
    private const val IID_USER_CONSENT_VERIFIER_STATICS = "af4f3f91-564c-4ddc-b8b5-973447627c65"
    private const val IID_ASYNC_INFO = "00000036-0000-0000-c000-000000000046"
    private const val RPC_E_CHANGED_MODE = -0x7FFEFEFA // 0x80010106

    // UserConsentVerificationResult
    private const val VERIFIED = 0
    private const val DEVICE_NOT_PRESENT = 1
    private const val NOT_CONFIGURED_FOR_USER = 2
    private const val DISABLED_BY_POLICY = 3

    // AsyncStatus
    private const val STATUS_STARTED = 0
    private const val STATUS_COMPLETED = 1

    private class Runtime {
        val combase: NativeLibrary = NativeLibrary.getInstance("combase")
        val user32: NativeLibrary = NativeLibrary.getInstance("user32")
        val kernel32: NativeLibrary = NativeLibrary.getInstance("kernel32")
    }

    private val runtime: Runtime? by lazy {
        try {
            Runtime()
        } catch (t: Throwable) {
            System.err.println(
                "KSafe biometrics: Windows Hello bridge unavailable (${t.message}); " +
                    "verifyBiometric falls back to pass-through."
            )
            null
        }
    }

    val isAvailable: Boolean get() = runtime != null

    /** Calls COM vtable [slot] on [iface] (`this` is prepended), returning HRESULT. */
    private fun comCall(iface: Pointer, slot: Int, vararg args: Any?): Int {
        val fn = Function.getFunction(iface.getPointer(0).getPointer(slot * 8L))
        return fn.invokeInt(arrayOf(iface, *args))
    }

    private fun release(iface: Pointer?) {
        if (iface != null) runCatching { comCall(iface, 2) } // IUnknown::Release
    }

    /** Best-effort HWND for dialog anchoring: own foreground window → console → desktop. */
    private fun pickWindowHandle(rt: Runtime): Pointer? {
        val getForeground = rt.user32.getFunction("GetForegroundWindow")
        val foreground = getForeground.invokePointer(emptyArray())
        if (foreground != null) {
            val pidRef = IntByReference()
            rt.user32.getFunction("GetWindowThreadProcessId").invokeInt(arrayOf(foreground, pidRef))
            val ownPid = rt.kernel32.getFunction("GetCurrentProcessId").invokeInt(emptyArray())
            if (pidRef.value == ownPid) return foreground
        }
        return rt.kernel32.getFunction("GetConsoleWindow").invokePointer(emptyArray())
            ?: rt.user32.getFunction("GetDesktopWindow").invokePointer(emptyArray())
    }

    private fun createHString(rt: Runtime, s: String): Pointer? {
        val out = PointerByReference()
        val hr = rt.combase.getFunction("WindowsCreateString")
            .invokeInt(arrayOf(WString(s), s.length, out))
        return if (hr == 0) out.value else null
    }

    /**
     * `UserConsentVerifier.CheckAvailabilityAsync` — whether [evaluate] would show a real
     * Hello prompt. Prompt-free and fast (local COM round-trip); blocks briefly, so call it
     * off the caller's dispatcher. `Available` (0) → true; anything else (no device, not
     * configured, policy-disabled, busy) or any COM failure → false.
     */
    fun checkAvailability(timeoutMs: Long = 10_000): Boolean {
        val rt = runtime ?: return false
        var classHstr: Pointer? = null
        var statics: Pointer? = null
        var asyncOp: Pointer? = null
        var asyncInfo: Pointer? = null
        try {
            val hrInit = rt.combase.getFunction("RoInitialize").invokeInt(arrayOf(1))
            if (hrInit != 0 && hrInit != 1 && hrInit != RPC_E_CHANGED_MODE) return false

            classHstr = createHString(rt, RUNTIME_CLASS) ?: return false
            val staticsRef = PointerByReference()
            val hrFactory = rt.combase.getFunction("RoGetActivationFactory").invokeInt(
                arrayOf(classHstr, WinRtGuid.toWindowsBytes(IID_USER_CONSENT_VERIFIER_STATICS), staticsRef)
            )
            if (hrFactory != 0) return false
            statics = staticsRef.value

            // IUserConsentVerifierStatics is IInspectable-based → slot 6 is
            // CheckAvailabilityAsync(void** asyncOp) — the typed async op comes out
            // directly, no REFIID parameter (per the winmd vtable).
            val asyncRef = PointerByReference()
            if (comCall(statics, 6, asyncRef) != 0) return false
            asyncOp = asyncRef.value

            val infoRef = PointerByReference()
            if (comCall(asyncOp, 0, WinRtGuid.toWindowsBytes(IID_ASYNC_INFO), infoRef) != 0) return false
            asyncInfo = infoRef.value
            val deadline = System.nanoTime() + timeoutMs * 1_000_000
            while (true) {
                val statusRef = IntByReference()
                if (comCall(asyncInfo, 7, statusRef) != 0) return false
                if (statusRef.value != STATUS_STARTED) {
                    if (statusRef.value != STATUS_COMPLETED) return false
                    break
                }
                if (System.nanoTime() > deadline) {
                    runCatching { comCall(asyncInfo, 9) } // IAsyncInfo::Cancel
                    return false
                }
                Thread.sleep(5)
            }

            val resultRef = IntByReference()
            if (comCall(asyncOp, 8, resultRef) != 0) return false
            return resultRef.value == 0 // UserConsentVerifierAvailability.Available
        } catch (t: Throwable) {
            System.err.println("KSafe biometrics: Windows Hello availability check failed (${t.message})")
            return false
        } finally {
            release(asyncInfo)
            release(asyncOp)
            release(statics)
            val delete = runtime?.combase?.getFunction("WindowsDeleteString")
            classHstr?.let { runCatching { delete?.invokeInt(arrayOf(it)) } }
        }
    }

    /** Maps a `UserConsentVerificationResult` to the final decision. Pure, so it is unit-tested. */
    internal fun classifyResult(resultValue: Int, allowDeviceCredentialFallback: Boolean): Boolean = when (resultValue) {
        VERIFIED -> true
        // Hello IS installed but not usable for this device/user — a genuine "unavailable"
        // that Windows reports explicitly: pass through (permissive) / refuse (strict).
        DEVICE_NOT_PRESENT, NOT_CONFIGURED_FOR_USER, DISABLED_BY_POLICY ->
            unavailable(allowDeviceCredentialFallback)
        else -> false // Canceled, RetriesExhausted, DeviceBusy — a real denial, block.
    }

    /**
     * Shows the Windows Hello prompt and blocks until it resolves (call from a
     * background dispatcher). Returns true only on [VERIFIED].
     *
     * Unavailable-vs-error split, so a broken bridge can never be mistaken for a successful
     * auth: once the activation factory resolves, Hello IS present on this machine, so any
     * later COM/bridge failure fails CLOSED (`false`). Pass-through is reserved for a genuine
     * "Hello not usable" — the factory never resolved (runtime absent), or [classifyResult]
     * sees an explicit no-device / not-configured / policy-disabled result — where permissive
     * mode keeps the legacy pass-through and strict mode refuses. (The pre-fix code passed
     * through on *every* early failure, which is exactly what masked the u4/i4 GUID bug.)
     */
    fun evaluate(reason: String, allowDeviceCredentialFallback: Boolean, timeoutMs: Long = 300_000): Boolean {
        val rt = runtime ?: return false

        var classHstr: Pointer? = null
        var reasonHstr: Pointer? = null
        var factory: Pointer? = null
        var asyncOp: Pointer? = null
        var asyncInfo: Pointer? = null
        try {
            // MTA init; RPC_E_CHANGED_MODE means the thread already has an apartment — fine.
            val hrInit = rt.combase.getFunction("RoInitialize").invokeInt(arrayOf(1))
            if (hrInit != 0 && hrInit != 1 && hrInit != RPC_E_CHANGED_MODE) return unavailable(allowDeviceCredentialFallback)

            classHstr = createHString(rt, RUNTIME_CLASS) ?: return unavailable(allowDeviceCredentialFallback)
            val factoryRef = PointerByReference()
            val hrFactory = rt.combase.getFunction("RoGetActivationFactory").invokeInt(
                arrayOf(classHstr, WinRtGuid.toWindowsBytes(IID_USER_CONSENT_VERIFIER_INTEROP), factoryRef)
            )
            if (hrFactory != 0) return unavailable(allowDeviceCredentialFallback)
            factory = factoryRef.value

            // Factory resolved above → Hello IS present. From here, a failure is a bridge error,
            // not "Hello absent": fail closed (false), never pass through.
            reasonHstr = createHString(rt, reason) ?: return false
            val asyncRef = PointerByReference()
            // IUserConsentVerifierInterop is IInspectable-based → slot 6 is
            // RequestVerificationForWindowAsync(HWND, HSTRING, REFIID, void**).
            val hrRequest = comCall(
                factory, 6,
                pickWindowHandle(rt), reasonHstr,
                WinRtGuid.toWindowsBytes(WinRtGuid.ASYNC_OP_USER_CONSENT), asyncRef,
            )
            if (hrRequest != 0) return false // post-factory bridge error → fail closed (this was the masked bug)
            asyncOp = asyncRef.value

            // Wait via IAsyncInfo::get_Status (slot 7) — polling avoids implementing a
            // COM callback object for the Completed handler.
            val infoRef = PointerByReference()
            if (comCall(asyncOp, 0, WinRtGuid.toWindowsBytes(IID_ASYNC_INFO), infoRef) != 0) return false // bridge error → fail closed
            asyncInfo = infoRef.value
            val deadline = System.nanoTime() + timeoutMs * 1_000_000
            while (true) {
                val statusRef = IntByReference()
                if (comCall(asyncInfo, 7, statusRef) != 0) return false
                if (statusRef.value != STATUS_STARTED) {
                    if (statusRef.value != STATUS_COMPLETED) return false // Canceled / Error
                    break
                }
                if (System.nanoTime() > deadline) {
                    runCatching { comCall(asyncInfo, 9) } // IAsyncInfo::Cancel
                    return false
                }
                Thread.sleep(30)
            }

            // IAsyncOperation<T>::GetResults — slot 8 (6 IInspectable + put/get_Completed).
            val resultRef = IntByReference()
            if (comCall(asyncOp, 8, resultRef) != 0) return false
            return classifyResult(resultRef.value, allowDeviceCredentialFallback)
        } catch (t: Throwable) {
            System.err.println("KSafe biometrics: Windows Hello prompt failed (${t.message})")
            return false
        } finally {
            release(asyncInfo)
            release(asyncOp)
            release(factory)
            val delete = runtime?.combase?.getFunction("WindowsDeleteString")
            classHstr?.let { runCatching { delete?.invokeInt(arrayOf(it)) } }
            reasonHstr?.let { runCatching { delete?.invokeInt(arrayOf(it)) } }
        }
    }

    /**
     * Hello entirely absent on this machine: permissive mode preserves the documented
     * legacy pass-through (a capable prompt was never possible), strict mode refuses.
     */
    private fun unavailable(allowDeviceCredentialFallback: Boolean): Boolean {
        warnUnavailableOnce()
        return allowDeviceCredentialFallback
    }

    @Volatile private var warned = false
    private fun warnUnavailableOnce() {
        if (!warned) {
            warned = true
            System.err.println(
                "KSafe biometrics: Windows Hello is not available/configured on this machine — " +
                    "verifyBiometric passes through (allowDeviceCredentialFallback=true) or refuses (false). " +
                    "Configure Windows Hello in Settings > Accounts > Sign-in options for real prompts."
            )
        }
    }
}
