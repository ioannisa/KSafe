package eu.anifantakis.lib.ksafe.biometrics

import com.sun.jna.Function
import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLibrary
import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.PointerByReference
import java.security.MessageDigest

/**
 * Computes WinRT pinterface IIDs at runtime: an RFC 4122 v5 (SHA-1) UUID over the
 * WinRT pinterface namespace GUID + the type's signature string. These GUIDs are
 * never published as constants, so computing them is the only dependency-free route.
 * Locked in by unit tests against reference GUIDs (`IIterable<String>`, `IVector<String>`).
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
     * The enum signature is `i4`: a non-`[Flags]` enum has Int32 underlying type. `u4`
     * ([Flags]/UInt32) computes a different GUID, which `RequestVerificationForWindowAsync`
     * rejects with `E_NOINTERFACE`.
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
 * Platform limitation: Windows treats the Hello PIN as part of Hello itself and
 * `UserConsentVerifier` cannot exclude it, so `allowDeviceCredentialFallback = false`
 * cannot enforce biometrics-only here. The flag still keys the authorization cache
 * strictly and controls the unavailable-fallback behavior.
 */
internal object WindowsHello {

    private const val RUNTIME_CLASS = "Windows.Security.Credentials.UI.UserConsentVerifier"
    private const val IID_USER_CONSENT_VERIFIER_INTEROP = "39e050c3-4e74-441a-8dc0-b81104df949c"
    private const val IID_USER_CONSENT_VERIFIER_STATICS = "af4f3f91-564c-4ddc-b8b5-973447627c65"
    private const val IID_ASYNC_INFO = "00000036-0000-0000-c000-000000000046"
    private const val RPC_E_CHANGED_MODE = -0x7FFEFEFA // 0x80010106

    private const val VERIFIED = 0
    private const val DEVICE_NOT_PRESENT = 1
    private const val NOT_CONFIGURED_FOR_USER = 2
    private const val DISABLED_BY_POLICY = 3

    private const val STATUS_STARTED = 0
    private const val STATUS_COMPLETED = 1

    private class Runtime {
        // Win32 exports are stdcall; JNA's default is cdecl. Identical on x64/ARM64 (one
        // convention), but a 32-bit JVM would unbalance the stack without ALT_CONVENTION.
        // Kept inside Runtime so the first touch of any JNA class stays under the lazy's
        // catch and a broken JNA install still degrades to the pass-through, not a throw.
        private val stdcall = mapOf(Library.OPTION_CALLING_CONVENTION to Function.ALT_CONVENTION)

        val combase: NativeLibrary = NativeLibrary.getInstance("combase", stdcall)
        val user32: NativeLibrary = NativeLibrary.getInstance("user32", stdcall)
        val kernel32: NativeLibrary = NativeLibrary.getInstance("kernel32", stdcall)
    }

    private val runtime: Runtime? by lazyNativeBridge("Windows Hello") { Runtime() }

    val isAvailable: Boolean get() = runtime != null

    /** Byte offset of vtable [slot]: entries are pointer-sized (8 on x64/ARM64, 4 on x86). */
    internal fun vtableByteOffset(slot: Int): Long = slot.toLong() * Native.POINTER_SIZE

    /** Calls COM vtable [slot] on [iface] (`this` is prepended), returning HRESULT. */
    private fun comCall(iface: Pointer, slot: Int, vararg args: Any?): Int {
        val fn = Function.getFunction(iface.getPointer(0).getPointer(vtableByteOffset(slot)), Function.ALT_CONVENTION)
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

    private fun deleteHString(rt: Runtime, hstring: Pointer) {
        runCatching { rt.combase.getFunction("WindowsDeleteString").invokeInt(arrayOf(hstring)) }
    }

    /**
     * Runs [body] with a live MTA apartment on this thread, balancing only an init this call
     * owned: S_OK / S_FALSE mean THIS call incremented the per-thread apartment count, while
     * RPC_E_CHANGED_MODE means the thread already had an apartment (usable, but not ours to
     * uninitialize — otherwise the IO-pool thread leaves MTA and a later co-resident STA
     * component gets RPC_E_CHANGED_MODE). [onInitFailure] supplies the result when no apartment
     * could be entered at all.
     *
     * [body] must release its interfaces in its own `finally`: an inner `finally` runs before
     * this one, so the apartment is still live while they are released.
     */
    private inline fun <T> withComApartment(rt: Runtime, onInitFailure: () -> T, body: () -> T): T {
        val hrInit = rt.combase.getFunction("RoInitialize").invokeInt(arrayOf(1))
        if (hrInit != 0 && hrInit != 1 && hrInit != RPC_E_CHANGED_MODE) return onInitFailure()
        val ownsComInit = hrInit == 0 || hrInit == 1
        try {
            return body()
        } finally {
            if (ownsComInit) runCatching { rt.combase.getFunction("RoUninitialize").invoke(emptyArray<Any?>()) }
        }
    }

    /**
     * The [RUNTIME_CLASS] activation factory for [iid], or `null` when the class name or the
     * factory could not be obtained. The class-name HSTRING is an [in] parameter the factory
     * does not retain, so it is deleted as soon as the call returns.
     */
    private fun activationFactory(rt: Runtime, iid: String): Pointer? {
        val classHstr = createHString(rt, RUNTIME_CLASS) ?: return null
        try {
            val factoryRef = PointerByReference()
            val hr = rt.combase.getFunction("RoGetActivationFactory")
                .invokeInt(arrayOf(classHstr, WinRtGuid.toWindowsBytes(iid), factoryRef))
            return if (hr == 0) factoryRef.value else null
        } finally {
            deleteHString(rt, classHstr)
        }
    }

    /**
     * Polls `IAsyncInfo::get_Status` (slot 7) every [pollIntervalMs] until the operation leaves
     * Started — polling avoids implementing a COM callback object for the Completed handler.
     * `false` on a COM failure, on a terminal status other than Completed, and on [timeoutMs],
     * which cancels the native operation first. An interrupt (the caller's coroutine cancelling
     * through `runInterruptible`) cancels it too and propagates, or the ceremony would stay on
     * screen up to its own timeout.
     */
    /**
     * Awaits one WinRT async operation and returns its `Int` result, or null on any failure.
     *
     * Owns the `IAsyncInfo` it queries for and releases it on every exit — the reference a
     * duplicated copy of this sequence leaks. The caller keeps ownership of [asyncOp].
     */
    private fun awaitAsyncIntResult(asyncOp: Pointer?, timeoutMs: Long, pollIntervalMs: Long): Int? {
        if (asyncOp == null) return null
        val infoRef = PointerByReference()
        if (comCall(asyncOp, 0, WinRtGuid.toWindowsBytes(IID_ASYNC_INFO), infoRef) != 0) return null
        val asyncInfo = infoRef.value ?: return null
        return try {
            if (!awaitAsyncCompletion(asyncInfo, timeoutMs, pollIntervalMs)) return null
            // IAsyncOperation<T>::GetResults — slot 8 (6 IInspectable + put/get_Completed).
            val resultRef = IntByReference()
            if (comCall(asyncOp, 8, resultRef) != 0) null else resultRef.value
        } finally {
            release(asyncInfo)
        }
    }

    private fun awaitAsyncCompletion(asyncInfo: Pointer, timeoutMs: Long, pollIntervalMs: Long): Boolean {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        while (true) {
            val statusRef = IntByReference()
            if (comCall(asyncInfo, 7, statusRef) != 0) return false
            if (statusRef.value != STATUS_STARTED) return statusRef.value == STATUS_COMPLETED
            if (System.nanoTime() - deadline > 0) {   // overflow-safe vs a raw `> deadline`
                runCatching { comCall(asyncInfo, 9) } // IAsyncInfo::Cancel
                return false
            }
            try {
                Thread.sleep(pollIntervalMs)
            } catch (ie: InterruptedException) {
                runCatching { comCall(asyncInfo, 9) }
                throw ie
            }
        }
    }

    /**
     * `UserConsentVerifier.CheckAvailabilityAsync` — whether [evaluate] would show a real
     * Hello prompt. Prompt-free and fast (local COM round-trip); blocks briefly, so call it
     * off the caller's dispatcher. `Available` (0) → true; anything else (no device, not
     * configured, policy-disabled, busy) or any COM failure → false.
     */
    fun checkAvailability(timeoutMs: Long = 10_000): Boolean {
        val rt = runtime ?: return false
        return try {
            withComApartment(rt, onInitFailure = { false }) {
                var statics: Pointer? = null
                var asyncOp: Pointer? = null
                try {
                    statics = activationFactory(rt, IID_USER_CONSENT_VERIFIER_STATICS)
                        ?: return@withComApartment false

                    // IInspectable-based → slot 6 is CheckAvailabilityAsync(void** asyncOp);
                    // the typed async op comes out directly, no REFIID parameter.
                    val asyncRef = PointerByReference()
                    if (comCall(statics, 6, asyncRef) != 0) return@withComApartment false
                    asyncOp = asyncRef.value

                    // Polls 6x faster than the interactive prompt: this probe shows no UI, so the
                    // whole call is latency the caller waits on.
                    val result = awaitAsyncIntResult(asyncOp, timeoutMs, pollIntervalMs = 5)
                        ?: return@withComApartment false
                    result == 0 // UserConsentVerifierAvailability.Available
                } finally {
                    release(asyncOp)
                    release(statics)
                }
            }
        } catch (t: Throwable) {
            System.err.println("KSafe biometrics: Windows Hello availability check failed (${t.message})")
            false
        }
    }

    internal fun classifyResult(resultValue: Int, allowDeviceCredentialFallback: Boolean): Boolean = when (resultValue) {
        VERIFIED -> true
        // Explicit "unavailable" (installed but not usable): pass through (permissive) / refuse (strict).
        DEVICE_NOT_PRESENT, NOT_CONFIGURED_FOR_USER, DISABLED_BY_POLICY ->
            unavailable(allowDeviceCredentialFallback)
        else -> false // Canceled, RetriesExhausted, DeviceBusy — a real denial, block.
    }

    /**
     * Shows the Windows Hello prompt and blocks until it resolves (call from a
     * background dispatcher). Returns true only on [VERIFIED].
     *
     * Fail-closed: once the activation factory resolves, Hello IS present, so any later
     * COM/bridge failure returns `false`. Pass-through is reserved for a genuine "Hello not
     * usable" — factory never resolved, or [classifyResult] sees no-device / not-configured /
     * policy-disabled — where permissive mode passes through and strict mode refuses.
     */
    fun evaluate(reason: String, allowDeviceCredentialFallback: Boolean, timeoutMs: Long = 300_000): Boolean {
        val rt = runtime ?: return false
        return try {
            withComApartment(rt, onInitFailure = { unavailable(allowDeviceCredentialFallback) }) {
                var reasonHstr: Pointer? = null
                var factory: Pointer? = null
                var asyncOp: Pointer? = null
                try {
                    factory = activationFactory(rt, IID_USER_CONSENT_VERIFIER_INTEROP)
                        ?: return@withComApartment unavailable(allowDeviceCredentialFallback)

                    reasonHstr = createHString(rt, reason) ?: return@withComApartment false
                    val asyncRef = PointerByReference()
                    // IUserConsentVerifierInterop is IInspectable-based → slot 6 is
                    // RequestVerificationForWindowAsync(HWND, HSTRING, REFIID, void**).
                    val hrRequest = comCall(
                        factory, 6,
                        pickWindowHandle(rt), reasonHstr,
                        WinRtGuid.toWindowsBytes(WinRtGuid.ASYNC_OP_USER_CONSENT), asyncRef,
                    )
                    if (hrRequest != 0) return@withComApartment false
                    asyncOp = asyncRef.value

                    // The prompt is user-paced, so a slower poll costs nothing.
                    val result = awaitAsyncIntResult(asyncOp, timeoutMs, pollIntervalMs = 30)
                        ?: return@withComApartment false
                    classifyResult(result, allowDeviceCredentialFallback)
                } finally {
                    release(asyncOp)
                    release(factory)
                    reasonHstr?.let { deleteHString(rt, it) }
                }
            }
        } catch (ie: InterruptedException) {
            // Cancellation, not a denial — must reach runInterruptible, not read as `false`.
            throw ie
        } catch (t: Throwable) {
            System.err.println("KSafe biometrics: Windows Hello prompt failed (${t.message})")
            false
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
