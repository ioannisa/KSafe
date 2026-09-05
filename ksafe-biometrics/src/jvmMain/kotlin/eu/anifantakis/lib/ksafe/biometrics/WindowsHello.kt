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

/** WinRT pinterface IIDs as RFC 4122 v5 UUIDs; they are published nowhere as constants. */
internal object WinRtGuid {

    /** WinRT pinterface namespace GUID: {11f47ad5-7b73-42c0-abae-878b1e16adee}. */
    private val PINTERFACE_NAMESPACE = byteArrayOf(
        0x11, 0xf4.toByte(), 0x7a, 0xd5.toByte(), 0x7b, 0x73, 0x42, 0xc0.toByte(),
        0xab.toByte(), 0xae.toByte(), 0x87.toByte(), 0x8b.toByte(), 0x1e, 0x16, 0xad.toByte(), 0xee.toByte(),
    )

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

    /** The enum must be `i4`; `u4` yields a GUID `RequestVerificationForWindowAsync` rejects. */
    val ASYNC_OP_USER_CONSENT: String = pinterfaceGuid(
        "pinterface({9fc2b0bb-e446-44e2-aa61-9cab8f636af2};" +
            "enum(Windows.Security.Credentials.UI.UserConsentVerificationResult;i4))"
    )

    /** A canonical GUID string in the 16-byte little-endian layout JNA passes as REFIID. */
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
 * Windows Hello consent prompt for the JVM, over classic COM interop. Windows counts the Hello PIN
 * as part of Hello, so `allowDeviceCredentialFallback = false` cannot enforce biometrics-only here.
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
        // Win32 exports are stdcall, JNA defaults to cdecl: a 32-bit JVM unbalances the stack
        // without ALT_CONVENTION. Inside Runtime so a broken JNA install fails under the lazy.
        private val stdcall = mapOf(Library.OPTION_CALLING_CONVENTION to Function.ALT_CONVENTION)

        val combase: NativeLibrary = NativeLibrary.getInstance("combase", stdcall)
        val user32: NativeLibrary = NativeLibrary.getInstance("user32", stdcall)
        val kernel32: NativeLibrary = NativeLibrary.getInstance("kernel32", stdcall)
    }

    private val runtime: Runtime? by lazyNativeBridge("Windows Hello") { Runtime() }

    val isAvailable: Boolean get() = runtime != null

    internal fun vtableByteOffset(slot: Int): Long = slot.toLong() * Native.POINTER_SIZE

    private fun comCall(iface: Pointer, slot: Int, vararg args: Any?): Int {
        val fn = Function.getFunction(iface.getPointer(0).getPointer(vtableByteOffset(slot)), Function.ALT_CONVENTION)
        return fn.invokeInt(arrayOf(iface, *args))
    }

    private fun release(iface: Pointer?) {
        if (iface != null) runCatching { comCall(iface, 2) } // IUnknown::Release
    }

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
     * MTA apartment for [body], uninitialized only when this call entered it — on RPC_E_CHANGED_MODE
     * the thread already had one and dropping it evicts an STA. [body] releases in its own `finally`.
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

    /** The [RUNTIME_CLASS] activation factory for [iid]; the class-name HSTRING is freed on return. */
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
     * Awaits one WinRT async operation, releasing the `IAsyncInfo` it queries for on every exit;
     * [asyncOp] stays the caller's. Polls the status rather than installing a Completed handler.
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

    /** Whether [evaluate] would show a real prompt; blocks on a COM round-trip, so call it off-dispatcher. */
    fun checkAvailability(timeoutMs: Long = 10_000): Boolean {
        val rt = runtime ?: return false
        return try {
            withComApartment(rt, onInitFailure = { false }) {
                var statics: Pointer? = null
                var asyncOp: Pointer? = null
                try {
                    statics = activationFactory(rt, IID_USER_CONSENT_VERIFIER_STATICS)
                        ?: return@withComApartment false

                    // IInspectable-based → slot 6 is CheckAvailabilityAsync(void** asyncOp).
                    val asyncRef = PointerByReference()
                    if (comCall(statics, 6, asyncRef) != 0) return@withComApartment false
                    asyncOp = asyncRef.value

                    // No UI here, so the whole call is latency the caller waits on: poll fast.
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
        // Installed but not usable: pass through (permissive) / refuse (strict).
        DEVICE_NOT_PRESENT, NOT_CONFIGURED_FOR_USER, DISABLED_BY_POLICY ->
            unavailable(allowDeviceCredentialFallback)
        else -> false // Canceled, RetriesExhausted, DeviceBusy — a real denial, block.
    }

    /**
     * Shows the Windows Hello prompt and blocks until it resolves; call from a background dispatcher.
     * Fail-closed: once the factory resolves Hello is present, so a later COM failure returns `false`.
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
                    // IInspectable-based → slot 6 is RequestVerificationForWindowAsync.
                    val hrRequest = comCall(
                        factory, 6,
                        pickWindowHandle(rt), reasonHstr,
                        WinRtGuid.toWindowsBytes(WinRtGuid.ASYNC_OP_USER_CONSENT), asyncRef,
                    )
                    if (hrRequest != 0) return@withComApartment false
                    asyncOp = asyncRef.value

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
            // Cancellation, not a denial: must reach runInterruptible, not read as `false`.
            throw ie
        } catch (t: Throwable) {
            System.err.println("KSafe biometrics: Windows Hello prompt failed (${t.message})")
            false
        }
    }

    /** Hello absent on this machine: permissive mode passes through, strict mode refuses. */
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
