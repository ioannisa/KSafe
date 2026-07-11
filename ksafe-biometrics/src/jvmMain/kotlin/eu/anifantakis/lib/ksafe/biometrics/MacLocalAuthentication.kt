package eu.anifantakis.lib.ksafe.biometrics

import com.sun.jna.Callback
import com.sun.jna.CallbackReference
import com.sun.jna.Function
import com.sun.jna.Memory
import com.sun.jna.NativeLibrary
import com.sun.jna.Pointer
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.atomic.AtomicBoolean

/**
 * macOS Touch ID / password prompt for the JVM, bridged to `LocalAuthentication`'s
 * `LAContext` through the Objective-C runtime via JNA (`objc_msgSend`) — the same
 * pattern the `:ksafe` JVM key vaults use for C APIs, extended to ObjC messaging.
 *
 * Policy mapping mirrors the native `macosMain` target exactly:
 * `allowDeviceCredentialFallback = true` → `LAPolicyDeviceOwnerAuthentication`
 * (Touch ID, password, or Apple Watch — available on every Mac);
 * `false` → `LAPolicyDeviceOwnerAuthenticationWithBiometrics` (Touch ID only —
 * fails on hardware-less Macs, matching the native target's `false` there).
 *
 * The consent dialog is rendered by `coreauthd`/`SecurityAgent`, a separate system
 * process, so no NSApplication run loop is required — plain JVM apps work.
 */
internal object MacLocalAuthentication {

    private const val LA_POLICY_BIOMETRICS = 1L          // LAPolicyDeviceOwnerAuthenticationWithBiometrics
    private const val LA_POLICY_DEVICE_OWNER = 2L        // LAPolicyDeviceOwnerAuthentication
    private const val BLOCK_IS_GLOBAL = 1 shl 28

    /** ObjC completion-block signature: `void (^)(BOOL success, NSError *error)`. */
    internal interface LAReplyCallback : Callback {
        fun invoke(block: Pointer?, success: Byte, error: Pointer?)
    }

    private class Runtime {
        val objc: NativeLibrary = NativeLibrary.getInstance("objc")
        val msgSend: Function = objc.getFunction("objc_msgSend")
        val poolPush: Function = objc.getFunction("objc_autoreleasePoolPush")
        val poolPop: Function = objc.getFunction("objc_autoreleasePoolPop")
        val nsConcreteGlobalBlock: Pointer =
            NativeLibrary.getProcess().getGlobalVariableAddress("_NSConcreteGlobalBlock")
        val laContextClass: Pointer

        init {
            // Loading the framework registers LAContext with the ObjC runtime.
            NativeLibrary.getInstance(
                "/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication"
            )
            laContextClass = objc.getFunction("objc_getClass").invokePointer(arrayOf("LAContext"))
                ?: throw IllegalStateException("LAContext class not found after loading LocalAuthentication")
        }

        fun sel(name: String): Pointer = objc.getFunction("sel_registerName").invokePointer(arrayOf(name))

        fun msgSendPtr(receiver: Pointer, selector: Pointer, vararg args: Any?): Pointer? =
            msgSend.invokePointer(arrayOf(receiver, selector, *args))

        fun msgSendVoid(receiver: Pointer, selector: Pointer, vararg args: Any?) {
            msgSend.invoke(arrayOf(receiver, selector, *args))
        }
    }

    // Lazy so merely loading this class (e.g. on Windows) never touches macOS libraries;
    // a failure is remembered and surfaces as "bridge unavailable" rather than retrying.
    private val runtime: Runtime? by lazy {
        try {
            Runtime()
        } catch (t: Throwable) {
            System.err.println(
                "KSafe biometrics: macOS LocalAuthentication bridge unavailable (${t.message}); " +
                    "verifyBiometric falls back to pass-through."
            )
            null
        }
    }

    /** True when the ObjC bridge loaded; false means callers should use the legacy pass-through. */
    val isAvailable: Boolean get() = runtime != null

    /**
     * `LAContext.canEvaluatePolicy:error:` — whether [evaluate] would show a real prompt
     * for this policy. Synchronous and prompt-free.
     */
    fun canEvaluate(allowDeviceCredentialFallback: Boolean): Boolean {
        val rt = runtime ?: return false
        val policy = if (allowDeviceCredentialFallback) LA_POLICY_DEVICE_OWNER else LA_POLICY_BIOMETRICS
        val pool = rt.poolPush.invokePointer(emptyArray())
        var context: Pointer? = null
        return try {
            context = rt.msgSendPtr(rt.laContextClass, rt.sel("alloc"))
                ?.let { rt.msgSendPtr(it, rt.sel("init")) } ?: return false
            // BOOL return marshals as int; a null error out-pointer is valid.
            rt.msgSend.invokeInt(arrayOf(context, rt.sel("canEvaluatePolicy:error:"), policy, null)) != 0
        } catch (t: Throwable) {
            false
        } finally {
            context?.let { c -> runCatching { rt.msgSendVoid(c, rt.sel("release")) } }
            rt.poolPop.invoke(arrayOf(pool))
        }
    }

    /**
     * Shows the system authentication prompt and suspends until it resolves.
     * Cancelling the coroutine invalidates the pending prompt (mirrors appleMain).
     */
    suspend fun evaluate(reason: String, allowDeviceCredentialFallback: Boolean): Boolean {
        val rt = runtime ?: return false
        val policy = if (allowDeviceCredentialFallback) LA_POLICY_DEVICE_OWNER else LA_POLICY_BIOMETRICS

        return suspendCancellableCoroutine { continuation ->
            val resumed = AtomicBoolean(false)
            val released = AtomicBoolean(false)

            val pool = rt.poolPush.invokePointer(emptyArray())
            var context: Pointer? = null
            try {
                context = rt.msgSendPtr(rt.laContextClass, rt.sel("alloc"))
                    ?.let { rt.msgSendPtr(it, rt.sel("init")) }
                    ?: throw IllegalStateException("LAContext alloc/init returned nil")
                val ctx = context

                fun releaseContextOnce() {
                    if (released.compareAndSet(false, true)) {
                        runCatching { rt.msgSendVoid(ctx, rt.sel("release")) }
                    }
                }

                // NSString is autoreleased — covered by the pool around this setup block.
                // LAContext retains what it needs before evaluatePolicy returns.
                val reasonBytes = reason.toByteArray(Charsets.UTF_8)
                val reasonBuf = Memory((reasonBytes.size + 1).toLong()).apply {
                    write(0, reasonBytes, 0, reasonBytes.size)
                    setByte(reasonBytes.size.toLong(), 0)
                }
                val nsString = rt.objc.getFunction("objc_getClass").invokePointer(arrayOf("NSString"))!!
                val nsReason = rt.msgSendPtr(nsString, rt.sel("stringWithUTF8String:"), reasonBuf)
                    ?: throw IllegalStateException("NSString creation failed")

                // The reply callback: fires exactly once on LocalAuthentication's private
                // queue. References to callback/block/descriptor are held by this closure
                // (and JNA's CallbackReference) until resume, so nothing is collected early.
                val callback = object : LAReplyCallback {
                    override fun invoke(block: Pointer?, success: Byte, error: Pointer?) {
                        releaseContextOnce()
                        if (resumed.compareAndSet(false, true) && continuation.isActive) {
                            continuation.resumeWith(Result.success(success.toInt() != 0))
                        }
                        // Keep reasonBuf reachable until the prompt resolved.
                        reasonBuf.size()
                    }
                }

                // Hand-built ObjC block literal (LP64 layout): isa | flags | reserved |
                // invoke | descriptor. A GLOBAL block so Block_copy is a no-op and no
                // copy/dispose helpers are needed.
                val descriptor = Memory(16).apply {
                    setLong(0, 0)   // reserved
                    setLong(8, 32)  // Block_literal size
                }
                val block = Memory(32).apply {
                    setPointer(0, rt.nsConcreteGlobalBlock)
                    setInt(8, BLOCK_IS_GLOBAL)
                    setInt(12, 0)
                    setPointer(16, CallbackReference.getFunctionPointer(callback))
                    setPointer(24, descriptor)
                }

                continuation.invokeOnCancellation {
                    // Dismisses the pending system prompt; the reply then fires with
                    // success=false and the guarded resume above no-ops.
                    runCatching { rt.msgSendVoid(ctx, rt.sel("invalidate")) }
                    releaseContextOnce()
                }

                rt.msgSendVoid(ctx, rt.sel("evaluatePolicy:localizedReason:reply:"), policy, nsReason, block)
            } catch (t: Throwable) {
                context?.let { c -> if (released.compareAndSet(false, true)) runCatching { rt.msgSendVoid(c, rt.sel("release")) } }
                if (resumed.compareAndSet(false, true) && continuation.isActive) {
                    continuation.resumeWith(Result.failure(t))
                }
            } finally {
                rt.poolPop.invoke(arrayOf(pool))
            }
        }
    }
}
