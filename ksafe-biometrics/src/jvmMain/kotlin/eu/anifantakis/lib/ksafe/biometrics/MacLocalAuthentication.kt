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
 * macOS Touch ID / password prompt for the JVM, bridging `LAContext` through the ObjC runtime
 * via JNA. The dialog is rendered by `coreauthd`, so no NSApplication run loop is required.
 */
internal object MacLocalAuthentication {

    private const val LA_POLICY_BIOMETRICS = 1L          // LAPolicyDeviceOwnerAuthenticationWithBiometrics
    private const val LA_POLICY_DEVICE_OWNER = 2L        // LAPolicyDeviceOwnerAuthentication
    private const val BLOCK_IS_GLOBAL = 1 shl 28

    // Strong anchors for the native objects LA calls back into: they must outlive the cancellation
    // handler (LA still delivers one reply after invalidate), and JNA holds the callback weakly.
    private val pendingEvaluations = java.util.concurrent.ConcurrentHashMap<Any, List<Any>>()

    /** ObjC reply block `void (^)(BOOL success, NSError *error)`; the leading block pointer is
     *  the implicit first argument. */
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

    private val runtime: Runtime? by lazyNativeBridge("macOS LocalAuthentication") { Runtime() }

    val isAvailable: Boolean get() = runtime != null

    // Probe and prompt must ask about the same policy, or canEvaluate answers for a prompt never shown.
    private fun policyFor(allowDeviceCredentialFallback: Boolean): Long =
        if (allowDeviceCredentialFallback) LA_POLICY_DEVICE_OWNER else LA_POLICY_BIOMETRICS

    /** Whether [evaluate] would show a real prompt for this policy. Synchronous, prompt-free. */
    fun canEvaluate(allowDeviceCredentialFallback: Boolean): Boolean {
        val rt = runtime ?: return false
        val policy = policyFor(allowDeviceCredentialFallback)
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

    /** Shows the system prompt and suspends until it resolves; cancelling invalidates it. */
    suspend fun evaluate(reason: String, allowDeviceCredentialFallback: Boolean): Boolean {
        val rt = runtime ?: return false
        val policy = policyFor(allowDeviceCredentialFallback)

        return suspendCancellableCoroutine { continuation ->
            val resumed = AtomicBoolean(false)
            val released = AtomicBoolean(false)
            // Declared before the try so the catch (reply will never fire) can also drop the anchor.
            val anchorKey = Any()

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

                // NSString is autoreleased into the pool above; LAContext retains what it needs.
                // An empty localizedReason raises through JNA and aborts the JVM.
                val reasonBytes = promptReason(reason).toByteArray(Charsets.UTF_8)
                val reasonBuf = Memory((reasonBytes.size + 1).toLong()).apply {
                    write(0, reasonBytes, 0, reasonBytes.size)
                    setByte(reasonBytes.size.toLong(), 0)
                }
                val nsString = rt.objc.getFunction("objc_getClass").invokePointer(arrayOf("NSString"))!!
                val nsReason = rt.msgSendPtr(nsString, rt.sel("stringWithUTF8String:"), reasonBuf)
                    ?: throw IllegalStateException("NSString creation failed")

                // Fires once — on resolve, or after a cancel's invalidate — so it drops the anchor.
                val callback = object : LAReplyCallback {
                    override fun invoke(block: Pointer?, success: Byte, error: Pointer?) {
                        releaseContextOnce()
                        if (resumed.compareAndSet(false, true) && continuation.isActive) {
                            continuation.resumeWith(Result.success(success.toInt() != 0))
                        }
                        pendingEvaluations.remove(anchorKey)
                    }
                }

                // Hand-built ObjC block literal (LP64): isa | flags | reserved | invoke |
                // descriptor. Global, so Block_copy is a no-op and no copy/dispose helpers exist.
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

                pendingEvaluations[anchorKey] = listOf(callback, block, descriptor, reasonBuf, nsReason)

                continuation.invokeOnCancellation {
                    // Invalidate, never release: cancelled at registration this runs before
                    // evaluatePolicy, which would then message a freed object. LA's reply releases.
                    runCatching { rt.msgSendVoid(ctx, rt.sel("invalidate")) }
                }

                rt.msgSendVoid(ctx, rt.sel("evaluatePolicy:localizedReason:reply:"), policy, nsReason, block)
            } catch (t: Throwable) {
                // evaluatePolicy threw, so no reply will fire: drop the anchor here instead.
                pendingEvaluations.remove(anchorKey)
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
