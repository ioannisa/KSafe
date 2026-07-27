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
 * macOS Touch ID / password prompt for the JVM, bridging `LAContext` through the
 * ObjC runtime via JNA (`objc_msgSend`).
 *
 * `allowDeviceCredentialFallback = true` → `LAPolicyDeviceOwnerAuthentication`
 * (Touch ID, password, or Apple Watch); `false` →
 * `LAPolicyDeviceOwnerAuthenticationWithBiometrics` (Touch ID only, fails on
 * hardware-less Macs).
 *
 * The dialog is rendered by `coreauthd`/`SecurityAgent`, so no NSApplication run
 * loop is required — plain JVM apps work.
 */
internal object MacLocalAuthentication {

    private const val LA_POLICY_BIOMETRICS = 1L          // LAPolicyDeviceOwnerAuthenticationWithBiometrics
    private const val LA_POLICY_DEVICE_OWNER = 2L        // LAPolicyDeviceOwnerAuthentication
    private const val BLOCK_IS_GLOBAL = 1 shl 28

    // Strong, GC-durable anchors for the native objects LA invokes from its async reply (callback,
    // block, descriptor, reason buffer, NSString). This must OUTLIVE the continuation's cancellation
    // handler: after invalidate() LA still delivers the reply exactly once, AFTER that handler has
    // run and been dropped, so the block must stay reachable until the reply lands — where it (and
    // the catch, if the reply can never fire) removes its entry. JNA keeps the callback alive only
    // via a weak CallbackReference, so without a strong anchor the trampoline can be freed mid-prompt.
    private val pendingEvaluations = java.util.concurrent.ConcurrentHashMap<Any, List<Any>>()

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

    private val runtime: Runtime? by lazyNativeBridge("macOS LocalAuthentication") { Runtime() }

    /** True when the ObjC bridge loaded; false means callers should use the legacy pass-through. */
    val isAvailable: Boolean get() = runtime != null

    // The prompt and the probe must ask about the SAME policy, or canEvaluate answers for a
    // prompt that is never shown.
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

    /**
     * Shows the system authentication prompt and suspends until it resolves.
     * Cancelling the coroutine invalidates the pending prompt (mirrors appleMain).
     */
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

                // LA fires this once on its private queue after this lambda returns. JNA does not
                // keep the callback/block/descriptor alive via the native function pointer, and the
                // suspended coroutine doesn't capture them — the pendingEvaluations anchor keeps them
                // alive until this reply runs (the one point guaranteed to fire exactly once, on
                // resolve OR after a cancel's invalidate), then drops them here.
                val callback = object : LAReplyCallback {
                    override fun invoke(block: Pointer?, success: Byte, error: Pointer?) {
                        releaseContextOnce()
                        if (resumed.compareAndSet(false, true) && continuation.isActive) {
                            continuation.resumeWith(Result.success(success.toInt() != 0))
                        }
                        // LA will not touch these native objects again after this reply.
                        pendingEvaluations.remove(anchorKey)
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

                // Anchor every native object LA touches when the reply fires in a process-durable map
                // (not the cancellation handler): the handler is dropped the moment the continuation
                // completes, but on cancel LA still delivers the reply once AFTER invalidate() — the
                // reply removes the anchor, so it survives exactly that long.
                pendingEvaluations[anchorKey] = listOf(callback, block, descriptor, reasonBuf, nsReason)

                continuation.invokeOnCancellation {
                    // Only invalidate, never release: if cancelled at registration this runs
                    // synchronously before evaluatePolicy, and releasing the retain-count-1 context
                    // would make evaluatePolicy message a freed object (SIGSEGV). invalidate keeps it
                    // alive; LA's reply releases it (and removes the anchor) exactly once.
                    runCatching { rt.msgSendVoid(ctx, rt.sel("invalidate")) }
                }

                rt.msgSendVoid(ctx, rt.sel("evaluatePolicy:localizedReason:reply:"), policy, nsReason, block)
            } catch (t: Throwable) {
                // evaluatePolicy threw → no reply will ever fire → drop the anchor so it can't leak.
                // Idempotent, and mutually exclusive with the reply path, so no double-remove hazard.
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
