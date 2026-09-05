package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.Volatile

// The per-file state every `KSafe` on one physical store shares. DataStore refuses two active
// instances on one file, and siblings must share one engine or their key caches diverge from the
// single on-disk key slot and data is silently lost.
internal abstract class SharedStoreBackend(val scope: CoroutineScope) {
    /** Serializes sibling cores' batch commits. */
    val commitMutex = Mutex()

    val siblings = SiblingRegistry()

    /** Guarded by the owning registry's per-path lock. */
    var refCount: Int = 0

    private val engineLock = KSafeInitLock()

    @Volatile
    private var lazyEngine: KSafeEncryption? = null

    // The volatile read publishes a fully-constructed engine, so the hot path takes no lock.
    fun engineOrCreate(create: () -> KSafeEncryption): KSafeEncryption {
        lazyEngine?.let { return it }
        return engineLock.withLock { lazyEngine ?: create().also { lazyEngine = it } }
    }
}

// Capped under Android's ANR window: the wait blocks the (possibly main) caller thread.
internal const val BACKEND_TEARDOWN_TIMEOUT_MS = 2_000L

// Live backends by store path, ref-counted so only the last close tears one down. Creation is
// serialized per path, or one file gets two DataStores and DataStore throws; unrelated paths stay
// independent because creation can block on the teardown wait.
internal class SharedBackendRegistry<T : SharedStoreBackend>(
    private val dispatcher: CoroutineDispatcher,
    private val onTeardownTimeout: (String) -> Unit = {},
) {
    private val backends = KSafeConcurrentMap<T>()

    // Awaited before a recreate: DataStore frees a file only once its scope's Job completes.
    private val terminatingScopes = KSafeConcurrentMap<CoroutineScope>()

    private val pathLocks = KSafeConcurrentMap<KSafeInitLock>()

    private fun pathLock(path: String): KSafeInitLock {
        pathLocks[path]?.let { return it }
        val fresh = KSafeInitLock()
        return pathLocks.putIfAbsent(path, fresh) ?: fresh
    }

    fun acquire(path: String, create: (CoroutineScope) -> T): T = pathLock(path).withLock {
        backends[path]?.let {
            it.refCount++
            return@withLock it
        }
        terminatingScopes.remove(path)?.coroutineContext?.get(Job)?.let { priorJob ->
            val settled = runBlockingOnPlatform {
                withTimeoutOrNull(BACKEND_TEARDOWN_TIMEOUT_MS) { priorJob.join() } != null
            }
            if (!settled) onTeardownTimeout(path)
        }
        val scope = CoroutineScope(dispatcher + SupervisorJob())
        val backend = create(scope).also { it.refCount = 1 }
        backends[path] = backend
        backend
    }

    // The last release parks the scope for a later recreate to await, then cancels it.
    fun release(path: String): Unit = pathLock(path).withLock {
        val backend = backends[path] ?: return@withLock
        backend.refCount--
        if (backend.refCount <= 0) {
            backends.remove(path)
            terminatingScopes[path] = backend.scope
            backend.scope.cancel()
        }
    }
}
