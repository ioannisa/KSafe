package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.Volatile

/**
 * The per-file state every `KSafe` on one physical store shares: DataStore refuses two active
 * instances on one file, and sibling instances must also share one engine so their in-memory key
 * caches can't diverge from the single on-disk key slot (which would silently lose data).
 * Subclasses add the platform's own storage/engine handles.
 */
internal abstract class SharedStoreBackend(val scope: CoroutineScope) {
    /** One commit mutex per physical store: serializes sibling cores' batch commits. */
    val commitMutex = Mutex()

    /** Guarded by the owning registry's per-path lock. */
    var refCount: Int = 0

    private val engineLock = KSafeInitLock()

    @Volatile
    private var lazyEngine: KSafeEncryption? = null

    /**
     * The single engine every `KSafe` on this store shares, built on first use. Double-checked:
     * the volatile read publishes a fully-constructed engine, so the hot path takes no lock, and
     * the lock makes the construction itself happen once. Backends that pick their engine when
     * they pick their storage build it eagerly instead and never call this.
     */
    fun engineOrCreate(create: () -> KSafeEncryption): KSafeEncryption {
        lazyEngine?.let { return it }
        return engineLock.withLock { lazyEngine ?: create().also { lazyEngine = it } }
    }
}

/**
 * Bounded wait for a prior DataStore's teardown on recreate — capped under Android's ANR window
 * since it blocks the (possibly main) caller thread.
 */
internal const val BACKEND_TEARDOWN_TIMEOUT_MS = 2_000L

/**
 * Live [SharedStoreBackend]s by store path, ref-counted: only the last instance to close tears the
 * backend down. Creation is serialized per path, so one file never has two DataStores constructed
 * concurrently (which throws "multiple DataStores active for the same file"); unrelated paths stay
 * independent, since creation can block for the teardown wait below.
 *
 * @param dispatcher dispatcher for the backend scope — Kotlin/Native has no `Dispatchers.IO`.
 * @param onTeardownTimeout called when a prior backend did not finish tearing down in time; the
 *   first access may then transiently fail until it does, and then self-recovers.
 */
internal class SharedBackendRegistry<T : SharedStoreBackend>(
    private val dispatcher: CoroutineDispatcher,
    private val onTeardownTimeout: (String) -> Unit = {},
) {
    private val backends = KSafeConcurrentMap<T>()

    // Evicted backend's scope, awaited before a recreate: DataStore frees a file only once its
    // scope's Job completes, else the new DataStore hits "multiple DataStores active".
    private val terminatingScopes = KSafeConcurrentMap<CoroutineScope>()

    private val pathLocks = KSafeConcurrentMap<KSafeInitLock>()

    private fun pathLock(path: String): KSafeInitLock {
        pathLocks[path]?.let { return it }
        val fresh = KSafeInitLock()
        return pathLocks.putIfAbsent(path, fresh) ?: fresh
    }

    /** The shared backend for [path], created atomically on first use. */
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

    /**
     * Drops one ref; the last release evicts the entry, parks the scope for a later recreate to
     * await, and cancels it. Each `KSafe` must call this at most once (caller-guarded).
     */
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
