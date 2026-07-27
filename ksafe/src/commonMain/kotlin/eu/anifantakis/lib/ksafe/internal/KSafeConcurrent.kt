package eu.anifantakis.lib.ksafe.internal

import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.coroutines.CoroutineContext

// Thread-safe primitives for [KSafeCore]. Each target provides an `actual` tuned to
// its concurrency model: java.util.concurrent on JVM/Android, atomics/OS locks on
// Native, plain unsynchronized types on single-threaded web.

@PublishedApi
internal expect class KSafeAtomicFlag(initial: Boolean) {
    fun get(): Boolean
    fun set(value: Boolean)
    fun compareAndSet(expected: Boolean, new: Boolean): Boolean
}

@PublishedApi
internal expect class KSafeAtomicInt(initial: Int) {
    fun get(): Int
    fun set(value: Int)
    fun compareAndSet(expected: Int, new: Int): Boolean
}

/** Concurrent `String`-keyed map; callers use `remove` rather than storing `null`. */
@PublishedApi
internal expect class KSafeConcurrentMap<V : Any>() {
    operator fun get(key: String): V?
    operator fun set(key: String, value: V)
    fun remove(key: String): V?
    fun containsKey(key: String): Boolean
    fun clear()

    /** Returns a point-in-time copy. Safe to iterate. */
    fun snapshot(): Map<String, V>

    /**
     * Atomically replaces the mapping only when the current value is `==` [expected];
     * lets the write coalescer swap plaintext → ciphertext without clobbering newer writes.
     */
    fun replaceIf(key: String, expected: V, new: V): Boolean

    /**
     * Atomically inserts only when [key] is absent; returns the existing value, or `null`
     * if inserted. Lets cache repair restore a slot wiped by a concurrent clearAll
     * without overwriting a newer write's value.
     */
    fun putIfAbsent(key: String, value: V): V?

    /**
     * Atomically removes only when the current value is `==` [expected], so cache repair
     * rolls back exactly the value it restored — never a third writer's.
     */
    fun removeIf(key: String, expected: V): Boolean
}

@PublishedApi
internal expect class KSafeConcurrentSet<T : Any>() {
    fun add(value: T): Boolean
    fun contains(value: T): Boolean
    fun remove(value: T): Boolean
    fun snapshot(): Set<T>
}

/**
 * Runs [block] synchronously, blocking the caller. Throws on web, which cannot block
 * the main thread — the web backend pre-populates its cache and never hits this path.
 */
@PublishedApi
internal expect fun <T> runBlockingOnPlatform(block: suspend () -> T): T

/**
 * `flowOn` context for `getFlowRaw`'s per-emission decrypt. `Dispatchers.Default` on
 * JVM/Android/Apple: the OS-vault decrypt is a blocking IPC call that must not run on
 * the collector's dispatcher (often the main thread). `EmptyCoroutineContext` on
 * single-threaded web: decryption is async WebCrypto, and a dispatcher hop would break
 * the synchronous cold-start `getFlow().first()` self-heal.
 */
@PublishedApi
internal expect val decryptFlowContext: CoroutineContext

/**
 * Per-instance, reentrant, non-suspending lock for the flow delegates' one-shot lazy
 * init. Per-delegate so unrelated delegates never contend; reentrant so a nested
 * first-access on the same thread cannot self-deadlock; a real parking lock
 * (ReentrantLock / NSRecursiveLock) so blocking across the cold-start read doesn't
 * busy-spin. No-op on single-threaded web.
 */
@PublishedApi
internal expect class KSafeInitLock() {
    fun <R> withLock(block: () -> R): R
}

/**
 * One double-checked lazily-built value, held in a private field. Every delegate that must hand
 * out a single canonical instance needs this exact shape — a lock-free fast path plus a build
 * under [KSafeInitLock] — and each one that hand-writes it is a chance for a concurrent first
 * access to build a second instance and, with it, leak the coroutine that instance launched.
 *
 * Composition rather than a shared supertype: the delegates are `@PublishedApi internal` and
 * their supertypes are recorded in the committed ABI dumps, while a private field is not.
 */
internal class KSafeLazyRef<T : Any> {
    @Volatile private var value: T? = null
    private val initLock = KSafeInitLock()

    fun getOrPut(create: () -> T): T {
        value?.let { return it }
        return initLock.withLock {
            value ?: create().also { value = it }
        }
    }
}

/**
 * Inserts [value] into a key cache guarded by the purge fence [epoch], which a wipe bumps BEFORE
 * removing the persisted records the cache mirrors.
 *
 * [epochAtRead] must be captured BEFORE the read/mint that produced [value] — capturing it here
 * would miss a wipe that completed in between. The insert is skipped if a wipe raced that read,
 * and undone if one lands between the check and the put; the undo is conditional on [value] still
 * being the mapping, so it can never strip a newer legitimate re-mint.
 *
 * Written once because getting it wrong on one engine is silent: the cache would keep serving
 * key material whose persisted record is gone — readable for the rest of the session, gone after
 * relaunch, taking everything written under it.
 */
@OptIn(ExperimentalAtomicApi::class)
internal fun <V : Any> insertUnderPurgeFence(
    cache: KSafeConcurrentMap<V>,
    epoch: AtomicLong,
    key: String,
    value: V,
    epochAtRead: Long,
) {
    if (epoch.load() != epochAtRead) return
    cache[key] = value
    if (epoch.load() != epochAtRead) cache.removeIf(key, value)
}
