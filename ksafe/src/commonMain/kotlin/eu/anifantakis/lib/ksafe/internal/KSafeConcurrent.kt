package eu.anifantakis.lib.ksafe.internal

import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.coroutines.CoroutineContext

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

/** Concurrent `String`-keyed map; `null` is never stored, callers use `remove`. */
@PublishedApi
internal expect class KSafeConcurrentMap<V : Any>() {
    operator fun get(key: String): V?
    operator fun set(key: String, value: V)
    fun remove(key: String): V?
    fun containsKey(key: String): Boolean
    fun clear()

    /** A point-in-time copy, safe to iterate. */
    fun snapshot(): Map<String, V>

    /** Replaces only when the current value is `==` [expected], so a newer write survives. */
    fun replaceIf(key: String, expected: V, new: V): Boolean

    /** Inserts only when [key] is absent; returns the existing value, or `null` if inserted. */
    fun putIfAbsent(key: String, value: V): V?

    /** Removes only when the current value is `==` [expected], never a third writer's value. */
    fun removeIf(key: String, expected: V): Boolean
}

@PublishedApi
internal expect class KSafeConcurrentSet<T : Any>() {
    fun add(value: T): Boolean
    fun contains(value: T): Boolean
    fun remove(value: T): Boolean
    fun snapshot(): Set<T>
}

/** Runs [block] synchronously. Throws on web, which cannot block; its cache is pre-populated. */
@PublishedApi
internal expect fun <T> runBlockingOnPlatform(block: suspend () -> T): T

/**
 * `flowOn` context for the per-emission decrypt: `Dispatchers.Default` where that decrypt is a
 * blocking OS-vault call, `EmptyCoroutineContext` on web, where a hop breaks the cold-start read.
 */
@PublishedApi
internal expect val decryptFlowContext: CoroutineContext

/**
 * Per-delegate non-suspending lock for the one-shot lazy init: reentrant so a nested first access
 * cannot self-deadlock, a parking lock so the cold-start read does not busy-spin. No-op on web.
 */
@PublishedApi
internal expect class KSafeInitLock() {
    fun <R> withLock(block: () -> R): R
}

/**
 * One double-checked lazily-built value: racing first accesses cannot build two instances and leak
 * the loser's coroutine. Composition, not a supertype — supertypes land in the committed ABI dumps.
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
 * Inserts [value] into a key cache guarded by the wipe fence [epoch], which a wipe bumps BEFORE it
 * removes the persisted records. [epochAtRead] must be captured BEFORE the read that produced
 * [value], or a wipe racing that read goes unseen and the cache serves key material with no record.
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
