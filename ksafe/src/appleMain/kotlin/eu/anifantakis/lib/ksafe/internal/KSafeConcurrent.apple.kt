package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.concurrent.AtomicInt
import kotlin.concurrent.AtomicReference
import kotlin.coroutines.CoroutineContext
import platform.Foundation.NSRecursiveLock

@PublishedApi
internal actual fun <T> runBlockingOnPlatform(block: suspend () -> T): T = runBlocking { block() }

@PublishedApi
internal actual val decryptFlowContext: CoroutineContext = Dispatchers.Default

// Kotlin/Native has no object-monitor `synchronized`, so back each delegate's init lock with
// its own NSRecursiveLock: a real OS parking lock (waiters block, no spin), per-instance so
// unrelated delegates don't serialize, reentrant so a nested first-access can't deadlock.
@PublishedApi
internal actual class KSafeInitLock actual constructor() {
    private val lock = NSRecursiveLock()
    actual fun <R> withLock(block: () -> R): R {
        lock.lock()
        try {
            return block()
        } finally {
            lock.unlock()
        }
    }
}

// Uses AtomicInt (0/1) rather than AtomicReference<Boolean>: AtomicReference uses
// identity equality, and boxed Booleans don't have guaranteed stable identity on
// Kotlin/Native, which would break compareAndSet.
@PublishedApi
internal actual class KSafeAtomicFlag actual constructor(initial: Boolean) {
    private val ref = AtomicInt(if (initial) 1 else 0)
    actual fun get(): Boolean = ref.value == 1
    actual fun set(value: Boolean) { ref.value = if (value) 1 else 0 }
    actual fun compareAndSet(expected: Boolean, new: Boolean): Boolean =
        ref.compareAndSet(if (expected) 1 else 0, if (new) 1 else 0)
}

/**
 * Copy-on-write concurrent map — Kotlin/Native lacks a stdlib `ConcurrentHashMap`,
 * so mutation rebuilds the map and CAS-swaps an [AtomicReference].
 *
 * Reads are lock-free and see a consistent snapshot. Writes are retry-on-conflict.
 */
@PublishedApi
internal actual class KSafeConcurrentMap<V : Any> actual constructor() {
    private val ref = AtomicReference<Map<String, V>>(emptyMap())

    actual operator fun get(key: String): V? = ref.value[key]

    actual operator fun set(key: String, value: V) {
        while (true) {
            val current = ref.value
            val next = HashMap(current).also { it[key] = value }
            if (ref.compareAndSet(current, next)) return
        }
    }

    actual fun remove(key: String): V? {
        while (true) {
            val current = ref.value
            if (!current.containsKey(key)) return null
            val next = HashMap(current).also { it.remove(key) }
            val prev = current[key]
            if (ref.compareAndSet(current, next)) return prev
        }
    }

    actual fun containsKey(key: String): Boolean = ref.value.containsKey(key)

    actual fun clear() {
        // CAS loop so `clear()` can't be undone by a concurrent mutation retrying against the
        // pre-clear snapshot.
        while (true) {
            val current = ref.value
            if (ref.compareAndSet(current, emptyMap())) return
        }
    }

    actual fun snapshot(): Map<String, V> = ref.value

    actual fun replaceIf(key: String, expected: V, new: V): Boolean {
        while (true) {
            val current = ref.value
            if (current[key] != expected) return false
            val next = HashMap(current).also { it[key] = new }
            if (ref.compareAndSet(current, next)) return true
        }
    }

    actual fun putIfAbsent(key: String, value: V): V? {
        while (true) {
            val current = ref.value
            current[key]?.let { return it }
            val next = HashMap(current).also { it[key] = value }
            if (ref.compareAndSet(current, next)) return null
        }
    }

    actual fun removeIf(key: String, expected: V): Boolean {
        while (true) {
            val current = ref.value
            if (current[key] != expected) return false
            val next = HashMap(current).also { it.remove(key) }
            if (ref.compareAndSet(current, next)) return true
        }
    }
}

@PublishedApi
internal actual class KSafeConcurrentSet<T : Any> actual constructor() {
    private val ref = AtomicReference<Set<T>>(emptySet())

    actual fun add(value: T): Boolean {
        while (true) {
            val current = ref.value
            if (current.contains(value)) return false
            val next = HashSet(current).also { it.add(value) }
            if (ref.compareAndSet(current, next)) return true
        }
    }

    actual fun contains(value: T): Boolean = ref.value.contains(value)

    actual fun remove(value: T): Boolean {
        while (true) {
            val current = ref.value
            if (!current.contains(value)) return false
            val next = HashSet(current).also { it.remove(value) }
            if (ref.compareAndSet(current, next)) return true
        }
    }

    actual fun snapshot(): Set<T> = ref.value
}
