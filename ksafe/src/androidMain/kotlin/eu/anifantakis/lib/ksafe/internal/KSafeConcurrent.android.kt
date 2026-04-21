package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.runBlocking
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

@PublishedApi
internal actual fun <T> runBlockingOnPlatform(block: suspend () -> T): T = runBlocking { block() }

@PublishedApi
internal actual class KSafeAtomicFlag actual constructor(initial: Boolean) {
    private val ref = AtomicBoolean(initial)
    actual fun get(): Boolean = ref.get()
    actual fun set(value: Boolean) { ref.set(value) }
    actual fun compareAndSet(expected: Boolean, new: Boolean): Boolean = ref.compareAndSet(expected, new)
}

@PublishedApi
internal actual class KSafeConcurrentMap<V : Any> actual constructor() {
    private val map = ConcurrentHashMap<String, V>()
    actual operator fun get(key: String): V? = map[key]
    actual operator fun set(key: String, value: V) { map[key] = value }
    actual fun remove(key: String): V? = map.remove(key)
    actual fun containsKey(key: String): Boolean = map.containsKey(key)
    actual fun clear() { map.clear() }
    actual fun snapshot(): Map<String, V> = HashMap(map)
    actual fun replaceIf(key: String, expected: V, new: V): Boolean = map.replace(key, expected, new)
}

@PublishedApi
internal actual class KSafeConcurrentSet<T : Any> actual constructor() {
    private val set: MutableSet<T> = ConcurrentHashMap.newKeySet()
    actual fun add(value: T): Boolean = set.add(value)
    actual fun contains(value: T): Boolean = set.contains(value)
    actual fun remove(value: T): Boolean = set.remove(value)
    actual fun snapshot(): Set<T> = HashSet(set)
}
