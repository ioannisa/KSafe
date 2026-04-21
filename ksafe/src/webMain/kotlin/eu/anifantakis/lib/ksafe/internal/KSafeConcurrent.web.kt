package eu.anifantakis.lib.ksafe.internal

/**
 * Browsers execute JS/Wasm on a single main thread, so these "concurrent"
 * primitives are just unsynchronised wrappers. Keeping them behind the same
 * interface means [KSafeCore] compiles unchanged on the web target.
 */

@PublishedApi
internal actual class KSafeAtomicFlag actual constructor(initial: Boolean) {
    private var value: Boolean = initial
    actual fun get(): Boolean = value
    actual fun set(value: Boolean) { this.value = value }
    actual fun compareAndSet(expected: Boolean, new: Boolean): Boolean {
        if (value != expected) return false
        value = new
        return true
    }
}

@PublishedApi
internal actual class KSafeConcurrentMap<V : Any> actual constructor() {
    private val map = HashMap<String, V>()
    actual operator fun get(key: String): V? = map[key]
    actual operator fun set(key: String, value: V) { map[key] = value }
    actual fun remove(key: String): V? = map.remove(key)
    actual fun containsKey(key: String): Boolean = map.containsKey(key)
    actual fun clear() { map.clear() }
    actual fun snapshot(): Map<String, V> = HashMap(map)
    actual fun replaceIf(key: String, expected: V, new: V): Boolean {
        if (map[key] != expected) return false
        map[key] = new
        return true
    }
}

@PublishedApi
internal actual class KSafeConcurrentSet<T : Any> actual constructor() {
    private val set = HashSet<T>()
    actual fun add(value: T): Boolean = set.add(value)
    actual fun contains(value: T): Boolean = set.contains(value)
    actual fun remove(value: T): Boolean = set.remove(value)
    actual fun snapshot(): Set<T> = HashSet(set)
}

@PublishedApi
internal actual fun <T> runBlockingOnPlatform(block: suspend () -> T): T =
    error("runBlockingOnPlatform is not available on the web target; the web cache must be pre-populated synchronously.")
