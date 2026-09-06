package eu.anifantakis.lib.ksafe.internal

// Browsers run JS/Wasm on one thread, so these "concurrent" primitives are plain wrappers.

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
internal actual class KSafeAtomicInt actual constructor(initial: Int) {
    private var value: Int = initial
    actual fun get(): Int = value
    actual fun set(value: Int) { this.value = value }
    actual fun compareAndSet(expected: Int, new: Int): Boolean {
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

    actual fun putIfAbsent(key: String, value: V): V? {
        val existing = map[key]
        if (existing != null) return existing
        map[key] = value
        return null
    }

    actual fun removeIf(key: String, expected: V): Boolean {
        if (map[key] != expected) return false
        map.remove(key)
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

// A hop through the browser event loop would delay the first emission that ksafe-compose's
// cold-start `getFlow().first()` self-heal waits on, so getFlowRaw runs inline on the collector.
@PublishedApi
internal actual val decryptFlowContext: kotlin.coroutines.CoroutineContext =
    kotlin.coroutines.EmptyCoroutineContext

@PublishedApi
internal actual class KSafeInitLock actual constructor() {
    actual fun <R> withLock(block: () -> R): R = block()
}
