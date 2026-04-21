package eu.anifantakis.lib.ksafe.internal

/**
 * Internal thread-safe primitives used by [KSafeCore]. Each target provides an
 * `actual` implementation tuned to its concurrency model:
 *
 * | Target            | Backing implementation |
 * |-------------------|-----------------------|
 * | JVM / Android     | `java.util.concurrent.ConcurrentHashMap` + `AtomicBoolean` |
 * | iOS (Kotlin/Native) | `kotlin.concurrent.AtomicReference` with copy-on-write |
 * | Web (wasmJs/js)   | Plain `HashMap` — browsers are single-threaded |
 *
 * The surface area is deliberately narrow — only the operations [KSafeCore]
 * actually performs. Widening it later is cheap; widening the public API is
 * not, so we keep this internal.
 */

@PublishedApi
internal expect class KSafeAtomicFlag(initial: Boolean) {
    fun get(): Boolean
    fun set(value: Boolean)
    fun compareAndSet(expected: Boolean, new: Boolean): Boolean
}

/**
 * A concurrent `String`-keyed map. `V` is unconstrained but expected to be
 * non-null — callers use `remove` rather than storing `null`.
 */
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
     * Atomically replaces the mapping only when the current value is `==` [expected].
     * Returns `true` if the replacement happened. Used by the write coalescer to
     * swap plaintext → ciphertext in the cache without clobbering newer writes.
     */
    fun replaceIf(key: String, expected: V, new: V): Boolean
}

@PublishedApi
internal expect class KSafeConcurrentSet<T : Any>() {
    fun add(value: T): Boolean
    fun contains(value: T): Boolean
    fun remove(value: T): Boolean
    fun snapshot(): Set<T>
}

/**
 * Runs [block] synchronously, blocking the caller until it completes.
 *
 * Used by the sync APIs (`getDirect`, `getKeyInfo`) to guarantee cold-start data
 * consistency. Implemented as `runBlocking { block() }` on JVM/Android/iOS; on
 * the web target (which cannot block the main thread) it throws because the
 * web backend pre-populates its cache synchronously and should never hit this
 * path.
 */
@PublishedApi
internal expect fun <T> runBlockingOnPlatform(block: suspend () -> T): T
