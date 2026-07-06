package eu.anifantakis.lib.ksafe.internal

import kotlin.coroutines.CoroutineContext

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

    /**
     * Atomically inserts the mapping only when [key] is absent. Returns the
     * value already present (no change made), or `null` when [value] was
     * inserted. Used by the post-commit cache repair: restore a key's state
     * only when a concurrent clearAll wiped the slot — never over a newer
     * write's optimistic value, which would already occupy it.
     */
    fun putIfAbsent(key: String, value: V): V?

    /**
     * Atomically removes the mapping only when the current value is `==` [expected].
     * Returns `true` if the removal happened. Used by the post-commit cache repair to
     * roll back exactly the value it just restored when it discovers a concurrent
     * delete/newer write superseded it — without ever removing a third writer's value.
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

/**
 * The `flowOn` context for off-loading `getFlowRaw`'s per-emission decrypt (FEEDBACK_4 H8).
 *
 * `Dispatchers.Default` on JVM / Android / Apple — the OS-vault decrypt is a **blocking** IPC
 * call (on Android a synchronous Keystore Binder round-trip) that must not run on the collector's
 * dispatcher, which for a `getStateFlow` collected on a `viewModelScope` is the main thread.
 * `EmptyCoroutineContext` on single-threaded **web** (a `flowOn` no-op): decryption there is async
 * WebCrypto and there is no worker thread to move to, and forcing a dispatcher hop would break the
 * synchronous cold-start `getFlow().first()` self-heal.
 */
@PublishedApi
internal expect val decryptFlowContext: CoroutineContext

/**
 * A per-instance, reentrant, non-suspending mutual-exclusion lock for the
 * one-shot lazy init in the flow delegates (double-checked init: a fast-path
 * volatile read outside, the build inside). Each delegate owns its own lock, so
 * unrelated delegates never contend, and [withLock] may block across the
 * cold-start read without busy-spinning:
 *
 * | Target            | Backing lock |
 * |-------------------|--------------|
 * | JVM / Android     | `java.util.concurrent.locks.ReentrantLock` |
 * | Apple (Native)    | `NSRecursiveLock` — a real OS parking lock |
 * | Web (wasmJs/js)   | none — single-threaded; [withLock] just calls through |
 *
 * Reentrant so a nested first-access on the same thread cannot self-deadlock —
 * the property the previous Apple global busy-spin lock violated (FEEDBACK_4
 * M11: one process-wide spin lock, held across blocking disk/keychain I/O).
 */
@PublishedApi
internal expect class KSafeInitLock() {
    fun <R> withLock(block: () -> R): R
}
