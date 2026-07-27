package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.internal.KSafeAtomicInt
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.ksafeLogWarning
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.retryWhen

/** Wall-clock epoch millis; persisted as key-generation birth for the MaxAge rotation policy. */
@OptIn(kotlin.time.ExperimentalTime::class)
internal fun ksafeEpochMillis(): Long = kotlin.time.Clock.System.now().toEpochMilliseconds()

/**
 * Runs [block], swallowing every failure EXCEPT cancellation, which must always propagate — a
 * best-effort step that ate its own cancellation would keep a torn-down scope's work running.
 * Written once because the rethrow is the whole point and is easy to omit in a fresh copy.
 */
internal inline fun swallowingNonCancellation(block: () -> Unit) {
    runCatching(block).onFailure { if (it is CancellationException) throw it }
}

/**
 * Raises this counter to [value], never lowering it. The store's key generation is monotonic in
 * memory: a stale snapshot racing a just-committed rotation must not make new writes mint keys
 * under an old (possibly already-deleted) generation.
 */
internal fun KSafeAtomicInt.raiseToAtLeast(value: Int) {
    while (true) {
        val seen = get()
        if (value <= seen || compareAndSet(seen, value)) return
    }
}

/**
 * Deletes one engine key, downgrading any failure to a warning: the key material is already
 * unreferenced, so a vault hiccup must not fail an operation whose data half already committed.
 * [attempt] and [consequence] keep each caller's own diagnostic wording — only iOS has a sweep
 * that can reclaim a stranded key later, so the log line is the only trace elsewhere.
 */
internal suspend fun KSafeCore.deleteEngineKeyBestEffort(
    alias: String,
    attempt: String,
    consequence: String,
) {
    runCatching { engine.deleteKeySuspend(alias) }
        .onFailure {
            if (it is CancellationException) throw it
            ksafeLogWarning("KSafe: $attempt '$alias' ($consequence): ${it.message}")
        }
}

/**
 * Receives and applies every element currently queued in this channel without closing it,
 * stopping when the channel is momentarily empty. Used at teardown to hand queued-but-
 * unprocessed writes their cancellation instead of leaving awaiters hung forever.
 */
internal fun <T> Channel<T>.drainRemaining(action: (T) -> Unit) {
    while (true) {
        val next = tryReceive().getOrNull() ?: break
        action(next)
    }
}

/** Capped exponential backoff (50ms, 100, 200, 400, 800, then 1s) for [retryingTransientReads]. */
internal fun collectorRetryBackoffMs(attempt: Long): Long =
    minOf(1_000L, 50L shl minOf(attempt, 5L).toInt())

/**
 * Resubscribes on a transient collection failure instead of terminating. Without it a single
 * storage-read IOException (or an updateCache hiccup) permanently kills the snapshot collector,
 * freezing the in-memory cache for the whole process lifetime — every later read serves stale
 * data and no external change is ever observed. Cancellation still stops it; [onRetry] receives
 * the 1-based attempt and the failure so a permanent error (permission, corruption, programming
 * bug) is diagnosable from the logs even though the loop keeps retrying — terminating instead
 * would recreate the frozen-cache failure mode this helper exists to prevent.
 */
internal fun <T> Flow<T>.retryingTransientReads(
    onRetry: (attempt: Long, cause: Throwable) -> Unit = { _, _ -> },
): Flow<T> = retryWhen { cause, attempt ->
    if (cause is CancellationException) return@retryWhen false
    onRetry(attempt + 1, cause)
    delay(collectorRetryBackoffMs(attempt))
    true
}
