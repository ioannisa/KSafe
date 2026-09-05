package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.internal.KSafeAtomicInt
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.ksafeLogWarning
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.retryWhen

/** Wall-clock epoch millis; persisted as a key generation's birth time. */
@OptIn(kotlin.time.ExperimentalTime::class)
internal fun ksafeEpochMillis(): Long = kotlin.time.Clock.System.now().toEpochMilliseconds()

/**
 * Runs [block], swallowing every failure except cancellation: swallowing that one too would keep
 * a torn-down scope's work running.
 */
internal inline fun swallowingNonCancellation(block: () -> Unit) {
    runCatching(block).onFailure { if (it is CancellationException) throw it }
}

/**
 * Raises this counter to [value], never lowering it: a stale snapshot must not mint keys under an
 * already-rotated generation.
 */
internal fun KSafeAtomicInt.raiseToAtLeast(value: Int) {
    while (true) {
        val seen = get()
        if (value <= seen || compareAndSet(seen, value)) return
    }
}

/**
 * Deletes one engine key, downgrading failure to a warning: the key is already unreferenced, so a
 * vault hiccup must not fail an operation whose data half committed.
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
 * Applies every element currently queued without closing the channel. Teardown uses it to hand
 * queued writes their cancellation instead of leaving awaiters hung.
 */
internal fun <T> Channel<T>.drainRemaining(action: (T) -> Unit) {
    while (true) {
        val next = tryReceive().getOrNull() ?: break
        action(next)
    }
}

/** Capped exponential backoff (50ms doubling to 1s) for [retryingTransientReads]. */
internal fun collectorRetryBackoffMs(attempt: Long): Long =
    minOf(1_000L, 50L shl minOf(attempt, 5L).toInt())

/**
 * Resubscribes on a transient collection failure instead of terminating: one storage IOException
 * would otherwise kill the snapshot collector and freeze the cache for the whole process.
 */
internal fun <T> Flow<T>.retryingTransientReads(
    onRetry: (attempt: Long, cause: Throwable) -> Unit = { _, _ -> },
): Flow<T> = retryWhen { cause, attempt ->
    if (cause is CancellationException) return@retryWhen false
    onRetry(attempt + 1, cause)
    delay(collectorRetryBackoffMs(attempt))
    true
}

/** Capped backoff (250ms doubling to 30s) for a failed decrypt: a device locked overnight must not wake the key store every second. */
internal fun lockedDecryptRetryBackoffMs(attempt: Long): Long =
    minOf(30_000L, 250L shl minOf(attempt, 7L).toInt())
