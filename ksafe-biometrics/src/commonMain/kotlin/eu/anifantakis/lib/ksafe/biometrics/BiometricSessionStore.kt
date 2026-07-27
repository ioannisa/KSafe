package eu.anifantakis.lib.ksafe.biometrics

import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * Monotonic now, in milliseconds: a backward wall-clock jump must never extend a cached
 * authorization. `Double` because the web's source (`performance.now()`) is sub-millisecond;
 * the origin is arbitrary per platform, so only DIFFERENCES of two readings mean anything.
 */
internal expect fun biometricMonotonicNowMs(): Double

/**
 * The per-scope biometric authorization cache, shared by every platform so the read path, the
 * seed path and clearing can never drift apart.
 *
 * Entries are keyed by [BiometricAuthSession.sessionKey] and hold the [biometricMonotonicNowMs]
 * reading of the authentication that created them. PRESENCE of an entry is the only "is there an
 * authorization" sentinel: the stamp feeds elapsed-time math only, because a monotonic clock's
 * origin is arbitrary and its readings may legitimately be zero or negative.
 */
@OptIn(ExperimentalAtomicApi::class)
internal object BiometricSessionStore {

    // Immutable map behind a CAS loop, so a seed, a rollback and a clear racing each other can
    // never lose a write.
    private val sessions = AtomicReference<Map<String, Double>>(emptyMap())

    /** Whether [sessionKey] still holds an authorization inside [authorizationDuration]'s window. */
    fun isFresh(sessionKey: String?, authorizationDuration: BiometricAuthorizationDuration?): Boolean {
        val key = sessionKey ?: return false
        val duration = authorizationDuration ?: return false
        val lastAuth = sessions.load()[key] ?: return false
        return (biometricMonotonicNowMs() - lastAuth) < duration.duration
    }

    /**
     * Seeds [sessionKey], then re-checks its revocation epoch: a clear can land between the
     * caller's own epoch compare and this write, and clearing bumps the epoch BEFORE removing
     * timestamps, so the re-check always observes it and rolls the entry back. The rollback
     * removes only the entry this call wrote (stamp compare), never a newer one.
     */
    fun seedThenRecheckRevocation(sessionKey: String, epochAtPromptStart: Long) {
        val stamp = biometricMonotonicNowMs()
        seed(sessionKey, stamp)
        if (BiometricAuthSession.revocationEpoch(sessionKey) != epochAtPromptStart) {
            unseedIfUnchanged(sessionKey, stamp)
        }
    }

    /**
     * [seedThenRecheckRevocation] for a suspending prompt path: additionally skips the seed when
     * the caller's coroutine was cancelled, or when the scope was revoked while the prompt was up.
     */
    suspend fun seedIfActive(sessionKey: String, epochAtPromptStart: Long) {
        val stamp = biometricMonotonicNowMs()
        seedBiometricSessionIfActive(
            sessionKey, epochAtPromptStart,
            unseed = { unseedIfUnchanged(sessionKey, stamp) },
        ) {
            seed(sessionKey, stamp)
        }
    }

    /** Drops [scope]'s cached authorizations, or every scope's when `null`. */
    fun clear(scope: String?) {
        // Revoke BEFORE removing entries, so an in-flight prompt's success cannot re-seed a
        // window this clear is about to (or just did) remove.
        if (scope == null) {
            BiometricAuthSession.markAllRevoked()
            sessions.store(emptyMap())
            return
        }
        // Clear BOTH the permissive and the strict slot of the scope (see BiometricAuthSession).
        val permissiveKey = BiometricAuthSession.sessionKey(scope, requireStrict = false)
        val strictKey = BiometricAuthSession.sessionKey(scope, requireStrict = true)
        BiometricAuthSession.markRevoked(permissiveKey)
        BiometricAuthSession.markRevoked(strictKey)
        update { it - permissiveKey - strictKey }
    }

    private fun seed(sessionKey: String, stamp: Double) = update { it + (sessionKey to stamp) }

    private fun unseedIfUnchanged(sessionKey: String, stamp: Double) =
        update { if (it[sessionKey] == stamp) it - sessionKey else it }

    private inline fun update(transform: (Map<String, Double>) -> Map<String, Double>) {
        while (true) {
            val current = sessions.load()
            val updated = transform(current)
            // Identity means the transform declined to write (a rollback that found a newer entry).
            if (updated === current || sessions.compareAndSet(current, updated)) return
        }
    }
}
