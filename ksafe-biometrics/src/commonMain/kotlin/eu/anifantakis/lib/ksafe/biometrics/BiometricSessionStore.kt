package eu.anifantakis.lib.ksafe.biometrics

import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/** Monotonic now, in milliseconds, so a backward wall-clock jump cannot extend a cached
 *  authorization. The origin is arbitrary per platform, so only differences mean anything. */
internal expect fun biometricMonotonicNowMs(): Double

/** Per-scope biometric authorization cache, shared by every platform. Presence of an entry is the
 *  authorization; the stamp feeds elapsed-time math only, as a reading can be zero or negative. */
@OptIn(ExperimentalAtomicApi::class)
internal object BiometricSessionStore {

    // Immutable map behind a CAS loop, so a seed, a rollback and a clear can't lose a write.
    private val sessions = AtomicReference<Map<String, Double>>(emptyMap())

    fun isFresh(sessionKey: String?, authorizationDuration: BiometricAuthorizationDuration?): Boolean {
        val key = sessionKey ?: return false
        val duration = authorizationDuration ?: return false
        val lastAuth = sessions.load()[key] ?: return false
        return (biometricMonotonicNowMs() - lastAuth) < duration.duration
    }

    /** Seeds [sessionKey], then re-checks the revocation epoch: clearing bumps the epoch before
     *  removing timestamps, so a clear landing mid-call is observed and rolled back. */
    fun seedThenRecheckRevocation(sessionKey: String, epochAtPromptStart: Long) {
        val stamp = biometricMonotonicNowMs()
        seed(sessionKey, stamp)
        if (BiometricAuthSession.revocationEpoch(sessionKey) != epochAtPromptStart) {
            unseedIfUnchanged(sessionKey, stamp)
        }
    }

    /** [seedThenRecheckRevocation] for a suspending prompt: also skips the seed when the caller
     *  was cancelled, or the scope was revoked while the prompt was up. */
    suspend fun seedIfActive(sessionKey: String, epochAtPromptStart: Long) {
        val stamp = biometricMonotonicNowMs()
        seedBiometricSessionIfActive(
            sessionKey, epochAtPromptStart,
            unseed = { unseedIfUnchanged(sessionKey, stamp) },
        ) {
            seed(sessionKey, stamp)
        }
    }

    fun clear(scope: String?) {
        // Revoke before removing entries, or an in-flight prompt's success re-seeds a cleared window.
        if (scope == null) {
            BiometricAuthSession.markAllRevoked()
            sessions.store(emptyMap())
            return
        }
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
