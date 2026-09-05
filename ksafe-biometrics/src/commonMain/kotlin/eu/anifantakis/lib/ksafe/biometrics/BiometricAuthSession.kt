package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.ensureActive
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/** Shared decision helpers for the per-scope biometric authorization cache. */
@OptIn(ExperimentalAtomicApi::class)
internal object BiometricAuthSession {

    fun shouldCache(authorizationDuration: BiometricAuthorizationDuration?): Boolean =
        authorizationDuration != null && authorizationDuration.duration > 0

    /**
     * The cache slot a call maps to, or `null` when it opted out of caching. Strict
     * (biometrics-only) calls key a separate slot, so a device-credential success never satisfies one.
     */
    fun cacheKey(
        authorizationDuration: BiometricAuthorizationDuration?,
        allowDeviceCredentialFallback: Boolean,
    ): String? =
        if (shouldCache(authorizationDuration)) {
            sessionKey(authorizationDuration!!.scope, requireStrict = !allowDeviceCredentialFallback)
        } else {
            null
        }

    /** The epoch a prompt must still see when it succeeds; `0` for an uncached call, which never seeds. */
    fun epochAtPromptStart(cacheKey: String?): Long = cacheKey?.let { revocationEpoch(it) } ?: 0L

    /** Maps (scope, strength) to a cache key injectively, so no caller scope can forge another slot. */
    fun sessionKey(scope: String?, requireStrict: Boolean): String {
        val strength = if (requireStrict) STRICT_TAG else PERMISSIVE_TAG
        val scopePart = if (scope == null) GLOBAL_SCOPE_KEY else CALLER_SCOPE_PREFIX + scope
        return strength + scopePart
    }

    private const val STRICT_TAG = "S"
    private const val PERMISSIVE_TAG = "P"

    // Null-scope sentinel; its NUL prefix is unreachable from any caller scope.
    private const val GLOBAL_SCOPE_KEY = "\u0000ksafe-global-scope"
    private const val CALLER_SCOPE_PREFIX = "scope:"

    // Closes the clear-vs-in-flight-prompt race: a prompt captures its key's epoch before showing
    // UI and clearing bumps it, so a success landing after a clear no longer matches and can't seed.
    private class RevocationEpochs(val global: Long, val perKey: Map<String, Long>)

    private val revocationEpochs = AtomicReference(RevocationEpochs(0L, emptyMap()))

    /** Global epoch plus the key's own; both only grow, so a captured stamp is never revisited. */
    fun revocationEpoch(sessionKey: String): Long {
        val state = revocationEpochs.load()
        return state.global + (state.perKey[sessionKey] ?: 0L)
    }

    /** Revokes [sessionKey]: an in-flight prompt for it can no longer seed the cache. */
    fun markRevoked(sessionKey: String) {
        while (true) {
            val current = revocationEpochs.load()
            val bumped = RevocationEpochs(
                current.global,
                current.perKey + (sessionKey to (current.perKey[sessionKey] ?: 0L) + 1L),
            )
            if (revocationEpochs.compareAndSet(current, bumped)) return
        }
    }

    /** Revokes every key: no in-flight prompt may seed the cache after it. */
    fun markAllRevoked() {
        while (true) {
            val current = revocationEpochs.load()
            // Per-key entries must survive a global bump: dropping one would shrink that key's
            // stamp back toward a value an in-flight prompt may have captured.
            val bumped = RevocationEpochs(current.global + 1L, current.perKey)
            if (revocationEpochs.compareAndSet(current, bumped)) return
        }
    }
}

/** One in-progress trip through the authorization gate: its cache slot and the epoch a later seed must match. */
internal class BiometricAttempt(
    val cacheKey: String?,
    private val authorizationDuration: BiometricAuthorizationDuration?,
    val epochAtPromptStart: Long,
) {
    /** Re-check inside a prompt gate: a caller queued behind one that just authenticated skips a second prompt. */
    fun isFresh(): Boolean = BiometricSessionStore.isFresh(cacheKey, authorizationDuration)

    /** Seeds the slot after a real prompt success; skipped if the caller was cancelled or the scope revoked meanwhile. */
    suspend fun seedIfActive() {
        val key = cacheKey ?: return
        BiometricSessionStore.seedIfActive(key, epochAtPromptStart)
    }
}

/**
 * Prologue shared by every platform's `platformVerifyBiometric`; `null` means the cache already
 * holds a live authorization. The epoch is captured after the cache misses, so it brackets the prompt.
 */
internal fun beginBiometricAttempt(
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
): BiometricAttempt? {
    val cacheKey = BiometricAuthSession.cacheKey(authorizationDuration, allowDeviceCredentialFallback)
    if (BiometricSessionStore.isFresh(cacheKey, authorizationDuration)) return null
    return BiometricAttempt(
        cacheKey = cacheKey,
        authorizationDuration = authorizationDuration,
        epochAtPromptStart = BiometricAuthSession.epochAtPromptStart(cacheKey),
    )
}

/**
 * Runs [seed] only while the caller is active and [sessionKey]'s epoch still matches. A clear can
 * land between compare and write, so [unseed] must roll back this call's own entry, never a newer one.
 */
internal suspend fun seedBiometricSessionIfActive(
    sessionKey: String,
    epochAtPromptStart: Long,
    unseed: () -> Unit = {},
    seed: () -> Unit,
) {
    kotlinx.coroutines.currentCoroutineContext().ensureActive()
    if (BiometricAuthSession.revocationEpoch(sessionKey) != epochAtPromptStart) return
    seed()
    if (BiometricAuthSession.revocationEpoch(sessionKey) != epochAtPromptStart) unseed()
}
