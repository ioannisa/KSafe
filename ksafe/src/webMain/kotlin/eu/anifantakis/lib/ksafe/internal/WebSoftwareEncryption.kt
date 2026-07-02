package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Web (wasmJs + js) implementation of [KSafeEncryption].
 *
 * The AES-256-GCM key is a non-extractable WebCrypto `CryptoKey` persisted in
 * IndexedDB ([webKeyEnsure] / [webKeyEncrypt] / [webKeyDecrypt]); the raw key
 * bytes are never exposed to JS or written to a readable location.
 *
 * **Migration:** a key written by an older KSafe still lives in `localStorage`
 * under `"<storagePrefix>ksafe_key_<alias>"`. On first access for that alias the
 * legacy raw bytes are imported as a *non-extractable* key into IndexedDB and
 * the `localStorage` entry is deleted, so previously encrypted data keeps
 * decrypting while the raw key stops being recoverable going forward.
 *
 * WebCrypto is async-only, so the blocking [encrypt]/[decrypt] throw; all work
 * goes through the suspend variants (KSafe's web path is fully coroutine-based,
 * see [KSafeEncryption]).
 *
 * @property config Key-generation configuration (unused for generation now —
 *   WebCrypto fixes AES-GCM at 256-bit — kept for API symmetry).
 * @property storagePrefix Prefix scoping keys to this KSafe instance.
 */
@PublishedApi
internal class WebSoftwareEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    private val storagePrefix: String = "",
) : KSafeEncryption {

    companion object {
        private const val KEY_PREFIX = "ksafe_key_"
    }

    /**
     * Optional app-isolation prefix for the IndexedDB **destination** record.
     * The browser already isolates IndexedDB/localStorage by origin, so this
     * is defense-in-depth for multiple independent KSafe setups in one origin
     * and parity with the JVM namespace. Derived from
     * `KSafeConfig.appNamespace`; blank ⇒ no prefix (unchanged behaviour).
     */
    private val appNsPrefix: String =
        config.appNamespace?.trim()?.takeIf { it.isNotEmpty() }
            ?.replace(Regex("[^A-Za-z0-9._-]"), "_")?.take(120)
            ?.let { "$it:" } ?: ""

    /**
     * Frozen KSafe ≤ 2.0 `localStorage` key — the migration source. Must NOT
     * be namespaced or legacy data stops migrating.
     */
    private fun legacyKey(alias: String): String = "$storagePrefix$KEY_PREFIX$alias"

    /** IndexedDB record key (the namespaced destination). */
    private fun idbName(alias: String): String = "$appNsPrefix$storagePrefix$KEY_PREFIX$alias"

    /**
     * The pre-`appNamespace` IndexedDB record name — where the key lived before an
     * `appNamespace` was configured (`appNsPrefix` was empty). Equals [idbName] when no
     * namespace is set. Used to migrate the key forward on upgrade (FEEDBACK_4 FB3-H1).
     */
    private fun unNamespacedIdbName(alias: String): String = "$storagePrefix$KEY_PREFIX$alias"

    /** Aliases whose key+migration has been resolved this session. */
    private val ensured = HashSet<String>()
    private val ensureMutex = Mutex()

    /** Aliases whose pre-appNamespace key has already been namespace-migrated this session. */
    private val nsMigrated = HashSet<String>()

    /**
     * One-shot per alias: when an `appNamespace` is set, migrate a key written before the
     * namespace existed (at [unNamespacedIdbName]) to the namespaced record name ([idbName]),
     * so adding `appNamespace` on upgrade keeps existing encrypted data readable — the R4
     * data migration moved the ciphertext but the key's IndexedDB name is derived
     * independently (FEEDBACK_4 FB3-H1). Non-destructive: copies only if the destination is
     * absent and the source exists; the source key is left in place. No-op without a namespace.
     * Callers hold [ensureMutex].
     */
    private suspend fun migrateNamespacedKeyOnce(alias: String) {
        if (appNsPrefix.isEmpty() || alias in nsMigrated) return
        webKeyCopyIfAbsent(unNamespacedIdbName(alias), idbName(alias))
        nsMigrated.add(alias)
    }

    /**
     * Idempotently ensures a non-extractable key exists for [alias], migrating
     * a legacy `localStorage` raw key on first touch and then scrubbing it.
     */
    private suspend fun ensureKey(alias: String) {
        if (alias in ensured) return
        ensureMutex.withLock {
            if (alias in ensured) return
            // Migrate a pre-appNamespace IndexedDB key forward before resolving (FB3-H1).
            migrateNamespacedKeyOnce(alias)
            // Read the legacy key from the FROZEN (un-namespaced) localStorage
            // location; import it into the namespaced IndexedDB destination.
            val legacy = localStorageGet(legacyKey(alias)) // Base64 or null
            webKeyEnsure(idbName(alias), legacy, mintIfAbsent = true)
            if (legacy != null) {
                // Raw key now lives only as a non-extractable CryptoKey in IDB.
                localStorageRemove(legacyKey(alias))
            }
            ensured.add(alias)
        }
    }

    /**
     * Read-path key resolution (FEEDBACK_4 H-A): migrates a legacy `localStorage`
     * key if present, but NEVER mints a fresh key when the key is absent — so a
     * `decrypt` of ciphertext whose IndexedDB key was evicted fails recoverably
     * ("web key missing") instead of minting a key that can never decrypt it and
     * permanently poisoning the ciphertext. Does not add to [ensured] on a mint-free
     * miss, so a later `encrypt` can still create the key if genuinely absent.
     */
    private suspend fun ensureKeyForRead(alias: String) {
        if (alias in ensured) return
        ensureMutex.withLock {
            if (alias in ensured) return
            // Migrate a pre-appNamespace IndexedDB key forward so a read after adding
            // appNamespace on upgrade finds it at the namespaced name (FB3-H1).
            migrateNamespacedKeyOnce(alias)
            val legacy = localStorageGet(legacyKey(alias)) // Base64 or null
            webKeyEnsure(idbName(alias), legacy, mintIfAbsent = false)
            if (legacy != null) {
                // A legacy key provably decrypts existing data — importing it is safe on
                // the read path; scrub the raw copy and treat the alias as resolved.
                localStorageRemove(legacyKey(alias))
                ensured.add(alias)
            }
            // No legacy key: whether or not an IndexedDB key exists, do NOT mark
            // `ensured` — an absent key must stay mintable by a future encrypt.
        }
    }

    /**
     * Drops [alias] from the per-instance [ensured] short-circuit and ensures it
     * again — regenerating the IndexedDB key if it is gone. Used to self-heal
     * after another tab deleted the key (clearAll / logout): the cross-tab
     * `BroadcastChannel` eviction only clears the JS `mem` cache, not this Kotlin
     * set, so without this a surviving tab would short-circuit [ensureKey] forever
     * and every encrypted write would fail "web key missing" (deep-review H5).
     */
    private suspend fun reEnsureKey(alias: String) {
        ensureMutex.withLock { ensured.remove(alias) }
        ensureKey(alias)
    }

    private fun isWebKeyMissing(e: Throwable): Boolean =
        e.message?.contains("web key missing", ignoreCase = true) == true

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?
    ): ByteArray =
        throw UnsupportedOperationException("Web encryption is async-only. Use encryptSuspend().")

    override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray =
        throw UnsupportedOperationException("Web decryption is async-only. Use decryptSuspend().")

    @OptIn(ExperimentalEncodingApi::class)
    override suspend fun encryptSuspend(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
    ): ByteArray {
        ensureKey(identifier)
        return try {
            Base64.decode(webKeyEncrypt(idbName(identifier), Base64.encode(data)))
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
            // Another tab deleted this key (clearAll / logout) after we cached it in
            // `ensured`; regenerate a fresh IndexedDB key and retry once so this tab's
            // write succeeds instead of silently failing forever (deep-review H5).
            if (isWebKeyMissing(e)) {
                reEnsureKey(identifier)
                Base64.decode(webKeyEncrypt(idbName(identifier), Base64.encode(data)))
            } else throw e
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    override suspend fun decryptSuspend(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
        // Read path must never mint a key (FEEDBACK_4 H-A): if the IndexedDB key was
        // evicted while the ciphertext survives, this surfaces "web key missing"
        // (recoverable) rather than minting a key that permanently poisons the data.
        ensureKeyForRead(identifier)
        val plainB64 = webKeyDecrypt(idbName(identifier), Base64.encode(data))
        return Base64.decode(plainB64)
    }

    override fun deleteKey(identifier: String) {
        // Remove any leftover legacy localStorage entry (frozen key)…
        localStorageRemove(legacyKey(identifier))
        // …and fire-and-forget the IndexedDB removal (namespaced destination).
        webKeyDeleteNoWait(idbName(identifier))
        ensured.remove(identifier)
    }

    override suspend fun deleteKeySuspend(identifier: String) {
        localStorageRemove(legacyKey(identifier))
        webKeyDelete(idbName(identifier))
        ensured.remove(identifier)
    }

    /**
     * Eager sweep: imports every legacy raw key still sitting in `localStorage`
     * under `"<storagePrefix>ksafe_key_<alias>"` into IndexedDB and deletes the
     * `localStorage` entry — a key that is never read again must not keep its
     * extractable plaintext exposed indefinitely.
     *
     * Reuses [ensureKey] per alias: the `localStorage` entry is removed only
     * after the IndexedDB persist succeeds, and it's idempotent via the
     * `ensured` set + mutex. Best-effort and per-alias isolated.
     */
    override suspend fun migrateLegacyKeysSuspend() {
        val legacyPrefix = "$storagePrefix$KEY_PREFIX"
        val aliases = buildList {
            for (i in 0 until localStorageLength()) {
                val full = localStorageKey(i) ?: continue
                if (full.startsWith(legacyPrefix)) add(full.removePrefix(legacyPrefix))
            }
        }
        for (alias in aliases) {
            runCatching { ensureKey(alias) }
                // Cancellation must propagate — `ensureKey` suspends on a mutex,
                // and swallowing CancellationException would keep the loop
                // running on a cancelled coroutine.
                .onFailure { if (it is CancellationException) throw it }
        }
    }
}
