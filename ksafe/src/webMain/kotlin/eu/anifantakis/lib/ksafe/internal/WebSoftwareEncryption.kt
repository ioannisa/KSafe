package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Web (wasmJs + js) [KSafeEncryption]: an AES-256-GCM key held as a non-extractable WebCrypto
 * `CryptoKey` in IndexedDB, so raw key bytes are never exposed to JS. A legacy raw key still in
 * `localStorage` is imported as a non-extractable key on first touch and the `localStorage` entry
 * scrubbed, so existing data keeps decrypting while the raw key stops being recoverable.
 *
 * WebCrypto is async-only, so the blocking [encrypt]/[decrypt] throw; all work goes through the
 * suspend variants.
 *
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

    /** App-isolation prefix for the IndexedDB destination record; blank when no appNamespace is set. */
    private val appNsPrefix: String =
        config.appNamespace?.trim()?.takeIf { it.isNotEmpty() }
            ?.replace(Regex("[^A-Za-z0-9._-]"), "_")?.take(120)
            ?.let { "$it:" } ?: ""

    /** Frozen legacy `localStorage` key (migration source); never namespaced or legacy data stops migrating. */
    private fun legacyKey(alias: String): String = "$storagePrefix$KEY_PREFIX$alias"

    /** IndexedDB record key (the namespaced destination). */
    private fun idbName(alias: String): String = "$appNsPrefix$storagePrefix$KEY_PREFIX$alias"

    /** Pre-`appNamespace` IndexedDB record name; the migrate-forward source when a namespace is added. */
    private fun unNamespacedIdbName(alias: String): String = "$storagePrefix$KEY_PREFIX$alias"

    /** Aliases whose key+migration has been resolved this session. */
    private val ensured = HashSet<String>()
    private val ensureMutex = Mutex()

    /** Aliases whose pre-appNamespace key has already been namespace-migrated this session. */
    private val nsMigrated = HashSet<String>()

    /**
     * When an `appNamespace` is set, copy a key written before the namespace existed
     * ([unNamespacedIdbName]) to the namespaced record name ([idbName]), so existing encrypted
     * data stays readable on upgrade — the data namespace and the key's IndexedDB name isolate
     * independently. Non-destructive (copy only if the destination is absent); no-op without a
     * namespace. Callers hold [ensureMutex].
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
            migrateNamespacedKeyOnce(alias)
            val legacy = localStorageGet(legacyKey(alias))
            webKeyEnsure(idbName(alias), legacy, mintIfAbsent = true)
            if (legacy != null) {
                // Raw key now lives only as a non-extractable CryptoKey in IndexedDB.
                localStorageRemove(legacyKey(alias))
            }
            ensured.add(alias)
        }
    }

    /**
     * Read-path key resolution: migrates a legacy `localStorage` key if present, but NEVER mints
     * one when the key is absent — a `decrypt` of ciphertext whose IndexedDB key was evicted must
     * fail recoverably ("web key missing") rather than mint a key that can never decrypt it. A
     * mint-free miss is not marked [ensured], so a later `encrypt` can still create the key.
     */
    private suspend fun ensureKeyForRead(alias: String) {
        if (alias in ensured) return
        ensureMutex.withLock {
            if (alias in ensured) return
            migrateNamespacedKeyOnce(alias)
            val legacy = localStorageGet(legacyKey(alias))
            webKeyEnsure(idbName(alias), legacy, mintIfAbsent = false)
            if (legacy != null) {
                // A legacy key provably decrypts existing data, so importing it on the read path
                // is safe; scrub the raw copy and treat the alias as resolved.
                localStorageRemove(legacyKey(alias))
                ensured.add(alias)
            }
            // Absent key stays mintable: don't mark `ensured` so a future encrypt can create it.
        }
    }

    /**
     * Drops [alias] from [ensured] and re-ensures it, regenerating the IndexedDB key if gone.
     * Self-heals after another tab deleted the key (clearAll / logout): the cross-tab
     * `BroadcastChannel` eviction clears only the JS `mem` cache, not this Kotlin set, so without
     * this a surviving tab short-circuits [ensureKey] forever and every write fails.
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
            // Another tab deleted this key after we cached it in `ensured`; regenerate a fresh
            // IndexedDB key and retry once so this tab's write succeeds instead of failing forever.
            if (isWebKeyMissing(e)) {
                reEnsureKey(identifier)
                Base64.decode(webKeyEncrypt(idbName(identifier), Base64.encode(data)))
            } else throw e
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    override suspend fun decryptSuspend(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
        // Read path never mints a key: an evicted key surfaces "web key missing" (recoverable)
        // rather than minting one that can't decrypt the surviving ciphertext.
        ensureKeyForRead(identifier)
        val plainB64 = webKeyDecrypt(idbName(identifier), Base64.encode(data))
        return Base64.decode(plainB64)
    }

    override fun deleteKey(identifier: String) {
        localStorageRemove(legacyKey(identifier))
        webKeyDeleteNoWait(idbName(identifier))
        // Deliberately never delete unNamespacedIdbName: once an appNamespace is set that record
        // is the live key of any co-existing no-namespace KSafe on the same fileName (its idbName
        // equals our unNamespacedIdbName), so deleting it would be cross-instance data loss. The
        // orphan it leaves is a non-extractable key (no plaintext), a harmless cost.
        ensured.remove(identifier)
    }

    override suspend fun deleteKeySuspend(identifier: String) {
        localStorageRemove(legacyKey(identifier))
        webKeyDelete(idbName(identifier))
        // See deleteKey: unNamespacedIdbName is a co-existing sibling's live key, never deleted here.
        ensured.remove(identifier)
    }

    /**
     * Eager sweep: imports every legacy raw key still in `localStorage` into IndexedDB and deletes
     * the `localStorage` entry, so a key never read again doesn't keep its plaintext exposed.
     * Best-effort, per-alias isolated, idempotent via [ensureKey]'s `ensured` set + mutex.
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
                // Cancellation must propagate; swallowing it would keep looping on a cancelled coroutine.
                .onFailure { if (it is CancellationException) throw it }
        }
    }
}
