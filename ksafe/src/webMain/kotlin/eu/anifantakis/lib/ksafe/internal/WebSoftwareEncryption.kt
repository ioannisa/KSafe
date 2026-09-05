package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeBase64
import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.internal.coreparts.swallowingNonCancellation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Marks the point after which this (`appNamespace`, store) refuses every key migrate-forward.
 * `clearAll()` writes it — the same wipe seals the DATA copy-forwards, so no ciphertext can arrive
 * afterwards that would need a migrated key. One marker then does what a per-alias tombstone did
 * for every alias the store will ever delete, which matters because those tombstones are permanent
 * and compete with the user's own data for the origin's ~5 MB `localStorage` quota. `null` without
 * an `appNamespace`, where there is no retained source to seal.
 *
 * Named here rather than at either use site: the web factory writes it and the engine reads it,
 * and a marker whose two spellings drift apart silently stops sealing anything.
 */
internal fun webKeyMigrationSealMarker(
    appNamespace: String?,
    storagePrefix: String,
    fileName: String?,
): String? =
    canonicalNamespaceToken(appNamespace)?.let {
        // fileName, not just the prefix: KSafe() and KSafe("default") share one storage prefix
        // but wipe independently, and a seal is permanent — one store's clearAll must not close
        // the other's migrate-forward and strand its ciphertext undecryptable.
        "ksafe.__nskeyseal__.$it:${fileName ?: ""}:$storagePrefix$KSAFE_LEGACY_KEY_RECORD_PREFIX"
    }

/**
 * Whether [fileName] lands on the `ksafe_default_` legacy prefix that `KSafe()` and
 * `KSafe("default")` share. Neither store may delete that source, and neither one's seal
 * speaks for the other's key migrate-forward.
 */
internal fun webSharesDefaultLegacyPrefix(fileName: String?): Boolean =
    fileName == null || fileName == "default"

/**
 * Web (wasmJs + js) [KSafeEncryption]: an AES-GCM key held as a non-extractable WebCrypto
 * `CryptoKey` in IndexedDB, so raw key bytes are never exposed to JS. A legacy raw key still in
 * `localStorage` is imported as a non-extractable key on first touch and the `localStorage` entry
 * scrubbed. WebCrypto is async-only, so the blocking [encrypt]/[decrypt] throw; use the suspend
 * variants.
 *
 * @property storagePrefix Prefix scoping keys to this KSafe instance.
 */
@PublishedApi
internal class WebSoftwareEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    private val storagePrefix: String = "",
    private val fileName: String? = null,
) : KSafeEncryption {

    companion object {
        private const val KEY_PREFIX = KSAFE_LEGACY_KEY_RECORD_PREFIX
        private var warnedNoSubtle = false
    }

    init {
        // Warn at construction, not at first op: fire-and-forget writes fail async on the write
        // consumer, so a missing crypto.subtle otherwise surfaces as silent non-persistence.
        if (!warnedNoSubtle && !webCryptoSubtleAvailable()) {
            warnedNoSubtle = true
            ksafeLogWarning(
                "KSafe WARNING: crypto.subtle (WebCrypto) is unavailable — this page is NOT a " +
                    "secure context. Every encrypted read/write WILL FAIL (values will not persist); " +
                    "only KSafeWriteMode.Plain works here. Serve the app over HTTPS, or from a " +
                    "localhost / 127.0.0.1 origin, to enable encryption."
            )
        }
    }

    private val appNsPrefix: String =
        canonicalNamespaceToken(config.appNamespace)?.let { "$it:" } ?: ""

    /**
     * The ≤ 2.2.1 lossy namespaced record-name prefix, when it differs from the canonical one:
     * a shipped app's keys live under it, so it is probed as a migrate-forward source (before
     * the pre-namespace record — it was this app's ACTIVE prefix right up to the upgrade).
     */
    private val legacyLossyNsPrefix: String? =
        if (appNsPrefix.isEmpty()) null
        else legacyLossyWebNamespaceToken(config.appNamespace)?.let { "$it:" }?.takeIf { it != appNsPrefix }

    /** Legacy `localStorage` key (migration source); never namespaced or legacy data stops migrating. */
    private fun legacyKey(alias: String): String = "$storagePrefix$KEY_PREFIX$alias"

    private fun idbName(alias: String): String = "$appNsPrefix$storagePrefix$KEY_PREFIX$alias"

    /** Pre-`appNamespace` IndexedDB record name; the migrate-forward source when a namespace is added. */
    private fun unNamespacedIdbName(alias: String): String = "$storagePrefix$KEY_PREFIX$alias"

    /**
     * Persistent per-(namespace, alias) deletion marker. The migrate-forward sources are
     * retained (a co-existing sibling may own them), so only this blocks a FRESH engine from
     * re-copying a deleted key out of them — which would make old ciphertext backups
     * decryptable again and hand new writes pre-delete key material. Lives in `localStorage`
     * outside every data prefix, so `clearAll()` can't erase it.
     */
    private fun nsKeyTombstone(alias: String): String = "ksafe.__nskeydel__.${idbName(alias)}"

    /** See [webKeyMigrationSealMarker]; null when there is no namespace, hence no migrate-forward. */
    private val migrationSealMarker: String? =
        webKeyMigrationSealMarker(config.appNamespace, storagePrefix, fileName)

    /**
     * Whether a wipe has already closed this namespace's migrate-forward for good. Read fresh
     * every time: another tab's `clearAll()` seals it mid-session.
     */
    private fun keyMigrationSealed(): Boolean =
        migrationSealMarker != null && localStorageGet(migrationSealMarker) != null


    private val ensured = HashSet<String>()
    private val ensureMutex = Mutex()

    private val nsMigrated = HashSet<String>()

    /**
     * When an `appNamespace` is set, copy the pre-namespace key ([unNamespacedIdbName]) — or
     * the ≤ 2.2.1 lossy-namespaced record, probed first — to the canonical namespaced record
     * ([idbName]) so existing data stays readable on upgrade. Non-destructive (copy only if
     * destination absent); no-op without a namespace, and refused once this namespace has
     * deliberately deleted the alias (see [nsKeyTombstone]) or wiped the whole store (see
     * [webKeyMigrationSealMarker]). Callers hold [ensureMutex].
     */
    private suspend fun migrateNamespacedKeyOnce(alias: String) {
        if (appNsPrefix.isEmpty() || alias in nsMigrated) return
        if (!keyMigrationSealed() && localStorageGet(nsKeyTombstone(alias)) == null) {
            legacyLossyNsPrefix?.let { webKeyCopyIfAbsent("$it$storagePrefix$KEY_PREFIX$alias", idbName(alias)) }
            webKeyCopyIfAbsent(unNamespacedIdbName(alias), idbName(alias))
        }
        nsMigrated.add(alias)
    }

    /**
     * The legacy `localStorage` raw key is the single shared source for every namespace of this
     * fileName, and it is scrubbed right after import. If a namespaced instance imported it only
     * into its own record, a co-existing sibling (the no-namespace store, or another namespace)
     * whose migrated ciphertext still needs that key could never obtain it — permanent data loss.
     * So the key is first persisted durably into the shared un-namespaced record, where siblings
     * find it directly or via [migrateNamespacedKeyOnce]. Runs before the namespaced import and
     * before the scrub, so an interruption leaves the `localStorage` source in place and the
     * whole import re-runs.
     */
    private suspend fun preserveLegacyKeyForSiblings(alias: String, legacy: String?) {
        if (legacy != null && appNsPrefix.isNotEmpty()) {
            webKeyEnsure(
                unNamespacedIdbName(alias),
                legacy,
                mintIfAbsent = false,
                keySizeBits = config.aesKeySize.bits,
            )
        }
    }

    /**
     * Idempotently ensures a non-extractable key exists for [alias], migrating
     * a legacy `localStorage` raw key on first touch and then scrubbing it.
     */
    private suspend fun ensureKey(alias: String) = ensureKeyInternal(alias, mintIfAbsent = true)

    /**
     * Read-path key resolution: migrates a legacy `localStorage` key if present, but NEVER mints
     * one when the key is absent — a `decrypt` of ciphertext whose IndexedDB key was evicted must
     * fail recoverably ("web key missing") rather than mint a key that can never decrypt it. A
     * mint-free miss is not marked [ensured], so a later `encrypt` can still create the key.
     */
    private suspend fun ensureKeyForRead(alias: String) = ensureKeyInternal(alias, mintIfAbsent = false)

    private suspend fun ensureKeyInternal(alias: String, mintIfAbsent: Boolean) {
        if (alias in ensured) return
        ensureMutex.withLock {
            if (alias in ensured) return
            migrateNamespacedKeyOnce(alias)
            val legacy = localStorageGet(legacyKey(alias))
            preserveLegacyKeyForSiblings(alias, legacy)
            webKeyEnsure(
                idbName(alias),
                legacy,
                mintIfAbsent = mintIfAbsent,
                keySizeBits = config.aesKeySize.bits,
            )
            if (legacy != null) {
                localStorageRemove(legacyKey(alias))
            }
            // A mint-free MISS stays unmarked, so a later encrypt can still create the key; a
            // migrated legacy key is a hit either way.
            if (mintIfAbsent || legacy != null) ensured.add(alias)
        }
    }

    /**
     * Read-only warm, never a mint: a master minted over key-less ciphertext turns the orphan
     * sweep's "web key missing" into a GCM error it cannot classify, stranding the entry.
     */
    override suspend fun prewarmKey(
        identifier: String,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
    ) {
        ensureKeyForRead(identifier)
    }

    /**
     * Drops [alias] from [ensured] and re-ensures it, regenerating the IndexedDB key if gone.
     * Self-heals after another tab's clearAll/logout: cross-tab `BroadcastChannel` eviction clears
     * the JS `mem` cache but not this Kotlin set, so a surviving tab would otherwise short-circuit
     * [ensureKey] forever and every write would fail.
     */
    private suspend fun reEnsureKey(alias: String) {
        ensureMutex.withLock { ensured.remove(alias) }
        ensureKey(alias)
    }

    private fun isWebKeyMissing(e: Throwable): Boolean =
        e.message?.contains(KSafeEngineMessage.WEB_KEY_MISSING, ignoreCase = true) == true

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray =
        throw UnsupportedOperationException("Web encryption is async-only. Use encryptSuspend().")

    override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray =
        throw UnsupportedOperationException("Web decryption is async-only. Use decryptSuspend().")

    override suspend fun encryptSuspend(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray {
        ensureKey(identifier)
        val aadB64 = aad?.let { KSafeBase64.encode(it) }
        return try {
            KSafeBase64.decode(webKeyEncrypt(idbName(identifier), KSafeBase64.encode(data), aadB64))
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
            // Another tab deleted this key after we cached it in `ensured`: regenerate and retry once.
            if (isWebKeyMissing(e)) {
                reEnsureKey(identifier)
                KSafeBase64.decode(webKeyEncrypt(idbName(identifier), KSafeBase64.encode(data), aadB64))
            } else throw e
        }
    }

    override suspend fun decryptSuspend(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray {
        ensureKeyForRead(identifier)
        val plainB64 = webKeyDecrypt(idbName(identifier), KSafeBase64.encode(data), aad?.let { KSafeBase64.encode(it) })
        return KSafeBase64.decode(plainB64)
    }

    /**
     * Blocks the retained migrate-forward sources from re-supplying [identifier]'s deleted key to a
     * fresh engine. Skipped once a wipe has sealed this namespace's migration outright: the seal
     * already refuses every alias, so the per-alias marker would add nothing but another permanent
     * entry against the origin's shared `localStorage` quota — and the sweeps that reach here delete
     * speculatively, over whole alias ranges most of which never held a key.
     */
    private fun tombstoneDeletedKey(identifier: String) {
        if (appNsPrefix.isEmpty() || keyMigrationSealed()) return
        runCatching { localStorageSet(nsKeyTombstone(identifier), "1") }
    }

    override fun deleteKey(identifier: String) {
        localStorageRemove(legacyKey(identifier))
        webKeyDeleteNoWait(idbName(identifier))
        // Never delete unNamespacedIdbName: once an appNamespace is set it is the live key of any
        // co-existing no-namespace KSafe on the same fileName, so deleting it is cross-instance data
        // loss. The orphan left is a non-extractable key (no plaintext). A persistent tombstone
        // blocks the retained source from re-supplying the deleted key to a fresh engine.
        tombstoneDeletedKey(identifier)
        ensured.remove(identifier)
    }

    override suspend fun deleteKeySuspend(identifier: String) {
        localStorageRemove(legacyKey(identifier))
        webKeyDelete(idbName(identifier))
        // See deleteKey: unNamespacedIdbName is a co-existing sibling's live key, never deleted
        // here; the tombstone blocks it from re-seeding this namespace instead.
        tombstoneDeletedKey(identifier)
        ensured.remove(identifier)
    }

    /**
     * Eager sweep: imports every legacy raw key still in `localStorage` into IndexedDB and scrubs
     * the `localStorage` entry, so plaintext isn't left exposed for keys never read again.
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
            swallowingNonCancellation { ensureKey(alias) }
        }
    }
}
