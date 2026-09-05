package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeBase64
import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.internal.coreparts.swallowingNonCancellation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** `localStorage` marker written by `clearAll()`: past it this (`appNamespace`, store) refuses every
 *  key migrate-forward, so no wiped key is re-copied out of a retained source. */
internal fun webKeyMigrationSealMarker(
    appNamespace: String?,
    storagePrefix: String,
    fileName: String?,
): String? =
    canonicalNamespaceToken(appNamespace)?.let {
        // fileName, not just the prefix: KSafe() and KSafe("default") share one storage prefix but
        // wipe independently, and a seal is permanent.
        "ksafe.__nskeyseal__.$it:${fileName ?: ""}:$storagePrefix$KSAFE_LEGACY_KEY_RECORD_PREFIX"
    }

/** Whether [fileName] lands on the `ksafe_default_` legacy prefix that `KSafe()` and
 *  `KSafe("default")` share; neither store may delete that source. */
internal fun webSharesDefaultLegacyPrefix(fileName: String?): Boolean =
    fileName == null || fileName == "default"

/** Web [KSafeEncryption]: an AES-GCM key held as a non-extractable WebCrypto `CryptoKey` in
 *  IndexedDB. A legacy raw key in `localStorage` is imported on first touch and scrubbed.
 *  WebCrypto is async-only, so the blocking [encrypt]/[decrypt] throw. */
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
        // Warn at construction, not at first op: writes fail async on the write consumer, so a
        // missing crypto.subtle would otherwise look like silent non-persistence.
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

    /** The older lossy namespaced prefix, when it differs from the canonical one. Probed before
     *  the pre-namespace record: it was a shipped app's active prefix right up to the upgrade. */
    private val legacyLossyNsPrefix: String? =
        if (appNsPrefix.isEmpty()) null
        else legacyLossyWebNamespaceToken(config.appNamespace)?.let { "$it:" }?.takeIf { it != appNsPrefix }

    /** Legacy `localStorage` key (migration source); never namespaced or legacy data stops migrating. */
    private fun legacyKey(alias: String): String = "$storagePrefix$KEY_PREFIX$alias"

    private fun idbName(alias: String): String = "$appNsPrefix$storagePrefix$KEY_PREFIX$alias"

    /** Pre-`appNamespace` record name; the migrate-forward source when a namespace is added. */
    private fun unNamespacedIdbName(alias: String): String = "$storagePrefix$KEY_PREFIX$alias"

    /** Per-(namespace, alias) deletion marker, kept outside every data prefix so `clearAll()` cannot
     *  erase it: only this stops a fresh engine re-copying a deleted key out of a retained source. */
    private fun nsKeyTombstone(alias: String): String = "ksafe.__nskeydel__.${idbName(alias)}"

    private val migrationSealMarker: String? =
        webKeyMigrationSealMarker(config.appNamespace, storagePrefix, fileName)

    /** Read fresh every time: another tab's `clearAll()` seals the migrate-forward mid-session. */
    private fun keyMigrationSealed(): Boolean =
        migrationSealMarker != null && localStorageGet(migrationSealMarker) != null


    private val ensured = HashSet<String>()
    private val ensureMutex = Mutex()

    private val nsMigrated = HashSet<String>()

    /** Copies the pre-namespace key (lossy-namespaced probed first) to the canonical record, only
     *  if absent and unless the alias is tombstoned or sealed. Callers hold [ensureMutex]. */
    private suspend fun migrateNamespacedKeyOnce(alias: String) {
        if (appNsPrefix.isEmpty() || alias in nsMigrated) return
        if (!keyMigrationSealed() && localStorageGet(nsKeyTombstone(alias)) == null) {
            legacyLossyNsPrefix?.let { webKeyCopyIfAbsent("$it$storagePrefix$KEY_PREFIX$alias", idbName(alias)) }
            webKeyCopyIfAbsent(unNamespacedIdbName(alias), idbName(alias))
        }
        nsMigrated.add(alias)
    }

    /** The `localStorage` raw key is shared by every namespace of this fileName and is scrubbed right
     *  after import: persist it into the un-namespaced record first, or a sibling loses its only key. */
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

    private suspend fun ensureKey(alias: String) = ensureKeyInternal(alias, mintIfAbsent = true)

    /** Read path: migrates a legacy key but never mints one — a decrypt whose IndexedDB key was
     *  evicted must fail with "web key missing" rather than mint a key that cannot decrypt it. */
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
            // A mint-free miss stays unmarked, so a later encrypt can still create the key.
            if (mintIfAbsent || legacy != null) ensured.add(alias)
        }
    }

    /** Read-only warm, never a mint: a master minted over key-less ciphertext turns the sweep's
     *  "web key missing" into a GCM error it cannot classify, stranding the entry. */
    override suspend fun prewarmKey(
        identifier: String,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
    ) {
        ensureKeyForRead(identifier)
    }

    /** Self-heals after another tab's clearAll: cross-tab eviction clears the JS cache but not
     *  [ensured], so a surviving tab would short-circuit [ensureKey] forever and every write fail. */
    private suspend fun reEnsureKey(alias: String) {
        ensureMutex.withLock { ensured.remove(alias) }
        ensureKey(alias)
    }

    // Kotlin/Wasm re-wraps the JS error, so the branded opening is matched wherever it lands.
    private fun isWebKeyMissing(e: Throwable): Boolean =
        e.message?.contains(KSafeEngineMessage.WEB_KEY_MISSING_PREFIX, ignoreCase = true) == true

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

    /** Blocks the retained sources from re-supplying a deleted key. Skipped once a wipe has sealed
     *  the namespace — the seal refuses every alias, and these markers are permanent. */
    private fun tombstoneDeletedKey(identifier: String) {
        if (appNsPrefix.isEmpty() || keyMigrationSealed()) return
        runCatching { localStorageSet(nsKeyTombstone(identifier), "1") }
    }

    override fun deleteKey(identifier: String) {
        localStorageRemove(legacyKey(identifier))
        webKeyDeleteNoWait(idbName(identifier))
        // Never delete unNamespacedIdbName: it is the live key of any co-existing no-namespace
        // KSafe on the same fileName. The tombstone blocks it from re-seeding this namespace.
        tombstoneDeletedKey(identifier)
        ensured.remove(identifier)
    }

    override suspend fun deleteKeySuspend(identifier: String) {
        localStorageRemove(legacyKey(identifier))
        webKeyDelete(idbName(identifier))
        // See deleteKey: the un-namespaced record is a sibling's live key, never deleted here.
        tombstoneDeletedKey(identifier)
        ensured.remove(identifier)
    }

    /** Imports every legacy raw key still in `localStorage` and scrubs it, so plaintext is not
     *  left exposed for keys never read again. */
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
