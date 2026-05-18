package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeConfig
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Web (wasmJs + js) implementation of [KSafeEncryption].
 *
 * The AES-256-GCM key is a **non-extractable WebCrypto `CryptoKey` persisted in
 * IndexedDB** ([webKeyEnsure] / [webKeyEncrypt] / [webKeyDecrypt]). The raw key
 * bytes are never exposed to JS or written to a readable location — a hard
 * upgrade over the previous scheme, which exported the raw key and Base64'd it
 * into `localStorage` (recoverable by any XSS, extension, or profile read).
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
    @Suppress("unused") private val config: KSafeConfig = KSafeConfig(),
    private val storagePrefix: String = "",
) : KSafeEncryption {

    companion object {
        private const val KEY_PREFIX = "ksafe_key_"
    }

    /** Logical key name; reused verbatim as the IndexedDB record key. */
    private fun idbName(alias: String): String = "$storagePrefix$KEY_PREFIX$alias"

    /** Aliases whose key+migration has been resolved this session. */
    private val ensured = HashSet<String>()
    private val ensureMutex = Mutex()

    /**
     * Idempotently ensures a non-extractable key exists for [alias], migrating
     * a legacy `localStorage` raw key on first touch and then scrubbing it.
     */
    private suspend fun ensureKey(alias: String) {
        if (alias in ensured) return
        ensureMutex.withLock {
            if (alias in ensured) return
            val name = idbName(alias)
            val legacy = localStorageGet(name) // legacy raw key (Base64) or null
            webKeyEnsure(name, legacy)
            if (legacy != null) {
                // Raw key now lives only as a non-extractable CryptoKey in IDB.
                localStorageRemove(name)
            }
            ensured.add(alias)
        }
    }

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?
    ): ByteArray =
        throw UnsupportedOperationException("Web encryption is async-only. Use encryptSuspend().")

    override fun decrypt(identifier: String, data: ByteArray): ByteArray =
        throw UnsupportedOperationException("Web decryption is async-only. Use decryptSuspend().")

    @OptIn(ExperimentalEncodingApi::class)
    override suspend fun encryptSuspend(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
    ): ByteArray {
        ensureKey(identifier)
        val outB64 = webKeyEncrypt(idbName(identifier), Base64.encode(data))
        return Base64.decode(outB64)
    }

    @OptIn(ExperimentalEncodingApi::class)
    override suspend fun decryptSuspend(identifier: String, data: ByteArray): ByteArray {
        ensureKey(identifier)
        val plainB64 = webKeyDecrypt(idbName(identifier), Base64.encode(data))
        return Base64.decode(plainB64)
    }

    override fun deleteKey(identifier: String) {
        val name = idbName(identifier)
        // Remove any leftover legacy localStorage entry synchronously…
        localStorageRemove(name)
        // …and fire-and-forget the IndexedDB removal (no blocking IDB API).
        webKeyDeleteNoWait(name)
        ensured.remove(identifier)
    }

    override suspend fun deleteKeySuspend(identifier: String) {
        val name = idbName(identifier)
        localStorageRemove(name)
        webKeyDelete(name)
        ensured.remove(identifier)
    }

    /**
     * Eager one-time sweep: for every remaining legacy raw key still sitting
     * in `localStorage` under `"<storagePrefix>ksafe_key_<alias>"`, import it
     * as a non-extractable `CryptoKey` into IndexedDB and delete the
     * `localStorage` entry — so a key that is never read again doesn't keep
     * its extractable plaintext exposed to XSS/extensions indefinitely.
     *
     * Reuses [ensureKey] per alias: it already does the import-then-scrub
     * atomically (localStorage entry removed only after the IndexedDB persist
     * succeeds) and is idempotent via the `ensured` set + mutex. Best-effort
     * and per-alias isolated.
     */
    override suspend fun migrateLegacyKeysSuspend() {
        val legacyPrefix = "$storagePrefix$KEY_PREFIX"
        val aliases = buildList {
            for (i in 0 until localStorageLength()) {
                val full = localStorageKey(i) ?: continue
                if (full.startsWith(legacyPrefix)) add(full.removePrefix(legacyPrefix))
            }
        }
        for (alias in aliases) runCatching { ensureKey(alias) }
    }
}
