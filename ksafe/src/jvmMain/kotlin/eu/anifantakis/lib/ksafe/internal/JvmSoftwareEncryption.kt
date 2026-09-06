package eu.anifantakis.lib.ksafe.internal

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.internal.keyvault.DataStoreKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import eu.anifantakis.lib.ksafe.internal.keyvault.legacyResolvedJvmAppNamespace
import eu.anifantakis.lib.ksafe.internal.keyvault.resolveJvmAppNamespace
import eu.anifantakis.lib.ksafe.internal.keyvault.shadowedJvmAppNamespaces
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * JVM [KSafeEncryption]: software AES-GCM for the payload, with the AES key held in an OS secret
 * store via [JvmKeyVault] (DPAPI, login Keychain, Secret Service). Without one, keys fall back to
 * Base64-in-DataStore and migrate into the OS store once it is reachable.
 */
@PublishedApi
internal class JvmSoftwareEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    dataStore: DataStore<Preferences>? = null,
    vaultProvider: JvmKeyVaultProvider? = null,
) : KSafeEncryption {

    companion object {
        private const val FALLBACK_MINT_MARKER_SUFFIX = ".${KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK}"
    }

    private val vaults: JvmKeyVaultProvider =
        vaultProvider ?: JvmKeyVaultProvider(
            requireNotNull(dataStore) {
                "JvmSoftwareEncryption requires a dataStore unless a vaultProvider is provided"
            },
            resolveJvmAppNamespace(config.appNamespace),
            legacyAppNamespace = legacyResolvedJvmAppNamespace(config.appNamespace),
            shadowedAppNamespaces = shadowedJvmAppNamespaces(config.appNamespace),
        )

    @PublishedApi
    internal val keyVaultName: String get() = vaults.active.name

    @PublishedApi
    internal val keyVaultIsOsBacked: Boolean get() = vaults.active.isOsBacked

    /** OS vault present but failed its self-test: key mints and OS-resident reads throw until it returns. */
    @PublishedApi
    internal val osVaultUnavailable: Boolean get() = vaults.osVaultUnavailable

    private class CachedKey(val key: SecretKey, val epoch: Long)

    private val keyCache = ConcurrentHashMap<String, CachedKey>()

    /** A null key is a cached "no alternate": the probe below is paid once per alias, hit or miss. */
    private class CachedAlternate(val key: SecretKey?, val epoch: Long)

    private val alternateKeyCache = ConcurrentHashMap<String, CachedAlternate>()

    private val aliasLocks = AliasLocks()

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray {
        // A clearAll can land between resolving the key and returning the ciphertext; re-encrypt
        // under whatever owns the slot afterwards. Never re-persist this key — it is the material
        // clearAll promised to destroy.
        repeat(2) {
            val epochAtResolve = cacheEpoch.get()
            val secretKey = getOrCreateSecretKey(identifier)
            val out = encryptWith(secretKey, data, aad)
            if (cacheEpoch.get() == epochAtResolve) return out
            synchronized(aliasLocks.forAlias(identifier)) {
                val vaultBytes = runCatching { vaults.active.get(identifier) }.getOrNull()
                // Our key still owns the slot, so the ciphertext stays readable.
                if (vaultBytes != null && vaultBytes.contentEquals(secretKey.encoded)) return out
            }
        }
        // Two wipes raced this write; seal under the current resolution and stop re-checking.
        return encryptWith(getOrCreateSecretKey(identifier), data, aad)
    }

    private fun encryptWith(secretKey: SecretKey, data: ByteArray, aad: ByteArray?): ByteArray {
        val iv = secureRandomBytes(JvmAesGcm.IV_LENGTH_BYTES)
        val cipher = Cipher.getInstance(JvmAesGcm.TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(JvmAesGcm.TAG_LENGTH_BITS, iv))
        if (aad != null) cipher.updateAAD(aad)
        return iv + cipher.doFinal(data)
    }

    override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray {
        // Fail-closed: decrypt must not create a key; the orphan sweep reclaims stranded ciphertext.
        val secretKey = getExistingSecretKey(identifier)

        val iv = data.copyOfRange(0, JvmAesGcm.IV_LENGTH_BYTES)
        val ciphertext = data.copyOfRange(JvmAesGcm.IV_LENGTH_BYTES, data.size)

        return try {
            decryptWith(secretKey, iv, ciphertext, aad)
        } catch (e: AEADBadTagException) {
            // Off the hot path: only a tag failure gets here, and only a degraded-mint alias has a
            // second key. Rethrowing the original keeps the failure classification unchanged.
            val alternate = alternateKey(identifier, secretKey) ?: throw e
            try {
                decryptWith(alternate, iv, ciphertext, aad)
            } catch (_: AEADBadTagException) {
                throw e
            }
        }
    }

    private fun decryptWith(secretKey: SecretKey, iv: ByteArray, ciphertext: ByteArray, aad: ByteArray?): ByteArray {
        val cipher = Cipher.getInstance(JvmAesGcm.TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(JvmAesGcm.TAG_LENGTH_BITS, iv))
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    /**
     * The provisional key a dead-bridge session minted for this alias while the OS vault held the
     * live one. Both keys are kept for good: each session's writes are only readable under its own
     * key, and re-encrypting the other side's records would need a key nobody has at that moment.
     */
    private fun alternateKey(alias: String, resolved: SecretKey): SecretKey? {
        val epoch = cacheEpoch.get()
        alternateKeyCache[alias]?.takeIf { it.epoch == epoch }?.let { return it.key }
        val key = provisionalKey(alias, resolved)
        alternateKeyCache[alias] = CachedAlternate(key, epoch)
        return key
    }

    private fun provisionalKey(alias: String, resolved: SecretKey): SecretKey? {
        if (isFallbackMintMarker(alias)) return null
        val marker = runCatching { vaults.legacy.get(fallbackMintMarker(alias)) }.getOrNull() ?: return null
        if (!marker.contentEquals(DEGRADED_MINT_MARKER)) return null
        val bytes = runCatching { vaults.legacy.get(alias) }.getOrNull() ?: return null
        if (bytes.contentEquals(resolved.encoded)) return null
        return SecretKeySpec(bytes, "AES")
    }

    /**
     * Bumped by [onStoreCleared]; a cached key is served only while its tag matches, so a wipe
     * also invalidates entries a concurrent reader inserts after it.
     */
    private val cacheEpoch = java.util.concurrent.atomic.AtomicLong(0)

    private fun cachedKey(alias: String): SecretKey? =
        keyCache[alias]?.takeIf { it.epoch == cacheEpoch.get() }?.key

    override fun onStoreCleared() {
        cacheEpoch.incrementAndGet()
        keyCache.clear()
        alternateKeyCache.clear()
        // Runs on the write consumer, not the caller thread, so it can't race a write's key mint.
        runCatching { vaults.active.clearAll() }
        if (vaults.legacy !== vaults.active) runCatching { vaults.legacy.clearAll() }
    }

    override fun deleteKey(identifier: String) {
        synchronized(aliasLocks.forAlias(identifier)) {
            keyCache.remove(identifier)
            alternateKeyCache.remove(identifier)
            // Snapshot before the try: a degrade in the catch flips vaults.active to legacy and
            // would skip the legacy cleanup below, just when it is needed.
            val activeAtStart = vaults.active
            try {
                activeAtStart.delete(identifier)
            } catch (e: LinkageError) {
                vaults.degradeToLegacy(e)
            } catch (_: Throwable) {
            }
            if (activeAtStart !== vaults.legacy) {
                runCatching { vaults.legacy.delete(identifier) }
            }
            // Scrub the derived namespace too, else a recreate resurrects the key via the read-fallback.
            vaults.deleteFromLegacyNamespace(identifier)
        }
    }

    private fun getOrCreateSecretKey(alias: String): SecretKey =
        secretKey(alias, create = true)!!

    /** Resolve/create only: nothing is encrypted, so a raced wipe has no ciphertext to strand. */
    override suspend fun prewarmKey(
        identifier: String,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
    ) {
        // A dead native bridge is no proof the OS vault is empty, so a read-only session must
        // leave no provisional key behind: warm what is there and let a real write mint.
        if (vaults.degradedByLinkFailure) secretKey(identifier, create = false) else getOrCreateSecretKey(identifier)
    }

    /**
     * A miss on a healthy vault throws "no key found" so the orphan sweep reclaims the ciphertext;
     * a miss after a degrade throws "unavailable", which the sweep leaves alone.
     */
    private fun getExistingSecretKey(alias: String): SecretKey =
        secretKey(alias, create = false)
            ?: if (vaults.hasDegraded) {
                throw IllegalStateException(
                    "KSafe: key ${KSafeEngineMessage.VAULT_UNAVAILABLE} (degraded); cannot resolve key for identifier: $alias"
                )
            } else {
                throw IllegalStateException(KSafeEngineMessage.noKeyFound(alias))
            }

    /** The per-alias lock is also held by [deleteKey], to block cache-repopulation races. */
    private fun secretKey(alias: String, create: Boolean): SecretKey? {
        cachedKey(alias)?.let { return it }

        return synchronized(aliasLocks.forAlias(alias)) {
            cachedKey(alias)?.let { return it }
            // Epoch captured before the vault read: a purge during it leaves this entry stale.
            val epochAtRead = cacheEpoch.get()

            val key = try {
                resolveKeyVia(vaults.active, alias, create)
            } catch (e: LinkageError) {
                // JNA can fail to link on the first real call (jlink JRE without
                // `jdk.unsupported`) despite passing the construction-time self-test.
                vaults.degradeToLegacy(e)
                resolveKeyVia(vaults.active, alias, create)
            }

            if (key != null) keyCache[alias] = CachedKey(key, epochAtRead)
            key
        }
    }

    /**
     * Legacy-first when an OS vault is active: the OS vault is per-user and long-lived and can
     * hold a stale key from a previous install, so an existing legacy DataStore key wins and is
     * migrated in. Caller holds `aliasLocks.forAlias(alias)`.
     */
    private fun resolveKeyVia(active: JvmKeyVault, alias: String, create: Boolean): SecretKey? {
        val keyBytes: ByteArray? =
            if (active !== vaults.legacy) {
                // Last probe before "no key found": keys from an older namespace (launcher-derived,
                // shadowed) live only there and are migrated in on a hit.
                migrateLegacyLocked(alias)
                    ?: active.get(alias)
                    ?: vaults.recoverFromLegacyNamespace(alias)
            } else {
                // A deliberate opt-out owns what it resolves: an inherited provisional marker
                // would let the next healthy launch hand the alias back to the OS vault.
                active.get(alias)?.also {
                    if (vaults.softwareOptOutRequested) promoteProvisionalMarker(alias)
                }
            }

        return when {
            keyBytes != null -> SecretKeySpec(keyBytes, "AES")
            !create -> null
            vaults.osVaultUnavailable -> {
                // Fail-closed: the real key most likely lives in the unreachable OS vault, and a
                // fresh legacy key would overwrite it on the next healthy launch.
                throw IllegalStateException(
                    "KSafe: OS key vault is unavailable (locked/unreachable); " +
                        "refusing to create a key for identifier: $alias to avoid " +
                        "overwriting the real OS-vault key on a later healthy " +
                        "launch. Retry once the OS store is reachable, or set " +
                        "-Dksafe.jvm.keyVault=software to use software storage."
                )
            }
            else -> {
                val keyGen = KeyGenerator.getInstance("AES")
                keyGen.init(config.aesKeySize.bits)
                val generated = keyGen.generateKey()
                // Marker first: a crash between the writes must not leave an unmarked fallback key.
                if (active === vaults.legacy) {
                    vaults.legacy.put(fallbackMintMarker(alias), mintMarker())
                }
                active.put(alias, generated.encoded)
                generated
            }
        }
    }

    /**
     * Copies the legacy DataStore key into the OS vault, deleting the legacy copy only after
     * byte-verifying the OS store kept it — a keyring that silently no-ops `put()` must not
     * destroy the only copy. Caller holds `aliasLocks.forAlias(alias)`.
     */
    private fun migrateLegacyLocked(alias: String): ByteArray? {
        // A custody marker is bookkeeping, not key material: migrating one would clear the legacy
        // copy and disarm the conflict guard below, which reads the marker from the legacy vault.
        if (isFallbackMintMarker(alias)) return null
        val legacyBytes = vaults.legacy.get(alias) ?: return null
        // One snapshot for the whole migration: a degrade from another alias' thread makes
        // `active` the legacy vault, and copying it onto itself would delete the only copy.
        val active = vaults.active
        if (active === vaults.legacy) return legacyBytes
        try {
            // A fallback-minted legacy key must not overwrite a different live OS key: a software
            // session mints into the legacy slot while the real key sits in the OS vault, so keep
            // both. A marker-less legacy key is genuine and still replaces a stale OS copy.
            val existing = active.get(alias)
            val marker = vaults.legacy.get(fallbackMintMarker(alias))
            if (marker != null && existing != null && !existing.contentEquals(legacyBytes)) {
                // The OS key takes the alias back, but the provisional one is kept, not scrubbed:
                // decrypt retries with it, so writes from either side of the failure still read.
                if (marker.contentEquals(DEGRADED_MINT_MARKER)) {
                    degradedConflictWarning.warn {
                        "KSafe SECURITY WARNING: a session whose OS key vault bridge could " +
                            "not load minted a local key for '$alias' while the OS vault " +
                            "already held one. The OS vault is reachable again, so KSafe " +
                            "continues with the OS key. KSafe keeps BOTH keys and tries " +
                            "both on read, so nothing written before, during or after the " +
                            "failure is lost. Re-write the affected values to consolidate " +
                            "them under the OS key."
                    }
                    return existing
                }
                legacyConflictWarning.warn {
                    "KSafe SECURITY WARNING: the OS key vault and the local key file " +
                        "both hold a (different) key for '$alias'. This usually means " +
                        "a software-fallback session (-Dksafe.jvm.keyVault=software, " +
                        "or a runtime vault degrade under KSafe 3.1 or earlier) " +
                        "minted new keys while the OS vault held live ones. " +
                        "KSafe keeps BOTH keys and continues with the " +
                        "local one; values encrypted under the OS key stay recoverable. " +
                        "Resolve by re-writing wanted values (or deleting the stale " +
                        "local key file after verifying your data reads correctly)."
                }
                return legacyBytes
            }
            active.put(alias, legacyBytes)
            if (active.get(alias)?.contentEquals(legacyBytes) == true) {
                vaults.legacy.delete(alias)
                vaults.legacy.delete(fallbackMintMarker(alias))
            }
        } catch (e: LinkageError) {
            // The legacy copy is intact (delete is gated on read-back), so degrade and retry outside.
            throw e
        } catch (_: Throwable) {
            // Best-effort: a transient OS-vault hiccup must not destroy the legacy copy.
        }
        return legacyBytes
    }

    private val legacyConflictWarning = OneShotWarning()

    private val degradedConflictWarning = OneShotWarning()

    private fun fallbackMintMarker(alias: String) = "$alias$FALLBACK_MINT_MARKER_SUFFIX"

    private fun isFallbackMintMarker(alias: String) = alias.endsWith(FALLBACK_MINT_MARKER_SUFFIX)

    private val FALLBACK_MINT_MARKER = byteArrayOf(1)

    /** Same slot, a payload older stores never wrote: custody moved involuntarily. */
    private val DEGRADED_MINT_MARKER = byteArrayOf(2)

    /** Byte 2 → byte 1: custody stops being involuntary once a session asked for it. */
    private fun promoteProvisionalMarker(alias: String) {
        if (isFallbackMintMarker(alias)) return
        val marker = runCatching { vaults.legacy.get(fallbackMintMarker(alias)) }.getOrNull() ?: return
        if (!marker.contentEquals(DEGRADED_MINT_MARKER)) return
        runCatching { vaults.legacy.put(fallbackMintMarker(alias), FALLBACK_MINT_MARKER) }
    }

    private fun mintMarker(): ByteArray =
        if (vaults.degradedByLinkFailure) DEGRADED_MINT_MARKER else FALLBACK_MINT_MARKER

    /**
     * Moves every remaining legacy key out of the DataStore file into the OS store, so a
     * never-read-again key doesn't leave its plaintext in the file. Best-effort.
     */
    override suspend fun migrateLegacyKeysSuspend() {
        if (vaults.active === vaults.legacy || !vaults.active.isOsBacked) return
        val legacyStore = vaults.legacy as? DataStoreKeyVault ?: return
        withContext(Dispatchers.IO) {
            for (alias in legacyStore.legacyAliases()) {
                // A LinkageError is sticky for the whole engine, so a degrade ends this sweep and
                // routes later writes to the software vault.
                if (vaults.active === vaults.legacy) return@withContext
                try {
                    synchronized(aliasLocks.forAlias(alias)) {
                        if (vaults.legacy.get(alias) != null) migrateLegacyLocked(alias)
                    }
                } catch (e: LinkageError) {
                    vaults.degradeToLegacy(e)
                    return@withContext
                } catch (_: Throwable) {
                }
            }
        }
    }
}
