@file:OptIn(ExperimentalAtomicApi::class)

package eu.anifantakis.lib.ksafe.internal

import android.security.KeyStoreException as AndroidKeyStoreException
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import eu.anifantakis.lib.ksafe.KSafeConfig
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * Android [KSafeEncryption] backed by the Android Keystore. Relaxed DEFAULT entries use a
 * software DEK — wrapped (AES-GCM) by the non-exportable TEE KEK, persisted in the safe's own
 * DataStore, unwrapped once into [dekCache] — so per-value crypto runs in userspace instead of
 * a per-call TEE round-trip; StrongBox and strict `requireUnlockedDevice` entries stay on the
 * per-call TEE path. [useSoftwareDek] is a test/hotfix escape hatch forcing the TEE path.
 */
@PublishedApi
internal class AndroidKeystoreEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    private val dekStore: WrappedDekStore,
    private val useSoftwareDek: Boolean = true,
    private val loadKey: (String) -> SecretKey? = { alias -> keyStore.getKey(alias, null) as? SecretKey },
) : KSafeEncryption {

    companion object {

        // Kept as the Keystore spellings because KeyGenParameterSpec.Builder takes them
        // separately; the composed cipher transformation is JvmAesGcm.TRANSFORMATION.
        private const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
        private const val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
        private val keyStore by lazy { KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) } }

        // DEK envelope header (MAGIC||VERSION||IV||ct+tag) routes [decrypt] to the DEK path vs
        // legacy TEE blobs (IV||ct). A ~2^-40 IV collision is caught by the GCM-auth fallback.
        private val DEK_MAGIC = byteArrayOf(0x4B, 0x53, 0x44, 0x31) // "KSD1"
        private const val DEK_VERSION: Byte = 1
        private const val DEK_HEADER_LEN = 5 // MAGIC(4) + VERSION(1)
    }

    /** Cached SecretKey handles (a handle still means TEE cipher ops — hence the DEK path). */
    private val keyCache = java.util.concurrent.ConcurrentHashMap<String, SecretKey>()

    private val dekCache = KSafeConcurrentMap<ByteArray>()

    private val aliasLocks = AliasLocks()

    /**
     * Purge fence for [dekCache], bumped BEFORE `clearAll` wipes the DataStore that holds the
     * wrapped-DEK records. Without it, an insert racing the wipe could re-cache a DEK whose
     * record is gone, leaving every later encrypt on RAM-only key material unreadable after
     * relaunch.
     */
    private val dekCacheEpoch = AtomicLong(0)

    private fun cacheDek(alias: String, dek: ByteArray, epochAtRead: Long) =
        insertUnderPurgeFence(dekCache, dekCacheEpoch, alias, dek, epochAtRead)

    /**
     * The warm DEK for [alias], or null. A strict read never consults the cache: serving a cached
     * DEK would answer a locked device from RAM and defeat the unlock policy the entry was written
     * under. Paired with [maybeCacheDek] — the two guards must state the same condition.
     */
    private fun cachedDek(alias: String, requireUnlockedDevice: Boolean?): ByteArray? =
        if (requireUnlockedDevice == true) null else dekCache[alias]

    /** [cachedDek]'s write half: a strict DEK is never retained. */
    private fun maybeCacheDek(
        alias: String,
        dek: ByteArray,
        epochAtRead: Long,
        requireUnlockedDevice: Boolean?,
    ) {
        if (requireUnlockedDevice != true) cacheDek(alias, dek, epochAtRead)
    }

    /**
     * Runs a `Cipher.init`, translating a locked Keystore into the failure the core retries on.
     * The catch ORDER is the invariant: [KeyPermanentlyInvalidatedException] must be caught before
     * its supertype `InvalidKeyException`, or a definitive invalidation is masked as the transient
     * "device is locked" and never reaches the delete-and-recreate self-heal.
     */
    private inline fun initCipherTranslatingLock(init: () -> Unit) {
        try {
            init()
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw e
        } catch (e: java.security.InvalidKeyException) {
            throw keystoreLockedFailure(e)
        }
    }

    override fun onStoreCleared() {
        dekCacheEpoch.addAndFetch(1)
        dekCache.clear()
    }

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray {
        // DEK path is used IFF the KEK is created without setUnlockedDeviceRequired (must match generateNewKey).
        val resolvedRequireUnlocked = config.resolveRequireUnlockedDevice(requireUnlockedDevice)
        if (useSoftwareDek && !hardwareIsolated && !resolvedRequireUnlocked) {
            return encryptWithDek(identifier, data, aad)
        }
        return try {
            encryptWithKey(identifier, data, hardwareIsolated, requireUnlockedDevice, aad)
        } catch (e: KeyPermanentlyInvalidatedException) {
            deleteKeyInternal(identifier)
            encryptWithKey(identifier, data, hardwareIsolated, requireUnlockedDevice, aad)
        }
    }

    override suspend fun prewarmKey(
        identifier: String,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
    ) {
        // Warm only the Keystore key; the DEK is minted lazily on the first real encrypt so an
        // unencrypted-only safe never persists one and can't race a concurrent close().
        getOrCreateSecretKey(identifier, hardwareIsolated, requireUnlockedDevice)
    }

    /**
     * Read-only, best-effort warm of an already-persisted wrapped DEK into [dekCache], keeping
     * the first encrypted read off a blocking DataStore round-trip (ANR risk on the main
     * thread). Never creates or persists a DEK.
     */
    override suspend fun prewarmDekReadIfPresent(identifier: String, requireUnlockedDevice: Boolean?) {
        if (!useSoftwareDek || requireUnlockedDevice == true) return
        runCatching { getExistingDek(identifier, requireUnlockedDevice) }
    }

    /** Test-only: whether a DEK for [alias] is warm in the in-process cache. */
    @PublishedApi
    internal fun isDekCachedForTest(alias: String): Boolean = dekCache[alias] != null

    private fun encryptWithKey(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray? = null,
    ): ByteArray {
        val secretKey = getOrCreateSecretKey(identifier, hardwareIsolated, requireUnlockedDevice)
        val cipher = Cipher.getInstance(JvmAesGcm.TRANSFORMATION)

        initCipherTranslatingLock { cipher.init(Cipher.ENCRYPT_MODE, secretKey) }
        if (aad != null) cipher.updateAAD(aad)

        val output = ByteArray(JvmAesGcm.IV_LENGTH_BYTES + cipher.getOutputSize(data.size))
        System.arraycopy(cipher.iv, 0, output, 0, JvmAesGcm.IV_LENGTH_BYTES)
        cipher.doFinal(data, 0, data.size, output, JvmAesGcm.IV_LENGTH_BYTES)
        return output
    }

    private fun encryptWithDek(alias: String, data: ByteArray, aad: ByteArray? = null): ByteArray {
        // Bounded retry around a sibling clearAll racing this encrypt — the same shape and
        // reasoning as the JVM twin (JvmSoftwareEncryption.encrypt). The DEK this attempt used
        // is never re-persisted: it is exactly the material `clearAll()` promised to destroy,
        // and re-inserting it would make a pre-wipe backup of the store decryptable again. The
        // acknowledged write stays readable by RE-ENCRYPTING under whatever legitimately owns
        // the slot afterwards — a concurrent winner's DEK, or fresh post-wipe material.
        repeat(2) {
            // Snapshot the teardown epoch before capturing the DEK: if a sibling clearAll bumps
            // it mid-encrypt, the DEK we hold may already be wiped from the store even when the
            // shared cache was transiently re-populated by a concurrent mint.
            val epochBefore = dekCacheEpoch.load()
            val dek = resolveDekHealing(alias)
            val out = sealWithDek(dek, data, aad)
            // A null cache entry OR a bumped teardown epoch signals a concurrent sibling
            // clearAll wiped the persisted DEK during this encrypt.
            if (dekCache[alias] != null && dekCacheEpoch.load() == epochBefore) return out
            synchronized(aliasLocks.forAlias(alias)) {
                val epochAtRead = dekCacheEpoch.load()
                val stored = try { dekStore.load(alias) } catch (_: Throwable) { null }
                if (stored != null) {
                    val existing = try { unwrapDek(alias, stored) } catch (_: Throwable) { null }
                    // Our DEK still owns the slot (e.g. a concurrent re-mint of identical
                    // bytes) — the ciphertext is readable exactly as persisted, keep it.
                    if (existing != null && existing.contentEquals(dek)) {
                        cacheDek(alias, dek, epochAtRead)
                        return out
                    }
                }
                // Slot wiped, or a different DEK won it — fall through and re-encrypt.
            }
        }
        // Two consecutive teardowns raced this write; seal under the current resolution and
        // stop re-checking. The pathological tail fails toward erasure — never toward undoing
        // a wipe.
        return sealWithDek(resolveDekHealing(alias), data, aad)
    }

    /** The DEK to encrypt under, healing every definitively-broken state resolution can surface. */
    private fun resolveDekHealing(alias: String): ByteArray = try {
        getOrCreateDek(alias)
    } catch (e: KeyPermanentlyInvalidatedException) {
        // KEK permanently invalid: recreate the whole pair (ciphertext under it is lost anyway).
        regenerateDek(alias, deleteKek = true, requireUnlockedDevice = null)
    } catch (e: javax.crypto.AEADBadTagException) {
        // Corrupt wrapped DEK, healthy KEK: mint a fresh DEK under the SAME KEK — deleting
        // the KEK would destroy legacy TEE ciphertext still encrypted directly under it.
        regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
    } catch (e: IllegalArgumentException) {
        regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
    } catch (e: IndexOutOfBoundsException) {
        regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
    } catch (e: IllegalStateException) {
        // Wrapped DEK present but KEK absent (e.g. Auto Backup restore onto an empty Keystore):
        // mint a fresh DEK. A transient "device is locked" ISE must NOT trigger destructive
        // regen — rethrow so the write retries with data intact.
        if (e.message?.contains(KSafeEngineMessage.NO_KEY, ignoreCase = true) == true) {
            regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
        } else {
            throw e
        }
    }

    /** One AES-GCM seal of [data] under [dek], framed as `MAGIC||VERSION||IV||ct+tag`. */
    private fun sealWithDek(dek: ByteArray, data: ByteArray, aad: ByteArray?): ByteArray {
        val cipher = Cipher.getInstance(JvmAesGcm.TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(dek, KEY_ALGORITHM))
        if (aad != null) cipher.updateAAD(aad)
        val iv = cipher.iv
        val ct = cipher.doFinal(data)
        val out = ByteArray(DEK_HEADER_LEN + JvmAesGcm.IV_LENGTH_BYTES + ct.size)
        System.arraycopy(DEK_MAGIC, 0, out, 0, DEK_MAGIC.size)
        out[DEK_MAGIC.size] = DEK_VERSION
        System.arraycopy(iv, 0, out, DEK_HEADER_LEN, JvmAesGcm.IV_LENGTH_BYTES)
        System.arraycopy(ct, 0, out, DEK_HEADER_LEN + JvmAesGcm.IV_LENGTH_BYTES, ct.size)
        return out
    }

    override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray {
        // Kotlin has no multi-catch, so the clauses below stay separate; their BODY is one thing.
        fun legacyOrRethrow(original: Throwable): ByteArray =
            try {
                decryptLegacy(identifier, data, requireUnlockedDevice, aad)
            } catch (_: Throwable) {
                throw original
            }

        if (useSoftwareDek && hasDekHeader(data)) {
            return try {
                decryptWithDek(identifier, data, requireUnlockedDevice, aad)
            } catch (e: KeyPermanentlyInvalidatedException) {
                // KEK gone → this value is unrecoverable. Clean up stale DEK + KEK so future writes
                // regenerate — but re-validate under the alias lock first: a concurrent writer may
                // have healed them, and only a DEFINITIVE still-broken outcome may destroy state.
                synchronized(aliasLocks.forAlias(identifier)) {
                    val stillBroken = try {
                        val stored = try {
                            dekStore.load(identifier)
                        } catch (_: IllegalArgumentException) {
                            null
                        } catch (_: IndexOutOfBoundsException) {
                            null
                        }
                        if (stored == null) {
                            true
                        } else {
                            unwrapDek(identifier, stored)
                            false // a concurrent regenerate healed it — destroy nothing
                        }
                    } catch (_: KeyPermanentlyInvalidatedException) {
                        true
                    } catch (_: javax.crypto.AEADBadTagException) {
                        true
                    } catch (_: IllegalArgumentException) {
                        true
                    } catch (_: IndexOutOfBoundsException) {
                        true
                    } catch (t: IllegalStateException) {
                        // KEK absent = definitive; a transient "device is locked" ISE must not destroy.
                        t.message?.contains(KSafeEngineMessage.NO_KEY, ignoreCase = true) == true
                    } catch (_: Throwable) {
                        false // unknown ⇒ preserve
                    }
                    if (stillBroken) {
                        discardDek(identifier)
                        deleteKeyInternal(identifier)
                    }
                }
                throw IllegalStateException(
                    "${KSafeEngineMessage.noKeyFound(identifier)} (key permanently invalidated)",
                    e
                )
            } catch (e: javax.crypto.AEADBadTagException) {
                // Corrupt DEK ciphertext, or (~2^-40) a legacy TEE blob whose IV matches the magic.
                legacyOrRethrow(e)
            } catch (e: IllegalArgumentException) {
                // Malformed wrapped-DEK entry (decrypt never creates keys).
                legacyOrRethrow(e)
            } catch (e: IndexOutOfBoundsException) {
                legacyOrRethrow(e)
            } catch (e: IllegalStateException) {
                // No wrapped DEK for this alias: the blob may still (~2^-40) be a legacy TEE
                // blob whose random IV spells the DEK header — probe legacy before surfacing,
                // or the orphan sweep would reap a valid legacy entry as missing-key. Gated on
                // the canonical missing-DEK message so the transient "device is locked" ISE
                // still propagates unchanged.
                if (e.message?.contains(KSafeEngineMessage.NO_KEY, ignoreCase = true) == true) {
                    legacyOrRethrow(e)
                } else {
                    throw e
                }
            }
        }
        return decryptLegacy(identifier, data, requireUnlockedDevice, aad)
    }

    private fun decryptLegacy(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray? = null): ByteArray {
        return try {
            decryptWithKey(identifier, data, aad)
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Invalidated key: delete so future encrypts work; rethrow so the caller returns its default.
            deleteKeyInternal(identifier)
            throw e
        }
    }

    private fun decryptWithKey(identifier: String, data: ByteArray, aad: ByteArray? = null): ByteArray {
        val secretKey = getExistingSecretKey(identifier)
        val cipher = Cipher.getInstance(JvmAesGcm.TRANSFORMATION)

        val spec = GCMParameterSpec(JvmAesGcm.TAG_LENGTH_BITS, data, 0, JvmAesGcm.IV_LENGTH_BYTES)

        initCipherTranslatingLock { cipher.init(Cipher.DECRYPT_MODE, secretKey, spec) }
        if (aad != null) cipher.updateAAD(aad)

        return cipher.doFinal(data, JvmAesGcm.IV_LENGTH_BYTES, data.size - JvmAesGcm.IV_LENGTH_BYTES)
    }

    private fun decryptWithDek(alias: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray? = null): ByteArray {
        val dek = getExistingDek(alias, requireUnlockedDevice) // throws "No encryption key found" if the DEK is absent
        val cipher = Cipher.getInstance(JvmAesGcm.TRANSFORMATION)
        val spec = GCMParameterSpec(JvmAesGcm.TAG_LENGTH_BITS, data, DEK_HEADER_LEN, JvmAesGcm.IV_LENGTH_BYTES)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(dek, KEY_ALGORITHM), spec)
        if (aad != null) cipher.updateAAD(aad)
        val ctStart = DEK_HEADER_LEN + JvmAesGcm.IV_LENGTH_BYTES
        return cipher.doFinal(data, ctStart, data.size - ctStart)
    }

    private fun hasDekHeader(data: ByteArray): Boolean {
        if (data.size < DEK_HEADER_LEN + JvmAesGcm.IV_LENGTH_BYTES) return false
        for (i in DEK_MAGIC.indices) if (data[i] != DEK_MAGIC[i]) return false
        return data[DEK_MAGIC.size] == DEK_VERSION
    }

    override fun deleteKey(identifier: String) {
        deleteKeyInternal(identifier)
    }

    private fun deleteKeyInternal(identifier: String) {
        synchronized(aliasLocks.forAlias(identifier)) {
            keyCache.remove(identifier)
            // Generation-aware DEK records are per-alias, so deleting THIS alias's record with its
            // KEK is safe and is how the rotation sweep reclaims a superseded generation's DEK. In
            // legacy single-slot mode every alias collides on ONE record, so a per-entry delete must
            // NOT touch it or it would brick every DEFAULT value — reclaimed only by discardDek()/clearAll().
            dekCache.remove(identifier)
            if (dekStore.isGenerationAware) {
                try {
                    if (dekStore.load(identifier) != null) dekStore.delete(identifier)
                } catch (_: Exception) {
                }
            }

            try {
                keyStore.deleteEntry(identifier)
            } catch (_: Exception) {
            }
        }
    }

    private fun isDefinitivelyUnreadable(e: java.security.UnrecoverableKeyException): Boolean {
        val cause = e.cause
        val onKeyStoreApi = android.os.Build.VERSION.SDK_INT >= 33
        return isDefinitivelyUnreadableKey(
            hasCause = cause != null,
            keyStoreErrorCode = if (onKeyStoreApi) KeyStoreFault.errorCodeOf(cause) else null,
            isSystemError = onKeyStoreApi && KeyStoreFault.isSystemErrorOf(cause),
        )
    }

    /** Returns an existing Keystore key; never creates one — throws if absent (decrypt path). */
    private fun getExistingSecretKey(identifier: String): SecretKey {
        keyCache[identifier]?.let { return it }

        synchronized(aliasLocks.forAlias(identifier)) {
            keyCache[identifier]?.let { return it }

            // An alias can exist yet be unreadable (UnrecoverableKeyException after OS/keymaster
            // changes). On the decrypt path treat a PROVEN-permanent one as "absent" so the
            // canonical "No encryption key found" lets the orphan sweep reclaim the entry.
            val key = try {
                loadKey(identifier)
            } catch (e: java.security.UnrecoverableKeyException) {
                if (!isDefinitivelyUnreadable(e)) throw keystoreLockedFailure(e)
                null
            } ?: throw IllegalStateException(KSafeEngineMessage.noKeyFound(identifier))
            keyCache[identifier] = key
            return key
        }
    }

    /** Generates a new AES-GCM key in the Keystore; [hardwareIsolated] attempts StrongBox. */
    private fun generateNewKey(
        identifier: String,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?
    ): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KEY_ALGORITHM,
            ANDROID_KEYSTORE_PROVIDER
        )

        val builder = KeyGenParameterSpec.Builder(
            identifier,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(BLOCK_MODE)
            .setEncryptionPaddings(ENCRYPTION_PADDING)
            .setKeySize(config.aesKeySize.bits)

        val resolvedRequireUnlockedDevice = config.resolveRequireUnlockedDevice(requireUnlockedDevice)
        if (resolvedRequireUnlockedDevice && android.os.Build.VERSION.SDK_INT >= 28) {
            builder.setUnlockedDeviceRequired(true)
        }

        // StrongBox (physically separate security chip, API 28+); falls back to the TEE when absent.
        if (hardwareIsolated && android.os.Build.VERSION.SDK_INT >= 28) {
            builder.setIsStrongBoxBacked(true)
            return try {
                keyGenerator.init(builder.build())
                keyGenerator.generateKey()
            } catch (e: StrongBoxUnavailableException) {
                builder.setIsStrongBoxBacked(false)
                keyGenerator.init(builder.build())
                keyGenerator.generateKey()
            }
        }

        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    /** Returns the Keystore key for [identifier], creating it if absent (cached). */
    private fun getOrCreateSecretKey(
        identifier: String,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null
    ): SecretKey {
        keyCache[identifier]?.let { return it }

        synchronized(aliasLocks.forAlias(identifier)) {
            keyCache[identifier]?.let { return it }

            // A PROVEN-permanently-unreadable blob self-heals on this create path: delete it and
            // mint a fresh key (old ciphertext is unrecoverable regardless).
            val existing = try {
                loadKey(identifier)
            } catch (e: java.security.UnrecoverableKeyException) {
                if (!isDefinitivelyUnreadable(e)) throw keystoreLockedFailure(e)
                deleteKeyInternal(identifier)
                null
            }
            val key = existing ?: generateNewKey(identifier, hardwareIsolated, requireUnlockedDevice)

            keyCache[identifier] = key
            return key
        }
    }

    /**
     * Returns the raw DEK for [alias], creating + wrapping + persisting one on first use.
     * Serialized per alias so a burst of concurrent first-writes generates exactly one DEK.
     */
    private fun getOrCreateDek(alias: String, requireUnlockedDevice: Boolean? = null): ByteArray =
        dekFromCacheOrStore(alias, requireUnlockedDevice) {
            val dek = secureRandomBytes(config.aesKeySize.bytes)
            val wrapped = wrapDek(alias, dek)
            // Persist synchronously BEFORE returning: a crash before the wrapped DEK is durable
            // would strand an in-RAM-only DEK and orphan the ciphertext about to be written.
            dekStore.save(alias, wrapped)
            dek
        }

    /**
     * The cache/lock/re-check/load prologue both DEK lookups share, with [onStoreMiss] deciding
     * what an absent stored DEK means. Written once because the parts that are NOT the decision —
     * the per-alias lock, the purge-fence epoch captured BEFORE the load, and the cache guards —
     * are exactly the parts whose asymmetry is silent.
     */
    private inline fun dekFromCacheOrStore(
        alias: String,
        requireUnlockedDevice: Boolean?,
        onStoreMiss: () -> ByteArray,
    ): ByteArray {
        cachedDek(alias, requireUnlockedDevice)?.let { return it }
        synchronized(aliasLocks.forAlias(alias)) {
            cachedDek(alias, requireUnlockedDevice)?.let { return it }
            val epochAtRead = dekCacheEpoch.load()
            val stored = dekStore.load(alias)
            val dek = if (stored != null) unwrapDek(alias, stored) else onStoreMiss()
            maybeCacheDek(alias, dek, epochAtRead, requireUnlockedDevice)
            return dek
        }
    }

    /**
     * Recovery for an unrecoverable DEK on the encrypt path: drop the stored DEK and mint a fresh
     * one so new writes keep working.
     *
     * [deleteKek] selects what's broken:
     *  - `false` (DEK bad, KEK healthy — corrupt/malformed wrapped DEK, or DEK present whose KEK is
     *    merely absent): keep the KEK and mint a new DEK **wrapped by the same KEK**, preserving
     *    legacy TEE ciphertext encrypted directly under it; if the KEK is absent [getOrCreateDek]
     *    recreates it.
     *  - `true` (KEK permanently invalidated): delete the KEK and recreate the whole pair — the only
     *    case where destroying the KEK is justified.
     *
     * The whole re-validate + discard + (delete) + recreate runs under a single
     * [AliasLocks.forAlias] acquisition so it is atomic (inner calls re-enter the same reentrant
     * monitor). Without it, two writers hitting the same bad blob interleave and the second's discard wipes the DEK the
     * first just encrypted under — silently losing an acknowledged write. It also re-validates
     * before discarding: if a concurrent regenerate already produced a usable DEK, adopt it.
     */
    private fun regenerateDek(alias: String, deleteKek: Boolean, requireUnlockedDevice: Boolean?): ByteArray {
        synchronized(aliasLocks.forAlias(alias)) {
            // A concurrent regenerate may have healed it while we were blocked; adopt the fresh DEK
            // rather than discarding it (and the data just encrypted under it). load() can throw on
            // a malformed blob — treat that as "no usable stored DEK" and fall through to recreate.
            dekCache[alias]?.let { return it }
            val epochAtRead = dekCacheEpoch.load()
            val stored = try {
                dekStore.load(alias)
            } catch (_: IllegalArgumentException) {
                null
            } catch (_: IndexOutOfBoundsException) {
                null
            }
            if (stored != null) {
                try {
                    val dek = unwrapDek(alias, stored)
                    maybeCacheDek(alias, dek, epochAtRead, requireUnlockedDevice)
                    return dek
                } catch (_: KeyPermanentlyInvalidatedException) {
                } catch (_: javax.crypto.AEADBadTagException) {
                } catch (_: IllegalArgumentException) {
                } catch (_: IndexOutOfBoundsException) {
                } catch (e: IllegalStateException) {
                    // KEK absent → fall through to recreate. A TRANSIENT "device is locked" ISE must
                    // NOT destroy/recreate: rethrow so the caller retries with the stored DEK intact.
                    if (e.message?.contains(KSafeEngineMessage.NO_KEY, ignoreCase = true) != true) throw e
                }
            }
            discardDek(alias)
            // Delete the KEK ONLY when it is permanently invalidated; for a bad/missing DEK the KEK
            // is healthy and must survive so legacy TEE ciphertext under it stays decryptable.
            if (deleteKek) deleteKeyInternal(alias)
            return getOrCreateDek(alias, requireUnlockedDevice)
        }
    }

    /**
     * Returns the raw DEK for [alias] for the decrypt path. Never creates one — a missing
     * DEK throws the canonical "No encryption key found" message so [KSafeCore]'s orphan
     * cleanup reclaims the entry (matching the JVM/Apple engines).
     */
    private fun getExistingDek(alias: String, requireUnlockedDevice: Boolean?): ByteArray =
        dekFromCacheOrStore(alias, requireUnlockedDevice) {
            throw IllegalStateException(KSafeEngineMessage.noKeyFound(alias))
        }

    /** Encrypts (wraps) the raw [dek] with the TEE KEK at [kekAlias]. */
    private fun wrapDek(kekAlias: String, dek: ByteArray): ByteArray {
        // The KEK is the relaxed master key: not StrongBox, not unlock-required.
        val kek = getOrCreateSecretKey(kekAlias, hardwareIsolated = false, requireUnlockedDevice = false)
        val cipher = Cipher.getInstance(JvmAesGcm.TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, kek)
        val iv = cipher.iv
        val ct = cipher.doFinal(dek)
        val out = ByteArray(JvmAesGcm.IV_LENGTH_BYTES + ct.size)
        System.arraycopy(iv, 0, out, 0, JvmAesGcm.IV_LENGTH_BYTES)
        System.arraycopy(ct, 0, out, JvmAesGcm.IV_LENGTH_BYTES, ct.size)
        return out
    }

    /** Decrypts (unwraps) a [wrapped] DEK with the TEE KEK at [kekAlias]. */
    private fun unwrapDek(kekAlias: String, wrapped: ByteArray): ByteArray {
        val kek = getExistingSecretKey(kekAlias) // throws "No encryption key found" if KEK absent
        val cipher = Cipher.getInstance(JvmAesGcm.TRANSFORMATION)
        val spec = GCMParameterSpec(JvmAesGcm.TAG_LENGTH_BITS, wrapped, 0, JvmAesGcm.IV_LENGTH_BYTES)
        initCipherTranslatingLock { cipher.init(Cipher.DECRYPT_MODE, kek, spec) }
        return cipher.doFinal(wrapped, JvmAesGcm.IV_LENGTH_BYTES, wrapped.size - JvmAesGcm.IV_LENGTH_BYTES)
    }

    /** Drops a DEK from the cache and the wrapped-DEK store (used on KEK invalidation). */
    private fun discardDek(alias: String) {
        synchronized(aliasLocks.forAlias(alias)) {
            dekCache.remove(alias)
            try {
                dekStore.delete(alias)
            } catch (_: Exception) {
            }
        }
    }
}

/** JCE provider name of the Android Keystore; every caller of it spells it from here. */
internal const val ANDROID_KEYSTORE_PROVIDER: String = "AndroidKeyStore"

/**
 * The transient locked-Keystore failure the core retries on. Every site raises the identical
 * message, so the phrase the classifier matches cannot drift on one of them.
 */
private fun keystoreLockedFailure(cause: Throwable): IllegalStateException =
    IllegalStateException(
        "KSafe: Cannot access ${KSafeEngineMessage.KEYSTORE} key - ${KSafeEngineMessage.DEVICE_LOCKED}.",
        cause,
    )

/** Reads the framework signals off a Keystore cause; own class so API 33 types load only there. */
private object KeyStoreFault {
    fun errorCodeOf(cause: Throwable?): Int? = (cause as? AndroidKeyStoreException)?.numericErrorCode
    fun isSystemErrorOf(cause: Throwable?): Boolean = (cause as? AndroidKeyStoreException)?.isSystemError == true
}

/**
 * Whether an `UnrecoverableKeyException` PROVES the alias is permanently unreadable. Keystore
 * reports transient daemon faults through the same exception, and a wrong "permanent" verdict
 * destroys every value the key protects while a wrong "transient" one only retries.
 */
internal fun isDefinitivelyUnreadableKey(
    hasCause: Boolean,
    keyStoreErrorCode: Int?,
    isSystemError: Boolean,
): Boolean {
    // AndroidKeyStoreSpi re-wraps a permanently invalidated key as a cause-less exception.
    if (!hasCause) return true
    if (keyStoreErrorCode == null || isSystemError) return false
    return keyStoreErrorCode == AndroidKeyStoreException.ERROR_KEY_CORRUPTED ||
        keyStoreErrorCode == AndroidKeyStoreException.ERROR_KEY_DOES_NOT_EXIST
}
