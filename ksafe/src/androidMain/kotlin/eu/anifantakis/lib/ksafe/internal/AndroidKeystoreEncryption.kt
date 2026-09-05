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
 * Android [KSafeEncryption] backed by the Android Keystore. Relaxed DEFAULT entries encrypt under a
 * software DEK wrapped by the TEE key, so per-value crypto runs in userspace; StrongBox and strict
 * `requireUnlockedDevice` entries stay on the per-call TEE path, as does `useSoftwareDek = false`.
 */
@PublishedApi
internal class AndroidKeystoreEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    private val dekStore: WrappedDekStore,
    private val useSoftwareDek: Boolean = true,
    private val loadKey: (String) -> SecretKey? = { alias -> keyStore.getKey(alias, null) as? SecretKey },
) : KSafeEncryption {

    companion object {

        // KeyGenParameterSpec.Builder takes these separately; composed they are JvmAesGcm.TRANSFORMATION.
        private const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
        private const val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
        private val keyStore by lazy { KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) } }

        // Header (MAGIC||VERSION||IV||ct+tag) routes decrypt to the DEK path vs legacy blobs (IV||ct).
        private val DEK_MAGIC = byteArrayOf(0x4B, 0x53, 0x44, 0x31) // "KSD1"
        private const val DEK_VERSION: Byte = 1
        private const val DEK_HEADER_LEN = 5 // MAGIC(4) + VERSION(1)
    }

    private val keyCache = java.util.concurrent.ConcurrentHashMap<String, SecretKey>()

    private val dekCache = KSafeConcurrentMap<ByteArray>()

    private val aliasLocks = AliasLocks()

    /** Bumped before `clearAll` wipes the wrapped-DEK records, or an insert racing the wipe
     *  re-caches a DEK whose record is gone and later writes are unreadable after relaunch. */
    private val dekCacheEpoch = AtomicLong(0)

    private fun cacheDek(alias: String, dek: ByteArray, epochAtRead: Long) =
        insertUnderPurgeFence(dekCache, dekCacheEpoch, alias, dek, epochAtRead)

    /** A strict read never consults the cache: a cached DEK would answer a locked device from RAM. */
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

    /** [KeyPermanentlyInvalidatedException] must be caught before its supertype `InvalidKeyException`,
     *  or a permanent invalidation is masked as "device is locked" and never self-heals. */
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
        // DEK path IFF the KEK was minted without setUnlockedDeviceRequired — must match generateNewKey.
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
        // Only the Keystore key: minting a DEK here would persist one for a safe that never
        // encrypts, and could race a concurrent close().
        getOrCreateSecretKey(identifier, hardwareIsolated, requireUnlockedDevice)
    }

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
        // Bounded retry around a sibling clearAll racing this encrypt. The DEK used here is never
        // re-persisted — clearAll is destroying it; the write survives by re-encrypting instead.
        repeat(2) {
            // Epoch read before the DEK: a sibling clearAll may wipe the store mid-encrypt.
            val epochBefore = dekCacheEpoch.load()
            val dek = resolveDekHealing(alias)
            val out = sealWithDek(dek, data, aad)
            if (dekCache[alias] != null && dekCacheEpoch.load() == epochBefore) return out
            synchronized(aliasLocks.forAlias(alias)) {
                val epochAtRead = dekCacheEpoch.load()
                val stored = try { dekStore.load(alias) } catch (_: Throwable) { null }
                if (stored != null) {
                    val existing = try { unwrapDek(alias, stored) } catch (_: Throwable) { null }
                    // Our DEK still owns the slot; the ciphertext is readable as persisted.
                    if (existing != null && existing.contentEquals(dek)) {
                        cacheDek(alias, dek, epochAtRead)
                        return out
                    }
                }
            }
        }
        // Two teardowns raced this write; seal and stop — losing the write beats undoing a wipe.
        return sealWithDek(resolveDekHealing(alias), data, aad)
    }

    private fun resolveDekHealing(alias: String): ByteArray = try {
        getOrCreateDek(alias)
    } catch (e: KeyPermanentlyInvalidatedException) {
        // KEK permanently invalid: recreate the whole pair (ciphertext under it is lost anyway).
        regenerateDek(alias, deleteKek = true, requireUnlockedDevice = null)
    } catch (e: javax.crypto.AEADBadTagException) {
        // Corrupt DEK, healthy KEK: mint a fresh DEK under the SAME KEK — deleting the KEK
        // would destroy legacy TEE ciphertext encrypted directly under it.
        regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
    } catch (e: IllegalArgumentException) {
        regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
    } catch (e: IndexOutOfBoundsException) {
        regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
    } catch (e: IllegalStateException) {
        // KEK absent: mint a fresh DEK. A transient "device is locked" ISE must not regenerate
        // destructively — rethrow so the write retries with data intact.
        if (KSafeEngineMessage.isDefinitiveKeyMiss(e.message)) {
            regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
        } else {
            throw e
        }
    }

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
                // KEK gone: drop the stale DEK + KEK, but re-validate under the alias lock first —
                // a concurrent writer may have healed them, and only a definitive break may destroy.
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
                        KSafeEngineMessage.isDefinitiveKeyMiss(t.message)
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
                legacyOrRethrow(e)
            } catch (e: IndexOutOfBoundsException) {
                legacyOrRethrow(e)
            } catch (e: IllegalStateException) {
                // Same ~2^-40 case: probe legacy before surfacing, or the sweep reaps a valid entry.
                if (KSafeEngineMessage.isDefinitiveKeyMiss(e.message)) {
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
            // Generation-aware records are per-alias, so deleting this alias's is safe. In legacy
            // single-slot mode all aliases share ONE record — dropping it would brick every value.
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

    private fun getExistingSecretKey(identifier: String): SecretKey {
        keyCache[identifier]?.let { return it }

        synchronized(aliasLocks.forAlias(identifier)) {
            keyCache[identifier]?.let { return it }

            // An alias can exist yet be unreadable. On the decrypt path a proven-permanent one
            // counts as absent, so the orphan sweep can reclaim the entry.
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

    private fun getOrCreateSecretKey(
        identifier: String,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null
    ): SecretKey {
        keyCache[identifier]?.let { return it }

        synchronized(aliasLocks.forAlias(identifier)) {
            keyCache[identifier]?.let { return it }

            // A proven-permanently-unreadable blob self-heals here; its ciphertext is lost anyway.
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

    /** The raw DEK for [alias], minted on first use; serialized per alias so a burst mints one DEK. */
    private fun getOrCreateDek(alias: String, requireUnlockedDevice: Boolean? = null): ByteArray =
        dekFromCacheOrStore(alias, requireUnlockedDevice) {
            val dek = secureRandomBytes(config.aesKeySize.bytes)
            val wrapped = wrapDek(alias, dek)
            // Persist before returning: a crash with an in-RAM-only DEK orphans the ciphertext
            // about to be written.
            dekStore.save(alias, wrapped)
            dek
        }

    /** Shared prologue of both DEK lookups; the purge-fence epoch is read before the load. */
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

    /** Drops an unrecoverable DEK and mints a fresh one. Re-validate + discard + recreate run under
     *  one [AliasLocks.forAlias], or a second writer's discard wipes the DEK the first encrypted under. */
    private fun regenerateDek(alias: String, deleteKek: Boolean, requireUnlockedDevice: Boolean?): ByteArray {
        synchronized(aliasLocks.forAlias(alias)) {
            // A concurrent regenerate may have healed it while we were blocked; adopt that DEK
            // instead of discarding data just encrypted under it. A malformed blob = no stored DEK.
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
                    // KEK absent → recreate; a transient locked-device ISE must not, so rethrow.
                    if (!KSafeEngineMessage.isDefinitiveKeyMiss(e.message)) throw e
                }
            }
            discardDek(alias)
            // Only a permanently invalidated KEK may go; a healthy one must survive so legacy
            // TEE ciphertext encrypted directly under it stays decryptable.
            if (deleteKek) deleteKeyInternal(alias)
            return getOrCreateDek(alias, requireUnlockedDevice)
        }
    }

    /** The raw DEK for the decrypt path; never creates one. A miss throws the canonical
     *  "No encryption key found" so [KSafeCore]'s orphan cleanup reclaims the entry. */
    private fun getExistingDek(alias: String, requireUnlockedDevice: Boolean?): ByteArray =
        dekFromCacheOrStore(alias, requireUnlockedDevice) {
            throw IllegalStateException(KSafeEngineMessage.noKeyFound(alias))
        }

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

    private fun unwrapDek(kekAlias: String, wrapped: ByteArray): ByteArray {
        val kek = getExistingSecretKey(kekAlias) // throws "No encryption key found" if KEK absent
        val cipher = Cipher.getInstance(JvmAesGcm.TRANSFORMATION)
        val spec = GCMParameterSpec(JvmAesGcm.TAG_LENGTH_BITS, wrapped, 0, JvmAesGcm.IV_LENGTH_BYTES)
        initCipherTranslatingLock { cipher.init(Cipher.DECRYPT_MODE, kek, spec) }
        return cipher.doFinal(wrapped, JvmAesGcm.IV_LENGTH_BYTES, wrapped.size - JvmAesGcm.IV_LENGTH_BYTES)
    }

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

internal const val ANDROID_KEYSTORE_PROVIDER: String = "AndroidKeyStore"

/** The transient locked-Keystore failure the core retries on; one spelling so the phrase can't drift. */
private fun keystoreLockedFailure(cause: Throwable): IllegalStateException =
    IllegalStateException(
        "KSafe: Cannot access ${KSafeEngineMessage.KEYSTORE} key - ${KSafeEngineMessage.DEVICE_LOCKED}.",
        cause,
    )

/** Own class so the API 33 Keystore types load only where they exist. */
private object KeyStoreFault {
    fun errorCodeOf(cause: Throwable?): Int? = (cause as? AndroidKeyStoreException)?.numericErrorCode
    fun isSystemErrorOf(cause: Throwable?): Boolean = (cause as? AndroidKeyStoreException)?.isSystemError == true
}

/** Whether an `UnrecoverableKeyException` proves the alias is permanently unreadable — Keystore
 *  reports transient daemon faults the same way, and a wrong verdict destroys data. */
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
