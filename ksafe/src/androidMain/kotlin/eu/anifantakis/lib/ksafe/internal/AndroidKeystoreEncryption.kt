package eu.anifantakis.lib.ksafe.internal

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
) : KSafeEncryption {

    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val GCM_TAG_LENGTH = 128
        private const val GCM_IV_LENGTH = 12

        private const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val BLOCK_MODE =  KeyProperties.BLOCK_MODE_GCM
        private const val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
        private const val TRANSFORMATION = "$KEY_ALGORITHM/$BLOCK_MODE/$ENCRYPTION_PADDING"
        private val keyStore by lazy { KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) } }

        // DEK envelope header (MAGIC||VERSION||IV||ct+tag) routes [decrypt] to the DEK path vs
        // legacy TEE blobs (IV||ct). A ~2^-40 IV collision is caught by the GCM-auth fallback.
        private val DEK_MAGIC = byteArrayOf(0x4B, 0x53, 0x44, 0x31) // "KSD1"
        private const val DEK_VERSION: Byte = 1
        private const val DEK_HEADER_LEN = 5 // MAGIC(4) + VERSION(1)
    }

    /** Cached SecretKey handles (a handle still means TEE cipher ops — hence the DEK path). */
    private val keyCache = java.util.concurrent.ConcurrentHashMap<String, SecretKey>()

    /** Unwrapped raw DEK bytes per master alias; repopulated lazily after a restart. */
    private val dekCache = java.util.concurrent.ConcurrentHashMap<String, ByteArray>()

    /** Per-alias lock objects — avoids `intern()` pool pressure with dynamic key sets. */
    private val locks = java.util.concurrent.ConcurrentHashMap<String, Any>()
    private fun lockFor(alias: String): Any = locks.computeIfAbsent(alias) { Any() }

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?
    ): ByteArray {
        // Resolve the unlock policy exactly as generateNewKey does: the DEK path is used IFF
        // the KEK is created without `setUnlockedDeviceRequired`.
        val resolvedRequireUnlocked = requireUnlockedDevice ?: config.requireUnlockedDevice
        if (useSoftwareDek && !hardwareIsolated && !resolvedRequireUnlocked) {
            return encryptWithDek(identifier, data)
        }
        return try {
            encryptWithKey(identifier, data, hardwareIsolated, requireUnlockedDevice)
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Invalidated key: delete and recreate.
            deleteKeyInternal(identifier)
            encryptWithKey(identifier, data, hardwareIsolated, requireUnlockedDevice)
        }
    }

    override suspend fun prewarmKey(
        identifier: String,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
    ) {
        // Warm only the Keystore key. The DEK is created lazily on the first real encrypt, so
        // an unencrypted-only safe never persists one and prewarm can't race a concurrent
        // close() cancelling the store's scope.
        getOrCreateSecretKey(identifier, hardwareIsolated, requireUnlockedDevice)
    }

    /**
     * Read-only, best-effort warm of an already-persisted wrapped DEK into [dekCache], keeping
     * the first encrypted read off a blocking DataStore round-trip (an ANR risk on the main
     * thread). Never creates or persists a DEK, so an unencrypted-only safe stays DEK-free.
     */
    override suspend fun prewarmDekReadIfPresent(identifier: String, requireUnlockedDevice: Boolean?) {
        if (!useSoftwareDek || requireUnlockedDevice == true) return // strict/legacy paths have no cached DEK
        runCatching { getExistingDek(identifier, requireUnlockedDevice) }
    }

    /** Test-only: whether a DEK for [alias] is warm in the in-process cache. */
    @PublishedApi
    internal fun isDekCachedForTest(alias: String): Boolean = dekCache[alias] != null

    private fun encryptWithKey(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?
    ): ByteArray {
        val secretKey = getOrCreateSecretKey(identifier, hardwareIsolated, requireUnlockedDevice)
        val cipher = Cipher.getInstance(TRANSFORMATION)

        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        } catch (e: java.security.InvalidKeyException) {
            throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked.", e)
        }

        val output = ByteArray(GCM_IV_LENGTH + cipher.getOutputSize(data.size))
        System.arraycopy(cipher.iv, 0, output, 0, GCM_IV_LENGTH)
        cipher.doFinal(data, 0, data.size, output, GCM_IV_LENGTH)
        return output
    }

    /** Userspace AES-GCM under the cached DEK, producing a self-describing DEK blob. */
    private fun encryptWithDek(alias: String, data: ByteArray): ByteArray {
        val dek = try {
            getOrCreateDek(alias)
        } catch (e: KeyPermanentlyInvalidatedException) {
            // The KEK itself is permanently invalid: delete and recreate the whole pair.
            // Ciphertext under it is unrecoverable either way.
            regenerateDek(alias, deleteKek = true, requireUnlockedDevice = null)
        } catch (e: javax.crypto.AEADBadTagException) {
            // Corrupt wrapped DEK, healthy KEK: mint a fresh DEK under the SAME KEK — deleting
            // the KEK would destroy legacy TEE ciphertext still encrypted directly under it.
            regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
        } catch (e: IllegalArgumentException) {
            // Malformed wrapped-DEK blob (bad Base64 / too short): heal like corrupt, keep the KEK.
            regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
        } catch (e: IndexOutOfBoundsException) {
            // Same malformed case via an out-of-range read.
            regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
        } catch (e: IllegalStateException) {
            // Wrapped DEK present but KEK absent (e.g. Auto Backup restore onto an empty
            // Keystore): mint a fresh DEK. A transient "device is locked" ISE must NOT trigger
            // destructive regen — rethrow so the write retries with data intact.
            if (e.message?.contains("No encryption key found", ignoreCase = true) == true) {
                regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
            } else {
                throw e
            }
        }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(dek, KEY_ALGORITHM))
        val iv = cipher.iv
        val ct = cipher.doFinal(data)
        val out = ByteArray(DEK_HEADER_LEN + GCM_IV_LENGTH + ct.size)
        System.arraycopy(DEK_MAGIC, 0, out, 0, DEK_MAGIC.size)
        out[DEK_MAGIC.size] = DEK_VERSION
        System.arraycopy(iv, 0, out, DEK_HEADER_LEN, GCM_IV_LENGTH)
        System.arraycopy(ct, 0, out, DEK_HEADER_LEN + GCM_IV_LENGTH, ct.size)
        // dekCache[alias] going null signals a concurrent teardown (e.g. a sibling instance's
        // clearAll) wiped the persisted DEK slot during this encrypt; re-persist the DEK so
        // this acknowledged write stays decryptable. Normal path: one map lookup, no I/O.
        if (dekCache[alias] == null) {
            ensureDekPersisted(alias, dek)
        }
        return out
    }

    /**
     * Best-effort repair after a concurrent teardown: re-wraps and persists the DEK just
     * encrypted under — unless a different valid DEK already owns the single per-safe slot
     * (a concurrent fresh mint wins; ours faces the generic clearAll lost-write hazard).
     */
    private fun ensureDekPersisted(alias: String, dek: ByteArray) {
        synchronized(lockFor(alias)) {
            val stored = try { dekStore.load() } catch (_: Throwable) { null }
            if (stored != null) {
                val existing = try { unwrapDek(alias, stored) } catch (_: Throwable) { null }
                if (existing != null) {
                    // Ours → repopulate the cache; a different DEK owns the slot → don't clobber.
                    if (existing.contentEquals(dek)) dekCache[alias] = dek
                    return
                }
            }
            val wrapped = wrapDek(alias, dek)
            dekStore.save(wrapped)
            dekCache[alias] = dek
        }
    }

    override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
        if (useSoftwareDek && hasDekHeader(data)) {
            return try {
                decryptWithDek(identifier, data, requireUnlockedDevice)
            } catch (e: KeyPermanentlyInvalidatedException) {
                // KEK gone → this value is unrecoverable. Clean up the stale DEK + KEK so
                // future writes regenerate — but re-validate under the alias lock first: a
                // concurrent writer may already have healed them, and only a DEFINITIVE
                // still-broken outcome may destroy state (a transient failure proves nothing).
                synchronized(lockFor(identifier)) {
                    val stillBroken = try {
                        val stored = try {
                            dekStore.load()
                        } catch (_: IllegalArgumentException) {
                            null // malformed persisted blob — definitively unusable
                        } catch (_: IndexOutOfBoundsException) {
                            null
                        }
                        if (stored == null) {
                            true // nothing usable stored
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
                        t.message?.contains("No encryption key found", ignoreCase = true) == true
                    } catch (_: Throwable) {
                        false // unknown ⇒ conservative: preserve
                    }
                    if (stillBroken) {
                        discardDek(identifier)
                        deleteKeyInternal(identifier)
                    }
                }
                throw IllegalStateException(
                    "KSafe: No encryption key found for identifier: $identifier (key permanently invalidated)",
                    e
                )
            } catch (e: javax.crypto.AEADBadTagException) {
                // Corrupt DEK ciphertext, or (~2^-40) a legacy TEE blob whose IV matches the
                // magic: retry the legacy path; if that also fails, surface the original error.
                try {
                    decryptLegacy(identifier, data, requireUnlockedDevice)
                } catch (_: Throwable) {
                    throw e
                }
            } catch (e: IllegalArgumentException) {
                // Malformed wrapped-DEK entry: try the legacy path, else surface the error
                // (decrypt never creates keys; the next encrypt self-heals the DEK).
                try {
                    decryptLegacy(identifier, data, requireUnlockedDevice)
                } catch (_: Throwable) {
                    throw e
                }
            } catch (e: IndexOutOfBoundsException) {
                try {
                    decryptLegacy(identifier, data, requireUnlockedDevice)
                } catch (_: Throwable) {
                    throw e
                }
            }
        }
        return decryptLegacy(identifier, data, requireUnlockedDevice)
    }

    private fun decryptLegacy(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
        return try {
            decryptWithKey(identifier, data)
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Invalidated key: delete so future encrypts work; rethrow so the caller returns
            // its default (the data is unrecoverable).
            deleteKeyInternal(identifier)
            throw e
        }
    }

    private fun decryptWithKey(identifier: String, data: ByteArray): ByteArray {
        val secretKey = getExistingSecretKey(identifier)
        val cipher = Cipher.getInstance(TRANSFORMATION)

        val spec = GCMParameterSpec(GCM_TAG_LENGTH, data, 0, GCM_IV_LENGTH)

        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        } catch (e: java.security.InvalidKeyException) {
            throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked.", e)
        }

        return cipher.doFinal(data, GCM_IV_LENGTH, data.size - GCM_IV_LENGTH)
    }

    /** Userspace AES-GCM under the cached DEK for a self-describing DEK blob. */
    private fun decryptWithDek(alias: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
        val dek = getExistingDek(alias, requireUnlockedDevice) // throws "No encryption key found" if the DEK is absent
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, data, DEK_HEADER_LEN, GCM_IV_LENGTH)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(dek, KEY_ALGORITHM), spec)
        val ctStart = DEK_HEADER_LEN + GCM_IV_LENGTH
        return cipher.doFinal(data, ctStart, data.size - ctStart)
    }

    private fun hasDekHeader(data: ByteArray): Boolean {
        if (data.size < DEK_HEADER_LEN + GCM_IV_LENGTH) return false
        for (i in DEK_MAGIC.indices) if (data[i] != DEK_MAGIC[i]) return false
        return data[DEK_MAGIC.size] == DEK_VERSION
    }

    override fun deleteKey(identifier: String) {
        deleteKeyInternal(identifier)
    }

    private fun deleteKeyInternal(identifier: String) {
        synchronized(lockFor(identifier)) {
            keyCache.remove(identifier)
            // Drop the cached DEK but never the persisted one: its storage key is fixed per
            // safe, so a per-entry delete must not wipe the shared DEK and brick every DEFAULT
            // value. The persisted DEK is removed only by discardDek() and clearAll().
            dekCache.remove(identifier)

            try {
                keyStore.deleteEntry(identifier)
            } catch (_: Exception) {
                // keystore may be unavailable — best effort
            }
        }
    }

    /** Returns an existing Keystore key; never creates one — throws if absent (decrypt path). */
    private fun getExistingSecretKey(identifier: String): SecretKey {
        keyCache[identifier]?.let { return it }

        synchronized(lockFor(identifier)) {
            keyCache[identifier]?.let { return it }

            // An alias can exist yet be unreadable (UnrecoverableKeyException after OS/
            // keymaster changes). On the decrypt path treat it like "absent" so the canonical
            // "No encryption key found" lets the orphan sweep reclaim the entry.
            val key = try {
                keyStore.getKey(identifier, null) as? SecretKey
            } catch (e: java.security.UnrecoverableKeyException) {
                null
            } ?: throw IllegalStateException("KSafe: No encryption key found for identifier: $identifier")
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
            KEYSTORE_PROVIDER
        )

        val builder = KeyGenParameterSpec.Builder(
            identifier,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(BLOCK_MODE)
            .setEncryptionPaddings(ENCRYPTION_PADDING)
            .setKeySize(config.keySize)

        val resolvedRequireUnlockedDevice = requireUnlockedDevice ?: config.requireUnlockedDevice
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

        synchronized(lockFor(identifier)) {
            keyCache[identifier]?.let { return it }

            // An existing-but-unreadable blob (UnrecoverableKeyException) self-heals on this
            // create path: delete it and mint a fresh key. Old ciphertext under it is
            // unrecoverable regardless — the same outcome as key invalidation.
            val existing = try {
                keyStore.getKey(identifier, null) as? SecretKey
            } catch (e: java.security.UnrecoverableKeyException) {
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
    private fun getOrCreateDek(alias: String, requireUnlockedDevice: Boolean? = null, deleteKek: Boolean = false): ByteArray {
        if (requireUnlockedDevice != true) {
            dekCache[alias]?.let { return it }
        }
        synchronized(lockFor(alias)) {
            if (requireUnlockedDevice != true) {
                dekCache[alias]?.let { return it }
            }
            val stored = dekStore.load()
            if (stored != null) {
                val dek = unwrapDek(alias, stored)
                if (requireUnlockedDevice != true) {
                    dekCache[alias] = dek
                }
                return dek
            }
            val dek = secureRandomBytes(config.keySize / 8)
            val wrapped = wrapDek(alias, dek)
            // Persist synchronously BEFORE returning: a crash after returning but before
            // the wrapped DEK is durable would strand an in-RAM-only DEK and orphan the
            // ciphertext we're about to write.
            dekStore.save(wrapped)
            if (requireUnlockedDevice != true) {
                dekCache[alias] = dek
            }
            return dek
        }
    }

    /**
     * Recovery for an unrecoverable DEK on the encrypt path: drop the stored DEK and mint a
     * fresh one, keeping new writes working instead of failing forever.
     *
     * [deleteKek] selects what's actually broken:
     *  - `false` (the DEK is bad but the KEK is healthy — corrupt/malformed wrapped DEK, or a
     *    DEK present whose KEK is merely absent): keep the KEK and mint a new DEK **wrapped by
     *    the same KEK**. This preserves pre-upgrade legacy TEE ciphertext encrypted directly
     *    under that KEK; if the KEK is absent, [getOrCreateDek] recreates it.
     *  - `true` (the KEK itself is permanently invalidated): delete the KEK and recreate the
     *    whole pair — the only case where destroying the KEK is justified.
     *
     * The whole re-validate + discard + (delete) + recreate runs under a single [lockFor]
     * acquisition so it is **atomic** — the inner calls re-enter the same reentrant monitor.
     * Without this, two writers that both hit the same bad blob interleave and the second's
     * discard wipes the DEK the first just minted *after* the first already encrypted a value
     * under it — silently losing an acknowledged write. Atomicity alone isn't enough, so we
     * **re-validate before discarding**: if a concurrent regenerate already produced a usable
     * DEK, adopt it instead.
     */
    private fun regenerateDek(alias: String, deleteKek: Boolean, requireUnlockedDevice: Boolean?): ByteArray {
        synchronized(lockFor(alias)) {
            // A concurrent regenerate may have already healed it while we were blocked on the
            // lock. Adopt the fresh DEK rather than discarding it (and the data just encrypted
            // under it). `load()` itself can throw on a malformed (bad-Base64) blob — treat
            // that as "no usable stored DEK" and fall through to recreate; only a genuine
            // non-malformed load failure (rare DataStore read error) propagates.
            dekCache[alias]?.let { return it }
            val stored = try {
                dekStore.load()
            } catch (_: IllegalArgumentException) {
                null
            } catch (_: IndexOutOfBoundsException) {
                null
            }
            if (stored != null) {
                try {
                    val dek = unwrapDek(alias, stored)
                    if (requireUnlockedDevice != true) {
                        dekCache[alias] = dek
                    }
                    return dek
                } catch (_: KeyPermanentlyInvalidatedException) {
                    // Still unrecoverable — fall through to discard + recreate.
                } catch (_: javax.crypto.AEADBadTagException) {
                    // Still unrecoverable — fall through to discard + recreate.
                } catch (_: IllegalArgumentException) {
                    // Malformed stored blob (too short) — fall through.
                } catch (_: IndexOutOfBoundsException) {
                    // Malformed stored blob (out-of-range read) — fall through.
                } catch (e: IllegalStateException) {
                    // KEK absent ("No encryption key found") — fall through to recreate.
                    // A TRANSIENT "device is locked" ISE is NOT a reason to destroy/recreate:
                    // rethrow it so the caller retries later with the stored DEK intact.
                    if (e.message?.contains("No encryption key found", ignoreCase = true) != true) throw e
                }
            }
            discardDek(alias)
            // Delete the KEK ONLY when it is the thing that's broken (permanent invalidation).
            // For a bad/missing DEK the KEK is healthy and must survive so legacy TEE
            // ciphertext under it stays decryptable.
            if (deleteKek) deleteKeyInternal(alias)
            return getOrCreateDek(alias, requireUnlockedDevice)
        }
    }

    /**
     * Returns the raw DEK for [alias] for the decrypt path. Never creates one — a missing
     * DEK throws the canonical "No encryption key found" message so [KSafeCore]'s orphan
     * cleanup reclaims the entry (matching the JVM/Apple engines).
     */
    private fun getExistingDek(alias: String, requireUnlockedDevice: Boolean?): ByteArray {
        if (requireUnlockedDevice != true) {
            dekCache[alias]?.let { return it }
        }
        synchronized(lockFor(alias)) {
            if (requireUnlockedDevice != true) {
                dekCache[alias]?.let { return it }
            }
            val stored = dekStore.load()
                ?: throw IllegalStateException("KSafe: No encryption key found for identifier: $alias")
            val dek = unwrapDek(alias, stored)
            if (requireUnlockedDevice != true) {
                dekCache[alias] = dek
            }
            return dek
        }
    }

    /** Encrypts (wraps) the raw [dek] with the TEE KEK at [kekAlias]. One TEE op per alias. */
    private fun wrapDek(kekAlias: String, dek: ByteArray): ByteArray {
        // The KEK is the relaxed master key: not StrongBox, not unlock-required.
        val kek = getOrCreateSecretKey(kekAlias, hardwareIsolated = false, requireUnlockedDevice = false)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, kek)
        val iv = cipher.iv
        val ct = cipher.doFinal(dek)
        val out = ByteArray(GCM_IV_LENGTH + ct.size)
        System.arraycopy(iv, 0, out, 0, GCM_IV_LENGTH)
        System.arraycopy(ct, 0, out, GCM_IV_LENGTH, ct.size)
        return out
    }

    /** Decrypts (unwraps) a [wrapped] DEK with the TEE KEK at [kekAlias]. */
    private fun unwrapDek(kekAlias: String, wrapped: ByteArray): ByteArray {
        val kek = getExistingSecretKey(kekAlias) // throws "No encryption key found" if KEK absent
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, wrapped, 0, GCM_IV_LENGTH)
        try {
            cipher.init(Cipher.DECRYPT_MODE, kek, spec)
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Catch BEFORE InvalidKeyException (its supertype): permanent invalidation is
            // definitive (callers clear + regenerate), not the transient "device locked".
            throw e
        } catch (e: java.security.InvalidKeyException) {
            throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked.", e)
        }
        return cipher.doFinal(wrapped, GCM_IV_LENGTH, wrapped.size - GCM_IV_LENGTH)
    }

    /** Drops a DEK from the cache and the wrapped-DEK store (used on KEK invalidation). */
    private fun discardDek(alias: String) {
        synchronized(lockFor(alias)) {
            dekCache.remove(alias)
            try {
                dekStore.delete()
            } catch (_: Exception) {
                // store unavailable — best effort
            }
        }
    }
}
