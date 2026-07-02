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
 * Android implementation of [KSafeEncryption] using the Android Keystore System.
 *
 * Keys are hardware-backed (TEE, or StrongBox for `hardwareIsolated` writes),
 * non-exportable, application-bound, and deleted on uninstall.
 *
 * ## Software-DEK fast path (relaxed DEFAULT encryption)
 *
 * A non-exportable Keystore key can only run its AES-GCM cipher *inside* the TEE, so
 * every [decrypt] under such a key is a TEE round-trip — measured at ~8 ms/op on a
 * Galaxy S24 Ultra. To match the Apple and JVM engines (which hold raw key bytes in
 * RAM and do per-value AES in userspace at ~µs), **relaxed DEFAULT** entries
 * (`hardwareIsolated == false` and not `requireUnlockedDevice`) use a
 * **data-encryption key (DEK)**:
 *  - a random AES key generated once per master alias,
 *  - wrapped (AES-GCM) by the Keystore master key — the **KEK**, which never leaves the TEE,
 *  - persisted as Base64 in a reserved entry of the safe's own DataStore (no SharedPreferences),
 *  - unwrapped exactly once into [dekCache], then used for per-value userspace AES-GCM.
 *
 * DEK ciphertext is self-describing — `MAGIC || VERSION || IV || GCM(ct+tag)` — so
 * [decrypt] tells a DEK blob from a legacy TEE blob (`IV || GCM`) without any
 * envelope-version metadata. Legacy v1/v2 ciphertext, `hardwareIsolated` (StrongBox)
 * entries, and the strict `requireUnlockedDevice` master keep the per-call TEE path
 * unchanged: their plaintext is never derivable from RAM alone.
 *
 * @property config Configuration for key generation (key size, unlock policy).
 * @property dekStore Persistence for the KEK-wrapped DEK — the safe's own DataStore.
 * @property useSoftwareDek Escape hatch (tests / hotfix): when `false`, every entry uses
 *   the legacy per-call TEE path. Not exposed through the public API.
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

        // Software-DEK envelope header. New relaxed-DEFAULT ciphertext is tagged with
        // these 5 bytes so it can be distinguished from legacy TEE ciphertext (IV||ct),
        // which the engine can no longer tell apart by alias alone. "KSD1" = KSafe-DEK
        // v1. A random legacy IV colliding with the full header is ~2^-40 and is
        // additionally caught by the GCM-auth fallback in [decrypt].
        private val DEK_MAGIC = byteArrayOf(0x4B, 0x53, 0x44, 0x31) // "KSD1"
        private const val DEK_VERSION: Byte = 1
        private const val DEK_HEADER_LEN = 5 // MAGIC(4) + VERSION(1)
    }

    /**
     * Thread-safe cache for SecretKey *handles* to avoid repeated Keystore lookups.
     * Handles are cached after first access and remain valid until explicitly deleted.
     * (A handle does NOT make TEE cipher ops pure-CPU — hence the DEK fast path below.)
     */
    private val keyCache = java.util.concurrent.ConcurrentHashMap<String, SecretKey>()

    /**
     * In-process cache of unwrapped raw DEK bytes, keyed by master alias. Mirrors the
     * Apple engine's `keyBytesCache`: unwrap once via the TEE KEK, then serve userspace
     * AES from RAM. Not persisted — repopulated lazily on first use after a restart.
     */
    private val dekCache = java.util.concurrent.ConcurrentHashMap<String, ByteArray>()

    /** Per-alias lock objects — avoids `intern()` pool pressure with dynamic key sets. */
    private val locks = java.util.concurrent.ConcurrentHashMap<String, Any>()
    private fun lockFor(alias: String): Any = locks.computeIfAbsent(alias) { Any() }

    // ── encrypt ──────────────────────────────────────────────────────────────

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?
    ): ByteArray {
        // Resolve the unlock policy exactly as generateNewKey does, so the DEK fast
        // path is used IFF the KEK is created without `setUnlockedDeviceRequired` —
        // never for a key whose whole purpose is to be unusable while locked.
        val resolvedRequireUnlocked = requireUnlockedDevice ?: config.requireUnlockedDevice
        if (useSoftwareDek && !hardwareIsolated && !resolvedRequireUnlocked) {
            return encryptWithDek(identifier, data)
        }
        return try {
            encryptWithKey(identifier, data, hardwareIsolated, requireUnlockedDevice)
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Key was invalidated (e.g., device security settings changed)
            // Delete the old key and create a new one
            deleteKeyInternal(identifier)
            encryptWithKey(identifier, data, hardwareIsolated, requireUnlockedDevice)
        }
    }

    override suspend fun prewarmKey(
        identifier: String,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
    ) {
        // Warm ONLY the Keystore key — the expensive cold-start op. For a relaxed DEFAULT
        // master that key is the wrapping KEK; deliberately do NOT create or persist a DEK
        // here: the DEK is generated lazily on the first real encrypt, so an unencrypted-only
        // safe never writes one, and keeping prewarm off the safe's DataStore means a
        // construction-time prewarm can't race a concurrent close() cancelling the store's
        // scope.
        getOrCreateSecretKey(identifier, hardwareIsolated, requireUnlockedDevice)
    }

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

    /**
     * Userspace AES-GCM under the cached DEK, producing a self-describing DEK blob
     * (`MAGIC || VERSION || IV || ct+tag`). No TEE round-trip per call.
     */
    private fun encryptWithDek(alias: String, data: ByteArray): ByteArray {
        val dek = try {
            getOrCreateDek(alias)
        } catch (e: KeyPermanentlyInvalidatedException) {
            // The KEK itself is permanently invalid (e.g. lock-screen credential removed):
            // it cannot wrap anything anymore, so the KEK must be deleted and recreated.
            // Old DEK ciphertext AND legacy TEE ciphertext under it are unrecoverable either
            // way — the same outcome a TEE-only scheme has after key invalidation.
            regenerateDek(alias, deleteKek = true, requireUnlockedDevice = null)
        } catch (e: javax.crypto.AEADBadTagException) {
            // The persisted wrapped DEK fails GCM auth — the blob is corrupt or was wrapped
            // under a replaced key. This says NOTHING about the KEK's health, so mint a
            // fresh DEK under the SAME (healthy) KEK — do NOT delete the KEK, or pre-upgrade
            // legacy TEE ciphertext still encrypted directly under it would be destroyed.
            // A transient failure surfaces as "device is locked", not AEADBadTagException,
            // so this classification is deterministic.
            regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
        } catch (e: IllegalArgumentException) {
            // Malformed wrapped-DEK entry: invalid Base64 in load(), or a blob shorter than
            // the GCM IV in unwrapDek. Heal like a corrupt DEK — keep the KEK.
            regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
        } catch (e: IndexOutOfBoundsException) {
            // Same malformed case via an out-of-range read in GCMParameterSpec/doFinal.
            regenerateDek(alias, deleteKek = false, requireUnlockedDevice = null)
        } catch (e: IllegalStateException) {
            // The wrapped DEK is present but the KEK alias is ABSENT — e.g. Auto Backup
            // restored the DataStore (with the DEK) to a device whose Keystore is empty, and
            // an encrypted write beat the construction-time prewarm. getExistingSecretKey
            // throws "No encryption key found"; recover by minting a fresh DEK (getOrCreateDek
            // recreates the KEK too) instead of failing the whole batch forever. A TRANSIENT
            // "device is locked" ISE must NOT trigger destructive regen — rethrow it so the
            // write retries once the device unlocks, with data intact.
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
        // Cross-instance clearAll race (deep-review H4): two KSafe instances on one file
        // share this engine's dekCache but have separate write consumers, so a sibling's
        // clearAll can wipe the persisted DEK slot + KEK *after* we read the cached DEK and
        // *before* our ciphertext lands. We captured the raw DEK bytes above, so the
        // ciphertext stays recoverable as long as SOME wrapped copy of this DEK survives.
        // dekCache[alias] going null is the precise, cheap signal that a teardown for this
        // alias ran during our encrypt; re-persist the DEK (re-wrapping under a fresh KEK if
        // the old one was deleted) so an acknowledged post-clear write isn't orphaned. Normal
        // path: dekCache still holds our DEK → one map lookup, no I/O.
        if (dekCache[alias] == null) {
            ensureDekPersisted(alias, dek)
        }
        return out
    }

    /**
     * Best-effort repair after a concurrent teardown (clearAll on a sibling instance sharing
     * this engine): ensure the DEK we just encrypted under is durably wrapped so its ciphertext
     * stays decryptable. If the slot already holds a *different* valid DEK (a concurrent writer
     * minted a fresh one and now owns the single per-safe slot), we leave it — that write's data
     * wins the single-slot race, and ours is subject to the same generic lost-write hazard any
     * two-instances-one-file clearAll race has. Only runs when a teardown was observed.
     */
    private fun ensureDekPersisted(alias: String, dek: ByteArray) {
        synchronized(lockFor(alias)) {
            val stored = try { dekStore.load() } catch (_: Throwable) { null }
            if (stored != null) {
                val existing = try { unwrapDek(alias, stored) } catch (_: Throwable) { null }
                if (existing != null) {
                    // Slot already holds a usable DEK. If it's ours, just repopulate the cache;
                    // if it's a different one, a fresh mint owns the slot — don't clobber it.
                    if (existing.contentEquals(dek)) dekCache[alias] = dek
                    return
                }
            }
            // Slot empty or unusable: re-wrap our DEK (minting a KEK if the old one was deleted)
            // and persist, so the ciphertext just produced under it remains decryptable.
            val wrapped = wrapDek(alias, dek)
            dekStore.save(wrapped)
            dekCache[alias] = dek
        }
    }

    // ── decrypt ──────────────────────────────────────────────────────────────

    override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
        if (useSoftwareDek && hasDekHeader(data)) {
            return try {
                decryptWithDek(identifier, data, requireUnlockedDevice)
            } catch (e: KeyPermanentlyInvalidatedException) {
                // KEK gone → this value's DEK is unrecoverable. Clean up the stale DEK + KEK
                // so future writes regenerate — but ONLY if a concurrent writer hasn't already
                // healed them. A reader that observed the OLD KEK's invalidation must not
                // blindly delete a DEK/KEK a writer just regenerated, or it would orphan
                // brand-new writes made under the fresh DEK. Re-validate under the alias lock:
                // if the now-stored DEK unwraps cleanly (a concurrent regenerate replaced it),
                // leave everything intact; only destroy when it's genuinely still broken.
                synchronized(lockFor(identifier)) {
                    // Same discrimination as the encrypt-side twin regenerateDek: only a
                    // DEFINITIVE re-validation outcome — the stored DEK is genuinely still
                    // broken — may destroy state. A TRANSIENT failure (a momentary store
                    // read error, a locked-device ISE from the Keystore) proves nothing:
                    // leave everything intact and just surface the read failure below.
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
                        // KEK absent = definitive (mirrors regenerateDek);
                        // a transient "device is locked" ISE must NOT destroy.
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
                // Either genuinely corrupt DEK ciphertext, or (~2^-40) a legacy TEE blob
                // whose random IV happened to start with our magic. Retry the legacy path
                // on the ORIGINAL bytes; if that also fails, surface the original error.
                try {
                    decryptLegacy(identifier, data, requireUnlockedDevice)
                } catch (_: Throwable) {
                    throw e
                }
            } catch (e: IllegalArgumentException) {
                // Malformed wrapped-DEK entry (bad Base64 / too-short blob) surfaced while
                // unwrapping the DEK to read this value. Try the legacy path on the original
                // bytes, else surface the error so the read returns its default (decrypt
                // never creates keys; the next encrypt self-heals the DEK).
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
            // Key was invalidated - the encrypted data cannot be recovered
            // Delete the invalid key so future encryptions can work
            deleteKeyInternal(identifier)
            // Re-throw to let caller handle (will return default value)
            throw e
        }
    }

    private fun decryptWithKey(identifier: String, data: ByteArray): ByteArray {
        // Key was created with its accessibility setting - just retrieve it
        val secretKey = getExistingSecretKey(identifier)
        val cipher = Cipher.getInstance(TRANSFORMATION)

        // Read IV and ciphertext directly from `data` via offset/length
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

    // ── delete ─────────────────────────────────────────────────────────────-

    override fun deleteKey(identifier: String) {
        deleteKeyInternal(identifier)
    }

    private fun deleteKeyInternal(identifier: String) {
        synchronized(lockFor(identifier)) {
            keyCache.remove(identifier)
            // Drop this alias's cached DEK (no-op for per-entry / HARDWARE_ISOLATED
            // aliases, which never have one). We do NOT delete the persisted DEK here:
            // its storage key is fixed per safe, so a per-entry delete must not wipe the
            // shared DEK and brick every DEFAULT value. The persisted DEK is removed only
            // by discardDek() on KEK invalidation and by clearAll()'s storage.clear().
            dekCache.remove(identifier)

            try {
                keyStore.deleteEntry(identifier)
            } catch (_: Exception) {
                // Silently ignore - keystore may be unavailable
            }
        }
    }

    // ── Keystore key (KEK / legacy value key) ────────────────────────────────

    /**
     * Gets an existing key from the Keystore (for decryption).
     * Does not create a new key - if the key doesn't exist, throws an exception.
     *
     * @param identifier The key identifier/alias
     * @throws IllegalStateException if the key doesn't exist
     */
    private fun getExistingSecretKey(identifier: String): SecretKey {
        // Fast path: return cached key
        keyCache[identifier]?.let { return it }

        // Slow path: load from Keystore
        synchronized(lockFor(identifier)) {
            // Double-check after acquiring lock
            keyCache[identifier]?.let { return it }

            // `getKey` returns null for unknown aliases — single IPC. It can also throw
            // UnrecoverableKeyException when the alias EXISTS but its key blob can't be
            // loaded (seen after OS upgrades / keymaster-HAL changes / partial keystore
            // corruption). On the decrypt-only path we can't recreate, and the data is
            // unrecoverable either way, so treat "present but unreadable" exactly like
            // "absent": surface the canonical "No encryption key found" so the orphan sweep
            // reclaims the entry and the encrypt path self-heals.
            val key = try {
                keyStore.getKey(identifier, null) as? SecretKey
            } catch (e: java.security.UnrecoverableKeyException) {
                null
            } ?: throw IllegalStateException("KSafe: No encryption key found for identifier: $identifier")
            keyCache[identifier] = key
            return key
        }
    }

    /**
     * Generates a new AES key in the Android Keystore.
     *
     * When [hardwareIsolated] is true, attempts to generate the key in StrongBox hardware
     * (a physically separate security chip). If StrongBox is unavailable on the device,
     * falls back to the TEE (Trusted Execution Environment) automatically.
     *
     * @param identifier The key alias in the Keystore
     * @param hardwareIsolated Whether to attempt StrongBox key generation
     */
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

        // StrongBox: physically separate security chip (API 28+)
        // Falls back to TEE if the device doesn't have StrongBox hardware
        if (hardwareIsolated && android.os.Build.VERSION.SDK_INT >= 28) {
            builder.setIsStrongBoxBacked(true)
            return try {
                keyGenerator.init(builder.build())
                keyGenerator.generateKey()
            } catch (e: StrongBoxUnavailableException) {
                // Device doesn't have StrongBox — fall back to TEE
                builder.setIsStrongBoxBacked(false)
                keyGenerator.init(builder.build())
                keyGenerator.generateKey()
            }
        }

        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    /**
     * Gets an existing key from the Keystore or creates a new one if it doesn't exist.
     * Uses in-memory cache to avoid repeated Keystore lookups.
     *
     * Key generation parameters:
     * - Algorithm: AES
     * - Block Mode: GCM (hardcoded for security)
     * - Padding: None (hardcoded for security)
     * - Key Size: Configurable via [KSafeConfig.keySize]
     *
     * @param identifier The key identifier/alias
     * @param hardwareIsolated Whether to attempt StrongBox key generation for new keys
     */
    private fun getOrCreateSecretKey(
        identifier: String,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null
    ): SecretKey {
        // Fast path: return cached key
        keyCache[identifier]?.let { return it }

        // Slow path: load from Keystore (synchronized to prevent duplicate generation)
        synchronized(lockFor(identifier)) {
            // Double-check after acquiring lock
            keyCache[identifier]?.let { return it }

            // `getKey` returns null when the alias is absent — one IPC call. It can also throw
            // UnrecoverableKeyException when the alias exists but its blob is unreadable (OS
            // upgrade / keymaster-HAL change / partial corruption). On this CREATE path we can
            // self-heal: delete the unreadable blob and mint a fresh key so encrypted writes
            // recover. The lock is reentrant, so deleteKeyInternal here is safe. (Old
            // ciphertext under the unreadable key is unrecoverable regardless — the same
            // outcome as key invalidation.)
            val existing = try {
                keyStore.getKey(identifier, null) as? SecretKey
            } catch (e: java.security.UnrecoverableKeyException) {
                deleteKeyInternal(identifier)
                null
            }
            val key = existing ?: generateNewKey(identifier, hardwareIsolated, requireUnlockedDevice)

            // Cache the key for future use
            keyCache[identifier] = key
            return key
        }
    }

    // ── Software DEK (data-encryption key) ───────────────────────────────────

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
