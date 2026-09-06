package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption

/**
 * The [KSafeEncryption] doubles shared across the jvmTest suite. They live here because each was
 * pasted into two to four files verbatim, and a double whose failure phrase drifts in one copy
 * silently stops exercising the classification path its test exists to prove. jvmTest rather than
 * commonTest: `@Volatile` has no js/wasm target.
 */

/** Ciphertext == plaintext bytes, so a seeded snapshot's `Text` decrypts to exactly what it encodes. */
internal class IdentityEngine : KSafeEncryption {
    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray = data

    override fun decrypt(
        identifier: String,
        data: ByteArray,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray = data

    override fun deleteKey(identifier: String) {}
}

/** XOR-encrypts, but `decrypt` throws a transient device-locked error while armed. */
internal class ToggleTransientEngine : KSafeEncryption {
    @Volatile var failTransient = false
    private val xor = FakeEncryption()

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray = xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)

    override fun decrypt(
        identifier: String,
        data: ByteArray,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray {
        if (failTransient) throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked.")
        return xor.decrypt(identifier, data)
    }

    override fun deleteKey(identifier: String) {}
}

/**
 * XOR [FakeEncryption] whose `encrypt` throws when the plaintext contains [failMarker]. Keying
 * failure off the payload rather than the alias fails one key while its siblings still succeed.
 */
internal class MarkerFailEncryption(private val failMarker: String) : KSafeEncryption {
    private val xor = FakeEncryption()

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray {
        if (data.decodeToString().contains(failMarker)) {
            throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked. (test)")
        }
        return xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)
    }

    override fun decrypt(
        identifier: String,
        data: ByteArray,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray = xor.decrypt(identifier, data)

    override fun deleteKey(identifier: String) { /* no-op */ }
}

/** Runs [onDecrypt] (the racing write) before returning a fixed "old" plaintext. */
internal class RaceEngine : KSafeEncryption {
    @Volatile var onDecrypt: (() -> Unit)? = null

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray = data

    override fun decrypt(
        identifier: String,
        data: ByteArray,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray {
        onDecrypt?.invoke()
        onDecrypt = null // race only the first (seeded) decrypt
        return "\"old\"".encodeToByteArray() // JSON for String "old"
    }

    override fun deleteKey(identifier: String) {}
}
