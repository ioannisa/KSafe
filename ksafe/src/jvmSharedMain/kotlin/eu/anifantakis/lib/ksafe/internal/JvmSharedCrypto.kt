package eu.anifantakis.lib.ksafe.internal

import java.util.concurrent.ConcurrentHashMap

/**
 * AES-GCM layout shared by the two `javax.crypto` engines. Frozen: every persisted ciphertext is
 * `IV ‖ ct+tag` with exactly these sizes, so changing either number makes existing data
 * undecryptable — and changing it on only one of the two engines makes it undecryptable there.
 */
internal object JvmAesGcm {
    /** Authentication tag length, in bits. */
    const val TAG_LENGTH_BITS: Int = 128

    /** Nonce length, in bytes — the 96-bit GCM nonce, which needs no derivation step. */
    const val IV_LENGTH_BYTES: Int = 12

    /**
     * JCE transformation both engines' ciphers are built from. Identical to Android's
     * `KeyProperties.KEY_ALGORITHM_AES / BLOCK_MODE_GCM / ENCRYPTION_PADDING_NONE` triple, which
     * the Keystore key spec still needs separately.
     */
    const val TRANSFORMATION: String = "AES/GCM/NoPadding"
}

/**
 * Per-alias monitors for the engines' key resolution. Lock objects rather than `intern()`ed
 * alias strings: a dynamic key set would otherwise grow the string pool without bound.
 */
internal class AliasLocks {
    private val locks = ConcurrentHashMap<String, Any>()

    fun forAlias(alias: String): Any = locks.computeIfAbsent(alias) { Any() }
}
