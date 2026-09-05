@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.internal.cryptokit.ksafe_cryptokit_aes_gcm_decrypt
import eu.anifantakis.lib.ksafe.internal.cryptokit.ksafe_cryptokit_aes_gcm_encrypt
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned

/** AES-GCM via the CryptoKit bridge. Frozen on-disk framing: nonce(12) || ciphertext || tag(16). */
internal object AppleAesGcm {
    internal const val NONCE_SIZE_BYTES: Int = 12
    internal const val TAG_SIZE_BYTES: Int = 16

    // Mirrors the codes in KSafeCryptoKitBridge.swift; any other value is a generic failure.
    private const val STATUS_SUCCESS: Int = 0
    private const val STATUS_INVALID_ARGUMENT: Int = 1
    private const val STATUS_AUTHENTICATION_FAILED: Int = 2

    fun encrypt(
        key: ByteArray,
        plaintext: ByteArray,
        authenticatedData: ByteArray?,
        nonce: ByteArray = secureRandomBytes(NONCE_SIZE_BYTES),
    ): ByteArray {
        requireValidKey(key)
        require(nonce.size == NONCE_SIZE_BYTES) {
            "KSafe: AES-GCM nonce must be $NONCE_SIZE_BYTES bytes, got ${nonce.size}"
        }

        val ciphertext = ByteArray(plaintext.size)
        val tag = ByteArray(TAG_SIZE_BYTES)
        val status = key.withUBytePointer { keyPointer ->
            nonce.withUBytePointer { noncePointer ->
                plaintext.withUBytePointer { plaintextPointer ->
                    authenticatedData.withUBytePointer { authenticatedDataPointer ->
                        ciphertext.withUBytePointer { ciphertextPointer ->
                            tag.withUBytePointer { tagPointer ->
                                ksafe_cryptokit_aes_gcm_encrypt(
                                    key_pointer = keyPointer,
                                    key_count = key.size,
                                    nonce_pointer = noncePointer,
                                    nonce_count = nonce.size,
                                    plaintext_pointer = plaintextPointer,
                                    plaintext_count = plaintext.size,
                                    authenticated_data_pointer = authenticatedDataPointer,
                                    authenticated_data_count = authenticatedData?.size ?: 0,
                                    ciphertext_output = ciphertextPointer,
                                    tag_output = tagPointer,
                                )
                            }
                        }
                    }
                }
            }
        }
        checkStatus(status, operation = "encrypt")

        return ByteArray(NONCE_SIZE_BYTES + ciphertext.size + TAG_SIZE_BYTES).also { output ->
            nonce.copyInto(output)
            ciphertext.copyInto(output, destinationOffset = NONCE_SIZE_BYTES)
            tag.copyInto(output, destinationOffset = NONCE_SIZE_BYTES + ciphertext.size)
        }
    }

    fun decrypt(
        key: ByteArray,
        nonceCiphertextAndTag: ByteArray,
        authenticatedData: ByteArray?,
    ): ByteArray {
        requireValidKey(key)
        require(nonceCiphertextAndTag.size >= NONCE_SIZE_BYTES + TAG_SIZE_BYTES) {
            "KSafe: AES-GCM ciphertext is too short"
        }

        val ciphertextSize =
            nonceCiphertextAndTag.size - NONCE_SIZE_BYTES - TAG_SIZE_BYTES
        val nonce = nonceCiphertextAndTag.copyOfRange(0, NONCE_SIZE_BYTES)
        val ciphertext = nonceCiphertextAndTag.copyOfRange(
            NONCE_SIZE_BYTES,
            NONCE_SIZE_BYTES + ciphertextSize,
        )
        val tag = nonceCiphertextAndTag.copyOfRange(
            NONCE_SIZE_BYTES + ciphertextSize,
            nonceCiphertextAndTag.size,
        )
        val plaintext = ByteArray(ciphertextSize)

        val status = key.withUBytePointer { keyPointer ->
            nonce.withUBytePointer { noncePointer ->
                ciphertext.withUBytePointer { ciphertextPointer ->
                    tag.withUBytePointer { tagPointer ->
                        authenticatedData.withUBytePointer { authenticatedDataPointer ->
                            plaintext.withUBytePointer { plaintextPointer ->
                                ksafe_cryptokit_aes_gcm_decrypt(
                                    key_pointer = keyPointer,
                                    key_count = key.size,
                                    nonce_pointer = noncePointer,
                                    nonce_count = nonce.size,
                                    ciphertext_pointer = ciphertextPointer,
                                    ciphertext_count = ciphertext.size,
                                    tag_pointer = tagPointer,
                                    tag_count = tag.size,
                                    authenticated_data_pointer = authenticatedDataPointer,
                                    authenticated_data_count = authenticatedData?.size ?: 0,
                                    plaintext_output = plaintextPointer,
                                )
                            }
                        }
                    }
                }
            }
        }
        checkStatus(status, operation = "decrypt")
        return plaintext
    }

    private fun requireValidKey(key: ByteArray) {
        require(key.size == 16 || key.size == 32) {
            "KSafe: AES-GCM key must be 16 or 32 bytes, got ${key.size}"
        }
    }

    private fun checkStatus(status: Int, operation: String) {
        when (status) {
            STATUS_SUCCESS -> Unit
            STATUS_INVALID_ARGUMENT ->
                throw IllegalArgumentException("KSafe: invalid AES-GCM $operation arguments")
            STATUS_AUTHENTICATION_FAILED ->
                throw IllegalStateException("KSafe: AES-GCM authentication failed")
            else ->
                throw IllegalStateException(
                    "KSafe: CryptoKit AES-GCM $operation failed (status=$status)"
                )
        }
    }

    private inline fun <T> ByteArray?.withUBytePointer(
        block: (CPointer<UByteVar>?) -> T,
    ): T {
        // An empty array has no element to pin; the bridge takes a null pointer with count 0.
        if (this == null || isEmpty()) return block(null)
        return usePinned { pinned -> block(pinned.addressOf(0).reinterpret()) }
    }
}
