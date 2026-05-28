package eu.anifantakis.lib.ksafe.internal

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.Security.SecRandomCopyBytes
import platform.Security.kSecRandomDefault

/**
 * Apple (iOS + macOS) actual for [secureRandomBytes].
 *
 * Uses `SecRandomCopyBytes` from the Security framework — Apple's
 * cryptographically secure RNG. The pre-2.1.1 implementation called
 * `kotlin.random.Random.nextBytes(size)`, which is **not** a CSPRNG;
 * because this function generates the AES-256 master keys on
 * iOS/macOS (`AppleKeychainEncryption.getOrCreateKeychainKeySE` /
 * `getOrCreateKeychainKeyPlain`), the predictable-PRNG output
 * critically weakened encryption on those platforms. This actual
 * restores the contract promised by the common-main KDoc.
 */
@OptIn(ExperimentalForeignApi::class)
actual fun secureRandomBytes(size: Int): ByteArray {
    require(size > 0) { "size must be positive" }
    val buffer = ByteArray(size)
    val status = buffer.usePinned { pinned ->
        SecRandomCopyBytes(kSecRandomDefault, size.toULong(), pinned.addressOf(0))
    }
    check(status == 0) {
        "SecRandomCopyBytes failed with OSStatus=$status — Security framework CSPRNG unavailable"
    }
    return buffer
}
