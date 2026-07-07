package eu.anifantakis.lib.ksafe.internal

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.Security.SecRandomCopyBytes
import platform.Security.kSecRandomDefault

/**
 * Apple (iOS + macOS) actual for [secureRandomBytes], reading from `SecRandomCopyBytes` —
 * the Security-framework CSPRNG that also backs `SecKey*` key generation and CryptoKit.
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
