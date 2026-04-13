package eu.anifantakis.lib.ksafe

import java.security.SecureRandom

actual fun secureRandomBytes(size: Int): ByteArray {
    require(size > 0) { "size must be positive" }
    return ByteArray(size).also { SecureRandom().nextBytes(it) }
}
