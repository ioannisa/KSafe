// The facade class name is public JVM ABI, so it stays `KSafeSecureRandom_jvmKt` whatever this
// file is called.
@file:JvmName("KSafeSecureRandom_jvmKt")

package eu.anifantakis.lib.ksafe.internal

import java.security.SecureRandom

actual fun secureRandomBytes(size: Int): ByteArray {
    require(size > 0) { "size must be positive" }
    return ByteArray(size).also { SecureRandom().nextBytes(it) }
}
