package eu.anifantakis.lib.ksafe

import kotlin.random.Random

actual fun secureRandomBytes(size: Int): ByteArray {
    require(size > 0) { "size must be positive" }
    return Random.nextBytes(size)
}
