package eu.anifantakis.lib.ksafe

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * The Base64 alphabet KSafe persists ciphertext and key material under, on every target. Named
 * apart from the `encodeBase64`/`decodeBase64` that `KSafe.jvm.kt` publishes: one common
 * declaration cannot be public for the JVM and internal for everyone else.
 */
internal object KSafeBase64 {
    @OptIn(ExperimentalEncodingApi::class)
    fun encode(bytes: ByteArray): String = Base64.encode(bytes)

    @OptIn(ExperimentalEncodingApi::class)
    fun decode(encoded: String): ByteArray = Base64.decode(encoded)
}
