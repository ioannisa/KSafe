package eu.anifantakis.lib.ksafe

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * The Base64 alphabet KSafe persists ciphertext, secrets and key material under, on every
 * target: `kotlin.io.encoding.Base64` is common stdlib, so the per-platform wrappers this
 * replaces only ever differed by name.
 *
 * Kept internal and named apart from the top-level `encodeBase64`/`decodeBase64` that
 * `KSafe.jvm.kt` publishes: those are in the JVM ABI consumers already compiled against, and a
 * single common declaration cannot be public for the JVM and internal for everyone else.
 */
internal object KSafeBase64 {
    @OptIn(ExperimentalEncodingApi::class)
    fun encode(bytes: ByteArray): String = Base64.encode(bytes)

    @OptIn(ExperimentalEncodingApi::class)
    fun decode(encoded: String): ByteArray = Base64.decode(encoded)
}
