package eu.anifantakis.lib.ksafe.internal

import org.khronos.webgl.Uint8Array
import org.khronos.webgl.get

/**
 * Kotlin/JS actual implementation of [secureRandomBytes].
 *
 * Uses WebCrypto's `crypto.getRandomValues()` via a direct `external` binding.
 * Unlike wasmJs, we can return a `ByteArray` directly because Kotlin/JS can
 * iterate a `Uint8Array` without the Base64 round-trip used on wasmJs.
 */
private external object crypto {
    fun getRandomValues(array: Uint8Array): Uint8Array
}

actual fun secureRandomBytes(size: Int): ByteArray {
    require(size > 0) { "size must be positive" }
    val arr = Uint8Array(size)
    crypto.getRandomValues(arr)
    return ByteArray(size) { arr[it] }
}
