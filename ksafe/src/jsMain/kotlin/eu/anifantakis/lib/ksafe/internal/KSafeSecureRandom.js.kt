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
    // WebCrypto's getRandomValues rejects a view longer than 65536 bytes
    // (QuotaExceededError), so fill in chunks — otherwise getOrCreateSecret(size > 64KB)
    // would throw (FEEDBACK_4 low: JS/Wasm getOrCreateSecret > 65536).
    val out = ByteArray(size)
    var offset = 0
    while (offset < size) {
        val chunk = minOf(MAX_RANDOM_BYTES_PER_CALL, size - offset)
        val arr = Uint8Array(chunk)
        crypto.getRandomValues(arr)
        for (i in 0 until chunk) out[offset + i] = arr[i]
        offset += chunk
    }
    return out
}

private const val MAX_RANDOM_BYTES_PER_CALL = 65536
