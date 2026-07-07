package eu.anifantakis.lib.ksafe.internal

import org.khronos.webgl.Uint8Array
import org.khronos.webgl.get

/** WebCrypto `crypto.getRandomValues()` binding for the Kotlin/JS [secureRandomBytes] actual. */
private external object crypto {
    fun getRandomValues(array: Uint8Array): Uint8Array
}

actual fun secureRandomBytes(size: Int): ByteArray {
    require(size > 0) { "size must be positive" }
    // getRandomValues rejects views longer than 65536 bytes (QuotaExceededError),
    // so fill in 64KB chunks.
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
