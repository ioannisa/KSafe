package eu.anifantakis.lib.ksafe.internal

// getRandomValues rejects a view longer than MAX_RANDOM_BYTES_PER_CALL, so a larger request is
// filled one chunk at a time. Only the per-chunk interop call is target-specific.
actual fun secureRandomBytes(size: Int): ByteArray {
    require(size > 0) { "size must be positive" }
    val out = ByteArray(size)
    var offset = 0
    while (offset < size) {
        val chunk = minOf(MAX_RANDOM_BYTES_PER_CALL, size - offset)
        fillSecureRandomChunk(out, offset, chunk)
        offset += chunk
    }
    return out
}

internal expect fun fillSecureRandomChunk(out: ByteArray, offset: Int, length: Int)

private const val MAX_RANDOM_BYTES_PER_CALL = 65536
