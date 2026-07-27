package eu.anifantakis.lib.ksafe.internal

/**
 * Web (wasmJs + js) actual for [secureRandomBytes], reading from WebCrypto's `getRandomValues`.
 *
 * The chunking is the shared part: `getRandomValues` rejects a view longer than
 * [MAX_RANDOM_BYTES_PER_CALL] bytes (QuotaExceededError), so a larger request is filled one chunk
 * at a time. Only moving one chunk across the interop boundary is target-specific.
 */
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

/** Fills `out[offset until offset + length]` from WebCrypto; [length] is never above [MAX_RANDOM_BYTES_PER_CALL]. */
internal expect fun fillSecureRandomChunk(out: ByteArray, offset: Int, length: Int)

private const val MAX_RANDOM_BYTES_PER_CALL = 65536
