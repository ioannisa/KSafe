package eu.anifantakis.lib.ksafe

/**
 * Returns `true` if [needle], encoded as UTF-8, appears anywhere as a
 * contiguous subsequence of this [ByteArray].
 *
 * Used by the encryption-proof tests on every target to scan raw storage
 * bytes (DataStore protobuf file on Android/iOS/JVM, `localStorage` values
 * on wasmJs/js) for plaintext leaks without going through a platform-specific
 * `String(ByteArray, Charset)` overload — which doesn't exist uniformly
 * across Kotlin/Native and Kotlin/WASM.
 */
internal fun ByteArray.containsUtf8(needle: String): Boolean {
    val needleBytes = needle.encodeToByteArray()
    if (needleBytes.isEmpty()) return true
    if (needleBytes.size > this.size) return false
    outer@ for (i in 0..(this.size - needleBytes.size)) {
        for (j in needleBytes.indices) {
            if (this[i + j] != needleBytes[j]) continue@outer
        }
        return true
    }
    return false
}
