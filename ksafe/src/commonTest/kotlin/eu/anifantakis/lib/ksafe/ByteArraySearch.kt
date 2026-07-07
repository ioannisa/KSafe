package eu.anifantakis.lib.ksafe

/**
 * Returns `true` if [needle], UTF-8-encoded, appears as a contiguous subsequence of this
 * [ByteArray]. Used by encryption-proof tests to scan raw storage bytes for plaintext leaks
 * without a `String(ByteArray, Charset)` overload, which isn't uniform across Native and WASM.
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
