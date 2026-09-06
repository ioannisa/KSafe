package eu.anifantakis.lib.ksafe

/**
 * Returns `true` if [needle], UTF-8-encoded, appears as a contiguous subsequence of this [ByteArray].
 * Encryption-proof tests scan raw storage bytes for plaintext leaks with it, because
 * `String(ByteArray, Charset)` is not uniform across Native and WASM.
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
