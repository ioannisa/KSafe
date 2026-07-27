package eu.anifantakis.lib.ksafe.internal

private const val HEX_DIGITS = "0123456789abcdef"

/**
 * Lowercase hex, two digits per byte — an injective, `[0-9a-f]`-only encoding, so it is safe
 * inside identifiers that must not collide and must survive stores with a restricted alphabet.
 */
internal fun ByteArray.toLowercaseHex(): String {
    val sb = StringBuilder(size * 2)
    for (b in this) {
        val v = b.toInt() and 0xff
        sb.append(HEX_DIGITS[v ushr 4])
        sb.append(HEX_DIGITS[v and 0x0f])
    }
    return sb.toString()
}
