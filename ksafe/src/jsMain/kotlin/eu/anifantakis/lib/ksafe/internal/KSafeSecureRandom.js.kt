package eu.anifantakis.lib.ksafe.internal

import org.khronos.webgl.Uint8Array
import org.khronos.webgl.get

/** WebCrypto `crypto.getRandomValues()` binding for the Kotlin/JS [fillSecureRandomChunk] actual. */
private external object crypto {
    fun getRandomValues(array: Uint8Array): Uint8Array
}

internal actual fun fillSecureRandomChunk(out: ByteArray, offset: Int, length: Int) {
    val arr = Uint8Array(length)
    crypto.getRandomValues(arr)
    for (i in 0 until length) out[offset + i] = arr[i]
}
