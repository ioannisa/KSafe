@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeBase64

/**
 * Generates [size] random bytes via WebCrypto and returns them as a Base64 string. We round-trip
 * through Base64 because Kotlin/WASM cannot return a ByteArray directly from a JS external function.
 */
@JsFun(
    """(size) => {
    const arr = new Uint8Array(size);
    crypto.getRandomValues(arr);
    let binary = '';
    for (let i = 0; i < arr.length; i++) {
        binary += String.fromCharCode(arr[i]);
    }
    return btoa(binary);
}"""
)
private external fun _cryptoRandomBase64(size: Int): String

internal actual fun fillSecureRandomChunk(out: ByteArray, offset: Int, length: Int) {
    KSafeBase64.decode(_cryptoRandomBase64(length)).copyInto(out, offset)
}
