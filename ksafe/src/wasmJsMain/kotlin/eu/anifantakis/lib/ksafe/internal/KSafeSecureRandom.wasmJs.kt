@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeBase64

// Base64 because Kotlin/Wasm cannot return a ByteArray from a JS external function.
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
