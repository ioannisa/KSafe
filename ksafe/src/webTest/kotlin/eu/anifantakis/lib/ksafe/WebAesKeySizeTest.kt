package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.WebSoftwareEncryption
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals

/** Reads the persisted non-extractable CryptoKey's public algorithm metadata. */
internal expect suspend fun storedWebAesKeySizeBits(idbName: String): Int?

/**
 * Proves that [KSafeConfig.aesKeySize] reaches the real WebCrypto generateKey call on both
 * Kotlin/JS and Kotlin/Wasm, rather than merely round-tripping under a hard-coded key size.
 */
class WebAesKeySizeTest {

    @Test
    fun configuredKeySize_isUsedWhenWebCryptoMintsTheKey() = runTest {
        for (size in KSafeAesKeySize.entries) {
            val prefix = "ksafe_key_size_${Random.nextLong().toString().trimStart('-')}_"
            val alias = "master"
            val engine = WebSoftwareEncryption(
                config = KSafeConfig(aesKeySize = size),
                storagePrefix = prefix,
            )

            engine.encryptSuspend(alias, "key-size-proof".encodeToByteArray())

            assertEquals(
                size.bits,
                storedWebAesKeySizeBits("${prefix}ksafe_key_$alias"),
                "WebCrypto must mint the configured AES key size",
            )
            engine.deleteKeySuspend(alias)
        }
    }
}
