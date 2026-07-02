package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.secureRandomBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * FEEDBACK_4 low (JS/Wasm): WebCrypto's `getRandomValues` rejects a view longer than
 * 65536 bytes (QuotaExceededError), so `secureRandomBytes(size > 65536)` — reached via
 * `getOrCreateSecret(size = …)` for a large secret — used to throw. The web actuals now
 * fill in ≤64KB chunks.
 */
class WebSecureRandomChunkTest {

    @Test
    fun secureRandomBytes_largerThanWebCryptoQuota_isFilledInChunks() {
        val size = 70_000 // > 65536, spans two chunks
        val bytes = secureRandomBytes(size)

        assertEquals(size, bytes.size, "must return the requested number of bytes without throwing")
        // The bytes beyond the first 64KB chunk must actually be filled (not left zero),
        // proving the second chunk was populated.
        val tail = bytes.copyOfRange(65_536, size)
        assertTrue(tail.any { it != 0.toByte() }, "the chunk past the 64KB boundary must be randomized")
        // And the first chunk too.
        assertTrue(bytes.copyOfRange(0, 65_536).any { it != 0.toByte() }, "the first chunk must be randomized")
    }
}
