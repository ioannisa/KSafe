package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.secureRandomBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Locks in: `secureRandomBytes` fills in ≤64KB chunks, since WebCrypto's `getRandomValues` rejects a view longer than 65536 bytes. */
class WebSecureRandomChunkTest {

    @Test
    fun secureRandomBytes_largerThanWebCryptoQuota_isFilledInChunks() {
        val size = 70_000 // > 65536, spans two chunks
        val bytes = secureRandomBytes(size)

        assertEquals(size, bytes.size, "must return the requested number of bytes without throwing")
        // Bytes past the first 64KB chunk must be filled, proving the second chunk ran.
        val tail = bytes.copyOfRange(65_536, size)
        assertTrue(tail.any { it != 0.toByte() }, "the chunk past the 64KB boundary must be randomized")
        assertTrue(bytes.copyOfRange(0, 65_536).any { it != 0.toByte() }, "the first chunk must be randomized")
    }
}
