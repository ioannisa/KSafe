package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.currentTimeMillisWeb
import eu.anifantakis.lib.ksafe.internal.localStorageGet
import eu.anifantakis.lib.ksafe.internal.localStorageKey
import eu.anifantakis.lib.ksafe.internal.localStorageLength
import eu.anifantakis.lib.ksafe.internal.localStorageRemove
import eu.anifantakis.lib.ksafe.internal.localStorageSet
import eu.anifantakis.lib.ksafe.internal.secureRandomBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Verifies the web-interop `actual` bindings work in both the wasmJs and
 * js targets. These tests live in `webTest` so both targets run the same
 * assertions — any behavioural divergence between the two actual sets
 * (e.g. a Long-conversion bug on js, a `@JsFun` regression on wasmJs)
 * will surface here first.
 */
class WebInteropSmokeTest {

    @Test
    fun localStorageRoundtrip() {
        val key = "__ksafe_interop_test_key"
        try {
            localStorageRemove(key)
            assertNull(localStorageGet(key), "stale value left behind from a previous run")

            localStorageSet(key, "value-1")
            assertEquals("value-1", localStorageGet(key))

            localStorageSet(key, "value-2")
            assertEquals("value-2", localStorageGet(key))

            localStorageRemove(key)
            assertNull(localStorageGet(key))
        } finally {
            localStorageRemove(key)
        }
    }

    @Test
    fun localStorageLengthAndKeyEnumeration() {
        val prefix = "__ksafe_enum_test_"
        val keys = listOf("${prefix}a", "${prefix}b", "${prefix}c")
        try {
            keys.forEach { localStorageSet(it, "v") }

            val total = localStorageLength()
            assertTrue(total >= keys.size, "length must include the keys we just wrote")

            val seen = mutableSetOf<String>()
            for (i in 0 until total) {
                localStorageKey(i)?.let { if (it.startsWith(prefix)) seen += it }
            }
            assertEquals(keys.toSet(), seen)
        } finally {
            keys.forEach { localStorageRemove(it) }
        }
    }

    @Test
    fun currentTimeMillisIsPlausible() {
        val now = currentTimeMillisWeb()
        // 2020-01-01 in ms — a sanity floor that guards against e.g. a 0 return
        // from a broken Long conversion on either target.
        assertTrue(now > 1_577_836_800_000L, "expected a recent epoch ms, got $now")
    }

    @Test
    fun secureRandomBytesReturnsRequestedSizeAndIsNotAllZero() {
        val bytes = secureRandomBytes(32)
        assertEquals(32, bytes.size)
        assertTrue(bytes.any { it != 0.toByte() }, "all-zero result is effectively impossible")
    }

    @Test
    fun secureRandomBytesRejectsNonPositiveSize() {
        val threw = try {
            secureRandomBytes(0)
            false
        } catch (_: IllegalArgumentException) {
            true
        }
        assertTrue(threw, "secureRandomBytes(0) should throw IllegalArgumentException")
    }
}
