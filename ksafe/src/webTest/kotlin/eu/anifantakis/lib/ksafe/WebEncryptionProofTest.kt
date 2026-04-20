package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Proof-test for encryption on both web targets (Kotlin/WASM + Kotlin/JS).
 *
 * Lives in `webTest`, so the same test class is discovered and executed by
 * both `wasmJsBrowserTest` and `jsBrowserTest`. It exercises KSafe's write
 * plumbing with [FakeEncryption] (consistent with [WebKSafeTest] — the real
 * WebCrypto path is async and best exercised by real-app integration), then
 * walks the browser's `localStorage` directly and asserts:
 *
 *  1. For an encrypted write, no `localStorage` value belonging to this
 *     KSafe instance contains the plaintext sentinel.
 *  2. Round-trip through KSafe still returns the original plaintext.
 *  3. Baseline counter-test: a [KSafeWriteMode.Plain] write stores the
 *     plaintext verbatim under `ksafe_<fileName>___ksafe_value_<key>`,
 *     proving the negative assertion above is meaningful.
 */
class WebEncryptionProofTest {

    @Test
    fun encryptedWriteDoesNotLeakPlaintextToLocalStorage() = runTest {
        val fileName = WebKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName, testEngine = FakeEncryption())
        ksafe.awaitCacheReady()

        ksafe.put(KEY, SENTINEL) // encrypted
        // putEncryptedRaw writes to localStorage synchronously, but yield
        // once in case a future implementation moves it to the background.
        delay(100)

        assertEquals(SENTINEL, ksafe.get(KEY, "DEFAULT"), "encryption must round-trip")

        val prefix = "ksafe_${fileName}_"
        var valueKeyPresent = false
        var scannedEntries = 0
        val offending = mutableListOf<String>()
        try {
            for (i in 0 until localStorageLength()) {
                val k = localStorageKey(i) ?: continue
                if (!k.startsWith(prefix)) continue
                scannedEntries++
                val v = localStorageGet(k) ?: continue
                if (k == "${prefix}__ksafe_value_${KEY}") valueKeyPresent = true
                if (v.contains(SENTINEL)) offending.add("$k = $v")
            }
        } finally {
            // Leave localStorage clean between tests — webTest does NOT
            // reset it automatically.
            ksafe.clearAll()
        }

        assertTrue(
            scannedEntries > 0,
            "no entries under prefix '$prefix' were written — the test didn't actually persist"
        )
        assertTrue(
            valueKeyPresent,
            "expected an encrypted value entry 'ksafe_${fileName}___ksafe_value_$KEY' in localStorage"
        )
        assertTrue(
            offending.isEmpty(),
            "plaintext '$SENTINEL' leaked into localStorage: $offending"
        )
    }

    @Test
    fun plainModeWriteDoesLeakPlaintextToLocalStorage() = runTest {
        val fileName = WebKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName, testEngine = FakeEncryption())
        ksafe.awaitCacheReady()

        try {
            ksafe.put(KEY, SENTINEL, KSafeWriteMode.Plain)
            delay(100)

            assertEquals(SENTINEL, ksafe.get(KEY, "DEFAULT"))

            val fullKey = "ksafe_${fileName}___ksafe_value_${KEY}"
            val stored = localStorageGet(fullKey)
            assertNotNull(stored, "expected a plain value entry '$fullKey' in localStorage")
            assertEquals(
                SENTINEL, stored,
                "KSafeWriteMode.Plain is expected to store the sentinel verbatim"
            )
        } finally {
            ksafe.clearAll()
        }
    }

    @Test
    fun negativeAssertionIsNotVacuous() = runTest {
        // Defensive: assert that `containsUtf8` actually finds a sentinel it
        // is given. If `encodeToByteArray()` ever regressed on a specific
        // target, the encrypted-write proof would be silently vacuous.
        val bytes = "prefix-$SENTINEL-suffix".encodeToByteArray()
        assertTrue(bytes.containsUtf8(SENTINEL))
        assertFalse(bytes.containsUtf8("NOT_PRESENT_MARKER_123"))
    }

    companion object {
        private const val SENTINEL = "KSAFE_PLAINTEXT_PROOF_SENTINEL_XYZABC_1234567890"
        private const val KEY = "proof_token"
    }
}
