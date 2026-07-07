package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.localStorageGet
import eu.anifantakis.lib.ksafe.internal.localStorageKey
import eu.anifantakis.lib.ksafe.internal.localStorageLength
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Locks in: on both web targets an encrypted write leaks no plaintext into `localStorage`, while a [KSafeWriteMode.Plain] write stores it verbatim (the counter-test that keeps the negative assertion meaningful). */
class WebEncryptionProofTest {

    @Test
    fun encryptedWriteDoesNotLeakPlaintextToLocalStorage() = runTest {
        val fileName = WebKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName, testEngine = FakeEncryption())
        ksafe.awaitCacheReady()

        ksafe.put(KEY, SENTINEL) // encrypted
        // Currently a synchronous write; the delay guards against a future async move.
        delay(100)

        assertEquals(SENTINEL, ksafe.get(KEY, "DEFAULT"), "encryption must round-trip")

        val prefix = "ksafe.${fileName}:"
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
            // webTest does not reset localStorage automatically; clean up manually.
            ksafe.clearAll()
        }

        assertTrue(
            scannedEntries > 0,
            "no entries under prefix '$prefix' were written — the test didn't actually persist"
        )
        assertTrue(
            valueKeyPresent,
            "expected an encrypted value entry 'ksafe.${fileName}:__ksafe_value_$KEY' in localStorage"
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

            val fullKey = "ksafe.${fileName}:__ksafe_value_${KEY}"
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
        // Guards the encrypted-write proof against a vacuous pass if containsUtf8 or encodeToByteArray regressed on a target.
        val bytes = "prefix-$SENTINEL-suffix".encodeToByteArray()
        assertTrue(bytes.containsUtf8(SENTINEL))
        assertFalse(bytes.containsUtf8("NOT_PRESENT_MARKER_123"))
    }

    companion object {
        private const val SENTINEL = "KSAFE_PLAINTEXT_PROOF_SENTINEL_XYZABC_1234567890"
        private const val KEY = "proof_token"
    }
}
