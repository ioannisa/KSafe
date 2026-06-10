package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Regression tests for the write-coalescer's failure handling.
 *
 * Deep-review findings:
 *  - #4: one failing encrypt inside a coalesced batch must NOT drop the other
 *    (unrelated) writes that merely shared the 16 ms window.
 *  - #3: a write that fails to persist must NOT leave its optimistic value
 *    permanently served from the cache — the optimistic state is rolled back so
 *    reads fall back to the prior persisted value (or the default).
 *
 * Uses [KSafeMemoryPolicy.ENCRYPTED] so every read goes through the engine
 * (cache holds ciphertext, no plaintext side-cache), making the rollback
 * observable deterministically within one instance.
 */
class JvmBatchFailureIsolationTest {

    /**
     * Encrypts like the XOR [FakeEncryption], but `encrypt` throws — as if the
     * Keystore were unavailable (device locked) — whenever the *plaintext*
     * contains [failMarker]. Keying the failure off the payload (not the alias)
     * lets a single DEFAULT-protection key fail while other DEFAULT keys, which
     * share the master alias, still succeed.
     */
    private class MarkerFailEncryption(private val failMarker: String) : KSafeEncryption {
        private val xor = FakeEncryption()
        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
        ): ByteArray {
            if (data.decodeToString().contains(failMarker)) {
                throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked. (test)")
            }
            return xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)
        }

        override fun decrypt(identifier: String, data: ByteArray): ByteArray =
            xor.decrypt(identifier, data)

        override fun deleteKey(identifier: String) { /* no-op */ }
    }

    @Test
    fun failedEncryptedWrite_isRolledBack_readReturnsDefaultNotPhantom() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = MarkerFailEncryption("BAD"),
        )

        val ex = assertFailsWith<IllegalStateException> {
            ksafe.put("token", "BAD_secret", KSafeWriteMode.Encrypted())
        }
        assertTrue(
            ex.message?.contains("device is locked", ignoreCase = true) == true,
            "the awaiting caller must receive the encrypt failure; was: ${ex.message}",
        )

        // Deep-review #3: the never-persisted optimistic value must NOT be served.
        assertEquals(
            "none", ksafe.get("token", "none"),
            "a failed write must be rolled back — reads fall back to the default",
        )

        ksafe.close()
    }

    @Test
    fun failedWrite_doesNotClobberPriorPersistedValue() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = MarkerFailEncryption("BAD"),
        )

        // A good value lands first.
        ksafe.put("token", "good_secret", KSafeWriteMode.Encrypted())
        assertEquals("good_secret", ksafe.get("token", "none"))

        // A later overwrite whose encrypt fails must roll back to the prior value.
        assertFailsWith<IllegalStateException> {
            ksafe.put("token", "BAD_secret", KSafeWriteMode.Encrypted())
        }
        assertEquals(
            "good_secret", ksafe.get("token", "none"),
            "a failed overwrite must restore the previously persisted value, not the default or the phantom",
        )

        ksafe.close()
    }

    @Test
    fun failedOverwrite_underLazyPlainTextSideCache_restoresPriorValue() = runTest {
        // The side-cache policies (LAZY_PLAIN_TEXT here, permanent / no expiry)
        // keep an optimistic plaintext copy in the secondary plaintextCache,
        // which updateCache does not manage. On an OVERWRITE the prior value's
        // protection metadata survives, so reads take the encrypted path and
        // consult plaintextCache FIRST — the rollback must evict the failed
        // key's side-cache entry, otherwise the phantom is served for the whole
        // session (LAZY never expires). (deep-review #3)
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
            testEngine = MarkerFailEncryption("BAD"),
        )

        ksafe.put("token", "good_secret", KSafeWriteMode.Encrypted())
        assertEquals("good_secret", ksafe.get("token", "none"))

        assertFailsWith<IllegalStateException> {
            ksafe.put("token", "BAD_secret", KSafeWriteMode.Encrypted())
        }
        assertEquals(
            "good_secret", ksafe.get("token", "none"),
            "rollback must evict the optimistic plaintext side-cache entry; the prior value must survive",
        )
        // getDirect goes through the same side cache synchronously — also clean.
        assertEquals("good_secret", ksafe.getDirect("token", "none"))

        ksafe.close()
    }

    @Test
    fun failedOverwrite_underTimedCache_restoresPriorValue_notPhantom() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE,
            testEngine = MarkerFailEncryption("BAD"),
        )

        ksafe.put("token", "good_secret", KSafeWriteMode.Encrypted())
        assertEquals("good_secret", ksafe.get("token", "none"))

        assertFailsWith<IllegalStateException> {
            ksafe.put("token", "BAD_secret", KSafeWriteMode.Encrypted())
        }
        assertEquals(
            "good_secret", ksafe.get("token", "none"),
            "failed overwrite must restore the prior value in the side cache, not the phantom",
        )

        ksafe.close()
    }

    @Test
    fun oneFailingEncrypt_doesNotDropUnrelatedKeysInTheSameBatch() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = MarkerFailEncryption("BAD"),
        )

        // Issue the writes concurrently so the coalescer merges them into one
        // applyBatch transaction: the bad encrypted key, an unrelated good
        // encrypted key (shares the master alias), and a plain key.
        coroutineScope {
            launch {
                runCatching { ksafe.put("bad", "BAD_value", KSafeWriteMode.Encrypted()) }
            }
            launch { ksafe.put("goodEnc", "good_enc_value", KSafeWriteMode.Encrypted()) }
            launch { ksafe.put("goodPlain", "good_plain_value", KSafeWriteMode.Plain) }
        }

        // Deep-review #4: the unrelated writes must survive the sibling's failure.
        assertEquals("good_enc_value", ksafe.get("goodEnc", "missing"))
        assertEquals("good_plain_value", ksafe.get("goodPlain", "missing"))
        // …and the failed key is rolled back (deep-review #3).
        assertEquals("missing", ksafe.get("bad", "missing"))

        ksafe.close()
    }
}
