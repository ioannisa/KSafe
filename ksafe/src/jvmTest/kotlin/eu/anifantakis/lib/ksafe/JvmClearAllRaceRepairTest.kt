package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Regression tests for review R2: a put ordered AFTER an in-flight clearAll
 * (the canonical logout-then-write-fresh-state pattern) commits correctly to
 * disk — but its optimistic in-memory state, set at call time, was wiped by
 * `performClearAll` and nothing restored it: the post-commit ciphertext CAS
 * found the expected plaintext gone, dirty flags are permanent so the
 * reconciler skipped the key forever, and the acknowledged write read back as
 * the caller's default for the rest of the session.
 *
 * The fix is the owner-gated post-commit repair: an op that is still its key's
 * latest writer re-asserts its cache/metadata state via atomic putIfAbsent.
 *
 * The race is driven deterministically: `performClearAll` deletes per-entry
 * engine keys BEFORE wiping the caches, so an engine `deleteKey` hook fires the
 * racing put exactly in the window the finding describes.
 */
class JvmClearAllRaceRepairTest {

    /** XOR engine whose `deleteKey` runs [onDeleteKey] once — the racing put. */
    private class HookedXorEncryption : KSafeEncryption {
        private val xor = FakeEncryption()
        @Volatile var onDeleteKey: (() -> Unit)? = null
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray =
            xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)
        override fun decrypt(identifier: String, data: ByteArray): ByteArray =
            xor.decrypt(identifier, data)
        override fun deleteKey(identifier: String) {
            onDeleteKey?.also { onDeleteKey = null }?.invoke()
        }
    }

    private fun runScenario(policy: KSafeMemoryPolicy, mode: KSafeWriteMode) = runTest {
        val engine = HookedXorEncryption()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = policy,
            testEngine = engine,
        )

        // Seed one encrypted entry so performClearAll has a per-entry engine
        // key to delete — the pre-wipe step our racing put hooks into.
        ksafe.put("seed", "seed-value", KSafeWriteMode.Encrypted())

        // The racing put: issued while performClearAll is running, BEFORE the
        // cache wipe — its optimistic state is set and then wiped, and the op
        // itself is ordered after the ClearAll (it must survive).
        engine.onDeleteKey = {
            ksafe.putDirect("fresh", "fresh-value", mode)
        }

        ksafe.clearAll()

        // Drain the racing put's batch: the channel is FIFO with a single
        // consumer, so by the time this awaited write returns, "fresh" has
        // committed (and run its post-commit repair).
        ksafe.put("sync", "x", KSafeWriteMode.Plain)

        assertEquals(
            "fresh-value", ksafe.getDirect("fresh", "def"),
            "a put ordered after an in-flight clearAll must be readable once committed " +
                "(review R2; policy=$policy, mode=$mode)",
        )

        ksafe.close()
    }

    @Test
    fun encryptedPut_racingClearAll_isReadableAfterCommit_underEncryptedPolicy() =
        runScenario(KSafeMemoryPolicy.ENCRYPTED, KSafeWriteMode.Encrypted())

    @Test
    fun encryptedPut_racingClearAll_isReadableAfterCommit_underPlainTextPolicy() =
        runScenario(KSafeMemoryPolicy.PLAIN_TEXT, KSafeWriteMode.Encrypted())

    @Test
    fun encryptedPut_racingClearAll_isReadableAfterCommit_underLazySideCachePolicy() =
        runScenario(KSafeMemoryPolicy.LAZY_PLAIN_TEXT, KSafeWriteMode.Encrypted())

    @Test
    fun plainPut_racingClearAll_isReadableAfterCommit() =
        runScenario(KSafeMemoryPolicy.ENCRYPTED, KSafeWriteMode.Plain)
}
