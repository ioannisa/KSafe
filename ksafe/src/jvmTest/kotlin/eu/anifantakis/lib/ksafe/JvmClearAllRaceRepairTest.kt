package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * A put ordered AFTER an in-flight clearAll (the canonical
 * logout-then-write-fresh-state pattern) must be readable once committed: the
 * wipe clears the write's optimistic in-memory state, so the owner-gated
 * post-commit repair must restore it — an op that is still its key's latest
 * writer re-asserts its cache/metadata state via atomic putIfAbsent.
 *
 * The race is driven deterministically: `performClearAll` deletes per-entry
 * engine keys BEFORE wiping the caches, so an engine `deleteKey` hook fires
 * the racing put exactly in that window.
 */
class JvmClearAllRaceRepairTest {

    /** XOR engine whose `deleteKey` runs [onDeleteKey] once — the racing put. */
    private class HookedXorEncryption : KSafeEncryption {
        private val xor = FakeEncryption()
        @Volatile var onDeleteKey: (() -> Unit)? = null
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray =
            xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray =
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
                "(policy=$policy, mode=$mode)",
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
