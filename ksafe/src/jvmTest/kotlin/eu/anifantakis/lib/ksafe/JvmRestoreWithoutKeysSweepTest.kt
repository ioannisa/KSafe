package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Locks in: a store that comes back without its keys (a backup restored onto a new device, a lost
 * key file) has its encrypted entries reclaimed by the startup sweep on every tier. A master key
 * minted before the sweep turns "key missing" into a GCM failure that the sweep keeps forever.
 */
class JvmRestoreWithoutKeysSweepTest {

    private val tmp = File(
        System.getProperty("java.io.tmpdir"),
        "ksafe_restore_sweep_${System.nanoTime()}",
    ).apply { mkdirs() }

    @AfterTest
    fun tearDown() {
        tmp.deleteRecursively()
    }

    private val modes = linkedMapOf(
        "default" to KSafeWriteMode.Encrypted(),
        "strict" to KSafeWriteMode.Encrypted(requireUnlockedDevice = true),
        "isolated" to KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED),
    )

    private class Variant(val policy: KSafeMemoryPolicy, val lazyLoad: Boolean) {
        override fun toString() = "$policy, lazyLoad=$lazyLoad"
    }

    private val variants = KSafeMemoryPolicy.entries.flatMap { policy ->
        listOf(Variant(policy, lazyLoad = false), Variant(policy, lazyLoad = true))
    }

    private fun open(fileName: String, engine: KSafeEncryption, variant: Variant): KSafe = KSafe(
        fileName = fileName,
        lazyLoad = variant.lazyLoad,
        memoryPolicy = variant.policy,
        baseDir = tmp,
        testEngine = engine,
    )

    private suspend fun writeEveryTier(fileName: String, engine: KSafeEncryption, variant: Variant) {
        val first = open(fileName, engine, variant)
        modes.forEach { (key, mode) -> first.put(key, "v_$key", mode) }
        modes.keys.forEach { assertEquals("v_$it", first.get(it, ""), "premise: '$it' round-trips ($variant)") }
        first.close()
    }

    /** Lazy load runs the startup cleanup on first access, so touch the store before waiting. */
    private suspend fun awaitSweep(ksafe: KSafe, variant: Variant) {
        ksafe.getDirect("__touch__", "")
        val done = withTimeoutOrNull(20_000) {
            while (!ksafe.core.startupSweepFinished.get()) delay(10)
            true
        }
        assertTrue(done == true, "premise: the startup sweep must finish ($variant)")
        assertNull(ksafe.core.startupSweepFailure, "premise: the startup sweep must not fail ($variant)")
    }

    @Test
    fun restoreWithoutKeys_sweepReclaimsEveryTier() = runBlocking {
        for (variant in variants) {
            val fileName = JvmKSafeTest.generateUniqueFileName()
            writeEveryTier(fileName, StatefulFakeEncryption(), variant)

            val restored = open(fileName, StatefulFakeEncryption(firstKeyId = 1_000), variant)
            try {
                modes.keys.forEach {
                    assertEquals("", restored.get(it, ""), "'$it' has no key, so it reads as the default ($variant)")
                }
                awaitSweep(restored, variant)
                modes.keys.forEach {
                    assertNull(
                        restored.getKeyInfo(it),
                        "'$it' lost its key and must be reclaimed by the startup sweep, not kept forever ($variant)",
                    )
                }
            } finally {
                restored.close()
            }
        }
    }

    @Test
    fun restoreWithoutKeys_freshWriteWorksAndSurvivesARestart() = runBlocking {
        val variant = Variant(KSafeMemoryPolicy.ENCRYPTED, lazyLoad = false)
        val fileName = JvmKSafeTest.generateUniqueFileName()
        writeEveryTier(fileName, StatefulFakeEncryption(), variant)

        val newDevice = StatefulFakeEncryption(firstKeyId = 1_000)
        val restored = open(fileName, newDevice, variant)
        awaitSweep(restored, variant)
        modes.forEach { (key, mode) -> restored.put(key, "new_$key", mode) }
        modes.keys.forEach { assertEquals("new_$it", restored.get(it, ""), "a fresh write after the sweep must read back") }
        restored.close()

        val relaunched = open(fileName, newDevice, variant)
        try {
            awaitSweep(relaunched, variant)
            modes.keys.forEach {
                assertEquals("new_$it", relaunched.get(it, ""), "a fresh write must survive a restart")
                assertNotNull(relaunched.getKeyInfo(it), "the sweep must not reclaim a readable entry")
            }
        } finally {
            relaunched.close()
        }
    }

    @Test
    fun relaunchWithKeys_sweepKeepsEveryTier() = runBlocking {
        for (variant in variants) {
            val fileName = JvmKSafeTest.generateUniqueFileName()
            val sameDevice = StatefulFakeEncryption()
            writeEveryTier(fileName, sameDevice, variant)

            val relaunched = open(fileName, sameDevice, variant)
            try {
                awaitSweep(relaunched, variant)
                modes.keys.forEach {
                    assertEquals("v_$it", relaunched.get(it, ""), "'$it' still has its key and must read back ($variant)")
                    assertNotNull(relaunched.getKeyInfo(it), "the sweep must not reclaim '$it' ($variant)")
                }
            } finally {
                relaunched.close()
            }
        }
    }

    @Test
    fun freshStore_masterKeyIsStillMintedInTheBackground() = runBlocking {
        val variant = Variant(KSafeMemoryPolicy.ENCRYPTED, lazyLoad = false)
        val engine = StatefulFakeEncryption()
        val ksafe = open(JvmKSafeTest.generateUniqueFileName(), engine, variant)
        try {
            // Without it the first put pays key creation on the caller's thread.
            withTimeout(20_000) { while (engine.liveAliases().isEmpty()) delay(10) }
            assertTrue(engine.liveAliases().isNotEmpty(), "startup must still mint the master key ahead of the first put")
        } finally {
            ksafe.close()
        }
    }
}
