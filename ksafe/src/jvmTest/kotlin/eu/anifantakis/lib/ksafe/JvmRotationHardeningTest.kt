package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.test.runTest
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Rotation hardening extras:
 * - reserved master-sentinel user keys are rejected at the write/delete API (a key named
 *   "__ksafe_master__" produces an alias byte-identical to the master's — deleting it would
 *   destroy the KEK protecting every DEFAULT value);
 * - two live instances on one file may rotate simultaneously without losing anything;
 * - a transient vault outage mid-rotation reports `skipped` (never `failed`), leaves every
 *   entry readable, and the next pass completes the rotation.
 */
class JvmRotationHardeningTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_rothard_${System.nanoTime()}").apply { mkdirs() }

    @AfterTest fun tearDown() { tmp.deleteRecursively() }

    @Test
    fun reservedMasterNames_areRejectedOnWriteAndDelete() = runTest {
        assertTrue(KeySafeMetadataManager.isReservedUserKey("__ksafe_master__"))
        assertTrue(KeySafeMetadataManager.isReservedUserKey("__ksafe_master_locked__"))
        assertTrue(KeySafeMetadataManager.isReservedUserKey("__ksafe_master__.g2"), "rotation generations too")
        assertFalse(KeySafeMetadataManager.isReservedUserKey("my_master_key"), "ordinary keys pass")
        assertFalse(KeySafeMetadataManager.isReservedUserKey("__ksafe_master__x"), "only EXACT sentinels are reserved")

        val ksafe = KSafe(fileName = "guard", baseDir = tmp)
        ksafe.put("normal", "fine")
        assertFailsWith<IllegalArgumentException> { ksafe.put("__ksafe_master__", "boom") }
        assertFailsWith<IllegalArgumentException> { ksafe.putDirect("__ksafe_master_locked__", "boom") }
        assertFailsWith<IllegalArgumentException> { ksafe.delete("__ksafe_master__") }
        assertFailsWith<IllegalArgumentException> { ksafe.deleteDirect("__ksafe_master__.g3") }
        assertEquals("fine", ksafe.get("normal", ""), "normal traffic unaffected")
        ksafe.close()
    }

    @Test
    fun twoInstancesOnOneFile_rotatingSimultaneously_loseNothing() = runTest {
        val a = KSafe(fileName = "dualrot", baseDir = tmp)
        val b = KSafe(fileName = "dualrot", baseDir = tmp)
        for (i in 0 until 8) a.put("a$i", "va$i")
        for (i in 0 until 8) b.put("b$i", "vb$i")

        // Both instances rotate at once (redundant work is allowed; loss is not).
        coroutineScope {
            val ra = async { runCatching { a.rotateKeys() } }
            val rb = async { runCatching { b.rotateKeys() } }
            ra.await(); rb.await()
        }

        for (i in 0 until 8) {
            assertEquals("va$i", a.get("a$i", "MISSING"))
            assertEquals("vb$i", b.get("b$i", "MISSING"))
        }
        a.close(); b.close()

        // Cold reopen: everything decrypts from disk under whatever generations landed.
        val cold = KSafe(fileName = "dualrot", baseDir = tmp)
        for (i in 0 until 8) {
            assertEquals("va$i", cold.get("a$i", "MISSING"), "a$i must survive dual rotation + reopen")
            assertEquals("vb$i", cold.get("b$i", "MISSING"), "b$i must survive dual rotation + reopen")
        }
        cold.close()
    }

    /** Wraps [FakeEncryption]; while [outage] is set, every decrypt fails like an OS-vault outage. */
    private class FaultInjectingEncryption : KSafeEncryption {
        val inner = FakeEncryption()
        val outage = AtomicBoolean(false)

        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray =
            inner.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice, aad)

        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray {
            if (outage.get()) throw IllegalStateException("KSafe: key vault unavailable (degraded); cannot resolve key for identifier: $identifier")
            return inner.decrypt(identifier, data, requireUnlockedDevice, aad)
        }

        override fun deleteKey(identifier: String) = inner.deleteKey(identifier)
    }

    @Test
    fun vaultOutageMidRotation_reportsSkipped_neverFailed_andNextPassCompletes() = runTest {
        val engine = FaultInjectingEncryption()
        val ksafe = KSafe(fileName = "faultrot", baseDir = tmp, testEngine = engine)
        for (i in 0 until 6) ksafe.put("k$i", "v$i")

        // Total outage: every rotation decrypt fails with the outage signal.
        engine.outage.set(true)
        val duringOutage = ksafe.rotateKeys()
        assertEquals(0, duringOutage.failed, "an outage must never be reported as failed entries")
        assertEquals(6, duringOutage.skipped, "every entry pauses, awaiting the store's return")
        assertEquals(0, duringOutage.rotated)

        // Entries stayed readable throughout (their recorded generation still decrypts)...
        engine.outage.set(false)
        for (i in 0 until 6) assertEquals("v$i", ksafe.get("k$i", "MISSING"))

        // ...and the next pass completes the rotation.
        val afterRecovery = ksafe.rotateKeys()
        assertEquals(6, afterRecovery.rotated, "the retry pass rotates everything the outage skipped")
        assertEquals(0, afterRecovery.failed)
        for (i in 0 until 6) assertEquals("v$i", ksafe.get("k$i", "MISSING"))
        ksafe.close()
    }

    @Test
    fun sweepDoesNotDeleteTheMasterAliasASurvivingRelaxedEntryStillNeeds() = runTest {
        // On JVM (and Web) the master alias ignores requireUnlockedDevice, so both unlock
        // policies collapse onto ONE physical alias. When a rotation leaves a relaxed DEFAULT
        // entry skipped at an old generation, the sweep must NOT delete that generation's
        // master — the requireUnlocked=true pass would otherwise delete the alias the
        // requireUnlocked=false pass still needs. FakeEncryption regenerates keys from the
        // alias string (masking the data loss), so assert directly on which aliases were deleted.
        val engine = FaultInjectingEncryption()
        val fileName = "sweepc1"
        val ksafe = KSafe(fileName = fileName, baseDir = tmp, testEngine = engine)
        for (i in 0 until 4) ksafe.put("k$i", "v$i") // relaxed DEFAULT, generation 1

        val baseMaster = "$fileName:__ksafe_master__" // aliasWithGeneration(masterAlias, 1) == base

        // Total outage → every entry SKIPPED, all stay at generation 1; sweep runs for newGen=2.
        engine.outage.set(true)
        val r = ksafe.rotateKeys()
        assertEquals(4, r.skipped)
        engine.outage.set(false)

        assertFalse(
            engine.inner.deletedKeys.contains(baseMaster),
            "the generation-1 master is still referenced by 4 surviving entries — the sweep must NOT delete it (deleted: ${engine.inner.deletedKeys})",
        )
        // And the entries remain readable (belt-and-suspenders; Fake would pass this regardless).
        for (i in 0 until 4) assertEquals("v$i", ksafe.get("k$i", "MISSING"))
        ksafe.close()
    }

    @Test
    fun emptyStringDefaultKey_masterIsCountedAsReferenced() = runTest {
        val engine = FaultInjectingEncryption()
        val fileName = "sweeph1"
        val ksafe = KSafe(fileName = fileName, baseDir = tmp, testEngine = engine)
        ksafe.put("", "empty-key-secret")           // the "" DEFAULT key is valid
        ksafe.put("other", "x")
        val baseMaster = "$fileName:__ksafe_master__"

        engine.outage.set(true)
        ksafe.rotateKeys()                            // "" and "other" both skipped, stay at gen 1
        engine.outage.set(false)

        assertFalse(
            engine.inner.deletedKeys.contains(baseMaster),
            "the empty-string key still references the gen-1 master — it must be counted (deleted: ${engine.inner.deletedKeys})",
        )
        assertEquals("empty-key-secret", ksafe.get("", "MISSING"))
        ksafe.close()
    }
}
