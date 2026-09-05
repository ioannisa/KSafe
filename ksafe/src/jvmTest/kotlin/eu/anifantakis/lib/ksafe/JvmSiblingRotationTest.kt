package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in: `rotateKeys()` on one instance must not turn another live instance's OWN writes
 * into their default values. The rotation re-encrypts every persisted entry under a new master
 * and its sweep destroys the superseded one, so a sibling still holding the previous
 * generation's ciphertext in RAM would decrypt under a key that no longer exists.
 */
class JvmSiblingRotationTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_sibrot_${System.nanoTime()}")
        .apply { mkdirs() }

    @AfterTest fun tearDown() { tmp.deleteRecursively() }

    /** Real key lifecycle: [FakeEncryption] keeps decrypting after a delete and would hide this. */
    private fun newKSafe(
        fileName: String,
        engine: StatefulFakeEncryption,
        policy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
        lazyLoad: Boolean = false,
        ttl: kotlin.time.Duration = 5.seconds,
    ) = KSafe(
        fileName = fileName,
        baseDir = tmp,
        memoryPolicy = policy,
        lazyLoad = lazyLoad,
        plaintextCacheTtl = ttl,
        testEngine = engine,
    )

    /** Same file ⇒ one shared backend; without that these are not siblings and prove nothing. */
    private fun assertRealSiblings(a: KSafe, b: KSafe) {
        assertSame(
            a.core.commitMutex, b.core.commitMutex,
            "the two instances must share one physical store's backend",
        )
    }

    @Test
    fun encryptedPolicy_siblingRotation_leavesOwnWritesReadable() = runBlocking {
        val engine = StatefulFakeEncryption()
        val a = newKSafe("sibrotenc", engine)
        val b = newKSafe("sibrotenc", engine)
        try {
            assertRealSiblings(a, b)
            a.putDirect("token", "T")
            a.put("barrier", 1) // awaits its commit, so the token is durable before the rotation
            assertEquals("T", a.getDirect("token", ""), "precondition: the instance serves its own write")

            b.rotateKeys()

            assertEquals("T", a.getDirect("token", ""), "a sibling's rotation must not default this instance's own write")
            assertEquals("T", a.get("token", ""), "the suspend read must survive the rotation too")
            assertEquals(
                2, a.core.encMetaMap["token"]?.keyGeneration,
                "the instance must have adopted the rotated generation",
            )
        } finally {
            a.close(); b.close()
        }
    }

    @Test
    fun timedCachePolicy_siblingRotation_survivesTheSideCacheExpiring() = runBlocking {
        val engine = StatefulFakeEncryption()
        val a = newKSafe("sibrottimed", engine, KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE, ttl = 10.milliseconds)
        val b = newKSafe("sibrottimed", engine, KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE, ttl = 10.milliseconds)
        try {
            assertRealSiblings(a, b)
            a.putDirect("token", "T")
            a.put("barrier", 1)

            b.rotateKeys()
            delay(80) // the plaintext side cache expires; reads fall back to the ciphertext

            assertEquals("T", a.getDirect("token", ""), "an expired side cache must fall back to decryptable ciphertext")
        } finally {
            a.close(); b.close()
        }
    }

    /** A lazyLoad instance runs no snapshot collector, so nothing else would ever repair its copy. */
    @Test
    fun lazyLoadInstance_siblingRotation_leavesOwnWritesReadable() = runBlocking {
        val engine = StatefulFakeEncryption()
        val a = newKSafe("sibrotlazy", engine, lazyLoad = true)
        val b = newKSafe("sibrotlazy", engine)
        try {
            assertRealSiblings(a, b)
            a.putDirect("token", "T")
            a.put("barrier", 1)

            b.rotateKeys()
            assertEquals("T", a.getDirect("token", ""), "a collector-less instance must survive a sibling's rotation")

            b.rotateKeys()
            assertEquals("T", a.getDirect("token", ""), "and must survive a second one")
        } finally {
            a.close(); b.close()
        }
    }

    /** Once the last instance referencing them is gone, the superseded masters must still be reaped. */
    @Test
    fun closedInstance_noLongerHoldsSupersededMastersAlive() = runBlocking {
        val engine = StatefulFakeEncryption()
        val a = newKSafe("sibrotreap", engine)
        val b = newKSafe("sibrotreap", engine)
        try {
            assertRealSiblings(a, b)
            a.putDirect("token", "T")
            a.put("barrier", 1)
            b.put("token", "T2") // a's copy diverges, so no adoption can move it off the base master
            val baseMaster = b.core.masterAlias(false)

            b.rotateKeys()
            assertTrue(
                baseMaster in engine.liveAliases(),
                "precondition: a live instance's own copy still pins the base master",
            )

            a.close()
            b.rotateKeys()

            assertTrue(
                baseMaster !in engine.liveAliases(),
                "with no live instance on the base generation its master must be reaped: ${engine.liveAliases()}",
            )
        } finally {
            a.close(); b.close()
        }
    }

    /**
     * A sibling that legitimately serves an OLDER copy of an entry (its own write, kept by the
     * dirty flag while another instance overwrote the entry) must keep serving that copy — the
     * staleness is by design, silently degrading it into the default value is not.
     */
    @Test
    fun staleSiblingCopy_survivesTheRotationSweep() = runBlocking {
        val engine = StatefulFakeEncryption()
        val a = newKSafe("sibrotstale", engine)
        val b = newKSafe("sibrotstale", engine)
        try {
            assertRealSiblings(a, b)
            a.putDirect("token", "T")
            a.put("barrier", 1)
            b.put("token", "T2") // disk moves on; a keeps its own copy
            assertEquals("T", a.getDirect("token", ""), "precondition: the instance still serves its own copy")

            b.rotateKeys()

            assertEquals("T", a.getDirect("token", ""), "a still-referenced master must survive the sweep")
        } finally {
            a.close(); b.close()
        }
    }

    /** A sibling write landing inside the rotation's own commit must outlive the adoption. */
    @Test
    fun siblingWriteLandingDuringRotation_isNotOverwrittenByTheAdoption() = runBlocking {
        val engine = StatefulFakeEncryption()
        val a = newKSafe("sibrotrace", engine)
        val b = newKSafe("sibrotrace", engine)
        try {
            assertRealSiblings(a, b)
            a.putDirect("token", "T")
            a.put("barrier", 1)
            b.core.postApplyBatchHook = { keys -> if ("token" in keys) a.putDirect("token", "LATER") }

            b.rotateKeys()

            assertEquals("LATER", a.getDirect("token", ""), "the adoption must not overwrite the write it raced")
            a.put("barrier2", 1) // the racing write's own batch is committed by now
            assertEquals("LATER", a.get("token", ""), "the suspend read must serve it too")
            val disk = (a.core.storage.snapshot()[a.core.valueRawKey("token")] as StoredValue.Text).value
            assertEquals(
                disk, a.core.memoryCache[a.core.legacyEncryptedRawKey("token")],
                "the racing write's ciphertext, not the rotation's, must be what reached disk",
            )
        } finally {
            b.core.postApplyBatchHook = null
            a.close(); b.close()
        }
    }

    /** The per-entry twin of the case above: a stale copy rides its own alias, not the master. */
    @Test
    fun staleSiblingCopyOfHardwareIsolatedEntry_survivesTheRotation() = runBlocking {
        val engine = StatefulFakeEncryption()
        val a = newKSafe("sibrotstalehw", engine)
        val b = newKSafe("sibrotstalehw", engine)
        val strict = KSafeWriteMode.Encrypted(protection = KSafeEncryptedProtection.HARDWARE_ISOLATED)
        try {
            assertRealSiblings(a, b)
            a.putDirect("token", "T", strict)
            a.put("barrier", 1)
            b.put("token", "T2", strict)
            assertEquals("T", a.getDirect("token", ""), "precondition: the instance still serves its own copy")

            b.rotateKeys()

            assertEquals("T", a.getDirect("token", ""), "a still-referenced per-entry alias must survive the rotation")
        } finally {
            a.close(); b.close()
        }
    }
}
