package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.fail

/**
 * Locks in: `clearAll()` on one instance also wipes the in-memory copies every OTHER live
 * instance on the same physical store holds — the primary cache, the plaintext side cache,
 * the routing metadata and the key generation — so a wiped secret can never be read back
 * from a sibling for the rest of the process.
 */
class JvmSiblingClearAllTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_sib_${System.nanoTime()}")
        .apply { mkdirs() }

    @AfterTest fun tearDown() { tmp.deleteRecursively() }

    private fun newKSafe(
        fileName: String,
        policy: KSafeMemoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
        lazyLoad: Boolean = false,
    ) = KSafe(
        fileName = fileName,
        baseDir = tmp,
        memoryPolicy = policy,
        lazyLoad = lazyLoad,
        testEngine = FakeEncryption(),
    )

    /** Same file ⇒ one shared backend; without that these are not siblings and prove nothing. */
    private fun assertRealSiblings(a: KSafe, b: KSafe) {
        assertSame(
            a.core.commitMutex, b.core.commitMutex,
            "the two instances must share one physical store's backend",
        )
    }

    private suspend fun awaitTrue(message: String, timeoutMs: Long = 10_000, probe: suspend () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (probe()) return
            delay(20)
        }
        fail(message)
    }

    private fun siblingWipeLeavesNothingReadable(
        fileName: String,
        policy: KSafeMemoryPolicy,
        lazyLoadOnSibling: Boolean = false,
    ) = runBlocking {
        val a = newKSafe(fileName, policy, lazyLoad = lazyLoadOnSibling)
        val b = newKSafe(fileName, policy)
        try {
            assertRealSiblings(a, b)
            a.putDirect("token", "secret")
            a.put("barrier", 1) // awaits its commit, so the token is durable before the wipe
            assertEquals("secret", a.getDirect("token", ""), "precondition: the sibling holds the secret")

            b.clearAll()

            assertEquals("", a.getDirect("token", ""), "a wiped secret must not survive in a sibling's cache")
            assertEquals("", a.get("token", ""), "the suspend read must not serve the wiped secret either")
            assertNull(a.getKeyInfo("token"), "the sibling's routing metadata must be wiped too")
        } finally {
            a.close(); b.close()
        }
    }

    @Test
    fun defaultPolicy_siblingCacheIsWiped() =
        siblingWipeLeavesNothingReadable("siblazyplain", KSafeMemoryPolicy.LAZY_PLAIN_TEXT)

    @Test
    fun plainTextPolicy_siblingCacheIsWiped() =
        siblingWipeLeavesNothingReadable("sibplain", KSafeMemoryPolicy.PLAIN_TEXT)

    @Test
    fun encryptedPolicy_siblingCacheIsWiped() =
        siblingWipeLeavesNothingReadable("sibenc", KSafeMemoryPolicy.ENCRYPTED)

    @Test
    fun timedCachePolicy_siblingCacheIsWiped() =
        siblingWipeLeavesNothingReadable("sibtimed", KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)

    /** A lazyLoad sibling runs no collector at all, so nothing else would ever evict its copy. */
    @Test
    fun lazyLoadSibling_hasNoCollector_isStillWiped() =
        siblingWipeLeavesNothingReadable("siblazyload", KSafeMemoryPolicy.LAZY_PLAIN_TEXT, lazyLoadOnSibling = true)

    @Test
    fun writeOrderedAfterTheWipe_survivesOnBothInstances() = runBlocking {
        val a = newKSafe("sibafter")
        val b = newKSafe("sibafter")
        try {
            assertRealSiblings(a, b)
            a.put("token", "secret")

            b.clearAll()
            a.put("fresh", "v")

            assertEquals("v", a.getDirect("fresh", ""), "a write ordered after the wipe must stay in RAM")
            awaitTrue("the wiping instance never observed the post-wipe write") { b.get("fresh", "") == "v" }
            assertEquals("v", b.get("fresh", ""), "and must be readable from the wiping instance")
            assertEquals("", a.getDirect("token", ""), "the wiped secret must still be gone")
        } finally {
            a.close(); b.close()
        }
    }

    @Test
    fun siblingKeyGeneration_restartsAtTheBaseGeneration() = runBlocking {
        val a = newKSafe("sibgen")
        val b = newKSafe("sibgen")
        try {
            assertRealSiblings(a, b)
            a.put("token", "secret")
            a.rotateKeys()
            assertEquals(2, a.core.currentKeyGeneration.get(), "precondition: the store rotated")

            b.clearAll()

            assertEquals(
                1, a.core.currentKeyGeneration.get(),
                "a wiped store has no keygen record left — the sibling must restart at the base generation",
            )
        } finally {
            a.close(); b.close()
        }
    }

    /**
     * An optimistic write staged in RAM but not yet committed when the wipe lands may legitimately
     * end up on either side of it — but never on both: whatever survives on disk must be exactly
     * what the sibling still serves from RAM.
     */
    @Test
    fun optimisticWriteRacingTheWipe_endsConsistentWithDisk() = runBlocking {
        val a = newKSafe("sibrace")
        val b = newKSafe("sibrace")
        try {
            assertRealSiblings(a, b)
            repeat(40) { i ->
                val key = "raced$i"
                a.putDirect(key, "v$i")
                b.clearAll()
                a.put("barrier$i", i) // FIFO on a's consumer: the raced write is now settled

                val onDisk = a.core.storage.snapshot().containsKey(a.core.valueRawKey(key))
                assertEquals(
                    if (onDisk) "v$i" else "", a.getDirect(key, ""),
                    "iteration $i: the sibling's RAM must agree with what survived on disk",
                )
            }
        } finally {
            a.close(); b.close()
        }
    }

    @Test
    fun wipeSucceedsWhenASiblingWasClosed() = runBlocking {
        val a = newKSafe("sibclosed")
        val b = newKSafe("sibclosed")
        try {
            assertRealSiblings(a, b)
            a.put("token", "secret")
            a.close()

            b.clearAll()

            assertEquals("", b.get("token", ""), "the wipe itself must still work")
        } finally {
            a.close(); b.close()
        }
    }
}
