package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: a collector merge of a snapshot taken before rotateKeys() cannot undo the rotation in
 * the cache. The entries are only read in this process, so no dirty flag shields them; before the
 * fix the cache ended up with the old ciphertext, and every read returned the default.
 */
class JvmRotationStaleMergeTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_stale_${System.nanoTime()}").apply { mkdirs() }

    @AfterTest fun tearDown() { tmp.deleteRecursively() }

    /** A store written by an earlier process, opened again by one that only reads. */
    private fun readerOf(policy: KSafeMemoryPolicy, engine: StatefulFakeEncryption, fileName: String): KSafe {
        val writer = KSafe(fileName = fileName, baseDir = tmp, testEngine = engine, memoryPolicy = policy)
        runBlocking { writer.put("token", "secret") }
        writer.close()
        // lazyLoad: no collector, so the test decides when each snapshot is merged.
        val reader = KSafe(fileName = fileName, baseDir = tmp, testEngine = engine, memoryPolicy = policy, lazyLoad = true)
        assertEquals("secret", reader.getDirect("token", ""), "precondition ($policy)")
        return reader
    }

    @Test
    fun staleSnapshotMergedAfterRotation_keepsTheRotatedEntry() {
        for (policy in KSafeMemoryPolicy.entries) {
            val reader = readerOf(policy, StatefulFakeEncryption(), "after_${policy.name.lowercase()}")
            val beforeRotation = runBlocking { reader.core.storage.snapshot() }
            assertEquals(1, runBlocking { reader.rotateKeys() }.rotated)

            runBlocking { reader.core.updateCache(beforeRotation) }

            assertEquals("secret", reader.getDirect("token", ""), "getDirect ($policy)")
            assertEquals("secret", runBlocking { reader.get("token", "") }, "get ($policy)")
            reader.close()
        }
    }

    @Test
    fun rotationCommittedInsideAMerge_keepsTheRotatedEntry() {
        // The CI signature: the commit lands after the merge's metadata pass and before its value
        // pass, so new metadata met the old ciphertext.
        for (policy in KSafeMemoryPolicy.entries) {
            val reader = readerOf(policy, StatefulFakeEncryption(), "inside_${policy.name.lowercase()}")
            val beforeRotation = runBlocking { reader.core.storage.snapshot() }
            reader.core.cacheMergeMetaStoreHook = { _ ->
                reader.core.cacheMergeMetaStoreHook = null
                runBlocking { reader.rotateKeys() }
            }

            runBlocking { reader.core.updateCache(beforeRotation) }

            assertEquals(2, reader.core.encMetaMap["token"]?.keyGeneration, "rotated meta ($policy)")
            assertEquals("secret", reader.getDirect("token", ""), "getDirect ($policy)")
            reader.close()
        }
    }

    @Test
    fun newerSnapshotAfterRotation_isStillMerged() {
        // The fence holds back only the replaced ciphertext; a later write from a sibling arrives.
        for (policy in KSafeMemoryPolicy.entries) {
            val engine = StatefulFakeEncryption()
            val fileName = "newer_${policy.name.lowercase()}"
            val reader = readerOf(policy, engine, fileName)
            runBlocking { reader.rotateKeys() }

            val sibling = KSafe(fileName = fileName, baseDir = tmp, testEngine = engine, memoryPolicy = policy, lazyLoad = true)
            runBlocking { sibling.put("token", "newer") }
            runBlocking { reader.core.updateCache(reader.core.storage.snapshot()) }

            assertEquals("newer", reader.getDirect("token", ""), "sibling write ($policy)")
            sibling.close()
            reader.close()
        }
    }

    @Test
    fun staleSnapshotAfterRotation_doesNotRevertTheCachedCiphertext() {
        val reader = readerOf(KSafeMemoryPolicy.ENCRYPTED, StatefulFakeEncryption(), "cipher")
        val beforeRotation = runBlocking { reader.core.storage.snapshot() }
        runBlocking { reader.rotateKeys() }
        val cacheKey = KeySafeMetadataManager.legacyEncryptedRawKey("token")
        val rotated = reader.core.memoryCache[cacheKey]

        runBlocking { reader.core.updateCache(beforeRotation) }

        assertEquals(rotated, reader.core.memoryCache[cacheKey])
        assertEquals(2, reader.core.encMetaMap["token"]?.keyGeneration)
        reader.close()
    }
}
