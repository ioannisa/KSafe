package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertNull

/**
 * Locks in: a delete racing an encrypted write's post-commit repair never resurrects orphan protection/encMeta metadata for the deleted key.
 */
class JvmPostCommitRepairDeleteRaceTest {

    private class IdentityEngine : KSafeEncryption {
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun deleteKey(identifier: String) {}
    }

    @Test
    fun concurrentDeleteDuringRepair_doesNotResurrectMetadata_forDeletedEncryptedKey() {
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
            lazyLoad = true, // no collector, so no updateCache re-sync can mask the orphan
            testEngine = IdentityEngine(),
        )

        // The test-only hook fires between the repair's value insert and its metadata
        // inserts; deleting there is the exact interleaving that can resurrect orphans.
        var fired = false
        ksafe.core.postCommitRepairHook = { userKey ->
            if (userKey == "k" && !fired) {
                fired = true
                ksafe.core.deleteDirect("k")
            }
        }

        runBlocking { ksafe.put("k", "v", KSafeWriteMode.Encrypted()) }

        assertNull(
            ksafe.getKeyInfo("k"),
            "a delete racing the post-commit repair must not leave orphan protection/encMeta " +
                "for the deleted key",
        )

        ksafe.close()
    }
}
