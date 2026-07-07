package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertNull

/**
 * Locks in: a delete racing a plain write's post-commit repair never resurrects orphan protection metadata for the deleted key.
 */
class JvmPostCommitRepairPlainDeleteRaceTest {

    private class IdentityEngine : KSafeEncryption {
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun deleteKey(identifier: String) {}
    }

    @Test
    fun concurrentDeleteDuringRepair_doesNotResurrectMetadata_forDeletedPlainKey() {
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
            lazyLoad = true, // no collector, so no updateCache re-sync can mask the orphan
            testEngine = IdentityEngine(),
        )

        // The test-only hook fires mid-repair; deleting there is the interleaving
        // that can resurrect an orphan protection entry.
        var fired = false
        ksafe.core.postCommitRepairHook = { userKey ->
            if (userKey == "k" && !fired) {
                fired = true
                ksafe.core.deleteDirect("k")
            }
        }

        // Must be a Plain write — the 2-arg put defaults to Encrypted and would
        // route through the Encrypted repair branch instead.
        runBlocking { ksafe.put("k", "v", KSafeWriteMode.Plain) }

        assertNull(
            ksafe.getKeyInfo("k"),
            "a delete racing the plain post-commit repair must not leave orphan protection " +
                "for the deleted key",
        )

        ksafe.close()
    }
}
