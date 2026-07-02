package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertNull

/**
 * FEEDBACK_4 FB3-M3 (the Plain twin of FB3-H2): the post-commit repair re-asserts
 * a PLAIN write's `memoryCache` / `protectionMap` via separate `putIfAbsent`s to
 * survive a `clearAll` that wiped the optimistic state. Those inserts race a
 * caller-thread `delete()`, which claims `writeOwners` and wipes both maps. In the
 * losing interleaving the value insert runs first as a no-op, the delete then wipes
 * everything, and the `protectionMap` `putIfAbsent` RESURRECTS an orphan protection
 * literal for the now-deleted key — so `getKeyInfo` returns non-null for a deleted
 * key. The coupled cleanup keyed off the (now-absent) value, so it skipped the
 * orphan. The Plain branch now mirrors the Encrypted branch's `!containsKey`
 * orphan-drop.
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
            lazyLoad = true, // no collector → no updateCache re-sync to mask the orphan
            testEngine = IdentityEngine(),
        )

        var fired = false
        ksafe.core.postCommitRepairHook = { userKey ->
            if (userKey == "k" && !fired) {
                fired = true
                ksafe.core.deleteDirect("k") // synchronous wipe + writeOwners claim
            }
        }

        // MUST be a Plain write — the 2-arg put(key, value) defaults to Encrypted and
        // would route through the (already-fixed) Encrypted repair branch.
        runBlocking { ksafe.put("k", "v", KSafeWriteMode.Plain) }

        assertNull(
            ksafe.getKeyInfo("k"),
            "a delete racing the plain post-commit repair must not leave orphan protection " +
                "for the deleted key (FB3-M3)",
        )

        ksafe.close()
    }
}
