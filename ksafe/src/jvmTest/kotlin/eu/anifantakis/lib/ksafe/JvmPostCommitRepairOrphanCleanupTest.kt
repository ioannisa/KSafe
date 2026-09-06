package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Locks in: what the post-commit repair's orphan cleanup does to a newer write's metadata. A repair
 * that lost ownership undoes what it restored when the cache slot is empty, and cannot tell "the
 * key was deleted" from "a newer write published its metadata but not yet its value" — which is why
 * the optimistic paths publish the value first. Each pair below differs only in that slot.
 */
class JvmPostCommitRepairOrphanCleanupTest {

    private companion object {
        const val KEY = "k"
        const val OLDER = "v1"
        const val NEWER = "v2"
    }

    private class RepairOutcome(
        val newerWriteStagedProtection: String?,
        val valueSlotPresentWhenOlderRepairResumed: Boolean,
        val newerRepairRan: Boolean,
        val protectionWhenNewerRepairRan: String?,
        val encMetaWhenNewerRepairRan: KSafeCore.EncMeta?,
    )

    /**
     * Reports the metadata state at the start of the newer write's own repair, the last moment
     * before that repair hides whatever the older one did. Both writes share [mode] because the
     * cleanup is a value-matched `removeIf`. The window is set up rather than raced for: the repair
     * hook runs on the write loop, and a suspend put would await that same loop.
     *
     * @param rewindValueSlot removes the newer write's cached value after it stages, reproducing
     *   the instant a metadata-before-value ordering leaves visible.
     */
    private fun runRepairRace(rewindValueSlot: Boolean, mode: KSafeWriteMode): RepairOutcome {
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
            lazyLoad = true, // no collector, so no updateCache re-sync can mask the orphan
            testEngine = IdentityEngine(),
        )
        // Plain writes cache under the bare key; encrypted ones under the legacy encrypted slot.
        val valueSlot = if (mode is KSafeWriteMode.Encrypted) {
            KeySafeMetadataManager.legacyEncryptedRawKey(KEY)
        } else {
            KEY
        }

        var fires = 0
        var stagedProtection: String? = null
        var valueSlotPresent = true
        var newerRepairRan = false
        var protectionWhenNewerRepairRan: String? = null
        var encMetaWhenNewerRepairRan: KSafeCore.EncMeta? = null

        ksafe.core.postCommitRepairHook = { userKey ->
            if (userKey == KEY) {
                fires++
                when (fires) {
                    // Inside the older write's repair, between its value insert and its metadata
                    // inserts — the interleaving a newer write can actually hit.
                    1 -> {
                        ksafe.putDirect(KEY, NEWER, mode)
                        if (rewindValueSlot) ksafe.core.memoryCache.remove(valueSlot)
                        stagedProtection = ksafe.core.protectionMap[KEY]
                        valueSlotPresent = ksafe.core.memoryCache.containsKey(valueSlot)
                    }
                    // The newer write's own repair. Its metadata re-assert comes after this hook,
                    // so what is read here is what the older repair left behind.
                    2 -> {
                        newerRepairRan = true
                        protectionWhenNewerRepairRan = ksafe.core.protectionMap[KEY]
                        encMetaWhenNewerRepairRan = ksafe.core.encMetaMap[KEY]
                    }
                }
            }
        }

        runBlocking { ksafe.put(KEY, OLDER, mode) }
        // FIFO flush: the newer write was enqueued before this one, so when this returns its
        // commit — and its repair — have already run.
        runBlocking { ksafe.put("flush", "x", KSafeWriteMode.Plain) }

        ksafe.close()
        return RepairOutcome(
            stagedProtection,
            valueSlotPresent,
            newerRepairRan,
            protectionWhenNewerRepairRan,
            encMetaWhenNewerRepairRan,
        )
    }

    private fun assertPremises(outcome: RepairOutcome, expectValueSlot: Boolean) {
        assertNotNull(
            outcome.newerWriteStagedProtection,
            "premise: the newer write must have published its protection metadata",
        )
        assertEquals(
            expectValueSlot, outcome.valueSlotPresentWhenOlderRepairResumed,
            "premise: the newer write's value slot presence is the state under test",
        )
        assertTrue(outcome.newerRepairRan, "premise: the newer write's own repair must have run")
    }

    @Test
    fun encryptedRepairLeavesNewerMetadataAlone_whenTheNewerWriteHasAlreadyPublishedItsValue() {
        val outcome = runRepairRace(rewindValueSlot = false, mode = KSafeWriteMode.Encrypted())
        assertPremises(outcome, expectValueSlot = true)

        assertNotNull(
            outcome.protectionWhenNewerRepairRan,
            "a repair that lost ownership must not drop the protection of a newer write whose " +
                "value is already cached — the published value is what distinguishes it from a delete",
        )
        assertNotNull(
            outcome.encMetaWhenNewerRepairRan,
            "the routing metadata must survive alongside the protection literal",
        )
    }

    @Test
    fun encryptedRepairDropsNewerMetadata_whenTheNewerWriteHasNotPublishedItsValueYet() {
        val outcome = runRepairRace(rewindValueSlot = true, mode = KSafeWriteMode.Encrypted())
        assertPremises(outcome, expectValueSlot = false)

        // Current behaviour, not desired: metadata with no cached value is indistinguishable from
        // a deleted key, so the cleanup takes it and reads see no protection record until the
        // newer write's repair re-asserts it. The encrypted suspend path can still reach here.
        assertNull(
            outcome.protectionWhenNewerRepairRan,
            "a repair that lost ownership drops a newer write's protection while that write's " +
                "value slot is still empty — why the optimistic paths publish the value first",
        )
        assertNull(
            outcome.encMetaWhenNewerRepairRan,
            "the routing metadata is dropped with it, leaving the key unroutable for that window",
        )
    }

    @Test
    fun plainRepairLeavesNewerMetadataAlone_whenTheNewerWriteHasAlreadyPublishedItsValue() {
        // The plain branch carries its own copy of the cleanup and only tracks the protection
        // literal, since a plain write clears routing metadata outright.
        val outcome = runRepairRace(rewindValueSlot = false, mode = KSafeWriteMode.Plain)
        assertPremises(outcome, expectValueSlot = true)

        assertNotNull(
            outcome.protectionWhenNewerRepairRan,
            "a repair that lost ownership must not drop the protection of a newer plain write " +
                "whose value is already cached",
        )
    }

    @Test
    fun plainRepairDropsNewerMetadata_whenTheNewerWriteHasNotPublishedItsValueYet() {
        val outcome = runRepairRace(rewindValueSlot = true, mode = KSafeWriteMode.Plain)
        assertPremises(outcome, expectValueSlot = false)

        assertNull(
            outcome.protectionWhenNewerRepairRan,
            "the plain branch drops a newer write's protection the same way while its value slot " +
                "is still empty — why the plain staging caches the value before the literal",
        )
    }
}
