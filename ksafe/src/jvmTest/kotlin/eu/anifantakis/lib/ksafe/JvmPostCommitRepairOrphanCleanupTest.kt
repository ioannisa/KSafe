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
 * Locks in: what the post-commit repair's orphan cleanup does to a newer write's protection and
 * routing metadata, as a function of whether that newer write has published its cached value yet.
 *
 * When a repair loses ownership mid-way it must undo the metadata it just restored, because a
 * concurrent delete would otherwise leave protection/encMeta orphaned on a key that no longer has
 * a value. It recognises that case by the cache slot being empty (`!memoryCache.containsKey`).
 * That test cannot tell "the key was deleted" from "a newer write has published its metadata but
 * not yet its value" — so the optimistic write paths publish the cached value BEFORE the
 * protection literal, which keeps the second state from ever being observed.
 *
 * The tests below are identical except for one line: whether the newer write's value slot is
 * present when the older repair resumes. That isolates exactly the property the ordering exists to
 * guarantee, and shows what is lost without it. Both the plain and the encrypted repair branches
 * carry their own copy of the cleanup, so both are driven here.
 *
 * Not every write path holds that ordering today — the encrypted suspend path publishes its
 * metadata before its value, so it can expose the window these tests reproduce. That divergence is
 * known and deferred to 3.0.1. It cannot be driven from here: the repair hook runs ON the write
 * loop, and a suspend put awaits the very loop it would be blocking, so the window is set up
 * directly instead of by racing for it.
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
     * Commits a write, lands a newer write of the same mode inside its post-commit repair, and
     * reports the metadata state as seen at the START of the newer write's own repair — the last
     * moment before that repair re-asserts its metadata and hides whatever the older one did.
     *
     * Both writes share [mode] so the newer metadata is value-equal to what the older repair
     * restores; the cleanup is a value-matched `removeIf`, so mixing modes would make it silently
     * stop applying.
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

        // Current behaviour, not desired behaviour: metadata with no cached value is
        // indistinguishable from a deleted key, so the older repair's cleanup takes it. The key is
        // left routing-less until the newer write's own repair re-asserts it, and reads in that
        // window see no protection record for a key that has one on disk.
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
        // The plain repair branch carries its own copy of the cleanup and only tracks the
        // protection literal (a plain write clears routing metadata outright).
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
