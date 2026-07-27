package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.corruptQuarantineName
import eu.anifantakis.lib.ksafe.internal.sweepCorruptQuarantineCopies
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The sweep runs on every DataStore platform but the platforms name their quarantine copies
 * differently (Apple keeps one fixed-name copy, the JVM targets timestamp theirs), so the matching
 * has to cover both spellings without reaching past this store's own files.
 */
class CorruptStoreSweepTest {

    private val store = "eu_anifantakis_ksafe_datastore_main.preferences_pb"

    private fun sweep(names: List<String>): List<String> {
        val deleted = mutableListOf<String>()
        sweepCorruptQuarantineCopies(store, { names }, { deleted.add(it) })
        return deleted
    }

    @Test
    fun sweepsBothTheTimestampedAndTheFixedNameQuarantineSpelling() {
        val timestamped = corruptQuarantineName(store, 1_700_000_000_000L)
        val fixed = corruptQuarantineName(store)
        assertTrue(timestamped.startsWith(fixed), "the timestamped name must extend the fixed one")

        assertEquals(listOf(fixed, timestamped), sweep(listOf(fixed, timestamped)))
    }

    @Test
    fun leavesTheLiveStoreAndSiblingSafesAlone() {
        val siblingQuarantine =
            corruptQuarantineName("eu_anifantakis_ksafe_datastore_other.preferences_pb", 1L)
        assertEquals(
            emptyList(),
            sweep(listOf(store, "$store.lock", siblingQuarantine, "unrelated.txt")),
        )
    }

    @Test
    fun aFailedListingOrDeleteNeverFailsTheWipe() {
        sweepCorruptQuarantineCopies(store, { error("listing failed") }, { })

        val seen = mutableListOf<String>()
        sweepCorruptQuarantineCopies(
            store,
            { listOf(corruptQuarantineName(store, 1L), corruptQuarantineName(store, 2L)) },
            { name -> seen.add(name); error("delete failed") },
        )
        assertEquals(2, seen.size, "a failed delete must not abandon the remaining copies")
    }
}
