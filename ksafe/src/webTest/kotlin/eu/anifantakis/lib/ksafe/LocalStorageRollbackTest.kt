package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.rollbackPriors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

/** Locks in: [rollbackPriors] behavior, via a fake quota store so the mid-rollback quota condition is reproducible (it isn't with a real browser). */
class LocalStorageRollbackTest {

    /** In-memory store that throws (like `QuotaExceededError`) past a char cap. */
    private class FakeQuotaStore(private val capacityChars: Int) {
        val map = LinkedHashMap<String, String>()

        private fun used(): Int = map.values.sumOf { it.length }

        fun set(key: String, value: String) {
            val projected = used() - (map[key]?.length ?: 0) + value.length
            if (projected > capacityChars) throw RuntimeException("QuotaExceededError")
            map[key] = value
        }

        fun remove(key: String) {
            map.remove(key)
        }
    }

    /** Removing touched keys FIRST frees space so a deleted prior can be restored without hitting quota; arbitrary-order restore would lose it. */
    @Test
    fun rollback_removesTouchedKeysFirst_soNoDeletedValueIsLost() {
        val big = "x".repeat(100)
        val store = FakeQuotaStore(capacityChars = 150)
        // Partial post-failure state: A was deleted, C was put.
        store.map["C"] = "y".repeat(100)

        val priors = linkedMapOf<String, String?>(
            "A" to big, // existed before with a large value (the batch deleted it)
            "C" to null, // did not exist before (the batch created it)
        )

        rollbackPriors(priors, store::set, store::remove)

        assertEquals(big, store.map["A"], "A's pre-batch value must be restored, not lost to quota")
        assertFalse(store.map.containsKey("C"), "C (created by the failed batch) must be removed")
    }

    /** A prior that cannot be restored even after freeing the touched keys (larger than the whole quota) must propagate, not be silently swallowed. */
    @Test
    fun rollback_surfacesUnrestorableValue_insteadOfSwallowing() {
        val store = FakeQuotaStore(capacityChars = 50)
        store.map["C"] = "y".repeat(40)

        val priors = linkedMapOf<String, String?>(
            "A" to "x".repeat(100), // 100 > 50: cannot fit even after removals
            "C" to null,
        )

        val error = assertFailsWith<IllegalStateException> {
            rollbackPriors(priors, store::set, store::remove)
        }
        assertEquals(true, error.message?.contains("may be lost"))
    }

    /** A clean rollback (everything fits) restores priors and removes new keys. */
    @Test
    fun rollback_restoresPriorsAndRemovesNewKeys_whenSpaceFits() {
        val store = FakeQuotaStore(capacityChars = 1000)
        store.map["new"] = "created-by-batch"
        store.map["edited"] = "batch-overwrote-this"

        val priors = linkedMapOf<String, String?>(
            "new" to null, // should be removed
            "edited" to "original", // should be restored
            "deleted" to "was-here", // batch removed it; should be restored
        )

        rollbackPriors(priors, store::set, store::remove)

        assertFalse(store.map.containsKey("new"))
        assertEquals("original", store.map["edited"])
        assertEquals("was-here", store.map["deleted"])
    }
}
