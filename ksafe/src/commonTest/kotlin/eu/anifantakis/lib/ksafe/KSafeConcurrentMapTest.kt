package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeConcurrentMap
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Locks in: [KSafeConcurrentMap.removeIf] removes only when the current value matches, so the
 * post-commit cache repair rolls back exactly its own value — never a third writer's — and an
 * acknowledged delete can't be resurrected in memory.
 */
class KSafeConcurrentMapTest {

    @Test
    fun removeIf_removesOnlyWhenValueMatches() {
        val map = KSafeConcurrentMap<String>()
        map["k"] = "v1"

        assertFalse(map.removeIf("k", "other"), "removeIf must not remove when the value differs")
        assertEquals("v1", map["k"], "a non-matching removeIf must leave the entry untouched")

        assertTrue(map.removeIf("k", "v1"), "removeIf must remove when the value matches")
        assertNull(map["k"], "the entry must be gone after a matching removeIf")
    }

    @Test
    fun removeIf_neverClobbersAThirdWritersValue() {
        // Rollback safety: our repair inserted "mine", but a newer writer has since overwritten
        // the slot with "theirs". Rolling back with our own value must be a no-op — it must not
        // delete the newer writer's value.
        val map = KSafeConcurrentMap<String>()
        map["k"] = "theirs"

        assertFalse(map.removeIf("k", "mine"), "rollback of our value must not touch a newer writer's value")
        assertEquals("theirs", map["k"], "the newer writer's value must survive our rollback attempt")
    }

    @Test
    fun removeIf_onAbsentKey_isFalse() {
        val map = KSafeConcurrentMap<String>()
        assertFalse(map.removeIf("missing", "anything"), "removeIf on an absent key must be false")
    }
}
