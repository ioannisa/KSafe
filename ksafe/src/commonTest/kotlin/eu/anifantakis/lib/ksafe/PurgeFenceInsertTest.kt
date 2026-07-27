package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeConcurrentMap
import eu.anifantakis.lib.ksafe.internal.insertUnderPurgeFence
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Locks in the fence the Android DEK cache and the Apple key-bytes cache now share: a value read
 * before a wipe must never enter the cache after it, or the engine keeps serving key material
 * whose persisted record is gone — readable for the session, unreadable after the next launch.
 *
 * The put-then-revalidate undo is not reachable single-threaded (it needs a wipe to land between
 * the helper's two epoch reads); its value-conditional half is covered by [KSafeConcurrentMapTest].
 */
@OptIn(ExperimentalAtomicApi::class)
class PurgeFenceInsertTest {

    @Test
    fun insertsWhenNoPurgeRacedTheRead() {
        val cache = KSafeConcurrentMap<String>()
        val epoch = AtomicLong(0)
        val epochAtRead = epoch.load()

        insertUnderPurgeFence(cache, epoch, "k", "key-bytes", epochAtRead)

        assertEquals("key-bytes", cache["k"])
    }

    @Test
    fun skipsInsertWhenAPurgeLandedAfterTheRead() {
        val cache = KSafeConcurrentMap<String>()
        val epoch = AtomicLong(0)
        val epochAtRead = epoch.load()
        epoch.addAndFetch(1)

        insertUnderPurgeFence(cache, epoch, "k", "stale-bytes", epochAtRead)

        assertNull(cache["k"], "a value read before a wipe must never enter the cache after it")
    }

    @Test
    fun aSkippedInsertLeavesANewerRemintAlone() {
        val cache = KSafeConcurrentMap<String>()
        val epoch = AtomicLong(0)
        val epochAtRead = epoch.load()
        epoch.addAndFetch(1)
        cache["k"] = "fresh-bytes"

        insertUnderPurgeFence(cache, epoch, "k", "stale-bytes", epochAtRead)

        assertEquals("fresh-bytes", cache["k"], "the fence must not touch a post-wipe re-mint")
    }
}
