package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.localStorageGet
import eu.anifantakis.lib.ksafe.internal.localStorageRemove
import eu.anifantakis.lib.ksafe.internal.localStorageSet
import eu.anifantakis.lib.ksafe.internal.migrateLegacyLocalStoragePrefix
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * The localStorage key scheme must be prefix-free. The legacy `ksafe_<name>_`
 * scheme was not: `KSafe("user")`'s startsWith() scoping would ingest
 * `KSafe("user_cache")`'s entries and its `clearAll()` would DELETE the
 * sibling store, while `KSafe("default")` collided byte-for-byte with the
 * unnamed `KSafe()` despite using different crypto aliases. The
 * `ksafe.<name>:` scheme is prefix-free (`.`/`:` are outside the fileName
 * alphabet), with a one-time canonical-entry migration carrying shipped data
 * forward.
 */
class WebPrefixIsolationTest {

    @Test
    fun nestedFileNames_clearAll_doesNotWipeSiblingStore() = runTest {
        // "user"-style nested pair, unique per run so reruns don't collide.
        val base = WebKSafeTest.generateUniqueFileName()
        val outer = KSafe(fileName = base, testEngine = FakeEncryption())
        val nested = KSafe(fileName = "${base}_cache", testEngine = FakeEncryption())
        outer.awaitCacheReady()
        nested.awaitCacheReady()

        outer.put("k", "outer-value", KSafeWriteMode.Plain)
        nested.put("k", "nested-value", KSafeWriteMode.Plain)

        // The wipe must be scoped prefix-free: a startsWith() wipe would delete
        // every `ksafe_<base>_cache_*` entry too, destroying the sibling store.
        outer.clearAll()

        // Read through a FRESH instance so the answer comes from DISK — the
        // original instance's optimistic in-memory cache would mask the wipe.
        val nestedReopened = KSafe(fileName = "${base}_cache", testEngine = FakeEncryption())
        nestedReopened.awaitCacheReady()
        assertEquals(
            "nested-value",
            nestedReopened.get("k", "GONE"),
            "clearAll() on '$base' must not wipe the sibling store '${base}_cache' (review R7)",
        )
        nestedReopened.clearAll()
    }

    @Test
    fun nestedFileNames_snapshotsDoNotBleedAcrossStores() = runTest {
        val base = WebKSafeTest.generateUniqueFileName()
        val nested = KSafe(fileName = "${base}_cache", testEngine = FakeEncryption())
        nested.awaitCacheReady()
        nested.put("secret", "nested-only", KSafeWriteMode.Plain)

        // Constructed AFTER the nested store has data on disk: its snapshot
        // must not ingest the sibling's entries under garbled keys.
        val outer = KSafe(fileName = base, testEngine = FakeEncryption())
        outer.awaitCacheReady()
        assertEquals(
            "ABSENT",
            outer.get("cache___ksafe_value_secret", "ABSENT"),
            "the outer store must not see the nested store's entries under garbled keys",
        )

        outer.clearAll()
        nested.clearAll()
    }

    @Test
    fun fileNameDefault_isDistinctFromUnnamedInstance() = runTest {
        // Old scheme: both produced the prefix `ksafe_default_` — one shared
        // data slot under two different crypto aliases.
        val unnamed = KSafe(testEngine = FakeEncryption())
        val named = KSafe(fileName = "default", testEngine = FakeEncryption())
        unnamed.awaitCacheReady()
        named.awaitCacheReady()

        val key = "collision_probe_${WebKSafeTest.generateUniqueFileName()}"
        unnamed.put(key, "from-unnamed", KSafeWriteMode.Plain)
        named.put(key, "from-named", KSafeWriteMode.Plain)

        // Read through a FRESH unnamed instance so the answer comes from DISK
        // — under the old shared `ksafe_default_` slot the named put was the
        // last writer and overwrote the unnamed store's value on disk, masked
        // only by the original instance's optimistic cache.
        val unnamedReopened = KSafe(testEngine = FakeEncryption())
        unnamedReopened.awaitCacheReady()
        assertEquals(
            "from-unnamed", unnamedReopened.get(key, "GONE"),
            "the unnamed store's on-disk value must survive a write to the 'default'-named store",
        )
        assertEquals("from-named", named.get(key, "GONE"), "'default' store must keep its own value")

        // Clean up just the probe key (the unnamed namespace is shared by other tests).
        unnamedReopened.delete(key)
        named.clearAll()
    }

    @Test
    fun legacyPrefixData_isMigratedForward_andNestedSiblingLeftAlone() {
        val base = WebKSafeTest.generateUniqueFileName()

        // Simulate shipped 2.1.x data: canonical entries under the OLD prefixes
        // of both a store and its nested sibling.
        localStorageSet("ksafe_${base}___ksafe_value_k", "legacy-value")
        localStorageSet("ksafe_${base}_cache___ksafe_value_k", "sibling-value")

        migrateLegacyLocalStoragePrefix("ksafe_${base}_", "ksafe.${base}:")

        // Own canonical entry moved (copy + verify + delete)…
        assertEquals("legacy-value", localStorageGet("ksafe.${base}:__ksafe_value_k"))
        assertNull(localStorageGet("ksafe_${base}___ksafe_value_k"), "old entry must be removed after a verified copy")
        // …while the nested sibling's entry (non-canonical remainder for THIS
        // store) is left for the sibling's own migration.
        assertEquals(
            "sibling-value",
            localStorageGet("ksafe_${base}_cache___ksafe_value_k"),
            "the nested sibling's data must not be stolen by the shorter-named store's migration",
        )

        // And the sibling's own migration picks it up correctly.
        migrateLegacyLocalStoragePrefix("ksafe_${base}_cache_", "ksafe.${base}_cache:")
        assertEquals("sibling-value", localStorageGet("ksafe.${base}_cache:__ksafe_value_k"))

        localStorageRemove("ksafe.${base}:__ksafe_value_k")
        localStorageRemove("ksafe.${base}_cache:__ksafe_value_k")
    }
}
