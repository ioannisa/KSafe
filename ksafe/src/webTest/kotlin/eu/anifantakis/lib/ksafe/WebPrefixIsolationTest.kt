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
            "clearAll() on '$base' must not wipe the sibling store '${base}_cache'",
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

    /**
     * Round-3 audit R1 (findings 1/3/5): the migration must NOT move a nested
     * sibling store's FLAT 1.6/1.7 entry (bare `<key>` / `encrypted_<key>`).
     * Those remainders carry no canonical marker, so a shorter-named store's
     * migration cannot tell them apart from its own flat keys — moving them
     * both DELETES the sibling's only copy and SURFACES it under the shorter
     * store (cross-store plaintext bleed). The migration must leave every
     * non-canonical entry untouched to preserve the prefix-free isolation
     * guarantee; carrying legacy flat data forward is deferred to a design that
     * can disambiguate nested names.
     */
    @Test
    fun legacyFlatData_ofNestedSibling_isNotStolenByShorterStore() {
        val base = WebKSafeTest.generateUniqueFileName()
        // 1.6/1.7 flat layout: the nested sibling store "<base>_cache"'s plain
        // value for key "foo" lives at "ksafe_<base>_cache_foo" (no marker),
        // and its encrypted value at "ksafe_<base>_cache_encrypted_foo".
        localStorageSet("ksafe_${base}_cache_foo", "sibling-flat-plain")
        localStorageSet("ksafe_${base}_cache_encrypted_foo", "sibling-flat-cipher")

        // The shorter-named store migrates.
        migrateLegacyLocalStoragePrefix("ksafe_${base}_", "ksafe.${base}:")

        // The sibling's flat entries must be left exactly where they were…
        assertEquals(
            "sibling-flat-plain",
            localStorageGet("ksafe_${base}_cache_foo"),
            "a nested sibling's flat plain entry must not be stolen by the shorter-named store",
        )
        assertEquals(
            "sibling-flat-cipher",
            localStorageGet("ksafe_${base}_cache_encrypted_foo"),
            "a nested sibling's flat encrypted entry must not be stolen by the shorter-named store",
        )
        // …and must NOT have leaked into the shorter store's namespace.
        assertNull(
            localStorageGet("ksafe.${base}:cache_foo"),
            "the shorter store must not surface the sibling's flat data under its own prefix",
        )

        localStorageRemove("ksafe_${base}_cache_foo")
        localStorageRemove("ksafe_${base}_cache_encrypted_foo")
    }

    /**
     * FEEDBACK_4 FB3-M2: constructing an appNamespaced store must NOT cannibalize a
     * co-existing no-namespace store on the same fileName. The un-namespaced upgrade
     * migration's source prefix `ksafe.<file>:` is that sibling's LIVE prefix, and it
     * runs on every construction (no done-marker), so a destructive copy+delete stole
     * the sibling's data each launch. The migration must be non-destructive (copy-if-
     * absent, no source delete), mirroring the non-destructive key half (FB3-H1).
     */
    @Test
    fun appNamespacedStore_doesNotCannibalize_coexistingNoNamespaceStore() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()

        // A no-namespace store writes a value…
        val plain = KSafe(fileName = file, testEngine = FakeEncryption())
        plain.awaitCacheReady()
        plain.put("token", "plain-value", KSafeWriteMode.Plain)

        // …then a same-fileName appNamespaced store is constructed (runs the
        // un-namespaced migration in buildWebKSafe).
        KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.a"), testEngine = FakeEncryption())
            .awaitCacheReady()

        // Re-open the no-namespace store fresh so the read comes from localStorage.
        val plainReopened = KSafe(fileName = file, testEngine = FakeEncryption())
        plainReopened.awaitCacheReady()
        assertEquals(
            "plain-value", plainReopened.get("token", "GONE"),
            "a co-existing no-namespace store's value must survive construction of a same-fileName appNamespaced store (FB3-M2)",
        )

        // And a fresh no-namespace write after another namespaced construction must
        // also survive (proves it isn't just first-launch tolerant).
        plainReopened.put("token2", "fresh", KSafeWriteMode.Plain)
        KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.a"), testEngine = FakeEncryption())
            .awaitCacheReady()
        val plainReopened2 = KSafe(fileName = file, testEngine = FakeEncryption())
        plainReopened2.awaitCacheReady()
        assertEquals(
            "fresh", plainReopened2.get("token2", "GONE"),
            "repeated namespaced constructions must not delete the no-namespace store's fresh writes",
        )

        plainReopened2.clearAll()
    }

    /**
     * FEEDBACK_4 H1 (twin of FB3-M2): the flat legacy `ksafe_<file>_` prefix has NO
     * appNamespace segment — one SHARED source for every namespace of a fileName. When an
     * appNamespace is set the legacy→namespaced migration must be non-destructive, or the
     * first-constructed namespace copies the legacy data to itself AND deletes the shared
     * source, so every OTHER namespace of that fileName reads the default for keys it owned.
     */
    @Test
    fun legacyPrefix_withAppNamespace_isNotDeleted_soAllNamespacesCanMigrate() = runTest {
        val base = WebKSafeTest.generateUniqueFileName()
        // Shipped pre-namespace canonical data under the flat legacy prefix.
        localStorageSet("ksafe_${base}___ksafe_value_k", "legacy-value")

        // First namespaced store constructs → migrates the legacy prefix forward. It must
        // NOT delete the shared legacy source; a second namespace needs it too (H1).
        KSafe(fileName = base, config = KSafeConfig(appNamespace = "com.example.a"), testEngine = FakeEncryption())
            .awaitCacheReady()

        assertEquals(
            "legacy-value", localStorageGet("ksafe_${base}___ksafe_value_k"),
            "the shared legacy source must survive a namespaced construction (H1)",
        )
        assertEquals(
            "legacy-value", localStorageGet("ksafe.com.example.a@${base}:__ksafe_value_k"),
            "namespace A must have migrated the legacy value forward",
        )

        // A second same-fileName namespaced store must STILL find the legacy source and
        // migrate it — proving the first namespace did not destroy it for the rest.
        KSafe(fileName = base, config = KSafeConfig(appNamespace = "com.example.b"), testEngine = FakeEncryption())
            .awaitCacheReady()
        assertEquals(
            "legacy-value", localStorageGet("ksafe.com.example.b@${base}:__ksafe_value_k"),
            "namespace B must ALSO migrate the still-present legacy value (H1: the first namespace must not have deleted the shared source)",
        )

        localStorageRemove("ksafe_${base}___ksafe_value_k")
        localStorageRemove("ksafe.com.example.a@${base}:__ksafe_value_k")
        localStorageRemove("ksafe.com.example.b@${base}:__ksafe_value_k")
    }

    @Test
    fun migrate_withDeleteSourceFalse_copiesForward_withoutDeletingLiveSource() {
        val base = WebKSafeTest.generateUniqueFileName()
        localStorageSet("ksafe.${base}:__ksafe_value_k", "live-value")

        migrateLegacyLocalStoragePrefix("ksafe.${base}:", "ksafe.ns@${base}:", deleteSource = false)

        assertEquals("live-value", localStorageGet("ksafe.ns@${base}:__ksafe_value_k"), "must be copied forward")
        assertEquals(
            "live-value", localStorageGet("ksafe.${base}:__ksafe_value_k"),
            "the live un-namespaced source must NOT be deleted (deleteSource=false)",
        )

        // Idempotent + copy-if-absent: overwrite the source, migrate again, destination unchanged.
        localStorageSet("ksafe.${base}:__ksafe_value_k", "changed")
        migrateLegacyLocalStoragePrefix("ksafe.${base}:", "ksafe.ns@${base}:", deleteSource = false)
        assertEquals("live-value", localStorageGet("ksafe.ns@${base}:__ksafe_value_k"), "copy-if-absent: destination not overwritten")
        assertEquals("changed", localStorageGet("ksafe.${base}:__ksafe_value_k"), "source still present")

        localStorageRemove("ksafe.${base}:__ksafe_value_k")
        localStorageRemove("ksafe.ns@${base}:__ksafe_value_k")
    }

    /**
     * Round-3 audit R4 (findings 6/13): on web, `KSafeConfig.appNamespace` must
     * isolate the localStorage DATA namespace, not just the IndexedDB key record.
     * Two same-origin KSafe setups with the SAME fileName but DIFFERENT
     * appNamespace (the exact case appNamespace exists to separate) must not
     * collide on the same data slots and overwrite each other.
     */
    @Test
    fun appNamespace_isolatesTheDataStore_forSameFileName() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()
        val appA = KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.a"), testEngine = FakeEncryption())
        val appB = KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.b"), testEngine = FakeEncryption())
        appA.awaitCacheReady()
        appB.awaitCacheReady()

        appA.put("token", "value-A", KSafeWriteMode.Plain)
        appB.put("token", "value-B", KSafeWriteMode.Plain)

        // Read through FRESH instances so the answer comes from localStorage, not
        // the original instance's optimistic cache.
        val appAReopened = KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.a"), testEngine = FakeEncryption())
        val appBReopened = KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.b"), testEngine = FakeEncryption())
        appAReopened.awaitCacheReady()
        appBReopened.awaitCacheReady()

        assertEquals("value-A", appAReopened.get("token", "GONE"), "app A must keep its own value across a same-fileName different-appNamespace app")
        assertEquals("value-B", appBReopened.get("token", "GONE"), "app B must keep its own value")

        appAReopened.clearAll(); appBReopened.clearAll()
    }
}
