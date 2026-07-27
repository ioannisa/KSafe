package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.localStorageGet
import eu.anifantakis.lib.ksafe.internal.localStorageRemove
import eu.anifantakis.lib.ksafe.internal.localStorageSet
import eu.anifantakis.lib.ksafe.internal.migrateLegacyLocalStoragePrefix
import eu.anifantakis.lib.ksafe.internal.migratePrefixedEntries
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Locks in: the prefix-free `ksafe.<name>:` localStorage scheme — sibling and nested
 * stores never collide on `startsWith()` scoping or `clearAll()`, and the unnamed
 * `KSafe()` stays distinct from `KSafe("default")` — plus its one-time migration from
 * the legacy `ksafe_<name>_` scheme.
 */
class WebPrefixIsolationTest {

    @Test
    fun nestedFileNames_clearAll_doesNotWipeSiblingStore() = runTest {
        // Nested pair, unique per run so reruns don't collide.
        val base = WebKSafeTest.generateUniqueFileName()
        val outer = KSafe(fileName = base, testEngine = FakeEncryption())
        val nested = KSafe(fileName = "${base}_cache", testEngine = FakeEncryption())
        outer.awaitCacheReady()
        nested.awaitCacheReady()

        outer.put("k", "outer-value", KSafeWriteMode.Plain)
        nested.put("k", "nested-value", KSafeWriteMode.Plain)

        // Wipe must be prefix-free: a startsWith() wipe would also delete the sibling's entries.
        outer.clearAll()

        // Read via a FRESH instance so the answer comes from disk, not the optimistic cache.
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

        // Constructed after the sibling has data on disk; its snapshot must not ingest the sibling's entries.
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
    fun appNamespace_clearAll_doesNotResurrectSecretFromUnNamespacedSource() = runTest {
        val base = WebKSafeTest.generateUniqueFileName()

        // Pre-upgrade layout: a no-namespace store on this fileName holds the secret.
        val preUpgrade = KSafe(fileName = base, testEngine = FakeEncryption())
        preUpgrade.awaitCacheReady()
        preUpgrade.put("token", "secret", KSafeWriteMode.Plain)

        // Upgrade: add an appNamespace. The un-namespaced data copies forward once.
        val ns = KSafe(fileName = base, config = KSafeConfig(appNamespace = "app1"), testEngine = FakeEncryption())
        ns.awaitCacheReady()
        assertEquals("secret", ns.get("token", "GONE"), "the un-namespaced secret migrates forward on upgrade")

        // Logout wipes the namespaced store.
        ns.clearAll()

        // Reconstructing the namespaced store must NOT re-seed the secret from the still-present
        // un-namespaced source: the one-time done-marker (kept outside the cleared prefix) blocks it.
        val nsReopened = KSafe(fileName = base, config = KSafeConfig(appNamespace = "app1"), testEngine = FakeEncryption())
        nsReopened.awaitCacheReady()
        assertEquals(
            "GONE",
            nsReopened.get("token", "GONE"),
            "clearAll() must durably erase the secret; the copy-forward must not resurrect it",
        )

        // The co-existing no-namespace sibling still keeps its own data (never cannibalized).
        val siblingReopened = KSafe(fileName = base, testEngine = FakeEncryption())
        siblingReopened.awaitCacheReady()
        assertEquals("secret", siblingReopened.get("token", "GONE"), "the no-namespace sibling keeps its own data")

        nsReopened.clearAll()
        siblingReopened.clearAll()
    }

    @Test
    fun legacyPrefix_appNamespace_clearAll_doesNotResurrectSecret() = runTest {
        val base = WebKSafeTest.generateUniqueFileName()
        // Intermediate pre-appNamespace scheme: canonical data under the flat legacy `ksafe_<file>_`.
        localStorageSet("ksafe_${base}___ksafe_value_token", "legacy-secret")

        // First namespaced construction migrates the legacy value forward (once).
        val ns = KSafe(fileName = base, config = KSafeConfig(appNamespace = "app1"), testEngine = FakeEncryption())
        ns.awaitCacheReady()
        assertEquals(
            "legacy-secret", localStorageGet("ksafe.app1@${base}:__ksafe_value_token"),
            "the legacy value migrates forward on the first namespaced construction",
        )

        // Logout: web clear() sweeps only storagePrefix.
        ns.clearAll()
        assertNull(
            localStorageGet("ksafe.app1@${base}:__ksafe_value_token"),
            "clearAll must wipe the namespaced value",
        )

        // Reconstructing must NOT re-seed from the still-present legacy source: the one-time
        // done-marker (kept outside the cleared prefix) blocks the legacy copy-forward.
        val nsReopened = KSafe(fileName = base, config = KSafeConfig(appNamespace = "app1"), testEngine = FakeEncryption())
        nsReopened.awaitCacheReady()
        assertNull(
            localStorageGet("ksafe.app1@${base}:__ksafe_value_token"),
            "the legacy copy-forward must be one-time: a clearAll-wiped secret must not be resurrected",
        )

        nsReopened.clearAll()
        localStorageRemove("ksafe_${base}___ksafe_value_token")
    }

    /**
     * The migration done-markers are written best-effort: if the marker write failed
     * (quota/SecurityError) after a successful copy, reconstruction re-runs the copy-forward.
     * clearAll() must therefore seal the markers itself — an explicit wipe means the user chose
     * an empty store, and the retained source (which outlives the wipe by design) must not
     * re-seed the wiped secrets on the next construction.
     */
    @Test
    fun clearAll_sealsMigrationMarkers_soAFailedMarkerWriteCannotResurrectSecrets() = runTest {
        val base = WebKSafeTest.generateUniqueFileName()

        // Pre-upgrade layout: an un-namespaced store on this fileName holds the secret.
        val preUpgrade = KSafe(fileName = base, testEngine = FakeEncryption())
        preUpgrade.awaitCacheReady()
        preUpgrade.put("token", "secret", KSafeWriteMode.Plain)

        // Upgrade: the copy-forward runs and sets its one-time markers.
        val ns = KSafe(fileName = base, config = KSafeConfig(appNamespace = "app1"), testEngine = FakeEncryption())
        ns.awaitCacheReady()
        assertEquals("secret", ns.get("token", "GONE"), "the un-namespaced secret migrates forward on upgrade")

        // Simulate the marker writes having failed: copies succeeded but no marker exists —
        // the state that used to let the retained source re-seed the store after a wipe.
        localStorageRemove("ksafe.__nsmigrated__.app1@$base")
        localStorageRemove("ksafe.__legacymigrated__.app1@$base")

        ns.clearAll()

        // clear() sealed the markers, so reconstruction must not re-seed from the
        // still-present un-namespaced source.
        val nsReopened = KSafe(fileName = base, config = KSafeConfig(appNamespace = "app1"), testEngine = FakeEncryption())
        nsReopened.awaitCacheReady()
        assertEquals(
            "GONE",
            nsReopened.get("token", "GONE"),
            "clearAll() must seal the migration markers: a failed marker write must not allow resurrection",
        )

        // The co-existing no-namespace sibling still owns its data.
        val siblingReopened = KSafe(fileName = base, testEngine = FakeEncryption())
        siblingReopened.awaitCacheReady()
        assertEquals("secret", siblingReopened.get("token", "GONE"), "the no-namespace sibling keeps its own data")

        nsReopened.clearAll()
        siblingReopened.clearAll()
    }

    /**
     * A uniquely-named store MOVES its flat legacy prefix forward instead of copying it, and that
     * move is the one migration with no done-marker at all. A copy that failed (quota) — or a
     * source `remove` that failed — leaves the entry behind at the source, which is the state
     * seeded here: legacy entry present, no marker. `clearAll()` must seal the migration, or the
     * wipe frees the very quota that broke the copy and the next construction copies the
     * explicitly-wiped secret straight back in.
     */
    @Test
    fun clearAll_sealsTheLegacyMigration_ofAStoreThatOwnsItsLegacyPrefixAlone() = runTest {
        // Unique and not "default", so this store owns `ksafe_<base>_` alone and moves it.
        val base = WebKSafeTest.generateUniqueFileName()
        val legacySource = "ksafe_${base}___ksafe_value_token"
        val marker = "ksafe.__legacymigrated__.$base"

        localStorageSet(legacySource, "legacy-secret")
        val safe = KSafe(fileName = base, testEngine = FakeEncryption())
        safe.awaitCacheReady()
        assertEquals(
            "legacy-secret", localStorageGet("ksafe.$base:__ksafe_value_token"),
            "precondition: the legacy entry migrates forward on construction",
        )

        // The aftermath of a partly-failed migration: the source survived and no marker was set.
        localStorageSet(legacySource, "legacy-secret")
        localStorageRemove(marker)

        safe.clearAll()
        assertNull(
            localStorageGet("ksafe.$base:__ksafe_value_token"),
            "clearAll must wipe the migrated value",
        )

        val reopened = KSafe(fileName = base, testEngine = FakeEncryption())
        reopened.awaitCacheReady()
        assertNull(
            localStorageGet("ksafe.$base:__ksafe_value_token"),
            "an explicitly wiped secret must not be copied back in from the legacy leftover",
        )
        assertEquals(
            "GONE", reopened.get("token", "GONE"),
            "the wiped entry must stay gone after a reload",
        )

        localStorageRemove(legacySource)
        reopened.clearAll()
    }

    @Test
    fun fileNameDefault_isDistinctFromUnnamedInstance() = runTest {
        // Old scheme: both produced prefix `ksafe_default_` — one shared slot under two crypto aliases.
        val unnamed = KSafe(testEngine = FakeEncryption())
        val named = KSafe(fileName = "default", testEngine = FakeEncryption())
        unnamed.awaitCacheReady()
        named.awaitCacheReady()

        val key = "collision_probe_${WebKSafeTest.generateUniqueFileName()}"
        unnamed.put(key, "from-unnamed", KSafeWriteMode.Plain)
        named.put(key, "from-named", KSafeWriteMode.Plain)

        // Read via a FRESH unnamed instance (from disk): under the old shared slot the named put
        // was last writer and overwrote the unnamed store, masked only by the optimistic cache.
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

        // Legacy data: canonical entries under the OLD prefixes of a store and its nested sibling.
        localStorageSet("ksafe_${base}___ksafe_value_k", "legacy-value")
        localStorageSet("ksafe_${base}_cache___ksafe_value_k", "sibling-value")

        migrateLegacyLocalStoragePrefix("ksafe_${base}_", "ksafe.${base}:")

        // Own canonical entry moved (copy + verify + delete).
        assertEquals("legacy-value", localStorageGet("ksafe.${base}:__ksafe_value_k"))
        assertNull(localStorageGet("ksafe_${base}___ksafe_value_k"), "old entry must be removed after a verified copy")
        // The nested sibling's entry is left for the sibling's own migration.
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
     * The migration must NOT move a nested sibling store's FLAT legacy entry (bare `<key>` /
     * `encrypted_<key>`): it carries no canonical marker, so a shorter-named store cannot tell it
     * from its own flat keys — moving it would delete the sibling's only copy and surface it under
     * the shorter store (cross-store plaintext bleed). Every non-canonical entry is left untouched
     * to preserve prefix-free isolation.
     */
    @Test
    fun legacyFlatData_ofNestedSibling_isNotStolenByShorterStore() {
        val base = WebKSafeTest.generateUniqueFileName()
        // Flat legacy layout: the sibling's plain value at "ksafe_<base>_cache_foo" (no marker),
        // encrypted at "ksafe_<base>_cache_encrypted_foo".
        localStorageSet("ksafe_${base}_cache_foo", "sibling-flat-plain")
        localStorageSet("ksafe_${base}_cache_encrypted_foo", "sibling-flat-cipher")

        // The shorter-named store migrates.
        migrateLegacyLocalStoragePrefix("ksafe_${base}_", "ksafe.${base}:")

        // The sibling's flat entries must be left exactly where they were.
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
        // And must NOT have leaked into the shorter store's namespace.
        assertNull(
            localStorageGet("ksafe.${base}:cache_foo"),
            "the shorter store must not surface the sibling's flat data under its own prefix",
        )

        localStorageRemove("ksafe_${base}_cache_foo")
        localStorageRemove("ksafe_${base}_cache_encrypted_foo")
    }

    /**
     * Constructing an appNamespaced store must NOT cannibalize a co-existing no-namespace store on
     * the same fileName. The un-namespaced upgrade migration's source prefix `ksafe.<file>:` is that
     * sibling's LIVE prefix and runs on every construction, so it must be non-destructive
     * (copy-if-absent, no source delete), mirroring the non-destructive key migration.
     */
    @Test
    fun appNamespacedStore_doesNotCannibalize_coexistingNoNamespaceStore() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()

        // A no-namespace store writes a value…
        val plain = KSafe(fileName = file, testEngine = FakeEncryption())
        plain.awaitCacheReady()
        plain.put("token", "plain-value", KSafeWriteMode.Plain)

        // …then a same-fileName appNamespaced store is constructed (runs the un-namespaced migration).
        KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.a"), testEngine = FakeEncryption())
            .awaitCacheReady()

        // Re-open the no-namespace store fresh so the read comes from localStorage.
        val plainReopened = KSafe(fileName = file, testEngine = FakeEncryption())
        plainReopened.awaitCacheReady()
        assertEquals(
            "plain-value", plainReopened.get("token", "GONE"),
            "a co-existing no-namespace store's value must survive construction of a same-fileName appNamespaced store",
        )

        // A fresh no-namespace write after another namespaced construction must also survive.
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
     * The flat legacy `ksafe_<file>_` prefix has NO appNamespace segment — one SHARED source for
     * every namespace of a fileName. The legacy→namespaced migration must therefore be
     * non-destructive, or the first-constructed namespace copies the data to itself and deletes the
     * shared source, so every OTHER namespace of that fileName reads the default for keys it owned.
     */
    @Test
    fun legacyPrefix_withAppNamespace_isNotDeleted_soAllNamespacesCanMigrate() = runTest {
        val base = WebKSafeTest.generateUniqueFileName()
        // Pre-namespace canonical data under the flat legacy prefix.
        localStorageSet("ksafe_${base}___ksafe_value_k", "legacy-value")

        // First namespaced store migrates the legacy prefix forward but must NOT delete the shared source.
        KSafe(fileName = base, config = KSafeConfig(appNamespace = "com.example.a"), testEngine = FakeEncryption())
            .awaitCacheReady()

        assertEquals(
            "legacy-value", localStorageGet("ksafe_${base}___ksafe_value_k"),
            "the shared legacy source must survive a namespaced construction",
        )
        assertEquals(
            "legacy-value", localStorageGet("ksafe.com.example.a@${base}:__ksafe_value_k"),
            "namespace A must have migrated the legacy value forward",
        )

        // A second same-fileName namespaced store must STILL find and migrate the legacy source.
        KSafe(fileName = base, config = KSafeConfig(appNamespace = "com.example.b"), testEngine = FakeEncryption())
            .awaitCacheReady()
        assertEquals(
            "legacy-value", localStorageGet("ksafe.com.example.b@${base}:__ksafe_value_k"),
            "namespace B must ALSO migrate the still-present legacy value (the first namespace must not have deleted the shared source)",
        )

        localStorageRemove("ksafe_${base}___ksafe_value_k")
        localStorageRemove("ksafe.com.example.a@${base}:__ksafe_value_k")
        localStorageRemove("ksafe.com.example.b@${base}:__ksafe_value_k")
    }

    /**
     * `KSafe()` (unnamed) and `KSafe(fileName = "default")` share the same legacy migration source
     * (`ksafe_default_`) but get distinct new prefixes, so the legacy migration must be
     * non-destructive — otherwise whichever constructs first copies the shared data and deletes the
     * source, stranding it for the other.
     */
    @Test
    fun legacyDefaultPrefix_sharedByUnnamedAndDefaultNamed_isNotDeleted_soBothMigrate() = runTest {
        val k = "token_${WebKSafeTest.generateUniqueFileName()}" // unique key under the shared prefix
        // The legacy copy-forward is one-time per store, gated on a persistent done-marker. These
        // singleton stores share a GLOBAL marker (no fileName segment), so a prior test that already
        // constructed KSafe()/KSafe("default") would have set it and block this injected migration.
        // Clear both so this test drives the first-migration path deterministically.
        localStorageRemove("ksafe.__legacymigrated__.")
        localStorageRemove("ksafe.__legacymigrated__.default")
        localStorageSet("ksafe_default___ksafe_value_$k", "shared-legacy")

        // Unnamed instance migrates to `ksafe.:` WITHOUT deleting the shared source.
        KSafe(testEngine = FakeEncryption()).awaitCacheReady()
        assertEquals(
            "shared-legacy", localStorageGet("ksafe.:__ksafe_value_$k"),
            "the unnamed store must migrate the legacy value",
        )
        assertEquals(
            "shared-legacy", localStorageGet("ksafe_default___ksafe_value_$k"),
            "the shared legacy source must survive an unnamed construction",
        )

        // The 'default'-named instance still finds the source and migrates it too.
        KSafe(fileName = "default", testEngine = FakeEncryption()).awaitCacheReady()
        assertEquals(
            "shared-legacy", localStorageGet("ksafe.default:__ksafe_value_$k"),
            "the 'default'-named store must ALSO migrate the still-present shared legacy value",
        )

        localStorageRemove("ksafe_default___ksafe_value_$k")
        localStorageRemove("ksafe.:__ksafe_value_$k")
        localStorageRemove("ksafe.default:__ksafe_value_$k")
        localStorageRemove("ksafe.__legacymigrated__.")
        localStorageRemove("ksafe.__legacymigrated__.default")
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
     * On web, `KSafeConfig.appNamespace` must isolate the localStorage DATA namespace, not just the
     * IndexedDB key record: two same-origin setups with the SAME fileName but DIFFERENT appNamespace
     * must not collide on the same data slots and overwrite each other.
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

        // Read via FRESH instances so the answer comes from localStorage, not the optimistic cache.
        val appAReopened = KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.a"), testEngine = FakeEncryption())
        val appBReopened = KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.b"), testEngine = FakeEncryption())
        appAReopened.awaitCacheReady()
        appBReopened.awaitCacheReady()

        assertEquals("value-A", appAReopened.get("token", "GONE"), "app A must keep its own value across a same-fileName different-appNamespace app")
        assertEquals("value-B", appBReopened.get("token", "GONE"), "app B must keep its own value")

        appAReopened.clearAll(); appBReopened.clearAll()
    }

    /**
     * A per-entry copy failure (e.g. QuotaExceededError on one large value) must surface as a
     * `false` return so the construction-time done-markers are withheld and the migration retries
     * on the next construction. Otherwise the tiny marker write still succeeds, the migration
     * never re-runs, and the source values are stranded forever — the store silently reads
     * defaults. Entries that fit must still copy.
     */
    @Test
    fun migration_reportsPartialCopyFailure_soTheMarkerIsWithheld_andRetryCompletes() {
        val store = HashMap<String, String>()
        store["old___ksafe_value_big"] = "BIG-VALUE"
        store["old___ksafe_value_small"] = "small-value"

        fun migrate(set: (String, String) -> Unit) = migratePrefixedEntries(
            sourceKeys = store.keys.filter { it.startsWith("old_") },
            oldPrefix = "old_",
            newPrefix = "new_",
            deleteSource = false,
            get = { store[it] },
            set = set,
            remove = { store.remove(it) },
        )

        val partial = migrate { k, v ->
            if (k.contains("big")) throw IllegalStateException("quota exceeded") else store[k] = v
        }
        assertFalse(partial, "a swallowed per-entry copy failure must be reported so the done-marker is withheld")
        assertEquals("small-value", store["new___ksafe_value_small"], "entries that fit must still copy")
        assertNull(store["new___ksafe_value_big"], "the failed entry stays uncopied, awaiting retry")

        // Next construction (marker still absent) retries and completes; only now may the marker be set.
        val retry = migrate { k, v -> store[k] = v }
        assertTrue(retry, "a fully successful retry must report success so the marker can finally be set")
        assertEquals("BIG-VALUE", store["new___ksafe_value_big"], "the retry must complete the interrupted copy")
        assertEquals("small-value", store["new___ksafe_value_small"], "already-copied entries stay in place")
    }

    /**
     * With `deleteSource = true` a failed copy must keep its source (the only surviving copy)
     * while verified copies still release theirs, and the overall result still reports the
     * failure. Non-canonical entries are skipped, not counted as failures.
     */
    @Test
    fun migration_withDeleteSource_keepsSourceOfFailedCopy_andReleasesVerifiedOnes() {
        val store = HashMap<String, String>()
        store["old___ksafe_value_big"] = "BIG-VALUE"
        store["old___ksafe_value_small"] = "small-value"
        store["old_engine_record"] = "non-canonical"

        val result = migratePrefixedEntries(
            sourceKeys = store.keys.filter { it.startsWith("old_") },
            oldPrefix = "old_",
            newPrefix = "new_",
            deleteSource = true,
            get = { store[it] },
            set = { k, v -> if (k.contains("big")) throw IllegalStateException("quota exceeded") else store[k] = v },
            remove = { store.remove(it) },
        )

        assertFalse(result, "the failed copy must be reported even when other entries migrated")
        assertEquals("BIG-VALUE", store["old___ksafe_value_big"], "the failed entry's source is the only copy and must survive")
        assertNull(store["old___ksafe_value_small"], "a verified copy releases its source")
        assertEquals("small-value", store["new___ksafe_value_small"], "the verified copy is at the destination")
        assertEquals("non-canonical", store["old_engine_record"], "non-canonical entries are left untouched")
        assertNull(store["new_engine_record"], "non-canonical entries must not be migrated")
    }
}
