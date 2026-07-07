package eu.anifantakis.lib.ksafe

import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Locks in: DEFAULT writes share a per-datastore master key and are marked v2, while v1 on-disk entries still read via the legacy per-entry-key path. */
class JvmV2EnvelopeTest {

    private fun masterAliasFor(fileName: String): String = "$fileName:__ksafe_master__"

    private fun keyAliasFor(fileName: String, userKey: String): String = "$fileName:$userKey"

    private fun keyStorageRawKey(alias: String): String = "ksafe_key_$alias"

    private suspend fun snapshot(ksafe: KSafe): Preferences = ksafe.dataStore.data.first()

    private fun Preferences.getString(rawKey: String): String? =
        this[stringPreferencesKey(rawKey)]

    @Test
    fun newDefaultWritesAreMarkedV2InMetadata() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName)

        ksafe.put("foo", "bar")
        delay(300)

        val meta = snapshot(ksafe).getString("__ksafe_meta_foo__")
        assertNotNull(meta, "metadata for v2 entry must be persisted")
        assertTrue(meta.contains("\"v\":2"), "v2 envelope marker missing — got: $meta")
        assertTrue(meta.contains("\"p\":\"DEFAULT\""), "protection literal must be DEFAULT — got: $meta")

        assertEquals("bar", ksafe.get("foo", "DEFAULT"))
    }

    @Test
    fun defaultWritesUseSharedMasterKeyAndNotPerEntryKey() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName)

        ksafe.put("alpha", "1")
        ksafe.put("beta", "2")
        ksafe.put("gamma", "3")
        delay(500)

        val prefs = snapshot(ksafe)

        // One shared master (relaxed/non-locked variant); no per-entry key — all keys share it.
        val masterRaw = prefs.getString(keyStorageRawKey(masterAliasFor(fileName)))
        assertNotNull(masterRaw, "master key not persisted for v2 default writes")

        for (userKey in listOf("alpha", "beta", "gamma")) {
            val perEntry = prefs.getString(keyStorageRawKey(keyAliasFor(fileName, userKey)))
            assertNull(perEntry, "per-entry key for $userKey must not exist when v2 routes to master")
        }

        assertEquals("1", ksafe.get("alpha", "?"))
        assertEquals("2", ksafe.get("beta", "?"))
        assertEquals("3", ksafe.get("gamma", "?"))
    }

    @Test
    fun legacyV1EntryOnDiskRemainsReadable() = runTest {
        // A v1 entry carries the legacy literal "DEFAULT" meta (no `v` field) and must
        // still decrypt via the per-entry alias path.
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val seedKsafe = KSafe(fileName)
        seedKsafe.put("legacyKey", "legacyValue")
        delay(300)

        val ds = seedKsafe.dataStore
        assertTrue(snapshot(seedKsafe).getString("__ksafe_meta_legacyKey__")!!.contains("\"v\":2"))

        // Rewrite on-disk to the v1 shape: encrypt under the per-entry alias, replace meta with the legacy literal.
        val ciphertextB64 = seedKsafe.engine.encrypt(
            identifier = keyAliasFor(fileName, "legacyKey"),
            data = "\"legacyValue\"".encodeToByteArray(),
        ).let { encodeBase64(it) }
        ds.edit { prefs ->
            prefs[stringPreferencesKey("__ksafe_value_legacyKey")] = ciphertextB64
            prefs[stringPreferencesKey("__ksafe_meta_legacyKey__")] = "DEFAULT" // legacy literal
        }
        seedKsafe.close()
        delay(200) // let DataStore flush before reopening

        val reopened = KSafe(fileName)
        delay(400) // let cache populate
        assertEquals("legacyValue", reopened.get("legacyKey", "?"))
    }

    @Test
    fun overwritingV1EntryWithV2DoesNotBreakRead() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val seedKsafe = KSafe(fileName)

        // Fabricate a v1 entry on disk.
        val ciphertextB64 = seedKsafe.engine.encrypt(
            identifier = keyAliasFor(fileName, "k"),
            data = "\"v1value\"".encodeToByteArray(),
        ).let { encodeBase64(it) }
        seedKsafe.dataStore.edit { prefs ->
            prefs[stringPreferencesKey("__ksafe_value_k")] = ciphertextB64
            prefs[stringPreferencesKey("__ksafe_meta_k__")] = "DEFAULT"
        }
        seedKsafe.close()
        delay(200)

        val reopened = KSafe(fileName)
        delay(300)

        assertEquals("v1value", reopened.get("k", "?"))

        reopened.put("k", "v2value")
        delay(400)

        val meta = snapshot(reopened).getString("__ksafe_meta_k__")
        assertTrue(meta!!.contains("\"v\":2"), "overwrite must produce v2 meta — got: $meta")
        assertEquals("v2value", reopened.get("k", "?"))
    }

    @Test
    fun deletingV2DefaultEntryDoesNotRemoveMasterKey() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName)

        ksafe.put("a", "1")
        ksafe.put("b", "2")
        delay(400)

        assertNotNull(snapshot(ksafe).getString(keyStorageRawKey(masterAliasFor(fileName))))

        // Deleting one entry must leave the master — other entries still depend on it.
        ksafe.delete("a")
        delay(300)

        assertNotNull(
            snapshot(ksafe).getString(keyStorageRawKey(masterAliasFor(fileName))),
            "master key must survive single-entry delete (other entries still depend on it)"
        )
        assertEquals("2", ksafe.get("b", "?"))
    }

    @Test
    fun clearAllRemovesMasterKey() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName)

        ksafe.put("x", "y")
        delay(300)

        assertNotNull(snapshot(ksafe).getString(keyStorageRawKey(masterAliasFor(fileName))))

        ksafe.clearAll()
        delay(300)

        // The JVM shell wipes the DataStore file on clearAll, so the master key that lived in it is gone.
        val prefs = snapshot(ksafe)
        assertNull(
            prefs.getString(keyStorageRawKey(masterAliasFor(fileName))),
            "clearAll must drop the master key"
        )
        assertFalse(
            prefs.asMap().keys.any { it.name.startsWith("__ksafe_value_") },
            "no user values should remain after clearAll"
        )
    }

    @Test
    fun clearAllDeletesPerEntryHardwareIsolatedKeyNotJustMaster() = runTest {
        // Per-entry HARDWARE_ISOLATED (and legacy v1) keys live OUTSIDE the DataStore on real
        // OS-vault/web backends with no startup orphan sweep, so clearAll must delete them
        // explicitly or they leak across cycles. FakeEncryption records every deleteKey
        // identifier, so we can assert the engine was asked to drop them.
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val fake = FakeEncryption()
        val ksafe = KSafe(fileName = fileName, testEngine = fake)

        ksafe.put("plainSecret", "a")  // DEFAULT → master alias
        ksafe.put(
            "hwSecret", "b",
            mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED),
        )                               // HARDWARE_ISOLATED → per-entry alias
        delay(300)

        fake.deletedKeys.clear()        // ignore deletes from the writes themselves
        ksafe.clearAll()
        delay(300)

        assertTrue(
            fake.deletedKeys.contains(keyAliasFor(fileName, "hwSecret")),
            "clearAll must delete the per-entry HARDWARE_ISOLATED key; deleted=${fake.deletedKeys}",
        )
        assertTrue(
            fake.deletedKeys.contains(masterAliasFor(fileName)),
            "clearAll must still delete the master key; deleted=${fake.deletedKeys}",
        )
    }

    @Test
    fun clearAll_onFreshLazyInstance_stillDeletesPerEntryKeys() = runTest {
        // clearAll reads protectionMap for per-entry engine keys; on a fresh lazyLoad instance
        // that map is empty until loaded, so clearAll must load the cache first
        // (ensureCacheReadySuspend) or the on-disk HARDWARE_ISOLATED key leaks.
        val fileName = JvmKSafeTest.generateUniqueFileName()

        val seed = KSafe(fileName = fileName, testEngine = FakeEncryption())
        seed.put(
            "hwSecret", "b",
            mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED),
        )
        delay(300)
        seed.close()
        delay(200)

        val fake = FakeEncryption()
        val reopened = KSafe(fileName = fileName, lazyLoad = true, testEngine = fake)
        reopened.clearAll() // FIRST op — must still see the on-disk HW-isolated entry
        delay(200)

        assertTrue(
            fake.deletedKeys.contains(keyAliasFor(fileName, "hwSecret")),
            "clearAll on a fresh lazyLoad instance must still delete the per-entry " +
                "HARDWARE_ISOLATED key; deleted=${fake.deletedKeys}",
        )
    }
}
