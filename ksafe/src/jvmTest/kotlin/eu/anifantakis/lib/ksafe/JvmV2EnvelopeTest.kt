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

/**
 * Tests the v2 envelope: per-datastore master key for [KSafeProtection.DEFAULT]
 * writes, with v1 on-disk entries continuing to read through the legacy
 * per-entry-key path.
 *
 * Verifies the contract end-to-end against the real
 * [eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption] engine and the
 * underlying DataStore — no fakes — so a regression in routing or metadata
 * format would surface here.
 */
class JvmV2EnvelopeTest {

    private fun masterAliasFor(fileName: String): String = "$fileName:__ksafe_master__"

    private fun keyAliasFor(fileName: String, userKey: String): String = "$fileName:$userKey"

    private fun keyStorageRawKey(alias: String): String = "ksafe_key_$alias"

    /** Convenience: read the entire DataStore prefs map. */
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

        // Round-trip still works.
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

        // Master key must exist exactly once for the relaxed (non-locked) variant.
        val masterRaw = prefs.getString(keyStorageRawKey(masterAliasFor(fileName)))
        assertNotNull(masterRaw, "master key not persisted for v2 default writes")

        // No per-entry key should exist for any of the user keys — they all
        // share the master.
        for (userKey in listOf("alpha", "beta", "gamma")) {
            val perEntry = prefs.getString(keyStorageRawKey(keyAliasFor(fileName, userKey)))
            assertNull(perEntry, "per-entry key for $userKey must not exist when v2 routes to master")
        }

        // Reads round-trip.
        assertEquals("1", ksafe.get("alpha", "?"))
        assertEquals("2", ksafe.get("beta", "?"))
        assertEquals("3", ksafe.get("gamma", "?"))
    }

    @Test
    fun legacyV1EntryOnDiskRemainsReadable() = runTest {
        // Fabricate a v1 entry: write encrypted, then overwrite the meta to
        // the legacy literal "DEFAULT" form (no `v` field). KSafeCore must
        // still decrypt via the per-entry alias path because parseEnvelopeVersion
        // returns v1 for the literal form.
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val seedKsafe = KSafe(fileName)
        seedKsafe.put("legacyKey", "legacyValue")
        delay(300)

        // Pre-condition: the seed wrote v2.
        val ds = seedKsafe.dataStore
        assertTrue(snapshot(seedKsafe).getString("__ksafe_meta_legacyKey__")!!.contains("\"v\":2"))

        // Now mutate ON-DISK shape to look like a v1 entry: encrypt the value
        // under the per-entry alias and replace metadata with the legacy literal.
        // We do this by re-encrypting the value through the engine and patching
        // the prefs file directly.
        val ciphertextB64 = seedKsafe.engine.encrypt(
            identifier = keyAliasFor(fileName, "legacyKey"),
            data = "\"legacyValue\"".encodeToByteArray(),
        ).let { encodeBase64(it) }
        ds.edit { prefs ->
            prefs[stringPreferencesKey("__ksafe_value_legacyKey")] = ciphertextB64
            prefs[stringPreferencesKey("__ksafe_meta_legacyKey__")] = "DEFAULT" // legacy literal
        }
        seedKsafe.close()
        // Allow DataStore time to flush before reopening.
        delay(200)

        // Reopen — fresh KSafeCore reads the legacy entry via v1 path.
        val reopened = KSafe(fileName)
        delay(400) // let cache populate
        assertEquals("legacyValue", reopened.get("legacyKey", "?"))
    }

    @Test
    fun overwritingV1EntryWithV2DoesNotBreakRead() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val seedKsafe = KSafe(fileName)

        // Same as above: fabricate a v1 entry on disk.
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

        // Read v1 first (proves v1 path).
        assertEquals("v1value", reopened.get("k", "?"))

        // Overwrite with v2.
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

        // Master is created.
        assertNotNull(snapshot(ksafe).getString(keyStorageRawKey(masterAliasFor(fileName))))

        // Delete one entry — master stays.
        ksafe.delete("a")
        delay(300)

        assertNotNull(
            snapshot(ksafe).getString(keyStorageRawKey(masterAliasFor(fileName))),
            "master key must survive single-entry delete (other entries still depend on it)"
        )
        // The other entry must still decrypt.
        assertEquals("2", ksafe.get("b", "?"))
    }

    @Test
    fun clearAllRemovesMasterKey() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName)

        ksafe.put("x", "y")
        delay(300)

        // Sanity: master exists.
        assertNotNull(snapshot(ksafe).getString(keyStorageRawKey(masterAliasFor(fileName))))

        ksafe.clearAll()
        delay(300)

        // The DataStore file is also wiped by JVM shell's onClearAllCleanup,
        // so a follow-up snapshot would see the empty preferences. The master
        // key entry, which lived in the same file, must be gone.
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
        // Regression: clearAll used to delete only the master alias. Per-entry
        // HARDWARE_ISOLATED keys (and all legacy v1 keys) live OUTSIDE the
        // DataStore on the real OS-vault (Keychain/DPAPI/Secret Service) and web
        // (IndexedDB) backends, so wiping storage doesn't reclaim them — and those
        // platforms have no startup orphan sweep for engine keys. They leaked
        // across clearAll() cycles. clearAll must now explicitly delete them.
        //
        // FakeEncryption records every deleteKey identifier, so we can assert the
        // engine was asked to drop the per-entry alias regardless of where a real
        // engine would physically store it.
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val fake = FakeEncryption()
        val ksafe = KSafe(fileName = fileName, testEngine = fake)

        ksafe.put("plainSecret", "a")  // DEFAULT → master alias
        ksafe.put(
            "hwSecret", "b",
            mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED),
        )                               // HARDWARE_ISOLATED → per-entry alias
        delay(300)

        fake.deletedKeys.clear()        // ignore any deletes from the writes themselves
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
}
