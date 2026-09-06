package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeReservedKeys
import eu.anifantakis.lib.ksafe.internal.WebSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.localStorageGet
import eu.anifantakis.lib.ksafe.internal.localStorageKey
import eu.anifantakis.lib.ksafe.internal.localStorageLength
import eu.anifantakis.lib.ksafe.internal.localStorageSet
import eu.anifantakis.lib.ksafe.internal.webKeyMigrationSealMarker
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Locks in: the un-namespaced IndexedDB key record is a retained migration source, so a tombstone
 * must stop a fresh engine re-copying a deleted key out of it — otherwise old ciphertext backups
 * decrypt again. Tombstones are permanent localStorage entries clearAll() cannot erase, so the
 * rest pins how few may be written against the origin's ~5 MB quota.
 */
class WebKeyTombstoneTest {

    /** Every deletion tombstone belonging to the store built on [fileName]. */
    private fun tombstonesOf(fileName: String): List<String> = buildList {
        for (i in 0 until localStorageLength()) {
            val key = localStorageKey(i) ?: continue
            if (key.startsWith("ksafe.__nskeydel__.") && key.contains("ksafe_${fileName}_")) add(key)
        }
    }

    @Test
    fun deletedNamespacedKey_isNotResurrectedFromTheRetainedSource_byAFreshEngine() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()
        val enginePrefix = "ksafe_${file}_"
        val payload = "shared-secret".encodeToByteArray()

        // The un-namespaced sibling mints the shared source key (real WebCrypto).
        val noNs = WebSoftwareEncryption(KSafeConfig(), enginePrefix)
        val ct = noNs.encryptSuspend("token", payload)

        val cfg = KSafeConfig(appNamespace = "com.example.tomb")
        val ns = WebSoftwareEncryption(cfg, enginePrefix)
        assertContentEquals(payload, ns.decryptSuspend("token", ct), "precondition: migrate-forward works")

        ns.deleteKeySuspend("token")

        // Fresh engine, so fresh in-memory migration state: only the tombstone can stop the copy.
        val fresh = WebSoftwareEncryption(cfg, enginePrefix)
        assertFails("a deleted namespaced key must not be re-supplied by the retained source") {
            fresh.decryptSuspend("token", ct)
        }

        assertContentEquals(
            payload, noNs.decryptSuspend("token", ct),
            "the retained un-namespaced source must never be deleted by a namespaced delete",
        )
    }

    /**
     * The sweep enumerates both alias spellings, but the web factory strips `requireUnlockedDevice`
     * before the routing record is built, so no web entry can ever name the strict one.
     */
    @Test
    fun delete_writesNoTombstoneForTheAliasSpellingWebCanNeverMint() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()
        // Real engine: FakeEncryption writes no tombstones at all.
        val safe = KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.strict"))
        safe.awaitCacheReady()

        safe.put("token", "secret", KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))
        safe.delete("token")

        val tombstones = tombstonesOf(file)
        assertTrue(
            tombstones.isNotEmpty(),
            "precondition: deleting a per-entry-keyed entry tombstones the alias it actually used",
        )
        assertEquals(
            emptyList(), tombstones.filter { it.contains(KSafeReservedKeys.STRICT_VARIANT) },
            "no tombstone may name the strict alias spelling: web strips requireUnlockedDevice, " +
                "so no entry can ever be keyed under it",
        )

        safe.clearAll()
    }

    /**
     * `clearAll()` seals every copy-forward into this store, so no ciphertext can arrive that would
     * need a migrated key and a per-alias tombstone has nothing left to protect.
     */
    @Test
    fun clearAll_sealsTheKeyMigration_soLaterDeletesStopWritingTombstones() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()
        val config = KSafeConfig(appNamespace = "com.example.seal")
        val safe = KSafe(fileName = file, config = config)
        safe.awaitCacheReady()

        safe.put("first", "v1", KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))
        safe.clearAll()

        assertNotNull(
            localStorageGet(assertNotNull(webKeyMigrationSealMarker(config.appNamespace, "ksafe_${file}_", file))),
            "clearAll() must seal this namespace's key migrate-forward",
        )

        val afterClear = tombstonesOf(file).toSet()
        safe.put("second", "v2", KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))
        safe.delete("second")

        assertEquals(
            afterClear, tombstonesOf(file).toSet(),
            "with the migration sealed, a later delete must not add per-alias tombstones",
        )

        safe.clearAll()
    }

    /** The seal replaces the per-alias tombstones, so it has to carry their whole job. */
    @Test
    fun sealedNamespace_stillRefusesToResurrectADeletedKey() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()
        val enginePrefix = "ksafe_${file}_"
        val payload = "shared-secret".encodeToByteArray()

        val noNs = WebSoftwareEncryption(KSafeConfig(), enginePrefix)
        val ct = noNs.encryptSuspend("token", payload)

        val config = KSafeConfig(appNamespace = "com.example.sealtomb")
        val ns = WebSoftwareEncryption(config, enginePrefix)
        assertContentEquals(payload, ns.decryptSuspend("token", ct), "precondition: migrate-forward works")

        // The state a clearAll leaves behind, without the per-alias tombstone.
        localStorageSet(assertNotNull(webKeyMigrationSealMarker(config.appNamespace, enginePrefix, null)), "1")
        ns.deleteKeySuspend("token")

        val fresh = WebSoftwareEncryption(config, enginePrefix)
        assertFails("a sealed namespace must not be re-supplied by the retained source") {
            fresh.decryptSuspend("token", ct)
        }
        assertContentEquals(
            payload, noNs.decryptSuspend("token", ct),
            "the retained un-namespaced source must stay untouched",
        )
    }
}
