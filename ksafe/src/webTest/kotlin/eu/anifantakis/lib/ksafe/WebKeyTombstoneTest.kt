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
 * Locks in: the un-namespaced IndexedDB key record is a RETAINED migration source (a
 * co-existing no-namespace sibling may own it live), so after a namespaced delete a
 * persistent tombstone must keep a FRESH engine from re-copying the deleted key out of it —
 * otherwise old ciphertext backups become decryptable again and the erasure contract of
 * `delete()`/`clearAll()` is silently undone.
 *
 * Those tombstones are permanent `localStorage` entries competing with the user's data for the
 * origin's ~5 MB quota and `clearAll()` deliberately cannot erase them, so the rest of this class
 * pins how few of them may be written: never for an alias spelling this platform can't mint, and
 * never once a wipe has sealed the migration they exist to block.
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

        // The namespaced engine migrates the key forward and can decrypt…
        val cfg = KSafeConfig(appNamespace = "com.example.tomb")
        val ns = WebSoftwareEncryption(cfg, enginePrefix)
        assertContentEquals(payload, ns.decryptSuspend("token", ct), "precondition: migrate-forward works")

        // …then deliberately deletes its copy.
        ns.deleteKeySuspend("token")

        // A FRESH engine (fresh in-memory migration state) must NOT re-copy the retained
        // source key: the deleted key stays deleted for this namespace.
        val fresh = WebSoftwareEncryption(cfg, enginePrefix)
        assertFails("a deleted namespaced key must not be re-supplied by the retained source") {
            fresh.decryptSuspend("token", ct)
        }

        // The sibling's live key is untouched — its own data keeps decrypting.
        assertContentEquals(
            payload, noNs.decryptSuspend("token", ct),
            "the retained un-namespaced source must never be deleted by a namespaced delete",
        )
    }

    /**
     * The delete sweep enumerates a per-entry alias in both the plain and the strict spelling, but
     * the web factory strips `requireUnlockedDevice` before the entry's routing record is built, so
     * no web entry can ever name the strict spelling. Tombstoning it burns the origin's shared
     * `localStorage` quota on an alias that cannot exist — and nothing can ever reclaim it.
     */
    @Test
    fun delete_writesNoTombstoneForTheAliasSpellingWebCanNeverMint() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()
        // REAL engine: FakeEncryption writes no tombstones at all.
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
     * `clearAll()` seals every copy-forward INTO this store, data and keys alike, so after a wipe
     * there is nothing left for a per-alias tombstone to protect: no ciphertext can arrive that
     * would need a migrated key. Continuing to write one per deleted alias only grows the
     * permanent, unreclaimable share of the origin quota the store consumes.
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

    /**
     * The seal replaces the per-alias tombstones, so it has to carry their whole job: a namespace
     * that deleted a key must still not have it re-supplied by the retained un-namespaced source.
     */
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
