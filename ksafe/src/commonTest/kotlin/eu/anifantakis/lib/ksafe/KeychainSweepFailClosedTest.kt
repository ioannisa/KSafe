package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeAliasFormat
import eu.anifantakis.lib.ksafe.internal.KSafeReservedKeys
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.keychainOrphanKeyId
import eu.anifantakis.lib.ksafe.internal.keychainOrphanSweepBlocked
import eu.anifantakis.lib.ksafe.internal.keychainOrphansToDelete
import eu.anifantakis.lib.ksafe.internal.keychainSweepValidKeys
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in: the Apple orphan sweep stands down whenever the store holds no evidence of ANY
 * encrypted entry, however many other records it happens to hold. The sweep deletes Keychain and
 * Secure Enclave key material that cannot be recreated, so a store whose encrypted view is only
 * PARTIALLY present (failed migration, quarantined-corrupt file, a restore that brought the
 * Keychain back but not the DataStore) must not be read as "these keys are orphans".
 *
 * Composed from the same pure steps the Apple sweep runs, so the decision is exercised on every
 * target — the sweep itself is Keychain I/O a sandboxed unit-test process cannot reach.
 */
class KeychainSweepFailClosedTest {

    private val masters = setOf(KSafeReservedKeys.MASTER, KSafeReservedKeys.MASTER_LOCKED)
    private val legacyEncryptedPrefix = KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX

    /** Mirrors `cleanupOrphanedKeychainEntries`: derive → classify → fail-closed gate → delete. */
    private fun sweepDeletes(
        snapshot: Map<String, StoredValue>,
        keychainAccounts: List<String>,
        fileName: String? = null,
    ): List<String> {
        val validKeys = keychainSweepValidKeys(snapshot, legacyEncryptedPrefix)
        val prefix = "${KSafeAliasFormat.dottedBase(fileName)}."
        val sePrefix = "se.$prefix"
        val orphans = keychainAccounts.mapNotNull { account ->
            keychainOrphanKeyId(account, prefix, fileName, validKeys, masters, ownedKeyIds = validKeys)
                ?: keychainOrphanKeyId(account, sePrefix, fileName, validKeys, masters, ownedKeyIds = validKeys)
        }.toSet()
        if (keychainOrphanSweepBlocked(validKeys, orphans.size)) return emptyList()
        return keychainOrphansToDelete(orphans, isInFlight = { false })
    }

    /** The two Keychain items one HARDWARE_ISOLATED entry owns: wrapped key + Secure Enclave tag. */
    private fun keychainItemsFor(userKey: String): List<String> = listOf(
        "${KSafeAliasFormat.dottedBase(null)}.$userKey",
        "se.${KSafeAliasFormat.dottedBase(null)}.$userKey",
    )

    private fun encryptedEntry(userKey: String): Map<String, StoredValue> = mapOf(
        KeySafeMetadataManager.valueRawKey(userKey) to StoredValue.Text("ciphertext"),
        KeySafeMetadataManager.metadataRawKey(userKey) to StoredValue.Text(
            KeySafeMetadataManager.buildMetadataJson(
                protection = KSafeProtection.HARDWARE_ISOLATED,
                accessPolicy = null,
            )
        ),
    )

    @Test
    fun storeHoldingOnlyAReservedInternalRecord_reapsNothing() {
        // A rotation leaves `__ksafe_keygen__` behind. If the entries themselves are missing —
        // the store was reinitialised, or its file never arrived — that single record is the
        // whole store: it says nothing about which Keychain keys are live, so a sweep that
        // treats "the store has records" as proof would destroy every Secure Enclave key.
        val snapshot = mapOf(
            KeySafeMetadataManager.KEYGEN_RAW_KEY to StoredValue.Text("{\"g\":2}"),
        )
        assertEquals(
            emptyList(),
            sweepDeletes(snapshot, keychainItemsFor("token")),
            "a store with no encrypted entry at all must not have its Keychain keys reaped",
        )
    }

    @Test
    fun storeHoldingOnlyPlainValues_reapsNothing() {
        // The same partial view, reached the ordinary way: after the store was lost the app wrote
        // one unencrypted setting. A plain entry carries no protection metadata, so it accounts
        // for no Keychain key — and must not vouch for the store's encrypted view either.
        val snapshot = mapOf(
            KeySafeMetadataManager.valueRawKey("theme") to StoredValue.Text("dark"),
            KeySafeMetadataManager.metadataRawKey("theme") to StoredValue.Text(
                KeySafeMetadataManager.buildMetadataJson(protection = null, accessPolicy = null)
            ),
        )
        assertEquals(
            emptyList(),
            sweepDeletes(snapshot, keychainItemsFor("token")),
            "a store holding only plaintext entries must not have its Keychain keys reaped",
        )
    }

    @Test
    fun storeThatLostOnlyItsProtectionMetadata_reapsNothing() {
        // Half a partial view: the ciphertext rows survived but their metadata did not, so no
        // entry can be matched to a key. Reaping here destroys the keys for ciphertext that is
        // still on disk — the most recoverable state there is, made unrecoverable.
        val snapshot = mapOf(
            KeySafeMetadataManager.valueRawKey("token") to StoredValue.Text("ciphertext"),
        )
        assertEquals(
            emptyList(),
            sweepDeletes(snapshot, keychainItemsFor("token")),
            "ciphertext without its metadata must not have its key reaped",
        )
    }

    @Test
    fun emptyStore_reapsNothing() {
        assertEquals(
            emptyList(),
            sweepDeletes(emptyMap(), keychainItemsFor("token")),
            "an empty store alongside scoped Keychain entries is a partial view, not an orphan set",
        )
    }

    @Test
    fun storeWithOneLiveEncryptedEntry_stillReapsAGenuineOrphan() {
        // The fail-closed gate must not disable the sweep: once the store proves its encrypted
        // view is present, a key with no entry behind it is reclaimable as before.
        val snapshot = encryptedEntry("token")
        val deleted = sweepDeletes(snapshot, keychainItemsFor("ghost"))
        assertEquals(
            listOf("ghost"),
            deleted.distinct(),
            "a store with live encrypted entries must still reap a genuinely orphaned key",
        )
        assertTrue(
            sweepDeletes(snapshot, keychainItemsFor("token")).isEmpty(),
            "the live entry's own key must be preserved",
        )
    }

    @Test
    fun legacyEncryptedEntryCountsAsEvidence() {
        // Pre-canonical stores hold `encrypted_<key>` rows and no metadata; they are real
        // encrypted entries and must vouch for the store the same way canonical ones do.
        val snapshot = mapOf(
            "${legacyEncryptedPrefix}token" to StoredValue.Text("ciphertext"),
        )
        assertEquals(
            listOf("ghost"),
            sweepDeletes(snapshot, keychainItemsFor("ghost")).distinct(),
            "a legacy encrypted entry must let the sweep run",
        )
    }
}
