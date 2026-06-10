package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.keychainOrphanKeyId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Unit tests for the Apple orphan sweep's classification step
 * ([keychainOrphanKeyId]) — the logic the v2 master-key data-loss bug lived in.
 *
 * The surrounding sweep is pure Keychain I/O that a sandboxed/simulator unit
 * test can't exercise (the iOS simulator returns `errSecNotAvailable` for a bare
 * test binary), so the decision is tested directly here, on every platform.
 */
class KeychainOrphanClassificationTest {

    // fileName = "vault" → these are the per-instance account prefixes.
    private val prefix = "eu.anifantakis.ksafe.vault."
    private val sePrefix = "se.eu.anifantakis.ksafe.vault."
    private val masters = setOf("__ksafe_master__", "__ksafe_master_locked__")

    @Test
    fun reservedMasterSentinelIsNeverAnOrphan() {
        // The v2 master rides every DEFAULT value, so it is never in validKeys.
        // Reserved ⇒ must be preserved. This is the data-loss fix.
        assertNull(
            keychainOrphanKeyId("${prefix}__ksafe_master__", prefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters),
            "reserved master sentinel must never be classified as an orphan",
        )
        assertNull(
            keychainOrphanKeyId("${prefix}__ksafe_master_locked__", prefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters),
            "reserved locked-master sentinel must never be classified as an orphan",
        )
    }

    @Test
    fun masterSentinelWouldBeDeletedWithoutReservation() {
        // Documents the bug: with no reservation the master is classified as an
        // orphan (it's never a user key) and would be deleted → all DEFAULT data lost.
        assertEquals(
            "__ksafe_master__",
            keychainOrphanKeyId("${prefix}__ksafe_master__", prefix, "vault", validKeys = setOf("token"), reservedKeyIds = emptySet()),
            "without the reservation the master is (wrongly) an orphan — this is the bug being fixed",
        )
    }

    @Test
    fun liveUserKeyIsNotAnOrphan() {
        assertNull(
            keychainOrphanKeyId("${prefix}token", prefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters),
            "a key with a live DataStore counterpart must be preserved",
        )
    }

    @Test
    fun unknownUserKeyIsAnOrphan() {
        // The fix must stay surgical: genuine orphans are still reaped.
        assertEquals(
            "ghost",
            keychainOrphanKeyId("${prefix}ghost", prefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters),
            "a per-entry key with no DataStore counterpart must still be reaped",
        )
    }

    @Test
    fun inFlightKeyIsNotAnOrphan_evenWhenAbsentFromValidKeys() {
        // Deep-review #30: a key the engine just created for a still-in-flight write hasn't
        // reached the DataStore snapshot (validKeys) yet — the sweep must NOT reap it, or it
        // destroys the key for an acknowledged concurrent write. Without the guard "fresh"
        // would be classified an orphan (absent from validKeys); the in-flight predicate
        // preserves it.
        assertEquals(
            "fresh",
            keychainOrphanKeyId("${prefix}fresh", prefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters),
            "precondition: without the in-flight guard, an absent key is an orphan",
        )
        assertNull(
            keychainOrphanKeyId(
                "${prefix}fresh", prefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters,
                isInFlight = { it == "fresh" },
            ),
            "a key for an in-flight write must be preserved, not reaped (#30)",
        )
    }

    @Test
    fun accountForADifferentInstanceIsIgnored() {
        assertNull(
            keychainOrphanKeyId("eu.anifantakis.ksafe.other.token", prefix, "vault", validKeys = emptySet(), reservedKeyIds = masters),
            "an account scoped to a different fileName must not be touched",
        )
    }

    @Test
    fun secureEnclavePrefixClassifiesIndependently() {
        // SE-wrapped generic-passwords and SE EC tags use the "se." prefix; the
        // master stays reserved and unknown SE keys are still orphans.
        assertNull(
            keychainOrphanKeyId("${sePrefix}__ksafe_master__", sePrefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters),
            "reserved master must be preserved on the SE prefix too",
        )
        assertEquals(
            "ghost",
            keychainOrphanKeyId("${sePrefix}ghost", sePrefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters),
        )
    }

    @Test
    fun noFileNameInstanceSkipsForeignNamedEntriesButStillReservesMaster() {
        // fileName == null → prefix is "eu.anifantakis.ksafe." and a key-id with a
        // further '.' belongs to a named instance; leave it alone.
        val rootPrefix = "eu.anifantakis.ksafe."
        assertNull(
            keychainOrphanKeyId("${rootPrefix}vault.token", rootPrefix, fileName = null, validKeys = emptySet(), reservedKeyIds = masters),
            "a named-instance entry must not be reaped by the no-fileName sweep",
        )
        // A bare key (no dot) belongs to this instance and, if unknown, is an orphan.
        assertEquals(
            "loose",
            keychainOrphanKeyId("${rootPrefix}loose", rootPrefix, fileName = null, validKeys = emptySet(), reservedKeyIds = masters),
        )
        // ...but the master sentinel (no dot) stays reserved even with no fileName.
        assertNull(
            keychainOrphanKeyId("${rootPrefix}__ksafe_master__", rootPrefix, fileName = null, validKeys = emptySet(), reservedKeyIds = masters),
            "master sentinel must stay reserved on the no-fileName instance",
        )
    }
}
