package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.keychainOrphanKeyId
import eu.anifantakis.lib.ksafe.internal.keychainOrphansToDelete
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Locks in: the Apple orphan sweep's classification step ([keychainOrphanKeyId] /
 * [keychainOrphansToDelete]) — an exact decision tested directly on every platform because
 * misclassifying a reserved master entry destroys the key for all DEFAULT data, and the
 * surrounding sweep is Keychain I/O a sandboxed/simulator unit test can't exercise.
 */
class KeychainOrphanClassificationTest {

    // fileName = "vault" → these are the per-instance account prefixes.
    private val prefix = "eu.anifantakis.ksafe.vault."
    private val sePrefix = "se.eu.anifantakis.ksafe.vault."
    // fileName = null (the root/default instance) → these prefixes. A named instance reaps ONLY
    // keys it provably owns, so the "an unknown key is reaped" semantics are exercised against the
    // ROOT sweep, which the owned-key guard leaves unchanged.
    private val rootPrefix = "eu.anifantakis.ksafe."
    private val rootSePrefix = "se.eu.anifantakis.ksafe."
    private val masters = setOf("__ksafe_master__", "__ksafe_master_locked__")

    @Test
    fun reservedMasterSentinelIsNeverAnOrphan() {
        // The master rides every DEFAULT value, so it is never in validKeys;
        // being reserved is what keeps it out of orphan classification.
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
        // With no reservation the master (never a user key) classifies as an orphan
        // and would be deleted, losing all DEFAULT data — the reservation is required.
        // Exercised on the ROOT sweep, where the owned-key guard does not apply.
        assertEquals(
            "__ksafe_master__",
            keychainOrphanKeyId("${rootPrefix}__ksafe_master__", rootPrefix, fileName = null, validKeys = setOf("token"), reservedKeyIds = emptySet()),
            "without the reservation the master is (wrongly) an orphan — this is the bug being fixed",
        )
    }

    @Test
    fun liveUserKeyIsNotAnOrphan() {
        // A named instance's own live key is in ownedKeyIds (= validKeys), so it passes the
        // owned-key guard and is then preserved by the validKeys check.
        assertNull(
            keychainOrphanKeyId("${prefix}token", prefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters, ownedKeyIds = setOf("token")),
            "a key with a live DataStore counterpart must be preserved",
        )
    }

    @Test
    fun unknownUserKeyIsAnOrphan_forTheRootSweep() {
        // The ROOT sweep reaps a per-entry key with no DataStore counterpart. (A NAMED
        // instance does not — see namedInstanceDoesNotReapAnUnprovableKey.)
        assertEquals(
            "ghost",
            keychainOrphanKeyId("${rootPrefix}ghost", rootPrefix, fileName = null, validKeys = setOf("token"), reservedKeyIds = masters),
            "a per-entry key with no DataStore counterpart must still be reaped by the root sweep",
        )
    }

    @Test
    fun inFlightKeyIsNotAnOrphan_evenWhenAbsentFromValidKeys() {
        // A key just created for a still-in-flight write hasn't reached the DataStore
        // snapshot (validKeys) yet — the sweep must not reap it, or it destroys the key
        // for an acknowledged concurrent write. Exercised on the ROOT sweep.
        assertEquals(
            "fresh",
            keychainOrphanKeyId("${rootPrefix}fresh", rootPrefix, fileName = null, validKeys = setOf("token"), reservedKeyIds = masters),
            "precondition: without the in-flight guard, an absent key is an orphan",
        )
        assertNull(
            keychainOrphanKeyId(
                "${rootPrefix}fresh", rootPrefix, fileName = null, validKeys = setOf("token"), reservedKeyIds = masters,
                isInFlight = { it == "fresh" },
            ),
            "a key for an in-flight write must be preserved, not reaped",
        )
    }

    @Test
    fun namedInstanceSweepDoesNotReapRootInstanceDottedKey() {
        // A root instance stored userKey "vault.token" → account "eu.anifantakis.ksafe.vault.token",
        // byte-identical to named-instance "vault"'s userKey "token". The named "vault" sweep must
        // NOT reap it (it can't prove ownership) — reaping would destroy the root instance's live
        // HARDWARE key.
        assertNull(
            keychainOrphanKeyId(
                "eu.anifantakis.ksafe.vault.token", prefix, fileName = "vault",
                validKeys = emptySet(), reservedKeyIds = masters, ownedKeyIds = emptySet(),
            ),
            "a named sweep must NOT reap a root instance's dotted key that collides with its scope",
        )
    }

    @Test
    fun namedInstanceDoesNotReapAnUnprovableKey() {
        // The contract: a named instance reaps ONLY keys it provably owns (ownedKeyIds).
        // A cross-session orphan it can't prove is its own is left as harmless clutter.
        assertNull(
            keychainOrphanKeyId("${prefix}ghost", prefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters, ownedKeyIds = setOf("token")),
            "a named instance must not reap a key it can't prove it owns",
        )
    }

    @Test
    fun orphanClassifiedThenReusedByConcurrentWrite_isNotDeleted() {
        // The sweep classifies on a frozen snapshot, then deletes on the same pass while writes
        // run in parallel on Native. A key can be a genuine orphan at classify time (no valid
        // entry, not in flight) yet be re-used by a concurrent put BEFORE the delete lands — the
        // delete-time re-check must drop it.
        val classified = keychainOrphanKeyId(
            "${prefix}ghost", prefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters,
            isInFlight = { false }, // classify time: not yet in flight → orphan
            ownedKeyIds = setOf("ghost"), // provably owned so the owned-key guard passes; this test targets the delete-time recheck
        )
        assertEquals("ghost", classified, "precondition: 'ghost' classifies as an orphan")

        // Between classify and delete a concurrent write re-used (and re-committed) it.
        val toDelete = keychainOrphansToDelete(setOf(classified!!), isInFlight = { it == "ghost" })
        assertTrue(
            toDelete.isEmpty(),
            "a key re-used by a concurrent write after classification must NOT be deleted",
        )
    }

    @Test
    fun orphanStillIdleAtDeleteTime_isDeleted() {
        // The common path: a classified orphan that is not in flight when the delete
        // loop reaches it must still be reaped.
        assertEquals(
            listOf("ghost"),
            keychainOrphansToDelete(setOf("ghost"), isInFlight = { false }),
            "a still-idle orphan must be deleted at delete time",
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
        // SE-wrapped generic-passwords and SE EC tags use the "se." prefix; the master
        // stays reserved (named instance) and, on the ROOT sweep, unknown SE keys are
        // still orphans.
        assertNull(
            keychainOrphanKeyId("${sePrefix}__ksafe_master__", sePrefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters),
            "reserved master must be preserved on the SE prefix too",
        )
        assertEquals(
            "ghost",
            keychainOrphanKeyId("${rootSePrefix}ghost", rootSePrefix, fileName = null, validKeys = setOf("token"), reservedKeyIds = masters),
            "an unknown SE key is still reaped by the root sweep",
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
