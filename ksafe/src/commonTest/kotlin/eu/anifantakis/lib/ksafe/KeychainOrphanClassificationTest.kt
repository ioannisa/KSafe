package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
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

    /** keyId projection: most assertions care about the physical id; owner is asserted separately. */
    private fun orphanId(
        accountOrTag: String,
        prefix: String,
        fileName: String?,
        validKeys: Set<String>,
        reservedKeyIds: Set<String>,
        isInFlight: (String) -> Boolean = { false },
        ownedKeyIds: Set<String> = emptySet(),
    ): String? = keychainOrphanKeyId(
        accountOrTag, prefix, fileName, validKeys, reservedKeyIds, isInFlight, ownedKeyIds,
    )?.keyId


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
            orphanId("${prefix}__ksafe_master__", prefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters),
            "reserved master sentinel must never be classified as an orphan",
        )
        assertNull(
            orphanId("${prefix}__ksafe_master_locked__", prefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters),
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
            orphanId("${rootPrefix}__ksafe_master__", rootPrefix, fileName = null, validKeys = setOf("token"), reservedKeyIds = emptySet()),
            "without the reservation the master is (wrongly) an orphan — this is the bug being fixed",
        )
    }

    @Test
    fun liveUserKeyIsNotAnOrphan() {
        // A named instance's own live key is in ownedKeyIds (= validKeys), so it passes the
        // owned-key guard and is then preserved by the validKeys check.
        assertNull(
            orphanId("${prefix}token", prefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters, ownedKeyIds = setOf("token")),
            "a key with a live DataStore counterpart must be preserved",
        )
    }

    @Test
    fun unknownUserKeyIsAnOrphan_forTheRootSweep() {
        // The ROOT sweep reaps a per-entry key with no DataStore counterpart. (A NAMED
        // instance does not — see namedInstanceDoesNotReapAnUnprovableKey.)
        assertEquals(
            "ghost",
            orphanId("${rootPrefix}ghost", rootPrefix, fileName = null, validKeys = setOf("token"), reservedKeyIds = masters),
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
            orphanId("${rootPrefix}fresh", rootPrefix, fileName = null, validKeys = setOf("token"), reservedKeyIds = masters),
            "precondition: without the in-flight guard, an absent key is an orphan",
        )
        assertNull(
            orphanId(
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
            orphanId(
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
            orphanId("${prefix}ghost", prefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters, ownedKeyIds = setOf("token")),
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
        assertEquals("ghost", classified?.keyId, "precondition: 'ghost' classifies as an orphan")

        // Between classify and delete a concurrent write re-used (and re-committed) it.
        val toDelete = keychainOrphansToDelete(setOf(classified!!), isInFlight = { it == "ghost" })
        assertTrue(
            toDelete.isEmpty(),
            "a key re-used by a concurrent write after classification must NOT be deleted",
        )
    }

    @Test
    fun strictVariantOrphan_deleteTimeGateChecksTheLogicalOwner() {
        // KFA-007 regression: the delete-time gate must re-check in-flight by the LOGICAL
        // owner, not the physical variant id — dirty tracking is keyed by user key, so an
        // id-keyed check would never match and a strict write started between classification
        // and deletion would lose its freshly minted key.
        val id = strictId("token", 1, null)
        val classified = keychainOrphanKeyId(
            "$rootPrefix$id", rootPrefix, fileName = null, validKeys = emptySet(), reservedKeyIds = masters,
        )
        assertEquals("token", classified?.owner, "the classifier must surface the logical owner")

        val toDelete = keychainOrphansToDelete(setOf(classified!!), isInFlight = { it == "token" })
        assertTrue(
            toDelete.isEmpty(),
            "an owner made in-flight after classification must veto the variant key's deletion",
        )
        assertEquals(
            listOf(id),
            keychainOrphansToDelete(setOf(classified), isInFlight = { false }),
            "an idle owner lets the variant key be reaped, by its full physical id",
        )
    }

    @Test
    fun orphanStillIdleAtDeleteTime_isDeleted() {
        // The common path: a classified orphan that is not in flight when the delete
        // loop reaches it must still be reaped.
        assertEquals(
            listOf("ghost"),
            keychainOrphansToDelete(
                setOf(eu.anifantakis.lib.ksafe.internal.KeychainOrphan("ghost", "ghost")),
                isInFlight = { false },
            ),
            "a still-idle orphan must be deleted at delete time",
        )
    }

    @Test
    fun accountForADifferentInstanceIsIgnored() {
        assertNull(
            orphanId("eu.anifantakis.ksafe.other.token", prefix, "vault", validKeys = emptySet(), reservedKeyIds = masters),
            "an account scoped to a different fileName must not be touched",
        )
    }

    @Test
    fun secureEnclavePrefixClassifiesIndependently() {
        // SE-wrapped generic-passwords and SE EC tags use the "se." prefix; the master
        // stays reserved (named instance) and, on the ROOT sweep, unknown SE keys are
        // still orphans.
        assertNull(
            orphanId("${sePrefix}__ksafe_master__", sePrefix, "vault", validKeys = setOf("token"), reservedKeyIds = masters),
            "reserved master must be preserved on the SE prefix too",
        )
        assertEquals(
            "ghost",
            orphanId("${rootSePrefix}ghost", rootSePrefix, fileName = null, validKeys = setOf("token"), reservedKeyIds = masters),
            "an unknown SE key is still reaped by the root sweep",
        )
    }

    @Test
    fun noFileNameInstanceSkipsForeignNamedEntriesButStillReservesMaster() {
        // fileName == null → prefix is "eu.anifantakis.ksafe." and a key-id with a
        // further '.' belongs to a named instance; leave it alone.
        val rootPrefix = "eu.anifantakis.ksafe."
        assertNull(
            orphanId("${rootPrefix}vault.token", rootPrefix, fileName = null, validKeys = emptySet(), reservedKeyIds = masters),
            "a named-instance entry must not be reaped by the no-fileName sweep",
        )
        // A bare key (no dot) belongs to this instance and, if unknown, is an orphan.
        assertEquals(
            "loose",
            orphanId("${rootPrefix}loose", rootPrefix, fileName = null, validKeys = emptySet(), reservedKeyIds = masters),
        )
        // ...but the master sentinel (no dot) stays reserved even with no fileName.
        assertNull(
            orphanId("${rootPrefix}__ksafe_master__", rootPrefix, fileName = null, validKeys = emptySet(), reservedKeyIds = masters),
            "master sentinel must stay reserved on the no-fileName instance",
        )
    }

    @Test
    fun rotatedGenerationKeys_areNeverClassifiedAsOrphans() {
        // Key rotation (3.0.0) suffixes aliases with `.gN`. validKeys/ownedKeyIds hold BARE
        // user keys, so a rotated id can never match them — the sweep must still preserve
        // every rotated key, or a rotation on iOS would be followed by its own keys' deletion.

        // Root sweep: the `.gN` suffix makes the id dotted → the named-instance guard keeps it.
        assertNull(
            orphanId("${rootPrefix}token.g2", rootPrefix, fileName = null, validKeys = setOf("token"), reservedKeyIds = masters),
            "a rotated per-entry key must survive the root sweep",
        )
        assertNull(
            orphanId("${rootPrefix}__ksafe_master__.g3", rootPrefix, fileName = null, validKeys = emptySet(), reservedKeyIds = masters),
            "a rotated master key must survive the root sweep",
        )

        // Named sweep: a rotated id is never in ownedKeyIds → preserved.
        assertNull(
            orphanId(
                "${prefix}token.g2", prefix, "vault",
                validKeys = setOf("token"), reservedKeyIds = masters, ownedKeyIds = setOf("token"),
            ),
            "a rotated per-entry key must survive the named sweep",
        )
        assertNull(
            orphanId(
                "${sePrefix}token.g2", sePrefix, "vault",
                validKeys = setOf("token"), reservedKeyIds = masters, ownedKeyIds = setOf("token"),
            ),
            "a rotated Secure Enclave key must survive the named SE sweep",
        )

        // Same guarantees for the REAL current formula (`.gN.__ksafe_gen__.h<fp>`), so the
        // alias builder and this classifier can't drift apart silently.
        val rootRotated = KSafeCore.perEntryAliasWithGeneration("token", 2, null, "token")
        assertNull(
            orphanId("$rootPrefix$rootRotated", rootPrefix, fileName = null, validKeys = setOf("token"), reservedKeyIds = masters),
            "a sentinel-format rotated key must survive the root sweep",
        )
        val namedRotated = KSafeCore.perEntryAliasWithGeneration("token", 2, "vault", "token")
        assertNull(
            orphanId(
                "$prefix$namedRotated", prefix, "vault",
                validKeys = setOf("token"), reservedKeyIds = masters, ownedKeyIds = setOf("token"),
            ),
            "a sentinel-format rotated key must survive the named sweep",
        )
    }

    /** Builds a key-id the way production does: base alias == the bare user key at this level. */
    private fun strictId(userKey: String, generation: Int, namespace: String?): String =
        KSafeCore.strictPerEntryAliasWithGeneration(userKey, generation, namespace, userKey)

    @Test
    fun strictVariantKeys_classifyByTheirRecoveredOwner() {
        // Strict alias variants ("<key>[.gN].__ksafe_strict__.h<fp>", 3.0.0+) must be
        // classified by the OWNING user key: a live/in-flight owner preserves the key (a
        // failed tighten's virgin key is reused by the retry), while a genuinely orphaned
        // variant (uninstall→reinstall residue) must be reclaimed — the generic dotted/owned
        // guards would otherwise strand strict keys and their SE artifacts forever.
        val rootId = strictId("token", 1, null)

        // Root sweep, owner still valid → preserved.
        assertNull(
            orphanId("$rootPrefix$rootId", rootPrefix, fileName = null, validKeys = setOf("token"), reservedKeyIds = masters),
            "a strict-variant key with a live owner must be preserved",
        )
        // Root sweep, owner in flight → preserved.
        assertNull(
            orphanId(
                "$rootPrefix$rootId", rootPrefix, fileName = null, validKeys = emptySet(),
                reservedKeyIds = masters, isInFlight = { it == "token" },
            ),
            "a strict-variant key with an in-flight owner must be preserved",
        )
        // Root sweep, owner gone → reclaimed (full variant id returned).
        assertEquals(
            rootId,
            orphanId("$rootPrefix$rootId", rootPrefix, fileName = null, validKeys = emptySet(), reservedKeyIds = masters),
            "an orphaned strict-variant key must be reclaimed by the root sweep",
        )
        // Root sweep, dotted owner → ambiguous with a named instance's key → preserved.
        val dottedId = strictId("a.b", 1, null)
        assertNull(
            orphanId("$rootPrefix$dottedId", rootPrefix, fileName = null, validKeys = emptySet(), reservedKeyIds = masters),
            "a dotted-owner strict variant is ambiguous on the root sweep and must be preserved",
        )
        // A fingerprint matching no candidate owner (foreign store / corrupt id) → preserved.
        assertNull(
            orphanId(
                "${rootPrefix}token.__ksafe_strict__.h0123456789abcdef", rootPrefix, fileName = null,
                validKeys = emptySet(), reservedKeyIds = masters,
            ),
            "a strict variant whose fingerprint resolves no owner must be preserved",
        )
        // Named sweep: reaped only when the recovered owner is provably owned.
        val namedGenId = strictId("token", 2, "vault")
        assertEquals(
            namedGenId,
            orphanId(
                "$sePrefix$namedGenId", sePrefix, "vault",
                validKeys = emptySet(), reservedKeyIds = masters, ownedKeyIds = setOf("token"),
            ),
            "an orphaned owned strict-variant key must be reclaimed by the named sweep",
        )
        assertNull(
            orphanId(
                "$prefix${strictId("token", 1, "vault")}", prefix, "vault",
                validKeys = emptySet(), reservedKeyIds = masters, ownedKeyIds = emptySet(),
            ),
            "an unowned strict-variant key must be preserved by the named sweep",
        )
    }

    @Test
    fun strictVariantGenerationAmbiguity_isResolvedByTheFingerprint() {
        // "foo.g2.__ksafe_strict__.h<fp>" is ambiguous by shape: the generation-1 variant of
        // user key "foo.g2", or the generation-2 variant of user key "foo". Only the
        // fingerprint (hashed over the owner) distinguishes them. A greedy parse that always
        // strips ".g2" would resolve owner "foo" for BOTH — and on a root store where no
        // entry "foo" exists, reap the LIVE key of entry "foo.g2" (the startup ciphertext
        // sweep then deletes the row: deterministic data loss).
        val gen1OfFooG2 = strictId("foo.g2", 1, null)
        val gen2OfFoo = strictId("foo", 2, null)
        // Same shape, different fingerprints — precondition of the whole test.
        assertTrue(gen1OfFooG2 != gen2OfFoo, "the two interpretations must differ only by fingerprint")

        // THE regression: entry "foo.g2" is live (strict, gen 1); no entry "foo" exists.
        // Its key must be preserved — a greedy parse would have resolved owner "foo" and
        // reaped it (the startup ciphertext sweep would then have deleted the row too).
        assertNull(
            orphanId("$rootPrefix$gen1OfFooG2", rootPrefix, fileName = null, validKeys = setOf("foo.g2"), reservedKeyIds = masters),
            "the live gen-1 strict key of user key 'foo.g2' must never be reaped",
        )
        // Once genuinely orphaned, its DOTTED owner keeps it preserved on the root sweep
        // (conservative litter, same stance as every dotted id there) even while an
        // unrelated "foo" is live — the fingerprint stops the misattribution, the dotted
        // guard stops the reclaim.
        assertNull(
            orphanId("$rootPrefix$gen1OfFooG2", rootPrefix, fileName = null, validKeys = setOf("foo"), reservedKeyIds = masters),
            "an orphaned dotted-owner variant stays preserved litter on the root sweep",
        )
        // On a NAMED store the ownership proof (ownedKeyIds) replaces the dot heuristic,
        // so the same dotted-owner variant IS reclaimable there.
        val namedDotted = strictId("foo.g2", 1, "vault")
        assertEquals(
            namedDotted,
            orphanId(
                "$prefix$namedDotted", prefix, "vault",
                validKeys = emptySet(), reservedKeyIds = masters, ownedKeyIds = setOf("foo.g2"),
            ),
            "an orphaned dotted-owner variant is reclaimed on the named sweep via ownership proof",
        )
        // The mirror image: the gen-2 variant of "foo" is owned by "foo".
        assertNull(
            orphanId("$rootPrefix$gen2OfFoo", rootPrefix, fileName = null, validKeys = setOf("foo"), reservedKeyIds = masters),
            "the gen-2 strict key of user key 'foo' must be preserved while 'foo' is live",
        )
        assertEquals(
            gen2OfFoo,
            orphanId("$rootPrefix$gen2OfFoo", rootPrefix, fileName = null, validKeys = setOf("foo.g2"), reservedKeyIds = masters),
            "an orphaned gen-2 'foo' variant must be reclaimed even while 'foo.g2' is live",
        )
    }
}
