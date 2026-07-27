package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeAliasFormat
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeReservedKeys
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.keychainOrphanKeyId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Lockstep between the alias PRODUCER and everything that has to reproduce or undo it.
 *
 * Three places touch the alias grammar: `KSafeCore` (authoritative producer), the JVM fallback
 * migration (forward re-derivation) and the Keychain orphan classifier (backward parse). The
 * migration now routes through `KSafeCore.aliasForRecordedMeta` / `aadForEnvelope` instead of
 * re-deriving — that half is locked in by `JvmFallbackMigrationAliasLockstepTest` in jvmTest,
 * because `JvmFallbackMigration` lives in jvmMain and commonTest cannot reach it.
 *
 * This file holds the two halves that ARE common:
 *
 *  - FORWARD: an entry's alias and associated data must survive the round-trip through its own
 *    persisted metadata. Every consumer derives from the metadata record, not from the write's
 *    live arguments, so a field the write routes on but the record does not carry (or does carry
 *    but nothing parses back) silently sends the read to a different key. That is exactly what
 *    the `sa` strict-variant marker was.
 *  - BACKWARD: `parse(build(x)) == x`. Stating the round-trip as a property covers the whole
 *    ambiguity class the `foo.g2` witness in [KeychainOrphanClassificationTest] samples one
 *    point of.
 */
class KSafeAliasDerivationLockstepTest {

    private val fileName: String? = "vault"
    private val keyNamespace: String? = fileName
    private val storeIdentity = "~/ksafe/vault"

    private val keyAlias: (String) -> String = { KSafeAliasFormat.dotted(fileName, it) }
    private val masterAlias: (Boolean) -> String = { unlocked ->
        KSafeAliasFormat.dotted(
            fileName,
            if (unlocked) KSafeReservedKeys.MASTER_LOCKED else KSafeReservedKeys.MASTER,
        )
    }

    private val envelopeVersions = listOf(
        KeySafeMetadataManager.ENVELOPE_VERSION_V1,
        KeySafeMetadataManager.ENVELOPE_VERSION_V2,
        KeySafeMetadataManager.ENVELOPE_VERSION_V3,
    )
    private val protections = listOf(KSafeProtection.DEFAULT, KSafeProtection.HARDWARE_ISOLATED)
    private val strictVariants = listOf(false, true)
    private val unlockPolicies = listOf(false, true)
    private val generations = listOf(1, 2, 3)

    private val userKeys = listOf("token", "a.b", "a:b", "foo.g2", "")

    // ---- FORWARD: the metadata record must carry every field the alias routes on ------------

    @Test
    fun everyAliasRoutingField_survivesTheRoundTripThroughItsPersistedMetadata() {
        var rows = 0
        for (userKey in userKeys) {
            for (envelopeVersion in envelopeVersions) {
                for (protection in protections) {
                    for (strict in strictVariants) {
                        for (unlocked in unlockPolicies) {
                            for (generation in generations) {
                                rows++
                                val direct = KSafeCore.aliasForRecordedMeta(
                                    userKey = userKey,
                                    protection = protection,
                                    envelopeVersion = envelopeVersion,
                                    requireUnlockedDevice = unlocked,
                                    keyGeneration = generation,
                                    strictAliasVariant = strict,
                                    masterAlias = masterAlias,
                                    keyAlias = keyAlias,
                                    keyNamespace = keyNamespace,
                                )
                                // What a write of this row persists, built by the production writer.
                                val record = KeySafeMetadataManager.buildMetadataJson(
                                    protection = protection,
                                    accessPolicy = KeySafeMetadataManager.accessPolicyFor(unlocked),
                                    envelopeVersion = envelopeVersion,
                                    keyGeneration = generation,
                                    strictAliasVariant = strict,
                                )
                                // What every consumer reconstructs from that record.
                                val parsed = KSafeCore.encMetaFromRaw(record)
                                val viaRecord = KSafeCore.aliasForRecordedMeta(
                                    userKey = userKey,
                                    protection = KeySafeMetadataManager.parseProtection(record),
                                    envelopeVersion = parsed.envelopeVersion,
                                    requireUnlockedDevice = parsed.requireUnlockedDevice,
                                    keyGeneration = parsed.keyGeneration,
                                    strictAliasVariant = parsed.strictAliasVariant,
                                    masterAlias = masterAlias,
                                    keyAlias = keyAlias,
                                    keyNamespace = keyNamespace,
                                )
                                assertEquals(
                                    direct, viaRecord,
                                    "alias diverged across the metadata round-trip for " +
                                        "key='$userKey' v=$envelopeVersion p=$protection " +
                                        "strict=$strict unlocked=$unlocked g=$generation — the " +
                                        "record does not carry (or does not parse back) a field " +
                                        "the alias routes on, so reads land on the wrong key",
                                )
                                assertContentEquals(
                                    KSafeCore.aadForEnvelope(
                                        storeIdentity, userKey, protection, unlocked,
                                        generation, envelopeVersion,
                                    ),
                                    KSafeCore.aadForEnvelope(
                                        storeIdentity, userKey,
                                        KeySafeMetadataManager.parseProtection(record),
                                        parsed.requireUnlockedDevice, parsed.keyGeneration,
                                        parsed.envelopeVersion,
                                    ),
                                    "associated data diverged across the metadata round-trip for " +
                                        "key='$userKey' v=$envelopeVersion p=$protection " +
                                        "unlocked=$unlocked g=$generation — the entry would fail " +
                                        "authentication and be read as an orphan",
                                )
                            }
                        }
                    }
                }
            }
        }
        assertEquals(
            userKeys.size * envelopeVersions.size * protections.size * strictVariants.size *
                unlockPolicies.size * generations.size,
            rows,
            "precondition: the full matrix must have run",
        )
    }

    @Test
    fun theThreeRoutingBranches_areAllReachedByTheMatrix() {
        // Guards the matrix itself: if a future change collapses a branch, the lockstep above
        // would still pass while covering less. Every branch of aliasForRecordedMeta must fire.
        val aliases = mutableSetOf<String>()
        for (envelopeVersion in envelopeVersions) {
            for (protection in protections) {
                for (strict in strictVariants) {
                    aliases += KSafeCore.aliasForRecordedMeta(
                        "token", protection, envelopeVersion, requireUnlockedDevice = false,
                        keyGeneration = 2, strictAliasVariant = strict,
                        masterAlias = masterAlias, keyAlias = keyAlias, keyNamespace = keyNamespace,
                    )
                }
            }
        }
        val master = KSafeCore.aliasWithGeneration(masterAlias(false), 2)
        val perEntry = KSafeCore.perEntryAliasWithGeneration(keyAlias("token"), 2, keyNamespace, "token")
        val strictPerEntry =
            KSafeCore.strictPerEntryAliasWithGeneration(keyAlias("token"), 2, keyNamespace, "token")
        assertTrue(master in aliases, "the master-riding branch must be reachable")
        assertTrue(perEntry in aliases, "the relaxed per-entry branch must be reachable")
        assertTrue(strictPerEntry in aliases, "the strict per-entry branch must be reachable")
    }

    // ---- BACKWARD: parse(build(x)) == x ----------------------------------------------------

    /**
     * User keys chosen to make the backward parse ambiguous by shape: `.gN` tails that could be
     * read as the alias's own generation suffix, embedded fingerprints, embedded sentinel
     * lookalikes, both delimiters, line terminators, unicode, empty and long.
     */
    private fun parseCorpus(): List<String> {
        val fingerprint = KSafeCore.aliasFingerprint(keyNamespace, "foo")
        return listOf(
            "", "token", "foo", "foo.g2", "foo.g2.g3", "foo.g0", "foo.g99999", "foo.g",
            "a.b", "a:b", "a.b:c", ".", ":", "..", "::",
            "foo.h$fingerprint", "foo.g2.h$fingerprint", ".h0123456789abcdef",
            "my__ksafe_strict__x", "__ksafe_stric__", "_ksafe_strict__",
            // Line terminators a default regex `.` skips, plus invisible spacing.
            "a\nb", "a\rb", "a\r\nb", "a\u2028b", "a\u2029b", "a\u0085b",
            "a\u00a0b", "a\u200bb", "a\u202eb",
            "ключ", "鍵", "🔐", "é", "foo.g٢",
            "z".repeat(2000),
        )
    }

    @Test
    fun everyBuiltStrictVariantKeyId_parsesBackToTheIdentityItWasBuiltFrom() {
        // A named store: ownership is proved by ownedKeyIds, so the classifier's dot heuristic
        // (a root-store guard, not a parse step) never masks a wrong parse. A recovered owner
        // that is not the original therefore fails the ownership check and surfaces as null.
        val prefix = "eu.anifantakis.ksafe.$fileName."
        for (userKey in parseCorpus()) {
            for (generation in listOf(1, 2, 3, 10_000)) {
                val keyId = KSafeCore.strictPerEntryAliasWithGeneration(
                    userKey, generation, keyNamespace, userKey,
                )
                val classified = keychainOrphanKeyId(
                    accountOrTag = prefix + keyId,
                    prefix = prefix,
                    fileName = fileName,
                    validKeys = emptySet(),
                    reservedKeyIds = emptySet(),
                    ownedKeyIds = setOf(userKey),
                    keyNamespace = keyNamespace,
                )
                assertEquals(
                    userKey, classified?.owner,
                    "parse(build(x)) != x for user key ${userKey.debug()} at generation " +
                        "$generation — the classifier recovered a different owner from " +
                        "${keyId.debug()}, so the sweep would reap a live key (or strand a dead one)",
                )
                assertEquals(
                    keyId, classified?.keyId,
                    "the classifier must delete the PHYSICAL id it was given, unchanged",
                )
            }
        }
    }

    @Test
    fun aLiveOwnerVetoesItsOwnParsedKeyId_atEveryGeneration() {
        // The other direction of the same property: because the parse recovers the true owner,
        // that owner being live must preserve the key. A parse that resolved the wrong owner
        // would let a live entry's key be reaped.
        val prefix = "eu.anifantakis.ksafe.$fileName."
        for (userKey in parseCorpus()) {
            for (generation in listOf(1, 2, 3)) {
                val keyId = KSafeCore.strictPerEntryAliasWithGeneration(
                    userKey, generation, keyNamespace, userKey,
                )
                assertEquals(
                    null,
                    keychainOrphanKeyId(
                        accountOrTag = prefix + keyId,
                        prefix = prefix,
                        fileName = fileName,
                        validKeys = setOf(userKey),
                        reservedKeyIds = emptySet(),
                        ownedKeyIds = setOf(userKey),
                        keyNamespace = keyNamespace,
                    )?.keyId,
                    "the strict key of live user key ${userKey.debug()} at generation $generation " +
                        "must never be classified as an orphan",
                )
            }
        }
    }

    /** Renders line terminators and other invisibles so a failure message is readable. */
    private fun String.debug(): String {
        val shown = if (length > 64) substring(0, 64) + "…(${length})" else this
        return "\"" + shown.map { c ->
            if (c.code in 32..126) "$c" else "\\u${c.code.toString(16).padStart(4, '0')}"
        }.joinToString("") + "\""
    }
}
