package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

/**
 * Locks in the injectivity of the generation-suffixed per-entry alias namespace and the
 * reservation of master-sentinel key names. A plain `.gN` suffix let user key `"foo"` at
 * generation 2 collide with user key `"foo.g2"` at generation 1 (rotating or deleting one
 * destroyed the other's vault key), and let a default store's dotted key alias a named
 * store's key at every generation; the fingerprint closes both for rotated generations.
 */
class KSafeAliasNamespaceTest {

    @Test
    fun generation1_staysTheBareBaseAlias_publishedFormat() {
        assertEquals(
            "p.foo",
            KSafeCore.perEntryAliasWithGeneration("p.foo", 1, null, "foo"),
            "generation 1 must keep the exact pre-rotation alias — published format",
        )
        assertEquals("p.foo", KSafeCore.perEntryAliasWithGeneration("p.foo", 0, "vault", "foo"))
    }

    @Test
    fun rotatedAlias_neverEqualsA_dotGSuffixedSiblingsBareAlias() {
        // "foo" rotated to g2 vs sibling key literally named "foo.g2" at g1.
        val rotatedFoo = KSafeCore.perEntryAliasWithGeneration("p.foo", 2, null, "foo")
        val bareTwin = "p.foo.g2" // keyAlias("foo.g2") at generation 1
        assertNotEquals(bareTwin, rotatedFoo, "the rotated alias must not shadow a sibling's bare alias")
    }

    @Test
    fun rotatedAlias_neverEqualsA_fingerprintBearingTwinsBareAlias() {
        // The fingerprint alone was not injective: the user key "foo.g2.h<fp(ns,foo)>" spelled
        // "foo"'s rotated alias VERBATIM as its own generation-1 bare alias — two logical
        // entries sharing one physical vault key. The `__ksafe_gen__` sentinel segment (barred
        // from user keys) closes the whole class, not just this witness.
        val fp = KSafeCore.aliasFingerprint(null, "foo")
        val fingerprintTwin = "foo.g2.h$fp"
        val rotatedFoo = KSafeCore.perEntryAliasWithGeneration("p.foo", 2, null, "foo")
        assertNotEquals(
            "p.$fingerprintTwin", // keyAlias(fingerprintTwin) at generation 1
            rotatedFoo,
            "a fingerprint-bearing user key must not reproduce a sibling's rotated alias",
        )
        // And the only remaining spelling of the rotated alias tail is not a legal user key.
        assertFailsWith<IllegalArgumentException> {
            KeySafeMetadataManager.requireWritableUserKey("foo.g2.__ksafe_gen__.h$fp")
        }
    }

    @Test
    fun generationSentinelSuffixedKeys_areRejectedForWrites() {
        assertFailsWith<IllegalArgumentException> {
            KeySafeMetadataManager.requireWritableUserKey("token.__ksafe_gen__")
        }
        assertFailsWith<IllegalArgumentException> {
            KeySafeMetadataManager.requireWritableUserKey("token.__ksafe_gen__.h0123456789abcdef")
        }
        // Non-fingerprint tails can't collide (rotated aliases always end in the 16-hex
        // fingerprint) and stay writable, mirroring the strict sentinel's contract.
        KeySafeMetadataManager.requireWritableUserKey("my__ksafe_gen__") // no dot boundary
        KeySafeMetadataManager.requireWritableUserKey("token.__ksafe_gen__.hzz") // not a fingerprint
    }

    @Test
    fun colonDelimitedSentinelKeys_areRejectedForWrites() {
        // JVM and web build aliases as "<fileName>:<userKey>", so a DEFAULT-store user key
        // "vault:__ksafe_master__" is byte-identical to the named store "vault"'s master alias.
        assertFailsWith<IllegalArgumentException> {
            KeySafeMetadataManager.requireWritableUserKey("vault:__ksafe_master__")
        }
        assertFailsWith<IllegalArgumentException> {
            KeySafeMetadataManager.requireWritableUserKey("vault:__ksafe_master_locked__")
        }
        assertFailsWith<IllegalArgumentException> {
            KeySafeMetadataManager.requireWritableUserKey("vault:__ksafe_swfb__")
        }
        assertFailsWith<IllegalArgumentException> {
            KeySafeMetadataManager.requireWritableUserKey("vault:__ksafe_strict__.h0123456789abcdef")
        }
        // A colon that is not a delimiter before a sentinel stays writable.
        KeySafeMetadataManager.requireWritableUserKey("a:b")
        KeySafeMetadataManager.requireWritableUserKey("my:key__ksafe_master__x")
    }

    @Test
    fun jvmVaultMarkerSuffixedKeys_areRejectedForWrites() {
        // The JVM deletion tombstone ("$alias.__ksafe_nsdel__") and software-fallback mint
        // marker ("$alias.__ksafe_swfb__") share the per-entry vault-alias plane, so a user key
        // ending in one aliases a sibling key's marker slot — reject it.
        assertFailsWith<IllegalArgumentException> {
            KeySafeMetadataManager.requireWritableUserKey("token.__ksafe_nsdel__")
        }
        assertFailsWith<IllegalArgumentException> {
            KeySafeMetadataManager.requireWritableUserKey("a.b.__ksafe_swfb__")
        }
        // No dot boundary → not the trailing segment → still writable.
        KeySafeMetadataManager.requireWritableUserKey("my__ksafe_nsdel__")
        KeySafeMetadataManager.requireWritableUserKey("my__ksafe_swfb__")
    }

    @Test
    fun rotatedAlias_isStoreDistinct_forTheSameBaseAlias() {
        // Default store's dotted key "vault.token" vs named store "vault"'s key "token":
        // both produce the same BASE alias, so only the fingerprint separates them.
        val root = KSafeCore.perEntryAliasWithGeneration("p.vault.token", 2, null, "vault.token")
        val named = KSafeCore.perEntryAliasWithGeneration("p.vault.token", 2, "vault", "token")
        assertNotEquals(root, named, "same-shaped aliases from different stores must diverge once rotated")
    }

    @Test
    fun rotatedAlias_isDeterministic_andGenerationDistinct() {
        fun alias(gen: Int) = KSafeCore.perEntryAliasWithGeneration("p.k", gen, "s", "k")
        assertEquals(alias(2), alias(2), "same identity must derive the same alias")
        assertNotEquals(alias(2), alias(3), "generations must not collide")
    }

    @Test
    fun masterSentinelSuffixedKeys_areRejectedForWrites() {
        // Their per-entry alias is byte-identical to SOME store's master alias — mutating
        // one could destroy every DEFAULT ciphertext of that store.
        assertFailsWith<IllegalArgumentException> {
            KeySafeMetadataManager.requireWritableUserKey("vault.__ksafe_master__")
        }
        assertFailsWith<IllegalArgumentException> {
            KeySafeMetadataManager.requireWritableUserKey("a.b.__ksafe_master_locked__")
        }
        assertFailsWith<IllegalArgumentException> {
            KeySafeMetadataManager.requireWritableUserKey("vault.__ksafe_master__.g3")
        }
    }

    @Test
    fun ordinaryDottedKeys_remainWritable() {
        // No exception: only the exact sentinel tail is reserved.
        KeySafeMetadataManager.requireWritableUserKey("vault.master")
        KeySafeMetadataManager.requireWritableUserKey("g2.foo")
        KeySafeMetadataManager.requireWritableUserKey("my__ksafe_master__") // no dot boundary
        KeySafeMetadataManager.requireWritableUserKey("vault.token")
    }

    @Test
    fun lineTerminatorsInThePrefix_cannotBypassTheSentinelGuard() {
        // A default `.` skips line terminators, so "a\nb.<sentinel>" once slipped past the
        // full-string match and could alias a sibling key's strict/rotated/master alias.
        val fp = KSafeCore.aliasFingerprint(null, "foo")
        for (terminator in listOf("\n", "\r", "\u2028", "\u2029")) {
            assertFailsWith<IllegalArgumentException>("terminator ${terminator.encodeToByteArray().toList()}") {
                KeySafeMetadataManager.requireWritableUserKey("a${terminator}b.__ksafe_strict__.h$fp")
            }
            assertFailsWith<IllegalArgumentException> {
                KeySafeMetadataManager.requireWritableUserKey("a${terminator}b.__ksafe_gen__.h$fp")
            }
            assertFailsWith<IllegalArgumentException> {
                KeySafeMetadataManager.requireWritableUserKey("a${terminator}b.__ksafe_master__")
            }
        }
        // Line terminators alone never make an ordinary key reserved.
        KeySafeMetadataManager.requireWritableUserKey("a\nb.token")
    }
}
