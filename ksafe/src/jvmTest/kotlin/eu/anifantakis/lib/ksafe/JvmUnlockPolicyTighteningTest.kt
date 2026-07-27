package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Locks in the copy-on-write unlock-policy transition for per-entry aliases: a strict
 * `HARDWARE_ISOLATED` write keys under the strict alias VARIANT, so a relaxed→strict rewrite
 * mints its strict key under a fresh alias, commits, and only then reclaims the old relaxed
 * alias. The old key is never touched before the write's own encrypt and commit succeed —
 * any failure in between (locked device, keystore outage, crash) leaves the previous value
 * fully decryptable. This replaced the delete-first scheme, which destroyed the relaxed key
 * before the encrypt and lost the previous value on any failure after the delete.
 */
class JvmUnlockPolicyTighteningTest {

    private fun hwiMode(requireUnlockedDevice: Boolean) = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
        requireUnlockedDevice = requireUnlockedDevice,
    )

    /** [StatefulFakeEncryption] that fails encrypts for chosen aliases (a locked device / vault outage). */
    private class FailingEncryption : StatefulFakeEncryption() {
        val failAliases = mutableSetOf<String>()
        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray {
            check(identifier !in failAliases) { "simulated keystore outage for '$identifier'" }
            return super.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice, aad)
        }
    }

    /** THE regression test: a failed tighten encrypt must leave the old value decryptable. */
    @Test
    fun tightenWithFailingEncrypt_preservesTheOldValue() = runTest {
        val engine = FailingEncryption()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = engine,
        )
        try {
            val key = "hw_secret"
            val baseAlias = ksafe.core.perEntryAlias(key, 1)
            val strictAlias = ksafe.core.strictPerEntryAlias(key, 1)

            ksafe.put(key, "v1", hwiMode(requireUnlockedDevice = false))
            assertNotNull(engine.keysByAlias[baseAlias], "the relaxed write must mint the base-alias key")

            engine.failAliases += strictAlias
            assertFailsWith<IllegalStateException> {
                ksafe.put(key, "v2", hwiMode(requireUnlockedDevice = true))
            }

            assertFalse(
                baseAlias in engine.deletedKeys,
                "a failed tighten must not have touched the relaxed key",
            )
            assertEquals(
                "v1", ksafe.get(key, "fallback"),
                "after a failed tighten the previous value must still decrypt",
            )

            // The failure was transient (device unlocked / vault back): the retry heals.
            engine.failAliases.clear()
            ksafe.put(key, "v2", hwiMode(requireUnlockedDevice = true))
            assertEquals("v2", ksafe.get(key, "fallback"))
        } finally {
            ksafe.close()
        }
    }

    @Test
    fun tighten_mintsUnderTheVariantAlias_andReclaimsTheRelaxedKeyOnlyAfterCommit() = runTest {
        val engine = StatefulFakeEncryption()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = engine,
        )
        try {
            val key = "hw_secret"
            val baseAlias = ksafe.core.perEntryAlias(key, 1)
            val strictAlias = ksafe.core.strictPerEntryAlias(key, 1)

            ksafe.put(key, "v1", hwiMode(requireUnlockedDevice = false))
            ksafe.put(key, "v2", hwiMode(requireUnlockedDevice = true))

            assertNotNull(engine.keysByAlias[strictAlias], "the strict rewrite must mint under the variant alias")
            assertTrue(baseAlias in engine.deletedKeys, "the superseded relaxed key must be reclaimed post-commit")
            assertNull(engine.keysByAlias[baseAlias], "the relaxed key must be gone after the reclaim")
            assertEquals("v2", ksafe.get(key, "fallback"))

            // Strict over strict: same variant alias, no re-mint, no further reclaim.
            val strictKeyId = engine.keysByAlias[strictAlias]
            ksafe.put(key, "v3", hwiMode(requireUnlockedDevice = true))
            assertEquals(strictKeyId, engine.keysByAlias[strictAlias], "a strict-over-strict rewrite reuses the key")
            assertEquals("v3", ksafe.get(key, "fallback"))
        } finally {
            ksafe.close()
        }
    }

    /** The fire-and-forget path captures the transition too, surviving same-batch coalescing. */
    @Test
    fun directPutTransition_migratesTheAliasToo() = runTest {
        val engine = StatefulFakeEncryption()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = engine,
        )
        try {
            val key = "hw_direct"
            ksafe.putDirect(key, "v1", hwiMode(requireUnlockedDevice = false))
            ksafe.putDirect(key, "v2", hwiMode(requireUnlockedDevice = true))
            // An awaited write behind the direct ones proves the queue has drained.
            ksafe.put("sync", "x", KSafeWriteMode.Plain)

            assertNotNull(engine.keysByAlias[ksafe.core.strictPerEntryAlias(key, 1)])
            assertEquals("v2", ksafe.get(key, "fallback"))
        } finally {
            ksafe.close()
        }
    }

    /** Loosening moves the entry back to the base alias and reclaims the variant key. */
    @Test
    fun loosen_movesBackToTheBaseAlias() = runTest {
        val engine = StatefulFakeEncryption()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = engine,
        )
        try {
            val key = "hw_loosen"
            val baseAlias = ksafe.core.perEntryAlias(key, 1)
            val strictAlias = ksafe.core.strictPerEntryAlias(key, 1)

            ksafe.put(key, "v1", hwiMode(requireUnlockedDevice = true))
            assertNotNull(engine.keysByAlias[strictAlias], "a fresh strict write mints directly under the variant")
            assertTrue(engine.deletedKeys.isEmpty(), "a fresh strict write has nothing to reclaim")

            ksafe.put(key, "v2", hwiMode(requireUnlockedDevice = false))
            assertNotNull(engine.keysByAlias[baseAlias])
            assertTrue(strictAlias in engine.deletedKeys, "the superseded strict key must be reclaimed")
            assertEquals("v2", ksafe.get(key, "fallback"))
        } finally {
            ksafe.close()
        }
    }

    /** DEFAULT-tier policy changes ride master aliases; nothing per-entry is minted or reclaimed. */
    @Test
    fun defaultTierWrites_neverTouchPerEntryAliases() = runTest {
        val engine = StatefulFakeEncryption()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = engine,
        )
        try {
            ksafe.put("d", "v1", KSafeWriteMode.Encrypted(requireUnlockedDevice = false))
            ksafe.put("d", "v2", KSafeWriteMode.Encrypted(requireUnlockedDevice = true))
            assertTrue(engine.deletedKeys.isEmpty(), "master-riding policy changes must not reclaim aliases")
            assertEquals("v2", ksafe.get("d", "fallback"))
        } finally {
            ksafe.close()
        }
    }

    /** delete() must sweep BOTH per-entry alias variants. */
    @Test
    fun delete_sweepsBothAliasVariants() = runTest {
        val engine = StatefulFakeEncryption()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = engine,
        )
        try {
            val key = "hw_del"
            ksafe.put(key, "v1", hwiMode(requireUnlockedDevice = true))
            ksafe.delete(key)
            assertTrue(ksafe.core.strictPerEntryAlias(key, 1) in engine.deletedKeys)
            assertTrue(ksafe.core.perEntryAlias(key, 1) in engine.deletedKeys)
        } finally {
            ksafe.close()
        }
    }

    /** clearAll() sweeps BOTH variants too — the wipe is the last chance to reclaim key material. */
    @Test
    fun clearAll_sweepsBothAliasVariants() = runTest {
        val engine = StatefulFakeEncryption()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = engine,
        )
        try {
            val key = "hw_wipe"
            ksafe.put(key, "v1", hwiMode(requireUnlockedDevice = true))
            ksafe.clearAll()
            assertTrue(ksafe.core.strictPerEntryAlias(key, 1) in engine.deletedKeys)
            assertTrue(ksafe.core.perEntryAlias(key, 1) in engine.deletedKeys)
        } finally {
            ksafe.close()
        }
    }

    /**
     * The alias sweeps skip the strict spelling only where the platform's pre-write mode transform
     * vetoes the unlock policy outright (web, whose strict read path async WebCrypto can't serve).
     * The Android/Apple transform must keep a strict HARDWARE_ISOLATED write strict, or their
     * sweeps would silently stop reclaiming strict key material.
     */
    @Test
    fun platformModeTransform_keepsAStrictHardwareIsolatedWriteStrict() {
        val strict = hwiMode(requireUnlockedDevice = true)
        assertEquals(
            strict,
            eu.anifantakis.lib.ksafe.internal.promoteDefaultToIsolated(strict, enabled = true),
            "the StrongBox/Secure Enclave promotion must not drop requireUnlockedDevice",
        )
    }

    /** Read routing: a legacy strict entry (no marker) keeps decrypting from the base alias. */
    @Test
    fun legacyStrictEntry_readsFromTheBaseAlias() = runTest {
        val engine = StatefulFakeEncryption()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = engine,
        )
        try {
            val key = "hw_legacy"
            // A pre-variant (≤2.2.1 / early-3.0.0) strict entry: strict metadata WITHOUT the
            // marker — its key lives under the bare per-entry alias.
            ksafe.core.encMetaMap[key] = eu.anifantakis.lib.ksafe.internal.KSafeCore.EncMeta(
                envelopeVersion = 2,
                requireUnlockedDevice = true,
                keyGeneration = 1,
                strictAliasVariant = false,
            )
            assertEquals(
                ksafe.core.perEntryAlias(key, 1),
                ksafe.core.aliasForRead(key, KSafeProtection.HARDWARE_ISOLATED),
                "a marker-less strict entry must keep resolving to the published base alias",
            )
            ksafe.core.encMetaMap[key] = eu.anifantakis.lib.ksafe.internal.KSafeCore.EncMeta(
                envelopeVersion = 2,
                requireUnlockedDevice = true,
                keyGeneration = 1,
                strictAliasVariant = true,
            )
            assertEquals(
                ksafe.core.strictPerEntryAlias(key, 1),
                ksafe.core.aliasForRead(key, KSafeProtection.HARDWARE_ISOLATED),
                "a marker-carrying strict entry must resolve to the variant alias",
            )
        } finally {
            ksafe.close()
        }
    }

    /** User keys spelling the strict-variant sentinel are rejected at the API boundary. */
    @Test
    fun strictSentinelUserKeys_areRejectedOnWrite() = runTest {
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = StatefulFakeEncryption(),
        )
        try {
            assertFailsWith<IllegalArgumentException> {
                ksafe.put("foo.__ksafe_strict__.h0123456789abcdef", "x")
            }
            assertFailsWith<IllegalArgumentException> {
                ksafe.putDirect("foo.__ksafe_strict__", "x")
            }
        } finally {
            ksafe.close()
        }
    }
}
