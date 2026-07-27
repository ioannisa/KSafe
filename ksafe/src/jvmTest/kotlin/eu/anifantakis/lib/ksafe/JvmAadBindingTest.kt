package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.test.runTest
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in the v3 authenticated envelope (3.0.0, invariant 10): after a rotation, the AES-GCM
 * associated data binds each ciphertext to its entry's identity and security metadata, so an
 * attacker with file access can no longer move a ciphertext to another slot (or tamper the
 * metadata it routes on) and have it decrypt in the wrong context — reads fail closed to the
 * caller's default. Pre-rotation (generation-1, v2) entries keep the exact pre-3.0.0 bytes,
 * so the swap boundary is also locked in: v2 is movable (the documented legacy behaviour),
 * v3 is not.
 */
class JvmAadBindingTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_aad_${System.nanoTime()}").apply { mkdirs() }

    @AfterTest fun tearDown() { tmp.deleteRecursively() }

    private suspend fun swapValueRecords(ksafe: KSafe, k1: String, k2: String) {
        val snap = ksafe.core.storage.snapshot()
        val r1 = KeySafeMetadataManager.valueRawKey(k1)
        val r2 = KeySafeMetadataManager.valueRawKey(k2)
        val v1 = snap[r1] as StoredValue.Text
        val v2 = snap[r2] as StoredValue.Text
        ksafe.core.storage.applyBatch(listOf(StorageOp.Put(r1, v2), StorageOp.Put(r2, v1)))
    }

    @Test
    fun afterRotation_swappedCiphertexts_failClosedToDefaults() = runTest {
        val ksafe = KSafe(fileName = "aad_v3", baseDir = tmp)
        ksafe.put("alpha", "alpha-secret")
        ksafe.put("beta", "beta-secret")
        ksafe.rotateKeys() // -> generation 2 -> v3 authenticated envelopes

        swapValueRecords(ksafe, "alpha", "beta")

        // Cold instance so nothing is served from RAM.
        ksafe.close()
        val reopened = KSafe(fileName = "aad_v3", baseDir = tmp)
        val alpha = reopened.get("alpha", "DEFAULT")
        val beta = reopened.get("beta", "DEFAULT")
        assertEquals("DEFAULT", alpha, "a relocated v3 ciphertext must fail authentication, not decrypt")
        assertEquals("DEFAULT", beta, "a relocated v3 ciphertext must fail authentication, not decrypt")
        assertTrue(alpha != "beta-secret" && beta != "alpha-secret", "no cross-served plaintext")
        reopened.close()
    }

    @Test
    fun afterRotation_tamperedMetadata_failsClosedToDefault() = runTest {
        val ksafe = KSafe(fileName = "aad_meta", baseDir = tmp)
        ksafe.put("token", "secret-token")
        ksafe.rotateKeys()

        // Rewrite the entry's metadata with a doctored generation: the read path now derives
        // a different alias AND a different AAD — either way the read must fail closed.
        val metaKey = KeySafeMetadataManager.metadataRawKey("token")
        val doctored = KeySafeMetadataManager.buildMetadataJson(
            protection = KSafeProtection.DEFAULT,
            accessPolicy = null,
            envelopeVersion = KeySafeMetadataManager.ENVELOPE_VERSION_V3,
            keyGeneration = 2,
        ).replace("\"g\":2", "\"g\":5")
        ksafe.core.storage.applyBatch(listOf(StorageOp.Put(metaKey, StoredValue.Text(doctored))))

        ksafe.close()
        val reopened = KSafe(fileName = "aad_meta", baseDir = tmp)
        assertEquals("DEFAULT", reopened.get("token", "DEFAULT"), "tampered metadata must never yield plaintext")
        reopened.close()
    }

    @Test
    fun beforeRotation_v2StaysByteCompatible_swapBoundaryDocumented() = runTest {
        val ksafe = KSafe(fileName = "aad_v2", baseDir = tmp)
        ksafe.put("one", "one-secret")
        ksafe.put("two", "two-secret")

        // Generation-1 metadata is v2 — the exact pre-3.0.0 envelope (free downgrade).
        val meta = (ksafe.core.storage.snapshot()[KeySafeMetadataManager.metadataRawKey("one")] as StoredValue.Text).value
        assertEquals(KeySafeMetadataManager.ENVELOPE_VERSION_V2, KeySafeMetadataManager.parseEnvelopeVersion(meta))

        // The documented v2 limitation: same-master ciphertexts are relocatable. This lock-in
        // makes the security BOUNDARY explicit — authentication of entry identity begins at v3
        // (i.e. after the store's first rotation).
        swapValueRecords(ksafe, "one", "two")
        ksafe.close()
        val reopened = KSafe(fileName = "aad_v2", baseDir = tmp)
        assertEquals("two-secret", reopened.get("one", "DEFAULT"), "v2 has no AAD binding (pre-rotation compat)")
        reopened.close()
    }

    @Test
    fun jvmLiveV3Aad_bindsTheBaseDirPath_notJustFileName() = runTest {
        val ksafe = KSafe(fileName = "aad_dir", baseDir = tmp)
        ksafe.put("token", "secret")
        ksafe.rotateKeys() // -> generation 2 -> v3

        // aadForRead reflects the core's own storeIdentity. The LIVE core must bind the full baseDir
        // path (matching what the fallback migration binds), not just the fileName. Regression guard:
        // the factory fed the path identity to createJvmBackend/migration but left KSafeCore on
        // fileName only, so a v3 entry written live would fail the migration's path-AAD decrypt.
        val aad = ksafe.core.aadForRead("token", KSafeProtection.DEFAULT)
            ?: error("expected a non-null v3 AAD after rotation")
        val aadStr = aad.decodeToString()
        assertTrue(
            aadStr.contains(tmp.absolutePath),
            "live v3 AAD must bind the baseDir path, not just the fileName; got: $aadStr",
        )
        ksafe.close()
    }
}
