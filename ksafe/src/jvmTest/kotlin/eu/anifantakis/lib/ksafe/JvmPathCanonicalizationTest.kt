package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.test.runTest
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * Locks in the KFA-014 path-canonicalization fix: one physical store reached under different
 * baseDir spellings (symlinked, `..`, relative) resolves to ONE v3 AAD identity, so a rotated
 * entry written under one spelling reads back under another — and entries written by a prior
 * (non-canonical) build are recovered through the core's fallback-identity decrypt path.
 */
class JvmPathCanonicalizationTest {

    private val root = File(System.getProperty("java.io.tmpdir"), "ksafe_canon_${System.nanoTime()}").apply { mkdirs() }
    private val realDir = File(root, "real").apply { mkdirs() }

    @AfterTest fun tearDown() { root.deleteRecursively() }

    @Test
    fun rotatedEntry_writtenViaSymlinkSpelling_readsBackViaRealSpelling() = runTest {
        val link = File(root, "link")
        Files.createSymbolicLink(link.toPath(), realDir.toPath())

        val viaLink = KSafe(fileName = "vault", baseDir = link)
        viaLink.put("token", "secret")
        viaLink.rotateKeys() // -> v3, AAD now binds the (canonical) store identity
        assertEquals("secret", viaLink.get("token", "DEFAULT"))
        viaLink.close()

        // A different spelling of the SAME physical dir canonicalizes identically -> reads.
        val viaReal = KSafe(fileName = "vault", baseDir = realDir)
        assertEquals(
            "secret", viaReal.get("token", "DEFAULT"),
            "a rotated v3 entry must read across equivalent path spellings",
        )
        viaReal.close()
    }

    @Test
    fun rotatedEntry_writtenViaDotSegmentSpelling_readsBackViaCleanSpelling() = runTest {
        val dotty = File(realDir, "sub/../") // resolves to realDir
        File(realDir, "sub").mkdirs()

        val viaDotty = KSafe(fileName = "v2", baseDir = dotty)
        viaDotty.put("k", "v")
        viaDotty.rotateKeys()
        viaDotty.close()

        val viaClean = KSafe(fileName = "v2", baseDir = realDir)
        assertEquals("v", viaClean.get("k", "DEFAULT"))
        viaClean.close()
    }

    /**
     * The fallback-identity decrypt path: a v3 entry whose AAD was written under the raw
     * (pre-canonicalization) identity is re-bound to that identity on disk, then read back by a
     * fresh instance whose PRIMARY identity is canonical — the read must fall back, not default.
     */
    @Test
    fun fallbackIdentityV3Entry_isRecovered() = runTest {
        val link = File(root, "link2")
        Files.createSymbolicLink(link.toPath(), realDir.toPath())

        val ks = KSafe(fileName = "lr", baseDir = link)
        ks.put("secret", "value-1")
        ks.rotateKeys() // v3, bound to the store's (canonical) identity

        // Read the store's ACTUAL identities from the live core — the symlink spelling is
        // non-canonical, so a distinct fallback identity exists.
        val fallback = ks.core.fallbackStoreIdentity
        assertNotEquals("", fallback, "precondition: a symlink baseDir yields a distinct fallback identity")
        assertNotEquals(ks.core.storeIdentity, fallback)

        // Decrypt the entry's EXACT stored plaintext (JSON-encoded) under its current canonical
        // AAD, then re-encrypt it under the LEGACY identity's AAD and overwrite the record —
        // simulating an entry a pre-canonicalization build wrote.
        val protection = KSafeProtection.DEFAULT
        val meta = ks.core.encMetaMap["secret"]!!
        val alias = ks.core.aliasForRead("secret", protection)
        val canonicalAad = KeySafeMetadataManager.aadFor(ks.core.storeIdentity, "secret", protection, meta.requireUnlockedDevice, meta.keyGeneration)
        val fallbackAad = KeySafeMetadataManager.aadFor(fallback, "secret", protection, meta.requireUnlockedDevice, meta.keyGeneration)
        val curB64 = (ks.core.storage.snapshot()[KeySafeMetadataManager.valueRawKey("secret")] as StoredValue.Text).value
        val storedPlaintext = ks.core.engine.decryptSuspend(alias, kotlin.io.encoding.Base64.decode(curB64), aad = canonicalAad)
        val reEnc = ks.core.engine.encryptSuspend(alias, storedPlaintext, aad = fallbackAad)
        ks.core.storage.applyBatch(
            listOf(
                eu.anifantakis.lib.ksafe.internal.StorageOp.Put(
                    KeySafeMetadataManager.valueRawKey("secret"),
                    StoredValue.Text(kotlin.io.encoding.Base64.encode(reEnc)),
                ),
            ),
        )
        ks.close()

        // Fresh instance: primary=canonical (mismatches the re-bound entry), the fallback matches.
        val reopened = KSafe(fileName = "lr", baseDir = link)
        assertEquals(
            "value-1", reopened.get("secret", "DEFAULT"),
            "a v3 entry bound to the fallback identity must read via the fallback, not default",
        )
        reopened.close()
    }
}
