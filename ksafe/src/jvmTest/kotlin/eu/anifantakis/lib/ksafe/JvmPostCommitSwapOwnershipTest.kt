package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: a same-valued write landing between an in-flight batch's commit and that batch's
 * post-commit plaintext→ciphertext swap never leaves the RAM cache holding the OLDER batch's
 * ciphertext while disk holds the newer one.
 */
class JvmPostCommitSwapOwnershipTest {

    /** Per-alias keys plus a per-call nonce, so two encrypts of one value differ byte-wise. */
    private class NoncedStatefulEncryption : KSafeEncryption {
        private val inner = StatefulFakeEncryption()
        private val nonce = AtomicInteger()

        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray = byteArrayOf(nonce.incrementAndGet().toByte()) +
            inner.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice, aad)

        override fun decrypt(
            identifier: String,
            data: ByteArray,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray =
            inner.decrypt(identifier, data.copyOfRange(1, data.size), requireUnlockedDevice, aad)

        override fun deleteKey(identifier: String) = inner.deleteKey(identifier)
    }

    /**
     * Runs [racer] once, from inside the committing batch's post-apply seam, then proves the
     * cache slot and the on-disk record agree.
     */
    private fun assertCacheAgreesWithDisk(
        policy: KSafeMemoryPolicy,
        racer: (KSafe) -> Unit,
    ): KSafe {
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = policy,
            lazyLoad = true, // no collector, so nothing can mask the desync
            testEngine = NoncedStatefulEncryption(),
        )
        var fired = false
        ksafe.core.postApplyBatchHook = { keys ->
            if (!fired && "k" in keys) {
                fired = true
                ksafe.core.postApplyBatchHook = null
                racer(ksafe)
            }
        }

        runBlocking {
            ksafe.put("k", "v")
            ksafe.put("barrier", 1) // the racing write's own batch is committed by now

            val disk = (
                ksafe.core.storage.snapshot()[KeySafeMetadataManager.valueRawKey("k")]
                    as StoredValue.Text
                ).value
            val cached = ksafe.core.memoryCache[KeySafeMetadataManager.legacyEncryptedRawKey("k")]
            assertEquals(
                disk,
                cached,
                "the RAM cache must hold the ciphertext that actually reached disk; an older " +
                    "batch's post-commit swap must not win against a newer same-valued write",
            )
        }
        return ksafe
    }

    @Test
    fun newerWriteWithDifferentRouting_leavesCacheMatchingDisk() {
        val ksafe = assertCacheAgreesWithDisk(KSafeMemoryPolicy.ENCRYPTED) { safe ->
            safe.putDirect(
                "k",
                "v",
                KSafeWriteMode.Encrypted(protection = KSafeEncryptedProtection.HARDWARE_ISOLATED),
            )
        }
        try {
            assertEquals(
                "v",
                runBlocking { ksafe.get("k", "") },
                "the entry must still read back; a cached ciphertext from the superseded " +
                    "routing decrypts under the newer entry's alias and yields the default",
            )
        } finally {
            ksafe.close()
        }
    }

    @Test
    fun newerWriteWithIdenticalRouting_leavesCacheMatchingDisk() {
        assertCacheAgreesWithDisk(KSafeMemoryPolicy.ENCRYPTED) { safe ->
            safe.putDirect("k", "v", KSafeWriteMode.Encrypted())
        }.close()
    }

    @Test
    fun newerWriteWithDifferentRouting_leavesCacheMatchingDisk_lazyPlainText() {
        assertCacheAgreesWithDisk(KSafeMemoryPolicy.LAZY_PLAIN_TEXT) { safe ->
            safe.putDirect(
                "k",
                "v",
                KSafeWriteMode.Encrypted(protection = KSafeEncryptedProtection.HARDWARE_ISOLATED),
            )
        }.close()
    }
}
