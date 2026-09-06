package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: the v3 AAD binds the full store identity, so two stores differing only in directory get
 * different associated data and a rotated ciphertext cannot be transplanted between them and still
 * authenticate. Every platform factory feeds a path-inclusive identity into
 * [KeySafeMetadataManager.aadFor]; same-store authentication lives in the per-platform AAD tests.
 */
class AadStoreIdentityBindingTest {

    @Test
    fun differentStorePaths_produceDifferentAad() {
        val a = KeySafeMetadataManager.aadFor(
            storeIdentity = "/dirA/eu_anifantakis_ksafe_datastore_s",
            userKey = "token",
            protection = null,
            requireUnlockedDevice = false,
            keyGeneration = 2,
        )
        val b = KeySafeMetadataManager.aadFor(
            storeIdentity = "/dirB/eu_anifantakis_ksafe_datastore_s",
            userKey = "token",
            protection = null,
            requireUnlockedDevice = false,
            keyGeneration = 2,
        )
        assertFalse(
            a.contentEquals(b),
            "the same fileName under different directories must not share v3 AAD",
        )
    }

    @Test
    fun sameStorePath_producesStableAad() {
        fun aad() = KeySafeMetadataManager.aadFor(
            storeIdentity = "/dir/eu_anifantakis_ksafe_datastore_s",
            userKey = "token",
            protection = null,
            requireUnlockedDevice = false,
            keyGeneration = 2,
        )
        assertTrue(aad().contentEquals(aad()), "identical inputs must produce identical AAD")
    }
}
