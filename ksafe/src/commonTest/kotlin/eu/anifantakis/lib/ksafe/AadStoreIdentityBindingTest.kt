package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The v3 AAD binds the full store identity, so two stores whose only difference is their directory
 * (same fileName) get different associated data — a rotated ciphertext can't be transplanted between
 * them and still authenticate. This locks the injective, directory-sensitive encoding. Each platform
 * factory feeds a directory/path-inclusive identity into [KeySafeMetadataManager.aadFor] (Android
 * datastorePath, Apple datastoreFilePath, JVM resolvedBaseDir + fileName); same-store v3
 * authentication (record swap / metadata tamper) is covered by the per-platform AAD binding tests.
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
