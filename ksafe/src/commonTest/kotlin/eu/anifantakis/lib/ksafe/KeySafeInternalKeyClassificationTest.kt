package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Locks in: [KeySafeMetadataManager.isInternalStorageKey] matches only the genuine internal
 * prefixes (`__ksafe_*` and the web engine's `ksafe_key_*`), so a flat user key that merely
 * begins with `ksafe_` (e.g. "ksafe_theme") is preserved as a user value, not filtered out.
 */
class KeySafeInternalKeyClassificationTest {

    @Test
    fun genuineInternalKeysAreStillFiltered() {
        assertTrue(KeySafeMetadataManager.isInternalStorageKey("__ksafe_meta_token__"), "canonical metadata is internal")
        assertTrue(KeySafeMetadataManager.isInternalStorageKey("__ksafe_value_token"), "canonical value is internal")
        assertTrue(KeySafeMetadataManager.isInternalStorageKey("__ksafe_prot_token__"), "legacy protection is internal")
        assertTrue(KeySafeMetadataManager.isInternalStorageKey("__ksafe____DEK____"), "the Android DEK entry is internal")
        assertTrue(KeySafeMetadataManager.isInternalStorageKey("ksafe_key_master"), "the web engine key store is internal")
    }

    @Test
    fun flatUserKeyBeginningWithKsafe_isNotTreatedAsInternal() {
        // A flat plaintext user key named "ksafe_theme".
        assertFalse(
            KeySafeMetadataManager.isInternalStorageKey("ksafe_theme"),
            "a user key that merely begins with 'ksafe_' must NOT be filtered as internal",
        )
        assertFalse(KeySafeMetadataManager.isInternalStorageKey("ksafe_user_settings"), "another 'ksafe_'-prefixed user key")
    }

    @Test
    fun flatPlaintextUserKey_survivesClassification_asAUserValue() {
        // classifyStorageEntry routes non-internal, non-enveloped raw keys to a flat
        // plaintext user value, so "ksafe_theme" survives as a user value rather than being dropped.
        val classified = KeySafeMetadataManager.classifyStorageEntry(
            rawKey = "ksafe_theme",
            legacyEncryptedPrefix = "encrypted_",
            encryptedCacheKeyForUser = { "encrypted_$it" },
            stagedMetadata = emptyMap(),
            existingMetadata = emptyMap(),
        )
        assertNotNull(classified, "a flat plaintext 'ksafe_theme' must survive as a user value")
        assertEquals("ksafe_theme", classified.userKey)
        assertFalse(classified.encrypted)

        // ...while a genuine internal key still classifies as null (skipped).
        assertNull(
            KeySafeMetadataManager.classifyStorageEntry(
                rawKey = "ksafe_key_master",
                legacyEncryptedPrefix = "encrypted_",
                encryptedCacheKeyForUser = { "encrypted_$it" },
                stagedMetadata = emptyMap(),
                existingMetadata = emptyMap(),
            ),
            "the web engine key store must still be skipped",
        )
    }
}
