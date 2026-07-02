package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * FEEDBACK_4 M-C: [KeySafeMetadataManager.isInternalStorageKey] filters KSafe's
 * own storage keys out of the user-value view. It matched a blanket single-
 * underscore `ksafe_` prefix, which also swallowed pre-2.0 FLAT plaintext user
 * keys that merely began with `ksafe_` (e.g. "ksafe_theme") — silently dropping
 * them on upgrade. The filter must match only the genuine internal prefixes
 * (`__ksafe_*` and the web engine's `ksafe_key_*`), while still letting real
 * internal keys be skipped.
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
        // The exact regression: a pre-2.0 flat plaintext user key named "ksafe_theme".
        assertFalse(
            KeySafeMetadataManager.isInternalStorageKey("ksafe_theme"),
            "a user key that merely begins with 'ksafe_' must NOT be filtered as internal (M-C)",
        )
        assertFalse(KeySafeMetadataManager.isInternalStorageKey("ksafe_user_settings"), "another 'ksafe_'-prefixed user key")
    }

    @Test
    fun flatPlaintextUserKey_survivesClassification_asAUserValue() {
        // classifyStorageEntry routes non-internal, non-enveloped raw keys to a flat
        // plaintext user value. Before the fix "ksafe_theme" classified as internal → null
        // → the value was dropped on load.
        val classified = KeySafeMetadataManager.classifyStorageEntry(
            rawKey = "ksafe_theme",
            legacyEncryptedPrefix = "encrypted_",
            encryptedCacheKeyForUser = { "encrypted_$it" },
            stagedMetadata = emptyMap(),
            existingMetadata = emptyMap(),
        )
        assertNotNull(classified, "a flat plaintext 'ksafe_theme' must survive as a user value (M-C)")
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
