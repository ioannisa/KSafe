package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in the fail-closed classification of a canonical value entry: a `__ksafe_value_*`
 * slot holds base64 IV‖ciphertext when encrypted, so it may only be treated as plaintext when its
 * metadata is present, parses, and EXPLICITLY marks it non-encrypted. Absent, unparseable, or
 * `p`-missing metadata is unresolved and must route through decrypt rather than serving raw bytes.
 */
class KSafeClassificationTest {

    @Test
    fun explicitlyEncryptedMeta_isEncrypted() {
        assertTrue(KeySafeMetadataManager.isCanonicalValueEncrypted("""{"v":2,"p":"DEFAULT"}"""))
        assertTrue(KeySafeMetadataManager.isCanonicalValueEncrypted("""{"v":3,"p":"HARDWARE_ISOLATED"}"""))
        assertTrue(KeySafeMetadataManager.isCanonicalValueEncrypted("DEFAULT"), "legacy literal")
    }

    @Test
    fun explicitlyNoneMeta_isPlaintext() {
        // The exact payload a legitimate plaintext write persists.
        assertFalse(KeySafeMetadataManager.isCanonicalValueEncrypted("""{"v":3,"p":"NONE"}"""))
        assertFalse(KeySafeMetadataManager.isCanonicalValueEncrypted("NONE"), "legacy literal")
    }

    @Test
    fun unresolvedMeta_failsClosedToEncrypted() {
        // Absent (the crash-between-value-and-metadata-Put case on a non-atomic backend).
        assertTrue(KeySafeMetadataManager.isCanonicalValueEncrypted(null))
        // Unparseable (a tamperer truncated it).
        assertTrue(KeySafeMetadataManager.isCanonicalValueEncrypted("{not valid json"))
        assertTrue(KeySafeMetadataManager.isCanonicalValueEncrypted(""))
        // Parses but carries no protection marker at all — still unresolved, never plaintext.
        assertTrue(KeySafeMetadataManager.isCanonicalValueEncrypted("""{"v":3}"""))
        // An unknown protection value is not an explicit NONE.
        assertTrue(KeySafeMetadataManager.isCanonicalValueEncrypted("""{"p":"WAT"}"""))
    }
}
