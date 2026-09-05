package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.protectionByKeyFromSnapshot
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class SnapshotProtectionPrecedenceTest {

    private fun snapshot(vararg pairs: Pair<String, String>): Map<String, StoredValue> =
        pairs.associate { (k, v) -> k to StoredValue.Text(v) }

    @Test
    fun canonicalNone_winsOverAStaleLegacyDefault_inEitherOrder() {
        val meta = KeySafeMetadataManager.metadataRawKey("k") to "NONE"
        val legacy = KeySafeMetadataManager.legacyProtectionRawKey("k") to "DEFAULT"
        for (snap in listOf(snapshot(meta, legacy), snapshot(legacy, meta))) {
            assertFalse("k" in protectionByKeyFromSnapshot(snap), "canonical NONE means plain; the legacy record is stale")
        }
    }

    @Test
    fun bothCollectors_agree_onEveryPrecedenceCase() {
        val cases = listOf(
            snapshot(KeySafeMetadataManager.metadataRawKey("a") to "DEFAULT", KeySafeMetadataManager.legacyProtectionRawKey("a") to "HARDWARE_ISOLATED"),
            snapshot(KeySafeMetadataManager.legacyProtectionRawKey("b") to "HARDWARE_ISOLATED"),
            snapshot(KeySafeMetadataManager.metadataRawKey("c") to "NONE", KeySafeMetadataManager.legacyProtectionRawKey("c") to "DEFAULT"),
            snapshot(KeySafeMetadataManager.metadataRawKey("d") to """{"v":2,"p":"DEFAULT"}"""),
        )
        for (snap in cases) {
            val viaCollect = KeySafeMetadataManager.collectMetadata(
                snap.map { (k, v) -> k to (v as StoredValue.Text).value },
            ).mapNotNull { (k, lit) -> KeySafeMetadataManager.parseProtection(lit)?.let { k to it } }.toMap()
            assertEquals(viaCollect, protectionByKeyFromSnapshot(snap))
        }
    }
}
