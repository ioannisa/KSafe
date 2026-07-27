package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Pins how an entry's four routing fields are read out of its stored metadata.
 *
 * Every one of them decides which key an entry decrypts under, so a change of reading — not just
 * of writing — silently re-routes live data. The cases below are the ones where the four fields
 * DISAGREE about a record: a malformed value for one must not move the others, which is what
 * makes reading them field-by-field observably different from reading them together.
 */
class EntryRoutingParseTest {

    private val cases = listOf(
        Triple("absent metadata", null, KSafeCore.EncMeta(1, false, 1, false)),
        Triple("legacy literal DEFAULT", "DEFAULT", KSafeCore.EncMeta(1, false, 1, false)),
        Triple("legacy literal NONE", "NONE", KSafeCore.EncMeta(1, false, 1, false)),
        Triple("legacy literal HARDWARE_ISOLATED", "HARDWARE_ISOLATED", KSafeCore.EncMeta(1, false, 1, false)),
        Triple("not JSON at all", "}{ nonsense", KSafeCore.EncMeta(1, false, 1, false)),
        Triple("JSON, but an array", "[1,2,3]", KSafeCore.EncMeta(1, false, 1, false)),
        Triple("JSON, but a bare number", "123", KSafeCore.EncMeta(1, false, 1, false)),
        Triple("empty object", "{}", KSafeCore.EncMeta(1, false, 1, false)),
        Triple(
            "every field present",
            """{"v":3,"p":"DEFAULT","u":"unlocked","g":5,"sa":1}""",
            KSafeCore.EncMeta(3, true, 5, true),
        ),
        Triple("numbers spelled as strings", """{"v":"3","g":"5","sa":"1"}""", KSafeCore.EncMeta(3, false, 5, true)),
        Triple("unparseable version", """{"v":"abc","g":4}""", KSafeCore.EncMeta(1, false, 4, false)),
        Triple("generation below the floor", """{"g":0}""", KSafeCore.EncMeta(1, false, 1, false)),
        Triple("negative generation", """{"g":-5}""", KSafeCore.EncMeta(1, false, 1, false)),
        Triple(
            "generation above the ceiling",
            """{"g":999999}""",
            KSafeCore.EncMeta(1, false, KeySafeMetadataManager.MAX_KEY_GENERATION, false),
        ),
        Triple("strict flag is not 1", """{"sa":2}""", KSafeCore.EncMeta(1, false, 1, false)),
        Triple("strict flag is a boolean", """{"sa":true}""", KSafeCore.EncMeta(1, false, 1, false)),
        Triple("access policy is something else", """{"u":"whenever"}""", KSafeCore.EncMeta(1, false, 1, false)),
        // The isolation cases: one field is a shape no reader can take a primitive from.
        Triple(
            "version is an object, generation is fine",
            """{"v":{"nested":1},"g":7}""",
            KSafeCore.EncMeta(1, false, 7, false),
        ),
        Triple(
            "access policy is an array, strict flag is fine",
            """{"u":["unlocked"],"sa":1}""",
            KSafeCore.EncMeta(1, false, 1, true),
        ),
        Triple(
            "generation is an object, version is fine",
            """{"v":3,"g":{"x":2},"sa":1}""",
            KSafeCore.EncMeta(3, false, 1, true),
        ),
    )

    @Test
    fun eachCaseReadsExactlyTheseFourFields() {
        for ((name, raw, expected) in cases) {
            assertEquals(expected, KSafeCore.encMetaFromRaw(raw), "routing for: $name")
        }
    }

    /**
     * The four fields are also readable one at a time, by callers holding only a raw string.
     * Both ways must answer identically for every record — including the malformed ones, where
     * a shared parse could otherwise let one bad field take the rest of the record down with it.
     */
    @Test
    fun readingTheFieldsSeparatelyAgreesWithReadingThemTogether() {
        for ((name, raw, _) in cases) {
            val separately = KSafeCore.EncMeta(
                envelopeVersion = KeySafeMetadataManager.parseEnvelopeVersion(raw),
                requireUnlockedDevice = KeySafeMetadataManager.parseRequireUnlockedDevice(raw),
                keyGeneration = KeySafeMetadataManager.parseKeyGeneration(raw),
                strictAliasVariant = KeySafeMetadataManager.parseStrictAliasVariant(raw),
            )
            assertEquals(separately, KSafeCore.encMetaFromRaw(raw), "field-by-field vs together for: $name")
        }
    }
}
