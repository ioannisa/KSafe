package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.runBlocking
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse

/**
 * FEEDBACK_4 M7: the pre-2.1.4 `getOrCreateSecret` derived its storage key by collapsing every
 * non-[A-Za-z0-9_] character to '_', so DISTINCT logical keys aliased to ONE slot and silently
 * shared/overwrote a single secret — e.g. the KDoc example `getOrCreateSecret("main.db")` collides
 * with the default `getOrCreateSecret()` (key = "main_db"). The storage key is now injective, and a
 * special-char key's pre-M7 secret is migrated forward non-destructively.
 */
@OptIn(ExperimentalEncodingApi::class)
class JvmGetOrCreateSecretKeyCollisionTest {

    private fun newKsafe() = KSafe(fileName = JvmKSafeTest.generateUniqueFileName(), testEngine = FakeEncryption())

    @Test
    fun distinctKeysThatSanitizeCollide_getDistinctSecrets() = runBlocking {
        val ksafe = newKsafe()
        try {
            val a = ksafe.getOrCreateSecret("main.db")
            val b = ksafe.getOrCreateSecret("main_db")
            assertFalse(
                a.contentEquals(b),
                "distinct keys that collapse to the same legacy slot must NOT share a secret (M7)",
            )
            // Stable and isolated across re-reads.
            assertContentEquals(a, ksafe.getOrCreateSecret("main.db"))
            assertContentEquals(b, ksafe.getOrCreateSecret("main_db"))
        } finally {
            ksafe.close()
        }
    }

    @Test
    fun specialCharKey_migratesPreM7Secret_nonDestructively() = runBlocking {
        val ksafe = newKsafe()
        try {
            // A pre-2.1.4 secret: stored under the collapsed legacy slot shared by "main.db"/"main_db".
            val seeded = Base64.encode(ByteArray(32) { 7 })
            ksafe.put("ksafe_secret_main_db", seeded, KSafeWriteMode.Encrypted())

            // The special-char key migrates it forward…
            val migrated = ksafe.getOrCreateSecret("main.db")
            assertContentEquals(
                Base64.decode(seeded), migrated,
                "a special-char key's pre-M7 secret must migrate forward from the legacy slot",
            )
            // …and the shared legacy slot survives (a co-existing safe key still reads it).
            val safe = ksafe.getOrCreateSecret("main_db")
            assertContentEquals(
                Base64.decode(seeded), safe,
                "the shared legacy slot must NOT be deleted — a co-existing safe sibling may own it (M7 non-destructive)",
            )
        } finally {
            ksafe.close()
        }
    }
}
