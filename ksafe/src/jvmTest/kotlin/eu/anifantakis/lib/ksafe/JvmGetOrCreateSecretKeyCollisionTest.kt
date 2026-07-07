package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.runBlocking
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse

/**
 * Locks in: getOrCreateSecret derives an injective storage key, so distinct logical keys (e.g. "main.db" vs "main_db") get distinct secrets, and a special-char key's legacy secret migrates forward non-destructively.
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
                "distinct keys that collapse to the same legacy slot must NOT share a secret",
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
            // A legacy secret stored under the collapsed slot shared by "main.db"/"main_db".
            val seeded = Base64.encode(ByteArray(32) { 7 })
            ksafe.put("ksafe_secret_main_db", seeded, KSafeWriteMode.Encrypted())

            // The special-char key migrates it forward…
            val migrated = ksafe.getOrCreateSecret("main.db")
            assertContentEquals(
                Base64.decode(seeded), migrated,
                "a special-char key's legacy secret must migrate forward from the collapsed slot",
            )
            // …and the shared legacy slot survives (a co-existing safe key still reads it).
            val safe = ksafe.getOrCreateSecret("main_db")
            assertContentEquals(
                Base64.decode(seeded), safe,
                "the shared legacy slot must NOT be deleted — a co-existing safe sibling may own it (non-destructive)",
            )
        } finally {
            ksafe.close()
        }
    }
}
