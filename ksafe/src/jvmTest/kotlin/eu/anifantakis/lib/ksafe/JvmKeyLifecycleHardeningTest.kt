package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.test.runTest
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in the key-lifecycle hardening around clearAll/rotation:
 * - a write racing clearAll commits under the RESET generation, stays visible to the next
 *   rotation, and leaves no above-generation master a later clearAll would miss;
 * - a stale pre-clear cache merge cannot republish wiped secrets after clearAll returns;
 * - an encrypted→plain overwrite reclaims the superseded per-entry platform key;
 * - RAM rotation metadata stays fresh under every memory policy, so getKeyInfo reports the
 *   rotated generation and clearAll's sweep names the right aliases.
 */
class JvmKeyLifecycleHardeningTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_klh_${System.nanoTime()}").apply { mkdirs() }

    @AfterTest fun tearDown() { tmp.deleteRecursively() }

    private val hwi = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)

    @Test
    fun writeRacingClearAll_commitsUnderTheResetGeneration_andStaysRotatable() = runTest {
        // deleteKey fires mid-performClearAll, before the generation reset — the exact window
        // where a caller-side write still captures the pre-clear generation.
        val engine = object : StatefulFakeEncryption() {
            var onDeleteKey: (() -> Unit)? = null
            override fun deleteKey(identifier: String) {
                onDeleteKey?.also { onDeleteKey = null }?.invoke()
                super.deleteKey(identifier)
            }
        }
        val ksafe = KSafe(fileName = "klh_race", baseDir = tmp, testEngine = engine)
        ksafe.put("seed", "s", hwi)
        ksafe.rotateKeys()
        ksafe.rotateKeys() // store at generation 3

        engine.onDeleteKey = { ksafe.putDirect("fresh", "value") }
        ksafe.clearAll()
        ksafe.put("drain", "d") // awaited write drains the queue behind the racing putDirect

        val meta = (ksafe.core.storage.snapshot()[KeySafeMetadataManager.metadataRawKey("fresh")] as? StoredValue.Text)?.value
        assertEquals(
            1, meta?.let { KeySafeMetadataManager.parseKeyGeneration(it) },
            "a survivor write must commit under the reset generation, not its stale captured one",
        )
        assertEquals("value", ksafe.get("fresh", ""), "the survivor write must stay readable")

        // The next rotation must include it (an unclamped gen-3 entry would be silently excluded).
        val rotation = ksafe.rotateKeys()
        assertTrue(rotation.rotated >= 1, "the survivor entry must be a rotation candidate, got $rotation")

        // After a final wipe no master above the store generation may survive.
        ksafe.clearAll()
        assertTrue(
            engine.liveAliases().none { "__ksafe_master__" in it },
            "no master key may survive a full wipe, got ${engine.liveAliases()}",
        )
        ksafe.close()
    }

    @Test
    fun stalePreClearMerge_cannotRepublishWipedSecrets() = runTest {
        val engine = StatefulFakeEncryption()
        val ksafe = KSafe(fileName = "klh_epoch", baseDir = tmp, testEngine = engine)
        ksafe.put("token", "wiped-secret")
        val staleSnapshot = ksafe.core.storage.snapshot()

        ksafe.clearAll()

        // Replays the race deterministically: a merge whose snapshot (and epoch — the counter
        // starts at 0 and the single clearAll above moved it to 1) predates the wipe finishes
        // AFTER clearAll returned. The epoch mismatch must make it redo from the post-clear
        // snapshot instead of publishing the stale one.
        ksafe.core.updateCache(staleSnapshot, epochAtSnapshot = 0)

        assertEquals("", ksafe.getDirect("token", ""), "a wiped secret must not resurrect from a stale merge")
        assertEquals(null, ksafe.getKeyInfo("token"), "wiped metadata must not resurrect either")
        ksafe.close()
    }

    @Test
    fun encryptedToPlainOverwrite_reclaimsTheSupersededPlatformKey() = runTest {
        val engine = StatefulFakeEncryption()
        val ksafe = KSafe(fileName = "klh_toplain", baseDir = tmp, testEngine = engine)
        ksafe.put("secret", "v", hwi)
        val ownedAlias = engine.liveAliases().single { "secret" in it }

        ksafe.put("secret", "now-plain", KSafeWriteMode.Plain)
        assertTrue(
            ownedAlias in engine.deletedKeys,
            "the superseded per-entry key must be reclaimed on encrypted→plain, got ${engine.deletedKeys}",
        )
        assertEquals("now-plain", ksafe.get("secret", ""))

        // Plain→plain must stay free of platform-key round-trips.
        val deletesBefore = engine.deletedKeys.size
        ksafe.put("secret", "still-plain", KSafeWriteMode.Plain)
        assertEquals(deletesBefore, engine.deletedKeys.size, "plain→plain must not touch engine keys")
        ksafe.close()
    }

    @Test
    fun rotatedGeneration_isReportedAndSwept_underEveryMemoryPolicy() = runTest {
        for (policy in KSafeMemoryPolicy.entries) {
            val engine = StatefulFakeEncryption()
            val ksafe = KSafe(
                fileName = "klh_${policy.name.lowercase()}",
                baseDir = tmp,
                memoryPolicy = policy,
                testEngine = engine,
            )
            ksafe.put("hw", "v", hwi)
            ksafe.rotateKeys()

            assertEquals(
                2, ksafe.getKeyInfo("hw")?.keyGeneration,
                "[$policy] getKeyInfo must report the rotated generation",
            )
            assertEquals("v", ksafe.get("hw", ""), "[$policy] the rotated entry must stay readable")

            ksafe.clearAll()
            assertTrue(
                engine.liveAliases().none { "hw" in it },
                "[$policy] clearAll must reclaim every generation's per-entry alias, got ${engine.liveAliases()}",
            )
            ksafe.close()
        }
    }
}
