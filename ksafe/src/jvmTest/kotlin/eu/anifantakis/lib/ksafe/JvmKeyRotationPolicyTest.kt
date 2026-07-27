package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds

/**
 * Locks in KSafeConfig.keyRotationPolicy (3.0.0): Never (default) performs no automatic
 * rotation; MaxAge stamps the generation's birth on the first launch under the policy and
 * rotates in the background on a later launch once the generation is older than allowed.
 *
 * Uses runBlocking (not runTest): the policy runs on the real background scope, so the test
 * polls in real time.
 */
class JvmKeyRotationPolicyTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_rotpol_${System.nanoTime()}").apply { mkdirs() }

    @AfterTest fun tearDown() { tmp.deleteRecursively() }

    private fun newKSafe(fileName: String, policy: KSafeKeyRotationPolicy) = KSafe(
        fileName = fileName,
        baseDir = tmp,
        config = KSafeConfig(keyRotationPolicy = policy),
        testEngine = FakeEncryption(),
    )

    private suspend fun awaitGeneration(ksafe: KSafe, expected: Int, timeoutMs: Long = 10_000) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (ksafe.core.currentKeyGeneration.get() == expected) return
            delay(50)
        }
        fail("key generation never reached $expected (still ${ksafe.core.currentKeyGeneration.get()})")
    }

    @Test
    fun maxAge_firstLaunchStampsBirth_laterLaunchRotates() = runBlocking {
        val fileName = "rotpol_maxage"
        // Launch 1: no stamped birth yet — the policy stamps it and does NOT rotate.
        val first = newKSafe(fileName, KSafeKeyRotationPolicy.MaxAge(1.milliseconds))
        first.put("token", "v1-secret")
        // Give the background stamp a moment, then confirm no rotation happened.
        delay(500)
        assertEquals(1, first.core.currentKeyGeneration.get(), "the first launch only stamps the birth")
        first.close()

        // Launch 2: the stamped generation is now older than maxAge — background rotation.
        val second = newKSafe(fileName, KSafeKeyRotationPolicy.MaxAge(1.milliseconds))
        awaitGeneration(second, 2)
        assertEquals("v1-secret", second.get("token", ""), "the rotated value must still decrypt")
        second.close()
    }

    @Test
    fun maxAge_notExceeded_doesNotRotate() = runBlocking {
        val fileName = "rotpol_fresh"
        val first = newKSafe(fileName, KSafeKeyRotationPolicy.MaxAge(1000.days))
        first.put("token", "fresh")
        delay(500)
        first.close()

        val second = newKSafe(fileName, KSafeKeyRotationPolicy.MaxAge(1000.days))
        second.put("warmup", "x") // force full startup
        delay(700)
        assertEquals(1, second.core.currentKeyGeneration.get(), "a fresh generation must not rotate")
        assertEquals("fresh", second.get("token", ""))
        second.close()
    }

    @Test
    fun never_isTheDefault_andNeverRotates() = runBlocking {
        assertEquals(KSafeKeyRotationPolicy.Never, KSafeConfig().keyRotationPolicy)

        val fileName = "rotpol_never"
        val first = newKSafe(fileName, KSafeKeyRotationPolicy.Never)
        first.put("token", "still-gen1")
        delay(400)
        first.close()

        val second = newKSafe(fileName, KSafeKeyRotationPolicy.Never)
        second.put("warmup", "x")
        delay(400)
        assertEquals(1, second.core.currentKeyGeneration.get())
        assertEquals("still-gen1", second.get("token", ""))
        second.close()
    }
}
