package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeSecretSlots
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Locks in: the startup orphan-ciphertext sweep never reaps a `getOrCreateSecret` slot.
 *
 * The refuse-to-rotate guard asks "is the ciphertext still there?". A secret slot is an ordinary
 * encrypted entry, so a sweep that deletes it when the backing key is gone (Auto Backup restore
 * onto a new device, Keystore invalidation, an evicted web CryptoKey) turns that guard into a
 * silent rotation: the next call mints a fresh random secret and hands it back as if it were the
 * original, and the SQLCipher database it keyed is locked forever.
 */
class JvmSecretSurvivesOrphanSweepTest {

    private val tmp = File(
        System.getProperty("java.io.tmpdir"),
        "ksafe_secret_sweep_${System.nanoTime()}",
    ).apply { mkdirs() }

    @AfterTest
    fun tearDown() {
        tmp.deleteRecursively()
    }

    private class Restored(val original: ByteArray, val ksafe: KSafe)

    /**
     * Creates a secret plus an ordinary encrypted entry, then reopens the same store file against
     * a vault holding no key material at all — the restored-onto-a-new-device shape. Returns once
     * the startup sweep has reaped the ordinary entry, so the secret slot's fate is decided.
     */
    private suspend fun restoreWithoutKeys(): Restored {
        val fileName = JvmKSafeTest.generateUniqueFileName()

        val first = KSafe(fileName = fileName, baseDir = tmp, testEngine = StatefulFakeEncryption())
        val original = first.getOrCreateSecret("main_db")
        // Same per-entry alias shape as the secret slot, so it is a genuine orphan next session;
        // its disappearance is the "the sweep has run" signal.
        first.put("canary", "v", KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))
        first.close()

        val second = KSafe(fileName = fileName, baseDir = tmp, testEngine = StatefulFakeEncryption())
        val swept = withTimeoutOrNull(20_000) {
            var clear = 0
            while (clear < 2) {
                clear = if (second.getKeyInfo("canary") == null) clear + 1 else 0
                delay(25)
            }
            true
        } ?: false
        assertTrue(swept, "premise: the startup orphan sweep must run and reap the ordinary orphan")
        return Restored(original, second)
    }

    @Test
    fun secretSlotSurvivesTheOrphanSweep_soTheRefuseToRotateGuardStillFires() = runBlocking {
        val restored = restoreWithoutKeys()

        assertNotNull(
            restored.ksafe.getKeyInfo("ksafe_secret_main_db"),
            "the secret slot's ciphertext must survive the orphan sweep — once it is gone the " +
                "refuse-to-rotate guard sees \"no secret\" and mints a replacement",
        )

        val ex = runCatching { restored.ksafe.getOrCreateSecret("main_db") }.exceptionOrNull()
        assertIs<IllegalStateException>(ex, "an unreadable existing secret must throw, not rotate")
        assertTrue(
            ex.message?.contains("Refusing to overwrite") == true,
            "must surface the refuse-to-rotate failure; was: ${ex.message}",
        )

        restored.ksafe.close()
    }

    @Test
    fun afterTheSweep_getOrCreateSecretNeverHandsBackADifferentSecret() = runBlocking {
        val restored = restoreWithoutKeys()

        val outcome = runCatching { restored.ksafe.getOrCreateSecret("main_db") }
        val returned = outcome.getOrNull()
        assertTrue(
            returned == null || returned.contentEquals(restored.original),
            "getOrCreateSecret returned a DIFFERENT secret than the one it stored — the caller " +
                "would open its SQLCipher database with a passphrase that was never used to " +
                "encrypt it, and the real one is gone",
        )

        restored.ksafe.close()
    }

    @Test
    fun theExemptedPrefixesAreTheSlotNamesGetOrCreateSecretActuallyWrites() = runBlocking {
        // The sweep exemption matches on these prefixes; if they ever stop naming the real slots
        // the exemption goes silently inert and the secret becomes reapable again.
        val ksafe = KSafe(fileName = JvmKSafeTest.generateUniqueFileName(), baseDir = tmp, testEngine = FakeEncryption())

        ksafe.getOrCreateSecret("plain_key")
        assertNotNull(
            ksafe.getKeyInfo(KSafeSecretSlots.PLAIN_PREFIX + "plain_key"),
            "a [A-Za-z0-9_] key must occupy PLAIN_PREFIX + key",
        )

        ksafe.getOrCreateSecret("hex.key")
        val hex = "hex.key".encodeToByteArray()
            .joinToString("") { b -> (b.toInt() and 0xff).toString(16).padStart(2, '0') }
        assertNotNull(
            ksafe.getKeyInfo(KSafeSecretSlots.HEX_PREFIX + hex),
            "a special-char key must occupy HEX_PREFIX + hex(utf8(key))",
        )

        ksafe.close()
    }
}
