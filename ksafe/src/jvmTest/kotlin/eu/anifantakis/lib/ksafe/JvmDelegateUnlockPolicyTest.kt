package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.runBlocking
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Locks in: the `by ksafe(...)` property delegate (and the flow factories) inherit the instance's
 * `KSafeConfig.requireUnlockedDevice`, matching `put`/`putDirect` — rather than silently writing at
 * the hardcoded `KSafeWriteMode.Encrypted()` default of `requireUnlockedDevice = false`, which would
 * create the backing key without the unlock requirement the app configured.
 */
class JvmDelegateUnlockPolicyTest {

    /** Records the `requireUnlockedDevice` each encrypt was asked for, keyed by alias. */
    private class RecordingEncryption : KSafeEncryption {
        private val xor = FakeEncryption()
        val requireUnlockByAlias = ConcurrentHashMap<String, Boolean>()
        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray {
            if (requireUnlockedDevice != null) requireUnlockByAlias[identifier] = requireUnlockedDevice
            return xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice, aad)
        }

        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray =
            xor.decrypt(identifier, data)

        override fun deleteKey(identifier: String) { /* no-op */ }
    }

    @Test
    fun delegateWrite_inheritsConfigRequireUnlockedDevice() {
        val engine = RecordingEncryption()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            config = KSafeConfig(requireUnlockedDevice = true),
            testEngine = engine,
        )

        var token by ksafe("", key = "auth_token")
        token = "secret" // `by ksafe(...)` delegate write, fire-and-forget

        // FIFO flush: a Plain write enqueued after the delegate write; when its suspend await
        // completes, the earlier encrypted delegate write has already reached the engine. Plain
        // does no encryption, so it records nothing itself.
        runBlocking { ksafe.put("__flush__", "x", KSafeWriteMode.Plain) }

        assertTrue(engine.requireUnlockByAlias.isNotEmpty(), "the delegate write must have reached the engine")
        assertTrue(
            engine.requireUnlockByAlias.values.all { it },
            "`by ksafe(...)` must inherit config.requireUnlockedDevice=true (via defaultEncryptedMode), not " +
                "the hardcoded Encrypted() default of false; recorded=${engine.requireUnlockByAlias}",
        )

        ksafe.close()
    }

    @Test
    fun delegateWrite_defaultsToUnlockedFalse_whenConfigDoesNotRequireIt() {
        // Control: with the default config (requireUnlockedDevice=false) the delegate must record
        // false — proving the assertion above tracks the actual configured value, not a constant.
        val engine = RecordingEncryption()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = engine,
        )

        var token by ksafe("", key = "auth_token")
        token = "secret"
        runBlocking { ksafe.put("__flush__", "x", KSafeWriteMode.Plain) }

        assertTrue(engine.requireUnlockByAlias.isNotEmpty(), "the delegate write must have reached the engine")
        assertTrue(
            engine.requireUnlockByAlias.values.none { it },
            "with the default config the delegate must write requireUnlockedDevice=false; recorded=${engine.requireUnlockByAlias}",
        )

        ksafe.close()
    }

    @Test
    fun defaultWriteMode_reflectsTheConfiguredUnlockPolicy() {
        // The public accessor adapters (Compose state) default through: it must mirror
        // KSafeConfig.requireUnlockedDevice exactly, both ways.
        val strict = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            config = KSafeConfig(requireUnlockedDevice = true),
            testEngine = FakeEncryption(),
        )
        val relaxed = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            testEngine = FakeEncryption(),
        )

        assertTrue((strict.defaultWriteMode as KSafeWriteMode.Encrypted).requireUnlockedDevice)
        assertTrue(!(relaxed.defaultWriteMode as KSafeWriteMode.Encrypted).requireUnlockedDevice)

        strict.close()
        relaxed.close()
    }
}
