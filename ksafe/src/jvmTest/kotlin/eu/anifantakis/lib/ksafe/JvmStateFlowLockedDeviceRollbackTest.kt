package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: when a `asMutableStateFlow` write fails and the durable re-read cannot resolve, the
 * flow falls back to the value it last had in sync with storage — not to the caller's default.
 *
 * A locked device produces both halves at once: the strict write cannot be encrypted, and the
 * entry that is still intact on disk cannot be decrypted, so the re-read returns whatever
 * fallback it was handed. Handing it the caller's default publishes "no value" over live data —
 * for the token below, the app sees a logged-out user while the session is intact on disk and
 * readable again the moment the device unlocks.
 */
class JvmStateFlowLockedDeviceRollbackTest {

    /**
     * XOR engine that refuses to encrypt a marked payload, and — once locked — cannot decrypt
     * anything either. Keying the write failure off the payload leaves the master-alias writes
     * working, so only the test's own write fails.
     */
    private class LockableMarkerEngine(private val failMarker: String) : KSafeEncryption {
        @Volatile
        var locked = false
        private val xor = FakeEncryption()

        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray {
            if (data.decodeToString().contains(failMarker)) {
                throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked. (test)")
            }
            return xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)
        }

        override fun decrypt(
            identifier: String,
            data: ByteArray,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray {
            if (locked) throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked. (test)")
            return xor.decrypt(identifier, data)
        }

        override fun deleteKey(identifier: String) { /* no-op */ }
    }

    private class TokenHolder(ksafe: KSafe, scope: CoroutineScope) {
        val token by ksafe.asMutableStateFlow(
            "logged_out",
            scope,
            key = "token",
            mode = KSafeWriteMode.Encrypted(),
        )
    }

    @Test
    fun failedPersist_whoseDurableReReadCannotResolve_keepsTheLastSyncedValue() {
        val engine = LockableMarkerEngine("BAD")
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED, // cacheHoldsCiphertext → every read decrypts
            testEngine = engine,
        )
        val scope = CoroutineScope(SupervisorJob())
        try {
            runBlocking {
                ksafe.put("token", "session_token", KSafeWriteMode.Encrypted())

                val flow = TokenHolder(ksafe, scope).token
                assertEquals("session_token", flow.value, "sanity: the flow starts in sync with storage")

                // The device locks: nothing decrypts from here on.
                engine.locked = true

                // An optimistic renewal whose encrypt fails in the write consumer.
                flow.value = "BAD_renewed"

                // An awaited write enqueued afterwards is processed in (or after) the failing
                // write's batch, and the fire-and-forget failure callback runs first — so the
                // reconcile has completed by the time this put returns.
                ksafe.put("flush", "x", KSafeWriteMode.Encrypted())

                assertEquals(
                    "session_token", flow.value,
                    "the renewal never reached storage and the intact session cannot be re-read " +
                        "while locked, so the flow must keep the value it last had in sync with " +
                        "storage instead of publishing the caller's default over it",
                )
            }
        } finally {
            scope.cancel()
            ksafe.close()
        }
    }
}
