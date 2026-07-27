package eu.anifantakis.ksafe.compose

import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.KSafeWriteMode
import eu.anifantakis.lib.ksafe.compose.mutableStateOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in, against a real store: a UI toggle flipped back to the value it started at is rolled
 * back when its persist fails, exactly like any other write.
 *
 * This is the module's default configuration — no `scope`, so nothing observes external changes
 * and nothing ever advances the state's in-sync baseline past the value it was created with. A
 * write back to that baseline is therefore indistinguishable from "no change" to any bookkeeping
 * keyed on the baseline, while storage has already moved on. The user-visible failure is a
 * setting that shows OFF forever while disk says ON, with no error and no way back.
 *
 * `KSafeComposeState`-level coverage of the same defect lives in `FailedPersistRollbackTest`;
 * this test exists because the claim is about the default wiring of the public factory, not
 * about the state class in isolation.
 */
class JvmToggleRollbackTest {

    private companion object {
        private val testCounter = AtomicInteger(0)
        private val runId: String = System.currentTimeMillis().toString(36)

        /** DataStore forbids two instances on one file, so every test gets its own. */
        fun uniqueFileName(): String = "togglerollback${runId}t${testCounter.incrementAndGet()}"

        const val KEY = "notifications"

        /** Encrypted, so the write routes through the JSON encoder the serializer below rejects. */
        val MODE = KSafeWriteMode.Encrypted()
    }

    /**
     * A settings flag whose serializer can be told to start rejecting the `off` state, so the
     * store accepts `off` while it is being seeded and refuses it later — a persist that fails
     * synchronously, on the caller's thread, for a value the state also started at.
     */
    data class Flag(val on: Boolean) {
        // Hand-written rather than generated: :ksafe-compose does not apply the serialization
        // compiler plugin, and kotlinx resolves `serializer<T>()` through this companion on JVM.
        companion object {
            fun serializer(): KSerializer<Flag> = ArmableFlagSerializer
        }
    }

    private object ArmableFlagSerializer : KSerializer<Flag> {
        @Volatile
        var rejectsOff: Boolean = false

        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("Flag", PrimitiveKind.BOOLEAN)

        override fun serialize(encoder: Encoder, value: Flag) {
            if (rejectsOff && !value.on) throw SerializationException("test: this store cannot write the off state")
            encoder.encodeBoolean(value.on)
        }

        override fun deserialize(decoder: Decoder): Flag = Flag(decoder.decodeBoolean())
    }

    @Test
    fun failedPersist_ofAToggleFlippedBackToItsStoredValue_showsTheDurableValue() {
        ArmableFlagSerializer.rejectsOff = false
        val ksafe = KSafe(fileName = uniqueFileName())
        try {
            runBlocking { ksafe.put(KEY, Flag(on = false), MODE) }

            // The default differs from the stored value on purpose: the state then starts warm,
            // so no cold-start self-heal coroutine runs and the rollback is the only thing that
            // can move this state.
            val delegate = ksafe.mutableStateOf(Flag(on = true), key = KEY, mode = MODE)
                .provideDelegate(null, ::probeFlag)
            assertEquals(
                Flag(on = false), delegate.getValue(null, ::probeFlag),
                "sanity: the state must start in sync with the stored value",
            )

            // The user turns the setting on. This one persists.
            delegate.setValue(null, ::probeFlag, Flag(on = true))

            // From here the store refuses the off state — the locked-device / quota-exhausted
            // shape, but synchronous so nothing here has to wait.
            ArmableFlagSerializer.rejectsOff = true

            // The user turns it back off. The persist fails and the saver reconciles before this
            // assignment returns.
            delegate.setValue(null, ::probeFlag, Flag(on = false))

            assertEquals(
                Flag(on = true), delegate.getValue(null, ::probeFlag),
                "the off write never reached storage, so the state must show the durable on " +
                    "value; showing off is a phantom the user can never clear",
            )
        } finally {
            ArmableFlagSerializer.rejectsOff = false
            ksafe.close()
        }
    }
}

/** Delegate target; the test passes an explicit key, so the property name is never used. */
private var probeFlag: JvmToggleRollbackTest.Flag = JvmToggleRollbackTest.Flag(on = false)
