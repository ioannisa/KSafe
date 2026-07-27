package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame

/**
 * Locks in: a serializer that throws during encode leaves the store completely untouched.
 * Before the fix the put paths mutated the ownership token, dirty flag, and routing
 * metadata BEFORE encoding; an encode-time throw then poisoned the key for the process
 * lifetime — the durable value became unreadable through get/getDirect (routing pointed at
 * an empty ciphertext slot) while nothing could repair it, because the cache merge skips
 * dirty keys. Also locks in single-encode on the plain paths: cache and disk must share one
 * representation even for a non-deterministic serializer.
 */
class JvmPutSerializerFailureTest {

    private class Poison

    private object ThrowingSerializer : KSerializer<Poison> {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("Poison", PrimitiveKind.STRING)

        override fun serialize(encoder: Encoder, value: Poison): Unit =
            throw SerializationException("encode-time failure (test)")

        override fun deserialize(decoder: Decoder): Poison =
            throw SerializationException("never decoded (test)")
    }

    private class Counted(val payload: String)

    private class CountingSerializer : KSerializer<Counted> {
        var serializeCalls = 0

        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("Counted", PrimitiveKind.STRING)

        override fun serialize(encoder: Encoder, value: Counted) {
            serializeCalls++
            encoder.encodeString(value.payload)
        }

        override fun deserialize(decoder: Decoder): Counted = Counted(decoder.decodeString())
    }

    /** The failed put must have left zero state: value, routing, dirty flag, and token untouched. */
    private fun assertNoTraceLeft(ksafe: KSafe, key: String, tokenBefore: Any?) {
        val core = ksafe.core
        val encryptedSlot = core.legacyEncryptedRawKey(key)
        assertEquals(
            "old-value", ksafe.getDirect(key, "fallback"),
            "the durable value must stay readable after a failed put",
        )
        assertEquals(
            "NONE", core.protectionMap[key],
            "the failed put must not commit its protection literal",
        )
        assertNull(core.encMetaMap[key], "the failed put must not commit routing metadata")
        assertFalse(
            core.dirtyKeys.contains(encryptedSlot),
            "the failed put must not leave a permanent dirty flag on the ciphertext slot",
        )
        assertFalse(
            core.memoryCache.containsKey(encryptedSlot),
            "the failed put must not leave a cached ciphertext-slot value",
        )
        assertSame(
            tokenBefore, core.writeOwners[key],
            "the failed put must not steal write ownership — that silently blocks an " +
                "older in-flight write's rollback",
        )
    }

    private fun runEncodeFailureScenario(memoryPolicy: KSafeMemoryPolicy) = runTest {
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = memoryPolicy,
            testEngine = FakeEncryption(),
        )
        try {
            val key = "poisoned"
            ksafe.put(key, "old-value", KSafeWriteMode.Plain)
            val tokenBefore = ksafe.core.writeOwners[key]

            assertFailsWith<SerializationException> {
                ksafe.core.putRaw(key, Poison(), KSafeWriteMode.Encrypted(), ThrowingSerializer)
            }
            assertNoTraceLeft(ksafe, key, tokenBefore)

            assertFailsWith<SerializationException> {
                ksafe.core.putDirectRaw(key, Poison(), KSafeWriteMode.Encrypted(), ThrowingSerializer)
            }
            assertNoTraceLeft(ksafe, key, tokenBefore)

            assertFailsWith<SerializationException> {
                ksafe.core.putRaw(key, Poison(), KSafeWriteMode.Plain, ThrowingSerializer)
            }
            assertFailsWith<SerializationException> {
                ksafe.core.putDirectRaw(key, Poison(), KSafeWriteMode.Plain, ThrowingSerializer)
            }
            assertNoTraceLeft(ksafe, key, tokenBefore)

            // The key is not bricked: an ordinary write still lands and reads back.
            ksafe.put(key, "recovered", KSafeWriteMode.Encrypted())
            assertEquals("recovered", ksafe.get(key, "fallback"))
        } finally {
            ksafe.close()
        }
    }

    @Test
    fun throwingSerializer_leavesNoTrace_encryptedPolicy() =
        runEncodeFailureScenario(KSafeMemoryPolicy.ENCRYPTED)

    // The side-cache policies keep a second plaintext cache the ENCRYPTED run never touches.
    @Test
    fun throwingSerializer_leavesNoTrace_timedCachePolicy() =
        runEncodeFailureScenario(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)

    @Test
    fun plainPuts_serializeExactlyOnce() = runTest {
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
            testEngine = FakeEncryption(),
        )
        try {
            val counting = CountingSerializer()
            ksafe.core.putRaw("counted", Counted("a"), KSafeWriteMode.Plain, counting)
            assertEquals(
                1, counting.serializeCalls,
                "a suspend plain put must encode once — cache and disk share the representation",
            )

            ksafe.core.putDirectRaw("counted", Counted("b"), KSafeWriteMode.Plain, counting)
            assertEquals(
                2, counting.serializeCalls,
                "a direct plain put must encode once — cache and disk share the representation",
            )
        } finally {
            ksafe.close()
        }
    }
}
