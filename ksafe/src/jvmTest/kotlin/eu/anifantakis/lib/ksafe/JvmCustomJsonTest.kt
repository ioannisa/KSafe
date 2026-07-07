package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.Contextual
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.contextual
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Locks in: a custom Json (KSafeConfig.json) with user-registered serializers is used for all user-payload operations, so @Contextual types round-trip; the default Json rejects them.
 */
class JvmCustomJsonTest {

    /** A kotlinx.serialization serializer for [UUID]. */
    private object UUIDSerializer : KSerializer<UUID> {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("UUID", PrimitiveKind.STRING)

        override fun serialize(encoder: Encoder, value: UUID) =
            encoder.encodeString(value.toString())

        override fun deserialize(decoder: Decoder): UUID =
            UUID.fromString(decoder.decodeString())
    }

    /** Data class that uses `@Contextual` for UUID — requires a custom SerializersModule. */
    @Serializable
    data class UserProfile(
        val name: String,
        @Contextual val id: UUID
    )

    private val customJson = Json {
        ignoreUnknownKeys = true
        serializersModule = SerializersModule {
            contextual(UUIDSerializer)
        }
    }

    private fun createKSafe(json: Json = KSafeDefaults.json): KSafe {
        val runId = JvmKSafeTest.generateUniqueFileName()
        return KSafe(runId, config = KSafeConfig(json = json))
    }

    @Test
    fun putDirect_getDirect_withContextualType() {
        val ksafe = createKSafe(customJson)
        val profile = UserProfile("Alice", UUID.fromString("550e8400-e29b-41d4-a716-446655440000"))

        ksafe.putDirect("profile", profile, KSafeWriteMode.Plain)
        val result: UserProfile = ksafe.getDirect("profile", UserProfile("", UUID.randomUUID()))

        assertEquals(profile, result)
    }

    @Test
    fun putDirect_getDirect_encrypted_withContextualType() {
        val ksafe = createKSafe(customJson)
        val profile = UserProfile("Bob", UUID.fromString("660e8400-e29b-41d4-a716-446655440000"))

        ksafe.putDirect("enc_profile", profile)
        val result: UserProfile = ksafe.getDirect("enc_profile", UserProfile("", UUID.randomUUID()))

        assertEquals(profile, result)
    }

    @Test
    fun put_get_withContextualType() = runTest {
        val ksafe = createKSafe(customJson)
        val profile = UserProfile("Carol", UUID.fromString("770e8400-e29b-41d4-a716-446655440000"))

        ksafe.put("s_profile", profile, KSafeWriteMode.Plain)
        val result: UserProfile = ksafe.get("s_profile", UserProfile("", UUID.randomUUID()))

        assertEquals(profile, result)
    }

    @Test
    fun put_get_encrypted_withContextualType() = runTest {
        val ksafe = createKSafe(customJson)
        val profile = UserProfile("Dave", UUID.fromString("880e8400-e29b-41d4-a716-446655440000"))

        ksafe.put("s_enc_profile", profile)
        val result: UserProfile = ksafe.get("s_enc_profile", UserProfile("", UUID.randomUUID()))

        assertEquals(profile, result)
    }

    @Test
    fun delegate_withContextualType() {
        val ksafe = createKSafe(customJson)
        val defaultProfile = UserProfile("default", UUID.fromString("000e0000-0000-0000-0000-000000000000"))
        var profile: UserProfile by ksafe(defaultProfile, "del_profile", KSafeWriteMode.Plain)

        val expected = UserProfile("Eve", UUID.fromString("990e8400-e29b-41d4-a716-446655440000"))
        profile = expected

        val readBack: UserProfile by ksafe(defaultProfile, "del_profile", KSafeWriteMode.Plain)
        assertEquals(expected, readBack)
    }

    @Test
    fun getFlow_withContextualType() = runTest {
        val ksafe = createKSafe(customJson)
        val profile = UserProfile("FlowUser", UUID.fromString("aa0e8400-e29b-41d4-a716-446655440000"))

        ksafe.put("flow_profile", profile, KSafeWriteMode.Plain)
        val result: UserProfile = ksafe.getFlow("flow_profile", UserProfile("", UUID.randomUUID())).first()

        assertEquals(profile, result)
    }

    @Test
    fun defaultJson_rejectsContextualType() {
        val ksafe = createKSafe() // uses KSafeDefaults.json — no UUID serializer registered
        val profile = UserProfile("Fail", UUID.randomUUID())

        assertFailsWith<kotlinx.serialization.SerializationException> {
            ksafe.putDirect("bad_profile", profile, KSafeWriteMode.Plain)
        }
    }

    @Test
    fun defaultJson_isSameSingleton() {
        val config1 = KSafeConfig()
        val config2 = KSafeConfig()

        assertTrue(config1.json === config2.json, "Default json should be the same singleton instance")
        assertEquals(config1, config2)
    }
}
