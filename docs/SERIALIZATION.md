# Custom JSON Serialization

By default, KSafe handles primitives, `@Serializable` data classes, lists, and nullable types automatically. But if you need to store **third-party types you don't own** (e.g., `UUID`, `Instant`, `BigDecimal`), you can inject a custom `Json` instance via `KSafeConfig`.

## Why is this needed?

Types like `java.util.UUID` or `kotlinx.datetime.Instant` live in external libraries — you can't add `@Serializable` to them. Instead, you write a small `KSerializer` that teaches kotlinx.serialization how to convert the type to/from a string, then register it once when creating `KSafe`.

## Step-by-Step

**1. Define custom serializers for types you don't own**

```kotlin
object UUIDSerializer : KSerializer<UUID> {
    override val descriptor = PrimitiveSerialDescriptor("UUID", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: UUID) = encoder.encodeString(value.toString())
    override fun deserialize(decoder: Decoder): UUID = UUID.fromString(decoder.decodeString())
}

object InstantSerializer : KSerializer<Instant> {
    override val descriptor = PrimitiveSerialDescriptor("Instant", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: Instant) = encoder.encodeString(value.toString())
    override fun deserialize(decoder: Decoder): Instant = Instant.parse(decoder.decodeString())
}
```

**2. Build a Json instance and register all your serializers in one place**

```kotlin
val customJson = Json {
    ignoreUnknownKeys = true
    serializersModule = SerializersModule {
        contextual(UUIDSerializer)
        contextual(InstantSerializer)
        // add as many as you need
    }
}
```

**3. Pass it via KSafeConfig — one setup, used everywhere**

```kotlin
val ksafe = KSafe(
    context = context,                              // Android; omit on JVM/iOS/WASM
    config = KSafeConfig(json = customJson)
)
```

**4. Use `@Contextual` types directly — no extra work at the call site**

```kotlin
@Serializable
data class UserProfile(
    val name: String,
    @Contextual val id: UUID,
    @Contextual val createdAt: Instant
)

// Works with all KSafe APIs
ksafe.putDirect("profile", UserProfile("Alice", UUID.randomUUID(), Instant.now()))
val profile: UserProfile = ksafe.getDirect("profile", defaultProfile)

// Suspend API
ksafe.put("profile", profile)
val loaded: UserProfile = ksafe.get("profile", defaultProfile)

// Flow
val profileFlow: Flow<UserProfile> = ksafe.getFlow("profile", defaultProfile)

// Property delegate
var saved: UserProfile by ksafe(defaultProfile, "profile", KSafeWriteMode.Plain)
```

> **Note:** If you don't need custom serializers, you don't need to configure anything — the default `Json { ignoreUnknownKeys = true }` is used automatically via `KSafeDefaults.json`.

> **Warning:** Changing the `Json` configuration for an existing `fileName` namespace may make previously stored non-primitive values unreadable. Primitives (`String`, `Int`, `Boolean`, etc.) are unaffected.
