# Custom JSON Serialization

By default, KSafe stores primitives, `@Serializable` classes, lists, and nullable values with no setup on your side. `@Serializable` is the kotlinx.serialization annotation that makes the compiler generate the JSON code for a class.

If you need to store a type you **don't own** — one you cannot annotate, such as `UUID` or a value type from a library you depend on — you can hand KSafe your own `Json` through `KSafeConfig`. A `Json` is the kotlinx.serialization object that holds the encoder settings and the serializers you have registered.

## Why is this needed?

KSafe stores anything kotlinx.serialization can turn into JSON. For your own classes that means adding `@Serializable` — see [Storing Complex Objects](USAGE.md#storing-complex-objects) if you have not set the serialization compiler plugin up yet.

You cannot add `@Serializable` to a class you don't own, such as `java.util.UUID`. For those you write a small `KSerializer`: an object that tells kotlinx.serialization how to write the type as JSON and how to read it back. There are then two ways to use it:

- **One or two fields:** point the field straight at the serializer — `@Serializable(with = UUIDSerializer::class) val id: UUID`, with `UUIDSerializer` written as in step 1. Nothing else changes, and you do not need the rest of this page.
- **Many fields, or the same type in many classes:** register the serializer once in a `Json` and hand that `Json` to KSafe through `KSafeConfig`. The fields then only need `@Contextual`. The rest of this page shows that path.

> **Writing common (multiplatform) code?** `java.util.UUID` and `java.time.Instant` exist only in JVM and Android source sets, so the example below does not compile in `commonMain`. Their multiplatform counterparts, `kotlin.uuid.Uuid` and `kotlin.time.Instant`, already have serializers in the kotlinx.serialization version KSafe depends on (1.11.0), so they need neither a custom `KSerializer` nor a custom `Json` — store them like any other field. One caveat on the Kotlin version KSafe builds against (2.3): `kotlin.time.Instant` is stable, but `kotlin.uuid.Uuid` is still an experimental standard-library type, so every declaration that mentions it needs `@OptIn(ExperimentalUuidApi::class)` or the build fails.

## Step-by-Step

**1. Define custom serializers for types you don't own**

A `KSerializer<T>` has three members: `descriptor` says what the JSON looks like (here: one string), `serialize` writes the value out, `deserialize` reads it back. Change those three lines and the type argument, and the same shape works for any type.

This example is written for a JVM or Android source set — see the note above before pasting it into common code.

```kotlin
import java.time.Instant
import java.util.UUID

object UUIDSerializer : KSerializer<UUID> {
    // What the JSON looks like: one string.
    override val descriptor = PrimitiveSerialDescriptor("UUID", PrimitiveKind.STRING)
    // Value -> JSON
    override fun serialize(encoder: Encoder, value: UUID) = encoder.encodeString(value.toString())
    // JSON -> value
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
    allowSpecialFloatingPointValues = true   // keep the KSafe defaults (see the table below)
    serializersModule = SerializersModule {
        // A serializersModule is the Json's registry of serializers. contextual(...) registers one
        // to be looked up by type at runtime — which is what @Contextual on a field asks for (step 4).
        contextual(UUIDSerializer)
        contextual(InstantSerializer)
        // add as many as you need
    }
}
```

**The `Json` you pass replaces `KSafeDefaults.json` — the one KSafe uses when you pass none — and KSafe does not merge the two.** Copy both default flags into yours, or you lose what they protect:

| Flag | What it does | What breaks without it |
|------|--------------|------------------------|
| `ignoreUnknownKeys = true` | When reading, skip JSON fields the class does not declare. | Version 2 of your app adds `nickname` to `UserProfile` and stores it. A user then runs version 1 — a rollback, or a second device still on the old build — and version 1 reads JSON with a field it does not know. Decoding fails, KSafe hands back your default value, and the profile looks wiped. |
| `allowSpecialFloatingPointValues = true` | Let `Double`/`Float` `NaN`, `+Infinity` and `-Infinity` be written and read. | An encrypted write of one of those values fails with `kotlinx.serialization.SerializationException` and stores nothing. Plain writes are unaffected: a plain number is stored as a number, while an encrypted value is always turned into JSON text first, and JSON has no spelling for `NaN` or `Infinity`. |

`ignoreUnknownKeys` covers *extra* fields only. For a field that is *missing* — JSON written by a build that did not have the field yet — give it a default value in the data class, e.g. `val nickname: String = ""`. No `Json` flag can supply one.

**3. Pass it via KSafeConfig — one setup, used everywhere**

```kotlin
val ksafe = KSafe(
    context = context,                    // Android only — JVM, iOS/macOS and web (JS/WASM) take no context
    config = KSafeConfig(json = customJson)
)
```

**4. Use `@Contextual` on those fields — nothing changes at the call site**

`@Contextual` tells the serialization compiler plugin: do not look for a serializer for this field at compile time; ask the `Json`'s `serializersModule` at runtime. That lookup finds what step 2 registered.

```kotlin
@Serializable
data class UserProfile(
    val name: String,
    @Contextual val id: UUID,
    @Contextual val createdAt: Instant
)

val defaultProfile = UserProfile("", UUID(0L, 0L), Instant.EPOCH)   // returned while nothing is stored
val profile = UserProfile("Alice", UUID.randomUUID(), Instant.now())

// Direct API: cache-backed, safe on the main thread — putDirect persists in the background
ksafe.putDirect("profile", profile)
val loaded: UserProfile = ksafe.getDirect("profile", defaultProfile)

// Suspend API: waits until the write is committed
ksafe.put("profile", profile)
val loadedAgain: UserProfile = ksafe.get("profile", defaultProfile)

// Flow: a stream that emits the current value and then every later change
val profileFlow: Flow<UserProfile> = ksafe.getFlow("profile", defaultProfile)

// Property delegate: read and assign it like a normal var
var saved: UserProfile by ksafe(defaultProfile, "profile")
```

The writes above are encrypted, which is KSafe's default. To store a value unencrypted instead, pass `KSafeWriteMode.Plain` as the last argument of `put`, `putDirect` or the delegate. Reads take no mode — they detect how each entry was written.

Every read and write on this instance goes through the same `Json`: the four shapes above, the flow delegates (`asFlow`, `asWritableFlow`, `asStateFlow`, `asMutableStateFlow` — see [Flow Delegates](USAGE.md#flow-delegates-reactive-reads)), the mode-typed views (`KSafePlain`, `KSafeEncrypted`, `KSafeHardwareIsolated`), and `ksafe-compose`'s `mutableStateOf` / `rememberKSafeState`. Each shape is shown in [USAGE](USAGE.md).

> **Forgot step 2 or 3?** The first write of a class with a `@Contextual` field fails — in any write mode, plain included — because the default `Json` has no serializer registered for that type. `put`, `putDirect`, assigning through a property delegate, and setting `.value` on an `asMutableStateFlow` all throw `kotlinx.serialization.SerializationException` from the calling line, before anything is stored. The `ksafe-compose` state holders are the exception: they catch the failure, log it, and revert the state to the stored value instead of throwing.

> **Note:** If you don't need custom serializers, you don't need to configure anything — the default `Json { ignoreUnknownKeys = true; allowSpecialFloatingPointValues = true }` is used automatically via `KSafeDefaults.json`.

> **Scope:** `Json` decides only how your value becomes text before KSafe encrypts it, and how that text becomes a value again after decryption. It has no say over the encryption itself: which key is used, where that key lives (Android Keystore, Apple Keychain, the OS secret store on JVM, a non-extractable WebCrypto key on web), whether a write asked for hardware-isolated storage, or the tamper check that a key rotation switches on for every encrypted entry (the authenticated envelope — see [Key Rotation](KEY_ROTATION.md#authenticated-envelope-v3)). KSafe also keeps its own bookkeeping — which entries are encrypted, and under which key generation — with a private codec of its own, so your `Json` cannot break that either.

> **Warning — changing `Json` for a store that already holds data.** A store is one named set of entries; the `fileName` argument of the `KSafe(...)` factory names it, and passing none gives you the default store. Values are kept as the JSON text your `Json` produced at write time. If a later build reads them with a `Json` that no longer accepts that text, the read does not throw: `get`, `getDirect`, `getFlow` and the delegates return your default value instead, so the data looks gone.
>
> - **Safe:** adding serializers to `serializersModule`. Existing data never used them.
> - **Breaks stored text:** removing a serializer a stored class relies on, or turning off `ignoreUnknownKeys`, `allowSpecialFloatingPointValues`, or any other flag the stored text depends on.
> - **Primitives written with `KSafeWriteMode.Plain`** (`String`, `Int`, `Long`, `Float`, `Double`, `Boolean`) are stored as native values, not as JSON, so no `Json` change touches them. **Encrypted values are JSON text, primitives included.** Ordinary numbers, strings and booleans decode under any settings; an encrypted `NaN` or `±Infinity` becomes unreadable if you drop `allowSpecialFloatingPointValues`.
>
> If you must tighten a setting, treat it like a schema change: the affected values come back as their defaults and have to be written again.
