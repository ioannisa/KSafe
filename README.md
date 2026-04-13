# KSafe — Secure Persist Library for Kotlin Multiplatform

_**The Universal Persistence Layer: `MutableState`, `MutableStateFlow`, and plain variables — all encrypted, all persisted, all surviving process death. For Android, iOS, Desktop, and Web.**_


[![Maven Central](https://img.shields.io/maven-central/v/eu.anifantakis/ksafe.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/eu.anifantakis/ksafe)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


![image](https://github.com/user-attachments/assets/692d9066-e953-4f13-9642-87661c5bc248)

## Demo Application
To see KSafe in action on several scenarios, I invite you to check out my demo application here:
[Demo CMP App Using KSafe](https://github.com/ioannisa/KSafeDemo)

## YouTube Demos
Check out my own video about how easy it is to adapt KSafe into your project and get seamless encrypted persistence, but also more videos from other content creators.

| Author's Video | Philipp Lackner's Video | Jimmy Plazas's Video |
|:--------------:|:---------------:|:---------------:|
| [<img width="200" alt="image" src="https://github.com/user-attachments/assets/8c317a36-4baa-491e-8c88-4c44b8545bad" />](https://youtu.be/mFKGx0DMZEA) | [<img width="200" alt="image" src="https://github.com/user-attachments/assets/59cce32b-634e-4b17-bb5f-5e084dff899f" />](https://youtu.be/cLyxWGV6GKg) | [<img width="200" alt="image" src="https://github.com/user-attachments/assets/65dba780-9c80-470c-9ad0-927a86510a26" />](https://youtu.be/M4U06OnAl-I) | 
| [KSafe - Kotlin Multiplatform Encrypted DataStore Persistence Library](https://youtu.be/mFKGx0DMZEA) | [How to Encrypt Local Preferences In KMP With KSafe](https://youtu.be/cLyxWGV6GKg) | [Encripta datos localmente en Kotlin Multiplatform con KSafe - Ejemplo + Arquitectura](https://youtu.be/M4U06OnAl-I) |

## What is KSafe

#### KSafe is the
1. **easiest to use**
2. **most secure**
3. **fastest**

library to persist encrypted and unencrypted data in Kotlin Multiplatform.

With simple property delegation, values feel like normal variables — you just read and write them, and KSafe handles the underlying cryptography, caching, and atomic DataStore persistence transparently across all four platforms: **Android**, **iOS**, **JVM/Desktop**, and **WASM/JS (Browser)**.

> Whether you are storing a harmless UI state or a highly sensitive biometric token, KSafe is the only local persistence dependency your KMP app needs.

#### Both worlds — `MutableState` and `MutableStateFlow`

KSafe gives you the full flexibility of **both** Compose and standard Kotlin patterns, with encryption and persistence behind the scenes:

```kotlin
// Compose MutableState — reactive UI, persisted, encrypted
var counter by kSafe.mutableStateOf(0)

// Kotlin MutableStateFlow — standard _state/state pattern, persisted, encrypted
private val _state by kSafe.asMutableStateFlow(MyState(), viewModelScope)
val state = _state.asStateFlow()

// Plain variable — no Compose, no Flow, just encrypted persistence
var token by kSafe("")
```

All three survive process death. All three are AES-256-GCM encrypted by default. No boilerplate.

### Complex Objects? Well yes!

Here's what that looks like in a real app — Ktor bearer authentication with **zero encryption boilerplate**:

```kotlin
// just mark serializable your object to persist
@Serializable
data class AuthTokens(
  val accessToken: String = "",
  val refreshToken: String = ""
)

// One line to encrypt, persist, and serialize the whole object - THAT'S IT!
var tokens by ksafe(AuthTokens())

install(Auth) {
  bearer {
    loadTokens {
      // Reads atomic object from hot cache (~0.007ms). No disk. No suspend.
      BearerTokens(tokens.accessToken, tokens.refreshToken)
    }
    refreshTokens {
      val newInfo = api.refreshAuth(tokens.refreshToken)

      // Atomic update: encrypts & persists as JSON in background (~13μs)
      tokens = AuthTokens(
        accessToken = newInfo.accessToken,
        refreshToken = newInfo.refreshToken
      )

      BearerTokens(tokens.accessToken, tokens.refreshToken)
    }
  }
}
```

No explicit encrypt/decrypt calls. No DataStore boilerplate. No `runBlocking`. Tokens are AES-256-GCM encrypted at rest, served from the hot cache at runtime, and survive process death — all through regular Kotlin property access.

Under the hood, each platform uses its native crypto engine — Android Keystore, iOS Keychain + CryptoKit, JVM's javax.crypto, and browser WebCrypto — unified behind a single API. Values are AES-256-GCM encrypted and persisted to DataStore (or localStorage on WASM).

KSafe covers every persistence pattern you need: Compose `MutableState` (`mutableStateOf`), Kotlin `MutableStateFlow` (`asMutableStateFlow`), read-only reactive flows (`asStateFlow` / `asFlow`), cross-screen sync (`mutableStateOf(scope=)`), and plain property delegates (`invoke`). Add built-in biometric authentication, configurable memory policies, and runtime security detection — all out of the box.

## Table of Contents

- [Quickstart](#quickstart)
- [Setup](#setup)
- [Basic Usage](#basic-usage)
    - [Property Delegation](#property-delegation-one-liner)
    - [Flow Delegates (Reactive Reads)](#flow-delegates-reactive-reads)
    - [Composable State](#composable-state-one-liner)
    - [Suspend API](#suspend-api-non-blocking)
    - [Direct API](#direct-api-recommended-for-performance)
    - [Write Mode API](#write-mode-api-per-entry-unlock-policy)
    - [Full ViewModel Example](#full-viewmodel-example)
- [Custom JSON Serialization](#custom-json-serialization)
- [Cryptographic Utilities](#cryptographic-utilities)
    - [Secure Random Bytes](#secure-random-bytes)
    - [Secret Generation](#secret-generation)
- [Performance Benchmarks](#performance-benchmarks)
- [Compatibility](#compatibility)
- [Biometric Authentication](#biometric-authentication)
- [Runtime Security Policy](#runtime-security-policy)
- [Memory Security Policy](#memory-security-policy)
- [Deep-Dive Documentation](#deep-dive-documentation)

***

## Quickstart

```kotlin
// 1. Create instance (Android needs context, others don't)
val ksafe = KSafe(context) // Android
val ksafe = KSafe()        // iOS / JVM / WASM

// 2. Store & retrieve with property delegation
var counter by ksafe(0)
counter++  // Auto-encrypted, auto-persisted

// 3. Compose state (read/write, reactive to external changes)
var username by ksafe.mutableStateOf("Guest", scope = viewModelScope)

// 4. Reactive flows (key from property name)
val darkMode: MutableStateFlow<Boolean> by ksafe.asMutableStateFlow(false, viewModelScope)

// 5. Or use suspend API
viewModelScope.launch {
    ksafe.put("user_token", token)
    val token = ksafe.get("user_token", "")
}

// 6. Protect actions with biometrics
ksafe.verifyBiometricDirect("Confirm payment") { success ->
    if (success) processPayment()
}
```

That's it. Your data is now AES-256-GCM encrypted with keys stored in Android Keystore, iOS Keychain, software-backed on JVM, or WebCrypto on WASM.

***

## Setup

[![Maven Central](https://img.shields.io/maven-central/v/eu.anifantakis/ksafe.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/eu.anifantakis/ksafe)

### 1 - Add the Dependency

```kotlin
// commonMain or Android-only build.gradle(.kts)
implementation("eu.anifantakis:ksafe:1.8.0")
implementation("eu.anifantakis:ksafe-compose:1.8.0") // ← Compose state (optional)
```

> Skip `ksafe-compose` if your project doesn't use Jetpack Compose, or if you don't intend to use the library's `mutableStateOf` persistence option

> **Note:** `kotlinx-serialization-json` is exposed as a **transitive dependency** — you do **not** need to add it manually to your project. KSafe already provides it.

### 2 - Apply the kotlinx-serialization plugin

If you want to use the library with data classes, you need to enable Serialization at your project.

Add Serialization definition to your `plugins` section of your `libs.versions.toml`
```toml
[versions]
kotlin = "2.2.21"

[plugins]
kotlin-serialization = { id = "org.jetbrains.kotlin.plugin.serialization", version.ref = "kotlin" }
```

and apply it at the same section of your `build.gradle.kts` file.
```Kotlin
plugins {
  //...
  alias(libs.plugins.kotlin.serialization)
}
```

### 3 - Instantiate

```kotlin
// Android
val ksafe = KSafe(context)

// iOS / JVM / WASM
val ksafe = KSafe()
```

With Koin (recommended for KMP):

```kotlin
// Android
actual val platformModule = module {
    single { KSafe(androidApplication()) }
}

// iOS / JVM / WASM
actual val platformModule = module {
    single { KSafe() }
}
```

For multi-instance setups (prefs vs vault), WASM `awaitCacheReady()`, and full platform-specific Koin examples, see [docs/SETUP.md](docs/SETUP.md).


## Basic Usage

### Property Delegation (One Liner)

```kotlin
var counter by ksafe(0)
```

Parameters:
* `defaultValue` - must be declared (type is inferred from it)
* `key` - if not set, the variable name is used as a key
* `mode` (overload) - `KSafeWriteMode.Plain` or `KSafeWriteMode.Encrypted(...)` for per-entry control

```Kotlin
class MyViewModel(ksafe: KSafe): ViewModel() {
  var counter by ksafe(0)

  init {
    // then just use it as a regular variable
    counter++
  }
}
```

> **Important:** The property delegate can ONLY use the default KSafe instance. If you need to use multiple KSafe instances with different file names, you must use the suspend or direct APIs.

### Flow Delegates (Reactive Reads)

KSafe has always offered `getFlow()` and `getStateFlow()` with explicit key strings. These new delegates extend the same property-name-as-key pattern from `invoke()` above to Flows and StateFlows — use whichever style you prefer.

**`asFlow`** returns a cold `Flow<T>` — ideal for repositories and data layers:

```kotlin
class UserRepository(private val kSafe: KSafe) {
    val username: Flow<String> by kSafe.asFlow(defaultValue = "Guest")
    val darkMode: Flow<Boolean> by kSafe.asFlow(defaultValue = false)

    // optional: explicit key override
    val theme: Flow<String> by kSafe.asFlow(defaultValue = "light", key = "app_theme")

    // writes use the existing API — the flow emits automatically
    suspend fun updateUsername(name: String) {
        kSafe.put("username", name)
    }
}
```

**`asStateFlow`** returns a hot `StateFlow<T>` — ideal for ViewModels:

```kotlin
class SettingsViewModel(private val kSafe: KSafe) : ViewModel() {
    val username: StateFlow<String> by kSafe.asStateFlow("Guest", viewModelScope)
    val darkMode: StateFlow<Boolean> by kSafe.asStateFlow(false, viewModelScope)

    fun onNameChanged(name: String) {
        viewModelScope.launch { kSafe.put("username", name) }
    }

    fun toggleDarkMode() {
        kSafe.putDirect("darkMode", !darkMode.value)
    }
}

// Consume in Compose
@Composable
fun SettingsScreen(viewModel: SettingsViewModel) {
    val username by viewModel.username.collectAsState()
    val darkMode by viewModel.darkMode.collectAsState()

    TextField(value = username, onValueChange = { viewModel.onNameChanged(it) })
    Switch(checked = darkMode, onCheckedChange = { viewModel.toggleDarkMode() })
}
```

**`asMutableStateFlow`** returns a read/write `MutableStateFlow<T>` — setting `.value` persists automatically. It's a drop-in replacement for the standard `MutableStateFlow` pattern:

```kotlin
// Standard Kotlin pattern
private val _state = MutableStateFlow(MoviesListState())
val state = _state.asStateFlow()

// KSafe equivalent — same pattern, but persisted + reactive to external changes
private val _state by kSafe.asMutableStateFlow(MoviesListState(), viewModelScope)
val state = _state.asStateFlow()
```

All standard `MutableStateFlow` operations work because we implement the full interface:

```kotlin
// .value = ...  ✅ persists
_state.value = _state.value.copy(loading = true)

// .update {} ✅ persists (uses compareAndSet internally)
_state.update { it.copy(loading = false, movies = list) }

// .asStateFlow() ✅ works (it's a real MutableStateFlow)
val state = _state.asStateFlow()

// collectAsState() ✅ works
val state by viewModel.state.collectAsState()
```

Full ViewModel example:

```kotlin
@Serializable
data class MoviesListState(
    val loading: Boolean = false,
    val movies: List<Movie> = emptyList(),
    val error: String? = null
)

class MoviesViewModel(private val kSafe: KSafe, private val api: MoviesApi) : ViewModel() {
    private val _state by kSafe.asMutableStateFlow(MoviesListState(), viewModelScope)
    val state = _state.asStateFlow()

    fun loadMovies() {
        _state.update { it.copy(loading = true) }
        viewModelScope.launch {
            try {
                val movies = api.getMovies()
                _state.update { it.copy(loading = false, movies = movies) }
            } catch (e: Exception) {
                _state.update { it.copy(loading = false, error = e.message) }
            }
        }
    }
}

@Composable
fun MoviesScreen(viewModel: MoviesViewModel) {
    val state by viewModel.state.collectAsState()

    when {
        state.loading -> CircularProgressIndicator()
        state.error != null -> Text("Error: ${state.error}")
        else -> LazyColumn {
            items(state.movies) { movie -> MovieItem(movie) }
        }
    }
}
```

> `asFlow` and `asStateFlow` are **read-only** — writes go through `put`/`putDirect`. Use `asMutableStateFlow` when you want read/write + reactivity without Compose. All three automatically pick up changes made anywhere.

### Composable State (One Liner)

```kotlin
var counter by ksafe.mutableStateOf(0)
```

Recomposition-proof and survives process death with zero boilerplate. Requires the `ksafe-compose` dependency.

```Kotlin
class MyViewModel(ksafe: KSafe): ViewModel() {
  var counter by ksafe.mutableStateOf(0)
    private set

  init {
    counter++
  }
}
```

When you need custom Compose equality semantics, use the advanced overload with `policy`:

```kotlin
import androidx.compose.runtime.neverEqualPolicy
import androidx.compose.runtime.referentialEqualityPolicy

// Default (recommended): structural equality
var profile by ksafe.mutableStateOf(Profile())

// Persist/recompose only when reference changes
var uiModel by ksafe.mutableStateOf(
    defaultValue = UiModel(),
    policy = referentialEqualityPolicy()
)

// Always treat assignment as a change (always persists)
var ticks by ksafe.mutableStateOf(
    defaultValue = 0,
    policy = neverEqualPolicy()
)
```

#### Reactive `mutableStateOf` with Cross-Screen Sync

The existing `mutableStateOf` (available since v1.0.0) now accepts an optional `scope` parameter.

**Without `scope`** — the state reads from cache at initialization and persists on write, but it's **isolated**. If another ViewModel or a background `put()` writes to the same key, this state won't see the change until the ViewModel is destroyed and recreated.

**With `scope`** — the state continuously observes the underlying flow. Changes from **any source** (another screen, another ViewModel, a background coroutine) are reflected **in real-time**.

```kotlin
// Without scope — isolated: reads once at init, writes persist, but no live sync
var username by ksafe.mutableStateOf("Guest")

// With scope — live subscription: auto-updates when ANY writer changes this key
var username by ksafe.mutableStateOf("Guest", scope = viewModelScope)
```

> If you only ever read/write from a single ViewModel, both behave identically. The `scope` parameter only matters when **multiple writers** exist for the same key.

This is especially useful when multiple screens share the same data:

```kotlin
class DashboardViewModel(kSafe: KSafe) : ViewModel() {
    // These auto-reflect changes made from other screens
    var username by kSafe.mutableStateOf("Guest", scope = viewModelScope)
    var notificationsEnabled by kSafe.mutableStateOf(false, scope = viewModelScope)
}

class SettingsViewModel(kSafe: KSafe) : ViewModel() {
    var username by kSafe.mutableStateOf("Guest", scope = viewModelScope)
    var notificationsEnabled by kSafe.mutableStateOf(false, scope = viewModelScope)
}

// When SettingsScreen writes, DashboardScreen auto-updates — no manual refresh
@Composable
fun DashboardScreen(viewModel: DashboardViewModel) {
    Text("Welcome, ${viewModel.username}")
    if (viewModel.notificationsEnabled) Text("Notifications ON")
}

@Composable
fun SettingsScreen(viewModel: SettingsViewModel) {
    TextField(value = viewModel.username, onValueChange = { viewModel.username = it })
    Switch(
        checked = viewModel.notificationsEnabled,
        onCheckedChange = { viewModel.notificationsEnabled = it }
    )
}
```

### Suspend API (non-blocking)

```Kotlin
// inside coroutine / suspend fn
ksafe.put("profile", userProfile)          // encrypt & persist
val cached: User = ksafe.get("profile", User())
```

### Direct API (Recommended for Performance)

```Kotlin
ksafe.putDirect("counter", 42)
val n = ksafe.getDirect("counter", 0)
```

> **Performance Note:** For bulk or concurrent operations, **always use the Direct API**. The Coroutine API waits for DataStore persistence on each call (~22 ms), while the Direct API returns immediately from the hot cache (~0.022 ms) — that's **~1000x faster**.

| API | Read | Write | Best For |
|-----|------|-------|----------|
| `getDirect`/`putDirect` | 0.007 ms | 0.022 ms | UI, bulk ops, high throughput |
| `get`/`put` (suspend) | 0.010 ms | 22 ms | When you must guarantee persistence |

### Write Mode API (Per-Entry Unlock Policy)

Use `KSafeWriteMode` when you need encrypted-only options like `requireUnlockedDevice`:

```kotlin
// Direct API
ksafe.putDirect(
    "token",
    token,
    mode = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.DEFAULT,
        requireUnlockedDevice = true
    )
)

// Suspend API
ksafe.put(
    "pin",
    pin,
    mode = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
        requireUnlockedDevice = true
    )
)

// Explicit plaintext write
ksafe.putDirect("theme", "dark", mode = KSafeWriteMode.Plain)
```

No-mode writes (`put`/`putDirect` without `mode`) use encrypted defaults and pick up `KSafeConfig.requireUnlockedDevice` as the default unlock policy.

### Storing Complex Objects

```Kotlin
@Serializable
data class AuthInfo(
  val accessToken: String = "",
  val refreshToken: String = "",
  val expiresIn: Long = 0L
)

var authInfo by ksafe(AuthInfo())   // encryption + JSON automatically

// Update
authInfo = authInfo.copy(accessToken = "newToken")
```

> Seeing "Serializer for class X' is not found"? Add `@Serializable` and make sure you have added the Serialization plugin to your app.

### Nullable Values

KSafe fully supports nullable types:

```Kotlin
// Store null values
val token: String? = null
ksafe.put("auth_token", token)

// Retrieve null values (returns null, not defaultValue)
val retrieved: String? = ksafe.get("auth_token", "default")
// retrieved == null ✓

// Nullable fields in serializable classes
@Serializable
data class UserProfile(
    val id: Int,
    val nickname: String?,
    val bio: String?
)
```

### Deleting Data

```Kotlin
ksafe.delete("profile")       // suspend (non-blocking)
ksafe.deleteDirect("profile") // blocking
```

When you delete a value, both the data and its associated encryption key are removed from secure storage.

### Full ViewModel Example

```Kotlin
class CounterViewModel(ksafe: KSafe) : ViewModel() {
  // regular Compose state (not persisted)
  var volatile by mutableStateOf(0)
    private set

  // persisted Compose state (AES encrypted)
  var persisted by ksafe.mutableStateOf(100)
    private set

  // persisted Compose state + flow observation (auto-updates from external changes)
  var shared by ksafe.mutableStateOf(0, scope = viewModelScope)
    private set

  // plain property-delegate preference
  var hits by ksafe(0)

  // reactive read-only StateFlow (key = "score")
  val score: StateFlow<Int> by ksafe.asStateFlow(0, viewModelScope)

  // reactive read/write MutableStateFlow (key = "level")
  val level: MutableStateFlow<Int> by ksafe.asMutableStateFlow(1, viewModelScope)

  fun inc() {
    volatile++
    persisted++
    shared++
    hits++
  }
}
```

***

## Custom JSON Serialization

By default, KSafe handles primitives, `@Serializable` data classes, lists, and nullable types automatically. But if you need to store **third-party types you don't own** (e.g., `UUID`, `Instant`, `BigDecimal`), you can inject a custom `Json` instance via `KSafeConfig`.

### Why is this needed?

Types like `java.util.UUID` or `kotlinx.datetime.Instant` live in external libraries — you can't add `@Serializable` to them. Instead, you write a small `KSerializer` that teaches kotlinx.serialization how to convert the type to/from a string, then register it once when creating `KSafe`.

### Step-by-Step

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

***

## Cryptographic Utilities

### Secure Random Bytes

KSafe exposes a cross-platform cryptographically secure random byte generator:

```kotlin
val nonce = secureRandomBytes(16)       // 128-bit nonce
val aesKey = secureRandomBytes(32)      // 256-bit key
val salt = secureRandomBytes(64)        // 512-bit salt
```

Each platform delegates to its strongest available CSPRNG:

| Platform | Source |
|----------|--------|
| Android  | `java.security.SecureRandom` |
| JVM      | `java.security.SecureRandom` |
| iOS      | `arc4random_buf` (kernel CSPRNG) |
| WASM     | `crypto.getRandomValues()` (WebCrypto API) |

This is the same primitive KSafe uses internally for IV and encryption key generation.

### Secret Generation

`getOrCreateSecret` generates a cryptographically secure random secret on first call and retrieves it on subsequent calls. The secret is stored with KSafe's hardware-backed encryption.

```kotlin
// Database encryption passphrase — one line
val passphrase = ksafe.getOrCreateSecret("main.db")

// API signing key with custom size
val signingKey = ksafe.getOrCreateSecret("api_signing_key", size = 64)

// HMAC key
val hmacKey = ksafe.getOrCreateSecret("hmac_auth")
```

By default, secrets are 32 bytes (256-bit) and stored with `HARDWARE_ISOLATED` protection (StrongBox on Android, Secure Enclave on iOS). You can customize this:

```kotlin
val secret = ksafe.getOrCreateSecret(
    key = "my_secret",
    size = 32,                                              // bytes (default)
    protection = KSafeEncryptedProtection.HARDWARE_ISOLATED, // default
    requireUnlockedDevice = false                            // default
)
```

#### Example: Room + SQLCipher

```kotlin
val passphrase = ksafe.getOrCreateSecret("main.db")
val factory = SupportFactory(passphrase)

Room.databaseBuilder(context, AppDatabase::class.java, "main.db")
    .openHelperFactory(factory)
    .build()
```

#### Example: SQLDelight (cross-platform)

```kotlin
val passphrase = ksafe.getOrCreateSecret("app.db")
// Pass to your platform-specific driver configuration
```

***

## Why use KSafe?

* **Hardware-backed security** - AES-256-GCM with keys stored in Android Keystore, iOS Keychain, software-backed on JVM, or WebCrypto on WASM. Per-property write control via `KSafeWriteMode` and encrypted tiers via `KSafeEncryptedProtection`
* **Biometric authentication** - Built-in Face ID, Touch ID, and Fingerprint support with smart auth caching
* **Root & Jailbreak detection** - Detect compromised devices with configurable WARN/BLOCK actions
* **Clean reinstalls** - Automatic cleanup ensures fresh starts after app reinstallation
* **One code path** - No expect/actual juggling—your common code owns the vault
* **Ease of use** - `var launchCount by ksafe(0)` —that is literally it
* **Versatility** - Primitives, data classes, sealed hierarchies, lists, sets, and nullable types
* **Performance** - Zero-latency UI reads with Hybrid Cache architecture
* **Desktop & Web Support** - Full JVM/Desktop and WASM/Browser support alongside Android and iOS

***

## How KSafe Compares

| Feature | SharedPrefs | DataStore | multiplatform-settings | KVault | KSafe |
|---------|-------------|-----------|------------------------|--------|-------|
| **Thread safety** | :x: ANRs possible | :white_check_mark: Coroutine-safe | :white_check_mark: Platform-native | :white_check_mark: Thread-safe | :white_check_mark: ConcurrentHashMap + coroutines |
| **Type safety** | :x: Runtime crashes | :white_check_mark: Compile-time | :white_check_mark: Generic API | :white_check_mark: Generic API | :white_check_mark: Reified generics + serialization |
| **Data corruption** | :x: Crash = data loss | :white_check_mark: Atomic | :x: Platform-dependent | :white_check_mark: Atomic | :white_check_mark: Uses DataStore atomicity |
| **API style** | :x: Callbacks | :white_check_mark: Flow | :white_check_mark: Sync | :white_check_mark: Sync | :white_check_mark: Both sync & async |
| **Encryption** | :x: None | :x: None | :x: None | :white_check_mark: Hardware-backed | :white_check_mark: Hardware-backed |
| **Cross-platform** | :x: Android only | :x: Android only | :white_check_mark: KMP | :white_check_mark: KMP | :white_check_mark: Android/iOS/JVM/WASM |
| **Nullable support** | :x: No | :x: No | :white_check_mark: Yes | :white_check_mark: Yes | :white_check_mark: Full support |
| **Complex types** | :x: Manual | :x: Manual/Proto | :x: Manual | :x: Manual | :white_check_mark: Auto-serialization |
| **Biometric auth** | :x: Manual | :x: Manual | :x: Manual | :x: Manual | :white_check_mark: Built-in |
| **Memory policy** | N/A | N/A | N/A | N/A | :white_check_mark: 3 policies (PLAIN_TEXT / ENCRYPTED / TIMED_CACHE) |
| **Hot cache** | :white_check_mark: Yes | :x: No | :white_check_mark: Yes | :x: No | :white_check_mark: ConcurrentHashMap |
| **Write batching** | :x: No | :x: No | :x: No | :x: No | :white_check_mark: 16ms coalescing |

***

## Performance Benchmarks

| API | Read | Write | Best For |
|-----|------|-------|----------|
| `getDirect`/`putDirect` | 0.007 ms | 0.022 ms | UI, bulk ops, high throughput |
| `get`/`put` (suspend) | 0.010 ms | 22 ms | When you must guarantee persistence |

**vs competitors (encrypted):** 14x faster reads than KVault, 15x faster than EncryptedSharedPreferences. Unencrypted writes match SharedPreferences.

For full benchmark tables, cold start numbers, and architecture details, see [docs/BENCHMARKS.md](docs/BENCHMARKS.md).


## Compatibility

| Platform | Minimum Version | Notes |
|----------|-----------------|-------|
| **Android** | API 23 (Android 6.0) | Hardware-backed Keystore on supported devices |
| **iOS** | iOS 13+ | Keychain-backed symmetric keys (protected by device passcode) |
| **JVM/Desktop** | JDK 11+ | Software-backed encryption |
| **WASM/Browser** | Any modern browser | WebCrypto API + localStorage |

| Dependency | Tested Version |
|------------|----------------|
| Kotlin | 2.0.0+ |
| Kotlin Coroutines | 1.8.0+ |
| DataStore Preferences | 1.1.0+ |
| Compose Multiplatform | 1.6.0+ (for ksafe-compose) |

***

## Using Multiple KSafe Instances

by [Mark Andrachek](https://github.com/mandrachek)

You can create multiple KSafe instances with different file names to separate different types of data:

```Kotlin
class MyViewModel : ViewModel() {
  private val userPrefs = KSafe(fileName = "userpreferences")
  private val appSettings = KSafe(fileName = "appsettings")
  private val cacheData = KSafe(fileName = "cache")

  // For named instances, use suspend or direct APIs:
  suspend fun saveUserToken(token: String) {
    userPrefs.put("auth_token", token)
  }
}
```

**Important Instance Management Rules:**
- **Each KSafe instance should be a singleton** - Create once and reuse throughout your app
- **Never create multiple instances pointing to the same file** - This can cause data inconsistency

```Kotlin
// ✅ Good: Singleton instances via DI
val appModule = module {
  single { KSafe() }  // Default instance
  single(named("user")) { KSafe(fileName = "userdata") }
  single(named("cache")) { KSafe(fileName = "cache") }
}

// ❌ Bad: Creating multiple instances for the same file
class ScreenA { val prefs = KSafe(fileName = "userdata") }
class ScreenB { val prefs = KSafe(fileName = "userdata") }  // DON'T DO THIS!
```

**File Name Requirements:**
- Must contain only lowercase letters (a-z)
- No numbers, special characters, or uppercase letters allowed
- Examples: `"userdata"`, `"settings"`, `"cache"`

***

# Advanced Topics

***

## Biometric Authentication

KSafe provides a **standalone biometric authentication helper** that works on both Android and iOS. This is a general-purpose utility that can protect **any action** in your app—not just KSafe persistence operations.

```kotlin
// Callback-based
ksafe.verifyBiometricDirect("Authenticate to increment") { success ->
    if (success) secureCounter++
}

// Suspend-based
if (ksafe.verifyBiometric("Authenticate to increment")) {
    secureCounter++
}
```

For authorization caching, scoped sessions, platform setup, and complete examples, see [docs/BIOMETRICS.md](docs/BIOMETRICS.md).

***

## Runtime Security Policy

KSafe can detect and respond to runtime security threats (root/jailbreak, debugger, emulator, debug builds):

```kotlin
val ksafe = KSafe(
    context = context,
    securityPolicy = KSafeSecurityPolicy(
        rootedDevice = SecurityAction.WARN,      // IGNORE, WARN, or BLOCK
        debuggerAttached = SecurityAction.BLOCK,
        debugBuild = SecurityAction.WARN,
        emulator = SecurityAction.IGNORE,
        onViolation = { violation ->
            analytics.log("Security: ${violation.name}")
        }
    )
)
```

For preset policies, BLOCK exception handling, Compose stability, root/jailbreak detection methods, and more, see [docs/SECURITY.md](docs/SECURITY.md).

***

## Memory Security Policy

Control the trade-off between performance and security for data in RAM:

```Kotlin
val ksafe = KSafe(
    fileName = "secrets",
    memoryPolicy = KSafeMemoryPolicy.ENCRYPTED // Default
)
```

| Policy | Best For | RAM Contents | Read Cost | Security |
|--------|----------|-------------|-----------|----------|
| `PLAIN_TEXT` | User settings, themes | Plaintext (forever) | O(1) lookup | Low — all data exposed in memory |
| `ENCRYPTED` (Default) | Tokens, passwords | Ciphertext only | AES-GCM decrypt every read | High — nothing plaintext in RAM |
| `ENCRYPTED_WITH_TIMED_CACHE` | Compose/SwiftUI screens | Ciphertext + short-lived plaintext | First read decrypts, then O(1) for TTL | Medium — plaintext only for recently-accessed keys, only for seconds |

For timed cache details, constructor parameters, encryption configuration, device lock-state policies, and multiple KSafe instances with different lock policies, see [docs/MEMORY.md](docs/MEMORY.md).

***

## Deep-Dive Documentation

For detailed coverage of KSafe's internals, advanced features, and reference material:

| Topic | Description |
|-------|-------------|
| [Setup with Koin](docs/SETUP.md) | Multi-instance setups (prefs vs vault), WASM `awaitCacheReady()`, full platform examples |
| [Performance Benchmarks](docs/BENCHMARKS.md) | Full benchmark tables, cold start numbers, architecture deep-dive |
| [Biometric Authentication](docs/BIOMETRICS.md) | Authorization caching, scoped sessions, platform setup, complete examples |
| [Security](docs/SECURITY.md) | Runtime security policy, encryption internals, threat model, hardware isolation, key storage queries |
| [Memory Policy](docs/MEMORY.md) | Timed cache, constructor parameters, encryption config, device lock-state policies |
| [Architecture](docs/ARCHITECTURE.md) | Hybrid hot cache, optimistic updates, encryption architecture diagram |
| [Testing](docs/TESTING.md) | Running tests, building iOS test app, test features |
| [Migration Guide](docs/MIGRATION.md) | Upgrading from v1.6.x → v1.7.0 and v1.1.x → v1.2.0+ |
| [Alternatives & Comparison](docs/COMPARISON.md) | KSafe vs EncryptedSharedPrefs, KVault, SQLCipher, and more |

***

## Licence

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
