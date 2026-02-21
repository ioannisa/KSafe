# KSafe — Secure Persist Library for Kotlin Multiplatform

_**Effortless Enterprise-Grade Encrypted Persistence with Biometric Authentication and Runtime Security for Android, iOS, Desktop, and Web.**_


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

### ⚡ The Dual-Purpose Advantage: Not Just for Secrets

Think KSafe is overkill for a simple "Dark Mode" toggle? Think again.

By setting `protection = KSafeProtection.NONE`, KSafe completely bypasses the cryptographic engine. What remains is a lightning-fast, zero-boilerplate wrapper around AndroidX DataStore with a concurrent hot-cache.

Setting up raw KMP DataStore requires writing `expect/actual` file paths across 4 platforms, managing `CoroutineScopes`, and dealing with async-only Flow reads. KSafe abstracts 100% of that. You get synchronous, O(1) reads backed by asynchronous disk writes—all in one line of code. **Unencrypted KSafe writes are actually benchmarked to be faster than native Android SharedPreferences.**

Whether you are storing a harmless UI state or a highly sensitive biometric token, KSafe is the only local persistence dependency your KMP app needs.

### Real-World Example

Here's what that looks like in a real app — Ktor bearer authentication with **zero encryption boilerplate**:

```kotlin
@Serializable
data class AuthTokens(
  val accessToken: String = "",
  val refreshToken: String = ""
)

// One line to encrypt, persist, and serialize the whole object
var tokens by ksafe(AuthTokens())

install(Auth) {
  bearer {
    loadTokens {
      // Reads atomic object from hot cache (~0.002ms). No disk. No suspend.
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

Under the hood, each platform uses its native crypto engine — Android Keystore, iOS Keychain + CryptoKit, JVM's javax.crypto, and browser WebCrypto — unified behind a single API. Values are AES-256-GCM encrypted and persisted to DataStore (or localStorage on WASM). Beyond property delegation, KSafe also offers Compose state integration (`ksafe.mutableStateOf()`), reactive flows (`getFlow()` / `getStateFlow()`), built-in biometric authentication, configurable memory policies, and runtime security detection (root/jailbreak, debugger, emulator) — all out of the box.

***

## Quickstart

```kotlin
// 1. Create instance (Android needs context, others don't)
val ksafe = KSafe(context) // Android
val ksafe = KSafe()        // iOS / JVM / WASM

// 2. Store & retrieve with property delegation
var counter by ksafe(0)
counter++  // Auto-encrypted, auto-persisted

// 3. Or use suspend API
viewModelScope.launch {
    ksafe.put("user_token", token)
    val token = ksafe.get("user_token", "")
}

// 4. Protect actions with biometrics
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
implementation("eu.anifantakis:ksafe:1.6.0")
implementation("eu.anifantakis:ksafe-compose:1.6.0") // ← Compose state (optional)
```

> Skip `ksafe-compose` if your project doesn't use Jetpack Compose, or if you don't intend to use the library's `mutableStateOf` persistence option

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

### 3 - Instantiate with Koin (Recommended)

Koin is the defacto DI solution for Kotlin Multiplatform, and is the ideal tool to provide KSafe as a singleton.

```Kotlin
// common
expect val platformModule: Module

// Android
actual val platformModule = module {
  single { KSafe(androidApplication()) }
}

// iOS
actual val platformModule = module {
  single { KSafe() }
}

// JVM/Desktop
actual val platformModule = module {
  single { KSafe() }
}

// WASM — call ksafe.awaitCacheReady() before first encrypted read (see note below)
actual val platformModule = module {
  single { KSafe() }
}
```

#### `ksafe.awaitCacheReady()` Required ONLY at WasmJs

> **WASM/JS:** WebCrypto encryption is async-only, so KSafe must finish decrypting its cache before your UI reads any encrypted values. Call `awaitCacheReady()` before rendering content.
>
> **With `startKoin` (classic):**
> ```kotlin
> fun main() {
>     startKoin {
>         modules(sharedModule, platformModule)
>     }
>
>     val body = document.body ?: return
>     ComposeViewport(body) {
>         var cacheReady by remember { mutableStateOf(false) }
>
>         LaunchedEffect(Unit) {
>             val ksafe: KSafe = getKoin().get()
>             ksafe.awaitCacheReady()
>             cacheReady = true
>         }
>
>         if (cacheReady) {
>             App()
>         }
>     }
> }
> ```
>
> **With `KoinMultiplatformApplication` (Compose):**
> ```kotlin
> fun main() {
>     val body = document.body ?: return
>     ComposeViewport(body) {
>         KoinMultiplatformApplication(config = createKoinConfiguration()) {
>             var cacheReady by remember { mutableStateOf(false) }
>
>             LaunchedEffect(Unit) {
>                 val ksafe: KSafe = getKoin().get()
>                 ksafe.awaitCacheReady()
>                 cacheReady = true
>             }
>
>             if (cacheReady) {
>                 AppContent() // your app's UI (without KoinMultiplatformApplication wrapper)
>             }
>         }
>     }
> }
> ```
>
> With `startKoin`, Koin is initialized before `ComposeViewport`, so `getKoin()` works immediately. With `KoinMultiplatformApplication`, `awaitCacheReady()` must go **inside** the composable — Koin isn't available until that scope.

Now you're ready to inject KSafe into your ViewModels!

***

## Basic Usage

### Property Delegation (One Liner)

```kotlin
var counter by ksafe(0)
```

Parameters:
* `defaultValue` - must be declared (type is inferred from it)
* `key` - if not set, the variable name is used as a key
* `encrypted` - by default is `true` (uses Keystore/Keychain)

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

> **Performance Note:** For bulk or concurrent operations, **always use the Direct API**. The Coroutine API waits for DataStore persistence on each call (~8.8 ms), while the Direct API returns immediately from the hot cache (~0.012 ms) — that's **~767x faster**.

| API | Read | Write | Best For |
|-----|------|-------|----------|
| `getDirect`/`putDirect` | 0.0016 ms | 0.012 ms | UI, bulk ops, high throughput |
| `get`/`put` (suspend) | 0.0014 ms | 8.8 ms | When you must guarantee persistence |

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
ksafe.put("auth_token", token, encrypted = true)

// Retrieve null values (returns null, not defaultValue)
val retrieved: String? = ksafe.get("auth_token", "default", encrypted = true)
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

  // plain property-delegate preference
  var hits by ksafe(0)

  fun inc() {
    volatile++
    persisted++
    hits++
  }
}
```

***

## Why use KSafe?

* **Hardware-backed security** - AES-256-GCM with keys stored in Android Keystore, iOS Keychain, software-backed on JVM, or WebCrypto on WASM
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

KSafe 1.4.1 introduces significant performance optimizations. Here are the benchmark results comparing KSafe against popular Android persistence libraries:

### Benchmark Environment
- **Device:** Physical Android device
- **Test:** 1000 sequential read/write operations, averaged
- **Libraries tested:** KSafe, SharedPreferences, EncryptedSharedPreferences, MMKV, DataStore, Multiplatform Settings, KVault

### Results Summary

#### Unencrypted Operations

| Library | Read | Write |
|---------|------|-------|
| SharedPreferences | 0.0006 ms | 0.0152 ms |
| MMKV | 0.0007 ms | 0.0577 ms |
| Multiplatform Settings | 0.0009 ms | 0.0192 ms |
| **KSafe** | **0.0016 ms** | **0.0115 ms** |
| DataStore | 1.10 ms | 3.76 ms |

> **Note:** KSafe unencrypted writes are now **faster than SharedPreferences** (0.0115 ms vs 0.0152 ms)!

#### Encrypted Read Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory)** | **0.0058 ms** | — |
| KSafe (ENCRYPTED memory) | 0.0276 ms | *(decrypts on-demand)* |
| KVault | 0.6003 ms | KSafe is **103x faster** |
| EncryptedSharedPreferences | 0.6817 ms | KSafe is **117x faster** |

#### Encrypted Write Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory)** | **0.0123 ms** | — |
| KSafe (ENCRYPTED memory) | 0.0531 ms | — |
| EncryptedSharedPreferences | 0.2064 ms | KSafe is **17x faster** |
| KVault | 1.05 ms | KSafe is **85x faster** |

### Key Performance Highlights

**vs DataStore (KSafe's backend):**
- :zap: **327x faster writes** (3.76 ms → 0.0115 ms)
- :zap: **687x faster reads** (1.10 ms → 0.0016 ms)

**vs KVault (encrypted KMP storage):**
- :zap: **103x faster encrypted reads** (0.60 ms → 0.0058 ms with PLAIN_TEXT memory)
- :zap: **85x faster encrypted writes** (1.05 ms → 0.0123 ms)

**vs EncryptedSharedPreferences:**
- :zap: **117x faster encrypted reads** (0.68 ms → 0.0058 ms with PLAIN_TEXT memory)
- :zap: **17x faster encrypted writes** (0.21 ms → 0.0123 ms)

**vs SharedPreferences (unencrypted baseline):**
- :zap: KSafe unencrypted writes are **faster** (0.0115 ms vs 0.0152 ms)
- Similar read performance (0.0016 ms vs 0.0006 ms)

**vs multiplatform-settings (Russell Wolf):**
- :zap: **1.7x faster writes** (0.0192 ms → 0.0115 ms)
- Similar read performance (0.0016 ms vs 0.0009 ms)
- KSafe adds: encryption, biometrics, type-safe serialization

### Cold Start / Reinitialization Performance

How fast can each library load existing data on app startup?

| Library | Keys | Time |
|---------|------|------|
| SharedPreferences | 201 | 0.0315 ms |
| Multiplatform Settings | 201 | 0.0400 ms |
| MMKV | 201 | 0.0402 ms |
| DataStore | 201 | 0.4901 ms |
| **KSafe (ENCRYPTED)** | 603 | **1.26 ms** :zap: |
| KVault | 320 | 4.77 ms |
| EncryptedSharedPrefs | 201 | 6.41 ms |
| KSafe (PLAIN_TEXT) | 1206 | 6.49 ms |

> **Note:** KSafe ENCRYPTED mode is **5x faster** to cold-start than PLAIN_TEXT mode. This is because ENCRYPTED defers decryption until values are accessed, while PLAIN_TEXT decrypts all values upfront during initialization.

KSafe's hot cache architecture means near-instant cold starts—the background DataStore collector preloads data, so `getDirect()` returns from warm cache.

### How KSafe Achieves This Performance

KSafe uses a **hot cache architecture** similar to SharedPreferences, but built on top of DataStore:

```
Vanilla DataStore:
  Read:  suspend → Flow.first() → disk I/O → ~1.1 ms
  Write: suspend → edit{} → serialize → disk I/O → ~3.8 ms

KSafe with Hot Cache:
  Read:  getDirect() → ConcurrentHashMap lookup → ~0.0016 ms (no disk!)
  Write: putDirect() → update HashMap + queue → ~0.012 ms (returns immediately)
         Background: batched DataStore.edit() (user doesn't wait)
```

**Optimizations in 1.4.1:**
1. **ConcurrentHashMap cache** - O(1) per-key reads and writes
2. **Write coalescing** - Batches writes within 16ms window into single DataStore edit
3. **Deferred encryption** - Encryption moved to background thread, UI thread returns instantly
4. **SecretKey caching** - Avoids repeated Android Keystore lookups

This means KSafe gives you DataStore's safety guarantees (atomic transactions, type-safe) with SharedPreferences-level performance.

***

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
    userPrefs.put("auth_token", token, encrypted = true)
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

### Two APIs

| Method | Type | Use Case |
|--------|------|----------|
| `verifyBiometricDirect(reason, authorizationDuration?) { success -> }` | Callback-based | Simple, non-blocking, works anywhere |
| `verifyBiometric(reason, authorizationDuration?): Boolean` | Suspend function | Coroutine-based, cleaner async code |

### Basic Usage

```kotlin
class MyViewModel(private val ksafe: KSafe) : ViewModel() {

    var secureCounter by ksafe.mutableStateOf(0)
        private set

    // Always prompt (no caching)
    fun incrementWithBiometric() {
        ksafe.verifyBiometricDirect("Authenticate to increment") { success ->
            if (success) secureCounter++
        }
    }

    // Coroutine-based approach
    fun incrementWithBiometricSuspend() {
        viewModelScope.launch {
            if (ksafe.verifyBiometric("Authenticate to increment")) {
                secureCounter++
            }
        }
    }
}
```

### Authorization Duration Caching

Avoid repeated biometric prompts by caching successful authentication:

```kotlin
data class BiometricAuthorizationDuration(
    val duration: Long,       // Duration in milliseconds
    val scope: String? = null // Optional scope identifier (null = global)
)

// Cache for 60 seconds (scoped to this ViewModel)
ksafe.verifyBiometricDirect(
    reason = "Authenticate",
    authorizationDuration = BiometricAuthorizationDuration(
        duration = 60_000L,
        scope = viewModelScope.hashCode().toString()
    )
) { success -> /* ... */ }
```

| Parameter | Meaning |
|-----------|---------|
| `authorizationDuration = null` | Always prompt (no caching) |
| `duration > 0` | Cache auth for this many milliseconds |
| `scope = null` | Global scope - any call benefits from cached auth |
| `scope = "xyz"` | Scoped auth - only calls with same scope benefit |

### Scoped Authorization Use Cases

```kotlin
// ViewModel-scoped: auth invalidates when ViewModel is recreated
BiometricAuthorizationDuration(60_000L, viewModelScope.hashCode().toString())

// User-scoped: auth invalidates on user change
BiometricAuthorizationDuration(300_000L, "user_$userId")

// Flow-scoped: auth shared across a multi-step flow
BiometricAuthorizationDuration(120_000L, "checkout_flow")
```

### Clearing Cached Authorization

```kotlin
ksafe.clearBiometricAuth()              // Clear all cached authorizations
ksafe.clearBiometricAuth("settings")    // Clear specific scope only
```

### Protecting Any Action

```kotlin
// Protect API calls
fun deleteAccount() {
    ksafe.verifyBiometricDirect("Confirm account deletion") { success ->
        if (success) api.deleteAccount()
    }
}

// Protect navigation
fun navigateToSecrets() {
    ksafe.verifyBiometricDirect("Authenticate to view secrets") { success ->
        if (success) navController.navigate("secrets")
    }
}
```

### Platform Setup

#### Android

**Permission** - Add to `AndroidManifest.xml`:
```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
```

**Activity Requirement** - BiometricPrompt requires `FragmentActivity` or `AppCompatActivity`:
```kotlin
// ❌ Won't work with biometrics
class MainActivity : ComponentActivity()

// ✅ Works with biometrics
class MainActivity : AppCompatActivity()
```

**Early Initialization** - KSafe must be initialized before any Activity is created:
```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        startKoin {
            androidContext(this@MyApplication)
            modules(appModule)
        }
        get<KSafe>()  // Force initialization
    }
}
```

**Customizing the Prompt:**
```kotlin
BiometricHelper.promptTitle = "Unlock Secure Data"
BiometricHelper.promptSubtitle = "Authenticate to continue"
```

#### iOS

**Info.plist** - Add Face ID usage description:
```xml
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to access secure data</string>
```

**Note:** On iOS Simulator, biometric verification always returns `true` since there's no biometric hardware.

### Complete Example

```kotlin
class SecureViewModel(private val ksafe: KSafe) : ViewModel() {

    // Regular persisted counter (no biometric)
    var counter by ksafe.mutableStateOf(0)
        private set

    // Counter that requires biometric to increment
    var bioCounter by ksafe.mutableStateOf(0)
        private set

    fun incrementCounter() {
        counter++  // No biometric prompt
    }

    // Always prompt
    fun incrementBioCounter() {
        ksafe.verifyBiometricDirect("Authenticate to save") { success ->
            if (success) {
                bioCounter++
            }
        }
    }

    // With 60s duration caching (scoped to this ViewModel instance)
    fun incrementBioCounterCached() {
        ksafe.verifyBiometricDirect(
            reason = "Authenticate to save",
            authorizationDuration = BiometricAuthorizationDuration(
                duration = 60_000L,
                scope = viewModelScope.hashCode().toString()
            )
        ) { success ->
            if (success) {
                bioCounter++
            }
        }
    }

    // Suspend function with caching
    fun incrementBioCounterAsync() {
        viewModelScope.launch {
            val authDuration = BiometricAuthorizationDuration(
                duration = 60_000L,
                scope = viewModelScope.hashCode().toString()
            )
            if (ksafe.verifyBiometric("Authenticate to save", authDuration)) {
                bioCounter++
            }
        }
    }

    // Call on logout to force re-authentication
    fun onLogout() {
        ksafe.clearBiometricAuth()  // Clear all cached auth
    }
}
```

**Key Points:**
- Biometrics is a **helper utility**, not tied to storage
- Use it to protect **any action** (persistence, API calls, navigation, etc.)
- Two APIs: callback-based (`verifyBiometricDirect`) and suspend (`verifyBiometric`)
- Optional duration caching with `BiometricAuthorizationDuration`
- Scoped authorization for fine-grained control over cache invalidation
- Works on Android (BiometricPrompt) and iOS (LocalAuthentication)
- On Android, requires `AppCompatActivity` and early KSafe initialization

***

## Runtime Security Policy

KSafe can detect and respond to runtime security threats:

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

| Check | Android | iOS | JVM | WASM | Description |
|-------|---------|-----|-----|------|-------------|
| `rootedDevice` | ✅ | ✅ | ❌ | ❌ | Detects rooted/jailbroken devices |
| `debuggerAttached` | ✅ | ✅ | ✅ | ❌ | Detects attached debuggers |
| `debugBuild` | ✅ | ✅ | ✅ | ❌ | Detects debug builds |
| `emulator` | ✅ | ✅ | ❌ | ❌ | Detects emulators/simulators |

### Actions Explained

| Action | Behavior | Use Case |
|--------|----------|----------|
| `IGNORE` | No detection performed | Development, non-sensitive apps |
| `WARN` | Callback invoked, app continues | Logging/analytics, user warnings |
| `BLOCK` | Callback invoked, throws `SecurityViolationException` | Banking, enterprise apps |

**Example behavior with `WARN`:**
```kotlin
val ksafe = KSafe(
    context = context,
    securityPolicy = KSafeSecurityPolicy(
        rootedDevice = SecurityAction.WARN,
        onViolation = { violation ->
            // This is called, but app continues working
            showWarningDialog("Security risk: ${violation.name}")
            analytics.log("security_warning", violation.name)
        }
    )
)
// KSafe initializes successfully, user sees warning
```

**Example behavior with `BLOCK`:**
```kotlin
val ksafe = KSafe(
    context = context,
    securityPolicy = KSafeSecurityPolicy(
        rootedDevice = SecurityAction.BLOCK,
        onViolation = { violation ->
            // This is called BEFORE the exception is thrown
            analytics.log("security_block", violation.name)
        }
    )
)
// If device is rooted: SecurityViolationException is thrown
// App must catch this or it will crash
```

### Preset Policies

```kotlin
KSafeSecurityPolicy.Default   // All checks ignored (backwards compatible)
KSafeSecurityPolicy.Strict    // Blocks on root/debugger, warns on debug/emulator
KSafeSecurityPolicy.WarnOnly  // Warns on everything, never blocks
```

### Handling BLOCK Exceptions

```kotlin
try {
    val ksafe = KSafe(context, securityPolicy = KSafeSecurityPolicy.Strict)
} catch (e: SecurityViolationException) {
    showSecurityErrorScreen(e.violation.name)
}
```

### Providing User-Friendly Descriptions

Since `SecurityViolation` is an enum without hardcoded messages, provide your own descriptions:

```kotlin
fun getViolationDescription(violation: SecurityViolation): String {
    return when (violation) {
        SecurityViolation.RootedDevice ->
            "The device is rooted (Android) or jailbroken (iOS). " +
            "This allows apps to bypass sandboxing and potentially access encrypted data."
        SecurityViolation.DebuggerAttached ->
            "A debugger is attached to the process. " +
            "This allows inspection of memory and runtime values including decrypted secrets."
        SecurityViolation.DebugBuild ->
            "The app is running in debug mode. " +
            "Debug builds may have weaker security settings and expose more information."
        SecurityViolation.Emulator ->
            "The app is running on an emulator/simulator. " +
            "Emulators don't have hardware-backed security like real devices."
    }
}
```

### Collecting Violations for UI Display

Since KSafe initializes before ViewModels, use a holder to bridge violations to your UI:

```kotlin
// 1. Create a holder to collect violations during initialization
object SecurityViolationsHolder {
    private val _violations = mutableListOf<SecurityViolation>()
    val violations: List<SecurityViolation> get() = _violations.toList()

    fun addViolation(violation: SecurityViolation) {
        if (violation !in _violations) {
            _violations.add(violation)
        }
    }
}

// 2. Configure KSafe to populate the holder
val ksafe = KSafe(
    context = context,
    securityPolicy = KSafeSecurityPolicy.Strict.copy(
        onViolation = { violation ->
            SecurityViolationsHolder.addViolation(violation)
        }
    )
)

// 3. Read from the holder in your ViewModel
class SecurityViewModel : ViewModel() {
    val violations = mutableStateListOf<UiSecurityViolation>()

    init {
        SecurityViolationsHolder.violations.forEach { violation ->
            violations.add(UiSecurityViolation(violation))
        }
    }
}
```

### Compose Stability for SecurityViolation

When using `SecurityViolation` in Jetpack Compose, the Compose compiler treats it as "unstable" because it resides in the core `ksafe` module. The `ksafe-compose` module provides `UiSecurityViolation`—a wrapper marked with `@Immutable`:

```kotlin
@Immutable
data class UiSecurityViolation(
    val violation: SecurityViolation
)
```

| Type | Compose Stability |
|------|------------------|
| `ImmutableList<SecurityViolation>` | Unstable (causes recomposition) |
| `ImmutableList<UiSecurityViolation>` | Stable (enables skipping) |

The [KSafeDemo app](https://github.com/ioannisa/KSafeDemo) makes use of `UiSecurityViolation`—visit the demo application's source to see it in action.

### Root Detection Methods (Android)

- `su` binary paths (`/system/bin/su`, `/system/xbin/su`, etc.)
- Magisk paths (`/sbin/.magisk`, `/data/adb/magisk`, etc.)
- BusyBox installation paths
- Xposed Framework files and stack trace detection
- Root management apps (Magisk Manager, SuperSU, KingRoot, etc.)
- Build tags (`test-keys`) and dangerous system properties

### Jailbreak Detection Methods (iOS)

- Cydia, Sileo, and other jailbreak app paths
- System write access test (fails on non-jailbroken devices)
- Common jailbreak tool paths (`/bin/bash`, `/usr/sbin/sshd`, etc.)

> **Limitation:** Sophisticated root-hiding tools (Magisk DenyList, Shamiko, Zygisk) can bypass most client-side detection methods.

***

## How Encryption Works

KSafe provides enterprise-grade encrypted persistence using DataStore Preferences with platform-specific secure key storage.

### Platform Details

| Platform | Cipher | Key Storage | Security |
|----------|--------|-------------|----------|
| **Android** | AES-256-GCM | Android Keystore (hardware-backed when available) | Keys non-exportable, app-bound, auto-deleted on uninstall |
| **iOS** | AES-256-GCM via CryptoKit | iOS Keychain Services | Protected by device passcode/biometrics, not in backups |
| **JVM/Desktop** | AES-256-GCM via javax.crypto | Software-backed in `~/.eu_anifantakis_ksafe/` | Relies on OS file permissions (0700 on POSIX) |
| **WASM/Browser** | AES-256-GCM via WebCrypto | `localStorage` (Base64-encoded) | Scoped per origin, ~5-10 MB limit |

### Encryption Flow

1. **Serialize value → plaintext bytes** using kotlinx.serialization
2. **Load (or generate) a random 256-bit AES key** from Keystore/Keychain (unique per preference key)
3. **Encrypt with AES-GCM** (nonce + auth-tag included)
4. **Persist Base64(ciphertext)** in DataStore under `encrypted_<key>`
5. **Keys managed by platform** - never stored in DataStore

**What is GCM?** GCM (Galois/Counter Mode) is an authenticated encryption mode that provides both confidentiality and integrity. The authentication tag detects any tampering—if someone modifies even a single bit of the ciphertext, decryption will fail.

### Security Boundaries & Threat Model

**What KSafe protects against:**
- ✅ Casual file inspection (data at rest is encrypted)
- ✅ Data extraction from unrooted device backups
- ✅ App data access by other apps (sandboxing + encryption)
- ✅ Reinstall data leakage (automatic cleanup)
- ✅ Tampering detection (GCM authentication tag)
- ✅ Rooted/jailbroken devices (detection with configurable WARN/BLOCK)
- ✅ Debugger attachment (detection with configurable WARN/BLOCK)
- ✅ Emulator/simulator usage (detection with configurable WARN/BLOCK)

**What KSafe does NOT protect against:**
- ❌ Sophisticated root-hiding tools (e.g., Magisk Hide) — detection can be bypassed
- ❌ Memory dump attacks while app is running (mitigated by `ENCRYPTED` or `ENCRYPTED_WITH_TIMED_CACHE` memory policy)
- ❌ Device owner with physical access and device unlock credentials
- ❌ Compromised OS or hardware

**Recommendations:**
- Use `KSafeSecurityPolicy.Strict` for high-security apps (Banking, Medical, Enterprise)
- Use `KSafeMemoryPolicy.ENCRYPTED` for highly sensitive data (tokens, passwords)
- Use `KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE` for encrypted data accessed frequently during UI rendering (Compose recomposition, SwiftUI re-render)
- Combine with biometric verification for critical operations
- Never store master secrets client-side; prefer server-derived tokens
- Consider certificate pinning for API communications

**A note on iOS and the Secure Enclave:** Android's TEE/StrongBox can perform AES encryption entirely in hardware — the key never enters app memory. iOS's Secure Enclave only supports asymmetric keys (EC P-256), so symmetric AES keys must be stored as Keychain items and loaded into app memory for use by CryptoKit. The Keychain database itself is encrypted by Secure Enclave-derived class keys, providing strong at-rest protection. This is not a KSafe limitation — it's how all iOS AES encryption works, including banking apps and Apple's own frameworks. See our [detailed article](KSafe_Article_v1.6.0.md) for a full comparison of the two hardware security models.

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

All three policies encrypt data on disk. The difference is how data is handled in memory:
- **PLAIN_TEXT:** Maximum performance — decrypts once on load, stores plain values forever
- **ENCRYPTED:** Maximum security — stores ciphertext in RAM, decrypts on-demand every read
- **ENCRYPTED_WITH_TIMED_CACHE:** Best balance — stores ciphertext in RAM, but caches decrypted values for a configurable TTL

### ENCRYPTED_WITH_TIMED_CACHE — The Balanced Policy

Under `ENCRYPTED` policy, every read triggers AES-GCM decryption. In UI frameworks like Jetpack Compose or SwiftUI, the same encrypted property may be read multiple times during a single recomposition/re-render. `ENCRYPTED_WITH_TIMED_CACHE` eliminates redundant crypto: only the first read decrypts; subsequent reads within the TTL window are pure memory lookups.

```kotlin
val ksafe = KSafe(
    context = context,
    memoryPolicy = KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE,
    plaintextCacheTtl = 5.seconds  // default; how long plaintext stays cached
)
```

**How it works internally:**
```
Read 1: decrypt → cache plaintext (TTL=5s) → return       ← one crypto operation
Read 2 (50ms later):  cache hit → return                   ← no decryption
Read 3 (100ms later): cache hit → return                   ← no decryption
...TTL expires...
Read 4: decrypt → cache plaintext (TTL=5s) → return        ← one crypto operation
```

**Thread safety:** Reads capture a local reference to the cached entry atomically. No background sweeper — expired entries are simply ignored on the next access. No race conditions possible.

### Lazy Loading

```Kotlin
val archive = KSafe(
    fileName = "archive",
    lazyLoad = true  // Skip preload, load on first request
)
```

### Constructor Parameters

```Kotlin
// Android
KSafe(
    context: Context,
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds  // only used with ENCRYPTED_WITH_TIMED_CACHE
)

// iOS / JVM / WASM
KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds  // only used with ENCRYPTED_WITH_TIMED_CACHE
)
```

### Encryption Configuration

```Kotlin
val ksafe = KSafe(
    context = context,
    config = KSafeConfig(
        keySize = 256,                  // AES key size: 128 or 256 bits
        requireUnlockedDevice = false   // Require device unlock for key access
    )
)
```

**Note:** The encryption algorithm (AES-GCM) is intentionally NOT configurable to prevent insecure configurations.

### Device Lock-State Policy

Control whether encrypted data is only accessible when the device is unlocked:

```kotlin
val ksafe = KSafe(
    context = context,
    config = KSafeConfig(requireUnlockedDevice = true)
)
```

| Platform | `false` (default) | `true` |
|----------|-------------------|--------|
| **Android** | Keys accessible at any time | `setUnlockedDeviceRequired(true)` (API 28+) |
| **iOS** | `AfterFirstUnlockThisDeviceOnly` | `WhenUnlockedThisDeviceOnly` |
| **JVM** | No effect (marker-only) | No effect (marker-only) |
| **WASM** | No effect (browser has no lock concept) | No effect |

**JVM note:** Desktop/server environments have no OS-level device lock concept. The `requireUnlockedDevice` setting is accepted but has no runtime effect — encrypted data is always accessible. A migration marker is written for consistency with Android/iOS, so switching between platforms doesn't trigger repeated migrations.

Changing this value in either direction triggers an automatic one-time migration on the next KSafe initialization. Android re-encrypts existing values with a new Keystore key (both `false`&rarr;`true` and `true`&rarr;`false`); iOS updates Keychain accessibility in-place via `SecItemUpdate`. The migration marker is only written on success, so a crash or locked-device failure safely retries on the next launch.

**Error behavior when locked:** When `requireUnlockedDevice = true` and the device is locked, encrypted **reads** (`getDirect`, `get`, `getFlow`) throw `IllegalStateException`. The suspend `put(encrypted = true)` also throws. However, `putDirect` does **not** throw to the caller — it queues the write to a background consumer that logs the error and drops the batch (the consumer stays alive for future writes after the device is unlocked). Your app can catch read-side exceptions to show a "device is locked" message instead of silently receiving default values.

#### Multiple Safes with Different Lock Policies

Because KSafe supports [multiple instances](#using-multiple-ksafe-instances), you can assign different lock policies to different data categories — keeping sensitive data locked while allowing less-sensitive data to remain accessible in the background:

```kotlin
// Android example with Koin
actual val platformModule = module {
    // Sensitive data: only accessible when device is unlocked
    single(named("secure")) {
        KSafe(
            context = androidApplication(),
            fileName = "secure",
            config = KSafeConfig(requireUnlockedDevice = true)
        )
    }

    // General preferences: accessible even when locked (e.g., for background sync)
    single(named("prefs")) {
        KSafe(
            context = androidApplication(),
            fileName = "prefs",
            config = KSafeConfig(requireUnlockedDevice = false)
        )
    }
}

// Usage in ViewModel
class MyViewModel(
    private val secureSafe: KSafe,  // tokens, passwords — locked when device is locked
    private val prefsSafe: KSafe    // settings, cache — always accessible
) : ViewModel() {
    var authToken by secureSafe("")
    var lastSyncTime by prefsSafe(0L)
}
```

This pattern is especially useful for apps that perform background work (push notifications, sync) while the device is locked — the background-safe instance can still access its data, while the secure instance protects sensitive values.

***

## Architecture: Hybrid "Hot Cache"

KSafe 1.2.0 introduced a completely rewritten core architecture focusing on zero-latency UI performance.

### How It Works

**Before (v1.1.x):** Every `getDirect()` call triggered a blocking disk read and decryption on the calling thread.

**Now (v1.2.0):** Data is preloaded asynchronously on initialization. `getDirect()` performs an **Atomic Memory Lookup (O(1))**, returning instantly.

**Safety:** If data is accessed before the preload finishes, the library automatically falls back to a blocking read.

### Optimistic Updates

`putDirect()` updates the in-memory cache **immediately**, allowing your UI to reflect changes instantly while disk encryption happens in the background.

### Encryption Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        KSafe API                            │
│         (get, put, getDirect, putDirect, delete)            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                      KSafeConfig                            │
│                        (keySize)                            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│               KSafeEncryption Interface                     │
│            encrypt() / decrypt() / deleteKey()              │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┬───────────────┐
          ▼               ▼               ▼               ▼
┌─────────────────┐ ┌───────────────┐ ┌─────────────┐ ┌─────────────┐
│    Android      │ │     iOS       │ │     JVM     │ │    WASM     │
│    Keystore     │ │   Keychain    │ │  Software   │ │  WebCrypto  │
│   Encryption    │ │  Encryption   │ │  Encryption │ │  Encryption │
└─────────────────┘ └───────────────┘ └─────────────┘ └─────────────┘
```

***

## Security Features

### Platform-Specific Protection

#### Android
* Keys stored in Android Keystore
* Hardware-backed encryption when available
* Keys bound to your application
* Automatic cleanup on app uninstall

#### iOS
* Keys stored in iOS Keychain Services
* Protected by device authentication
* Not included in iCloud/iTunes backups
* Automatic cleanup of orphaned keys on first app use after reinstall

#### JVM/Desktop
* AES-256-GCM encryption via standard javax.crypto
* Keys stored in user home directory with restricted permissions
* Suitable for desktop applications and server-side use

#### WASM/Browser
* AES-256-GCM encryption via WebCrypto API
* Keys and data stored in browser `localStorage` (Base64-encoded)
* Scoped per origin (~5-10 MB storage limit)
* Memory policy always `PLAIN_TEXT` internally (WebCrypto is async-only)

### Error Handling

If decryption fails (e.g., corrupted data or missing key), KSafe gracefully returns the default value, ensuring your app continues to function.

**Exception:** When `requireUnlockedDevice = true` and the device is locked, KSafe throws `IllegalStateException` instead of returning the default value. This allows your app to detect and handle the locked state explicitly (e.g., showing a "device is locked" message).

### Reinstall Behavior

KSafe ensures clean reinstalls on all platforms:
* **Android:** Keystore entries automatically deleted on uninstall. If Auto Backup restores the DataStore file without Keystore keys, orphaned ciphertext is detected and removed on next startup.
* **iOS:** Orphaned Keychain entries (keys without data) detected and cleaned on first use. Orphaned ciphertext (data without keys) detected and cleaned on startup.
* **JVM:** Orphaned ciphertext detected and cleaned on startup if encryption key files are lost.

> **Note on unencrypted values:** The orphaned ciphertext cleanup targets only encrypted entries (those with the `encrypted_` prefix in DataStore). Unencrypted values (`encrypted = false`) are not affected by this cleanup. On Android, if `android:allowBackup="true"` is set in the manifest, Auto Backup may restore unencrypted DataStore entries after reinstall with stale values from the last backup snapshot.

### iOS Keychain Cleanup Mechanism

* **Installation ID:** Each app install gets a unique ID stored in DataStore
* **First Access:** On first get/put operation after install, cleanup runs
* **Orphan Detection:** Compares Keychain entries with DataStore entries
* **Automatic Removal:** Deletes any Keychain keys without matching DataStore data

### Orphaned Ciphertext Cleanup (All Platforms)

On startup, KSafe probes each encrypted DataStore entry by attempting decryption:
* **Permanent failure** (key gone, invalidated, wrong key): entry removed from DataStore
* **Temporary failure** (device locked): skipped, retried on next launch
* Runs once per startup, after migration and before the DataStore collector begins

### Known Limitations

* **iOS:** Keychain access may require device to be unlocked depending on `requireUnlockedDevice` setting (default: accessible after first unlock)
* **Android:** Some devices may not have hardware-backed keystore; `setUnlockedDeviceRequired` requires API 28+
* **JVM:** No hardware security module; relies on file system permissions
* **WASM:** No hardware security; relies on browser `localStorage` which can be cleared by the user. Security checks (root, debugger, emulator) are no-ops
* **All Platforms:** Encrypted data is lost if encryption keys are deleted (by design for security)

***

## Testing & Development

by [Mark Andrachek](https://github.com/mandrachek)

### Running Tests

```bash
# Run all tests across all platforms
./gradlew allTests

# Run common tests only
./gradlew :ksafe:commonTest

# Run JVM tests
./gradlew :ksafe:jvmTest

# Run Android unit tests (Note: May fail in Robolectric due to KeyStore limitations)
./gradlew :ksafe:testDebugUnitTest

# Run Android instrumented tests on connected device/emulator (Recommended for Android)
./gradlew :ksafe:connectedDebugAndroidTest

# Run iOS tests on simulator
./gradlew :ksafe:iosSimulatorArm64Test

# Run a specific test class
./gradlew :ksafe:commonTest --tests "*.KSafeTest"
```

**Note:** iOS Simulator uses real Keychain APIs (software-backed), while real devices store Keychain data in a hardware-encrypted container protected by the device passcode.

### Building and Running the iOS Test App

#### Prerequisites
```bash
./gradlew :ksafe:linkDebugFrameworkIosSimulatorArm64  # For simulator
./gradlew :ksafe:linkDebugFrameworkIosArm64           # For physical device
```

#### Building for iOS Simulator
```bash
cd iosTestApp
xcodebuild -scheme KSafeTestApp \
           -configuration Debug \
           -sdk iphonesimulator \
           -arch arm64 \
           -derivedDataPath build \
           build
```

#### Installing and Running on Simulator
```bash
xcrun simctl list devices | grep "Booted"
xcrun simctl install DEVICE_ID build/Build/Products/Debug-iphonesimulator/KSafeTestApp.app
xcrun simctl launch DEVICE_ID com.example.KSafeTestApp
```

#### Building for Physical iOS Device
```bash
cd iosTestApp
xcodebuild -scheme KSafeTestApp \
           -configuration Debug \
           -sdk iphoneos \
           -derivedDataPath build \
           build
```

**Important Notes:**
- **Simulator:** Uses real Keychain APIs (software-backed)
- **Physical Device:** Uses hardware-encrypted Keychain (protected by device passcode). Requires developer profile to be trusted in Settings → General → VPN & Device Management

### Test App Features

The iOS test app demonstrates:
- Creating a KSafe instance with a custom file name
- Observing value changes through Flow simulation (via polling)
    - For production apps, consider using [SKIE](https://skie.touchlab.co/) or [KMP-NativeCoroutines](https://github.com/rickclephas/KMP-NativeCoroutines) for easier Flow consumption from iOS
- Using `putDirect` to immediately update values
- Real-time UI updates responding to value changes

***

## Migration Guide

### From v1.1.x to v1.2.0+

#### Binary Compatibility
The public API surface (`get`, `put`, `getDirect`, `putDirect`) remains backward compatible.

#### Behavior Changes
- **Initialization is now eager by default.** If you relied on KSafe doing absolutely nothing until the first call, pass `lazyLoad = true`.
- **Nullable values now work correctly.** No code changes needed, but you can now safely store `null` values.

#### Compose Module Import Fix
If upgrading from early 1.2.0 alphas, update your imports:
```kotlin
// Old (broken in alpha versions)
import eu.eu.anifantakis.lib.ksafe.compose.mutableStateOf

// New (correct)
import eu.anifantakis.lib.ksafe.compose.mutableStateOf
```

***

## Alternatives & Comparison

| Feature | KSafe | EncryptedSharedPrefs | KVault | Multiplatform Settings | SQLCipher |
|---------|-------|---------------------|--------|------------------------|-----------|
| **KMP Support** | ✅ Android, iOS, JVM, WASM | ❌ Android only | ✅ Android, iOS | ✅ Multi-platform | ⚠️ Limited |
| **Hardware-backed Keys** | ✅ Keystore/Keychain | ✅ Keystore | ✅ Keystore/Keychain | ❌ No encryption | ❌ Software |
| **Zero Boilerplate** | ✅ `by ksafe(0)` | ❌ Verbose API | ⚠️ Moderate | ⚠️ Moderate | ❌ SQL required |
| **Biometric Helper** | ✅ Built-in | ❌ Manual | ❌ Manual | ❌ Manual | ❌ Manual |
| **Compose State** | ✅ `mutableStateOf` | ❌ Manual | ❌ Manual | ❌ Manual | ❌ Manual |
| **Type Safety** | ✅ Reified generics | ⚠️ Limited | ✅ Good | ✅ Good | ❌ SQL strings |
| **Auth Caching** | ✅ Scoped sessions | ❌ No | ❌ No | ❌ No | ❌ No |

**When to choose KSafe:**
- You need encrypted persistence across Android, iOS, Desktop, and Web
- You want property delegation (`by ksafe(x)`) for minimal boilerplate
- You need integrated biometric authentication with smart caching
- You're using Jetpack Compose and want reactive encrypted state
- Performance is critical — KSafe is **103x faster** than KVault for encrypted reads, **85x faster** for writes

**When to consider alternatives:**
- You need complex queries → Consider SQLCipher or Room with encryption
- Android-only app with simple needs → EncryptedSharedPreferences works
- No encryption needed → Multiplatform Settings is lighter
- Simple KMP encryption needs → KVault is a good alternative (but slower)

***

## Licence

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
