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

**Fast. Easy. Synchronous *or* asynchronous. Encrypted *or* unencrypted.**

KSafe is the **easiest**, **most secure**, and **fastest** way to persist any value in Kotlin Multiplatform — and it is just as good a choice when you don't need encryption at all. One library, one API, every persistence pattern you'll ever use on **Android**, **iOS**, **JVM/Desktop**, and **WASM/JS (Browser)**.

If you've been told KSafe is "just for encrypted key/value storage" — that's wrong. It is the de-facto library for **simple persistence**, with or without encryption, and it never forces you into coroutines just because DataStore lives underneath.

### One line. Encrypted by default.

```kotlin
var counter by ksafe(0)
counter++   // auto-encrypted (AES-256-GCM), auto-persisted, survives process death
```

Read and write it like any normal Kotlin variable. No `suspend`. No `runBlocking`. No DataStore boilerplate. No explicit `encrypt`/`decrypt`. Reads come from a hot in-memory cache (~0.007ms); writes are encrypted and flushed to disk in the background.

### Don't need encryption? Same one-liner.

```kotlin
// Same delegate, plain storage — still synchronous, still survives process death
var counter by ksafe(0, mode = KSafeWriteMode.Plain)
```

That's it. Switch a single argument and you've got the simplicity of `SharedPreferences` / `NSUserDefaults` — but multiplatform, type-safe, object-aware, and backed by atomic DataStore writes.

### Compose `MutableState`? `MutableStateFlow`? Plain delegate? All persisted.

KSafe gives you **every** persistence shape you reach for, all with the same encryption-and-persistence guarantees behind them:

```kotlin
// 1. Plain property delegate — no Compose, no Flow, no coroutines required
var token by ksafe("")

// 2. Compose MutableState — reactive UI, persisted, encrypted
var username by ksafe.mutableStateOf("Guest")

// 3. Kotlin MutableStateFlow — the standard _state / state pattern, persisted
private val _state by ksafe.asMutableStateFlow(MoviesState(), viewModelScope)
val state = _state.asStateFlow()
```

All three survive process death. All three are AES-256-GCM encrypted by default. All three can be made plain with `mode = KSafeWriteMode.Plain`. **Zero boilerplate, on every target.**

> Even though KSafe is built on top of DataStore, **it does not force you to use coroutines**. The property delegate, the Compose `mutableStateOf` variant, and `getDirect`/`putDirect` are all fully synchronous — **but never blocking**. Reads are served from a hot in-memory cache, and writes update that cache immediately and enqueue the encrypt-and-flush work onto a background thread. Your call site returns instantly. Use the `suspend` API (`get` / `put`) only when *you* want to.

### Need a passphrase to encrypt databases? Also now included in one line. (v1.8.0)

KSafe isn't only for key/value pairs — it's the easiest way to bootstrap an encrypted SQLCipher / SQLDelight / Room database too:

```kotlin
// Generates a 256-bit secret on first call, returns the same one forever after.
// Stored hardware-isolated (StrongBox on Android, Secure Enclave on iOS).
val passphrase = ksafe.getOrCreateSecret("main.db")

Room.databaseBuilder(context, AppDatabase::class.java, "main.db")
    .openHelperFactory(SupportFactory(passphrase))
    .build()
```

One line replaces all of: secure random generation, hardware-backed key storage, persistence, and retrieval.

### Complex Objects? Of course.

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
- [Basic Usage](#basic-usage) — full reference in [docs/USAGE.md](docs/USAGE.md)
- [Custom JSON Serialization](#custom-json-serialization) — full guide in [docs/SERIALIZATION.md](docs/SERIALIZATION.md)
- [Cryptographic Utilities](#cryptographic-utilities) — full reference in [docs/SECURITY.md](docs/SECURITY.md)
- [Why use KSafe?](#why-use-ksafe)
- [How KSafe Compares](#how-ksafe-compares)
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

Five lines of code cover 95% of real-world use. For the full reference — flow delegates, Compose `policy`, cross-screen sync, write modes, nullable handling, deletion, and a full ViewModel example — see **[docs/USAGE.md](docs/USAGE.md)**.

```kotlin
// 1. Property delegate — synchronous, non-blocking, encrypted, persisted
var counter by ksafe(0)
counter++

// 2. Compose state — reactive UI + persistence (requires ksafe-compose)
var username by ksafe.mutableStateOf("Guest")

// 3. MutableStateFlow — the standard _state / state pattern, now persisted
private val _state by ksafe.asMutableStateFlow(MoviesState(), viewModelScope)
val state = _state.asStateFlow()

// 4. Suspend API — when you want to await the disk flush
viewModelScope.launch {
    ksafe.put("profile", user)
    val loaded: User = ksafe.get("profile", User())
}

// 5. Direct API — non-suspend, hot-cache reads, background-flushed writes (~1000x faster for bulk ops)
ksafe.putDirect("counter", 42)
val n = ksafe.getDirect("counter", 0)
```

**Per-entry plain / encrypted toggle.** Any of the above can opt into explicit plaintext or stricter encryption via `KSafeWriteMode`:

```kotlin
var theme by ksafe("light", mode = KSafeWriteMode.Plain)

ksafe.putDirect(
    "pin", pin,
    mode = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
        requireUnlockedDevice = true
    )
)
```

**Complex objects** work with zero extra code — mark them `@Serializable` and KSafe handles JSON + encryption automatically:

```kotlin
@Serializable
data class AuthInfo(val accessToken: String = "", val refreshToken: String = "")

var authInfo by ksafe(AuthInfo())
authInfo = authInfo.copy(accessToken = "newToken")
```

> **Note:** The property delegate can ONLY use the default KSafe instance. If you have multiple instances with different file names, use the suspend or direct APIs. See [docs/SETUP.md](docs/SETUP.md#multiple-instances).


## Custom JSON Serialization

Need to persist third-party types like `UUID`, `Instant`, or `BigDecimal` that you can't annotate with `@Serializable`? Register custom `KSerializer`s once via `KSafeConfig(json = customJson)` and use `@Contextual` fields at the call site — KSafe handles everything else.

See **[docs/SERIALIZATION.md](docs/SERIALIZATION.md)** for the full step-by-step with UUID/Instant examples.

***

## Cryptographic Utilities

KSafe also exposes two small, cross-platform crypto helpers:

```kotlin
// Cryptographically secure random bytes (SecureRandom / arc4random_buf / WebCrypto)
val nonce = secureRandomBytes(16)

// Generate-or-retrieve a hardware-isolated 256-bit secret (perfect for DB passphrases)
val passphrase = ksafe.getOrCreateSecret("main.db")
```

For sizes, protection tiers, and the full Room + SQLCipher / SQLDelight examples, see **[docs/SECURITY.md#cryptographic-utilities](docs/SECURITY.md#cryptographic-utilities)**.

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
| [Complete Usage Guide](docs/USAGE.md) | Every API shape: delegates, flow delegates, Compose state, suspend/direct APIs, write modes, nullables, full ViewModel |
| [Setup with Koin](docs/SETUP.md) | Multi-instance setups (prefs vs vault), WASM `awaitCacheReady()`, full platform examples |
| [Custom JSON Serialization](docs/SERIALIZATION.md) | Registering `KSerializer`s for `UUID`, `Instant`, and other third-party types |
| [Performance Benchmarks](docs/BENCHMARKS.md) | Full benchmark tables, cold start numbers, architecture deep-dive |
| [Biometric Authentication](docs/BIOMETRICS.md) | Authorization caching, scoped sessions, platform setup, complete examples |
| [Security](docs/SECURITY.md) | Runtime security policy, encryption internals, threat model, hardware isolation, key storage queries, crypto utilities |
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
