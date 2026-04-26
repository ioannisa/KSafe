# KSafe — Secure-by-Default Key/Value Persistence for Kotlin Multiplatform

_**The Universal Persistence Layer: `MutableState`, `MutableStateFlow`, and plain variables — all encrypted, all persisted, all surviving process death. For Android, iOS, Desktop, and Web.**_


[![Maven Central](https://img.shields.io/maven-central/v/eu.anifantakis/ksafe.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/eu.anifantakis/ksafe)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

![image](https://github.com/user-attachments/assets/4cfb7633-e109-41ae-975a-f034f0720485)

## Demo Application
KSafe in action across multiple scenarios: [Demo CMP App Using KSafe](https://github.com/ioannisa/KSafeDemo).

## YouTube Demos
From the author and the community:

| Author's Video | Philipp Lackner's Video | Jimmy Plazas's Video |
|:--------------:|:---------------:|:---------------:|
| [<img width="200" alt="image" src="https://github.com/user-attachments/assets/8c317a36-4baa-491e-8c88-4c44b8545bad" />](https://youtu.be/mFKGx0DMZEA) | [<img width="200" alt="image" src="https://github.com/user-attachments/assets/59cce32b-634e-4b17-bb5f-5e084dff899f" />](https://youtu.be/cLyxWGV6GKg) | [<img width="200" alt="image" src="https://github.com/user-attachments/assets/65dba780-9c80-470c-9ad0-927a86510a26" />](https://youtu.be/M4U06OnAl-I) | 
| [KSafe - Kotlin Multiplatform Encrypted DataStore Persistence Library](https://youtu.be/mFKGx0DMZEA) | [How to Encrypt Local Preferences In KMP With KSafe](https://youtu.be/cLyxWGV6GKg) | [Encripta datos localmente en Kotlin Multiplatform con KSafe - Ejemplo + Arquitectura](https://youtu.be/M4U06OnAl-I) |


## What is KSafe?

KSafe is a secure-by-default Kotlin Multiplatform key/value persistence library.

It lets you persist ordinary Kotlin variables, Compose `MutableState`, and `MutableStateFlow` across app restarts using one API across Android, iOS, JVM/Desktop, WASM, and Kotlin/JS.

Encrypted storage is the default. Plain storage is available per entry with `mode = KSafeWriteMode.Plain`.

**Fast. Easy. Synchronous or asynchronous. Encrypted or plain.**

KSafe gives you a complete persistence layer for Kotlin Multiplatform: property delegates or coroutines, encrypted or plain storage, hot in-memory reads, atomic DataStore writes, automatic serialization, and one API across platforms.

- **Easy?** ✔ Yes — one-line setup, property-delegate API
- **Encrypted by default?** ✔ Yes — AES-256-GCM by default
- **Plain storage?** ✔ Yes — opt out with one parameter
- **Synchronous?** ✔ Yes — non-blocking hot-cache reads when you do not want coroutines
- **Asynchronous?** ✔ Yes — full suspend API when you want guaranteed disk flushes
**Extras when you encrypt:**

* **Biometrics?** ✔ Yes — Face ID / Touch ID / Fingerprint on Android + iOS, with auth caching. Ships as the standalone optional `ksafe-biometrics` module so apps that don't need it pay nothing.
* **Root/jailbreak detection?** ✔ Yes — configurable WARN/BLOCK actions + analytics callback
* **Memory policy?** ✔ Yes — three RAM modes trading security vs performance
* **Database passphrase in one line?** ✔ Yes — hardware-isolated 256-bit secret for SQLCipher / SQLDelight / Room

## Where KSafe fits

KSafe brings together two things that are usually separate in Kotlin Multiplatform: 
1) effortless key/value persistence 
2) and serious encrypted storage.

Use it as a general-purpose persistence layer for settings, preferences, app state, Compose `MutableState`, and `MutableStateFlow`. 

* By default, KSafe stores values with AES-256-GCM encryption, backed by platform security primitives where available. 
* When encryption is not required for a specific entry, you can opt into plain storage with `mode = KSafeWriteMode.Plain`.

This gives you the best of both worlds: the simplicity of ordinary key/value storage and the protection of a secure storage layer, without changing APIs or rewriting your persistence model.
### One line. Encrypted by default.

```kotlin
var counter by ksafe(0)
counter++   // auto-encrypted (AES-256-GCM), auto-persisted, survives process death
```

Read and write it like any normal Kotlin variable — no `suspend`, no `runBlocking`, no DataStore boilerplate, no explicit `encrypt`/`decrypt`. Reads hit a hot in-memory cache (~0.007ms); writes encrypt and flush in the background.

### Don't need encryption? Same one-liner.

```kotlin
var counter by ksafe(0, mode = KSafeWriteMode.Plain)
```

One argument change and you have the simplicity of `SharedPreferences` / `NSUserDefaults` — multiplatform, type-safe, object-aware, backed by atomic DataStore writes.

### Compose `MutableState`? `MutableStateFlow`? Plain delegate? All persisted.

Every persistence shape you reach for, with the same guarantees behind each:

```kotlin
// 1. Plain property delegate — no Compose, no Flow, no coroutines required
var token by ksafe("")

// 2. Compose MutableState — reactive UI, persisted, encrypted
var username by ksafe.mutableStateOf("Guest")

// 3. Read-only StateFlow — observe from anywhere, writes go through ksafe.put()
val user: StateFlow<User> by ksafe.asStateFlow(User(), viewModelScope)

// 4. Read/write MutableStateFlow — the classic _state / state pattern, persisted
private val _state by ksafe.asMutableStateFlow(MoviesState(), viewModelScope)
val state = _state.asStateFlow()
```

All four survive process death, are AES-256-GCM encrypted by default, and can be made plain with `mode = KSafeWriteMode.Plain`. **Zero boilerplate, on every target.**

> **DataStore without the coroutines tax.** The property delegate, `mutableStateOf`, and `getDirect`/`putDirect` are fully synchronous — **but never blocking**. Reads come from a hot in-memory cache; writes update the cache immediately and enqueue the encrypt-and-flush onto a background thread. Call sites return instantly. Use the `suspend` API (`get` / `put`) only when *you* want to.

### Prefer coroutines? `put` and `get` too.

```kotlin
// inside any coroutine / suspend function
ksafe.put("profile", user)                       // awaits the disk flush
val profile: User = ksafe.get("profile", User())
```

Same encryption, same cache, same DataStore — just an API shape that awaits the write instead of enqueueing it. Reach for this when you want a guaranteed flush (payments, critical writes) or when the call site is already a coroutine.

### Need a passphrase to encrypt databases? Also one line. (v1.8.0)

KSafe isn't just for key/value pairs — it's the simplest way to bootstrap an encrypted SQLCipher / SQLDelight / Room database too:

```kotlin
// Generates a 256-bit secret on first call, returns the same one thereafter.
// Stored hardware-isolated (StrongBox on Android, Secure Enclave on iOS).
val passphrase = ksafe.getOrCreateSecret("main.db")

Room.databaseBuilder(context, AppDatabase::class.java, "main.db")
    .openHelperFactory(SupportFactory(passphrase))
    .build()
```

One line replaces: secure random generation, hardware-backed key storage, persistence, and retrieval.

### Complex Objects? Of course.

Ktor bearer authentication with **zero encryption boilerplate**:

```kotlin
@Serializable
data class AuthTokens(val accessToken: String = "", val refreshToken: String = "")

// One line to encrypt, persist, and serialize the whole object — that's it.
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
      tokens = AuthTokens(newInfo.accessToken, newInfo.refreshToken)

      BearerTokens(tokens.accessToken, tokens.refreshToken)
    }
  }
}
```

Under the hood, each platform uses its native crypto engine — Android Keystore, iOS Keychain + CryptoKit, JVM's `javax.crypto`, browser WebCrypto (on both Kotlin/WASM and Kotlin/JS) — unified behind one API. Values are AES-256-GCM encrypted and persisted to DataStore (localStorage on the web targets). Cross-screen sync (`scope =`), biometric auth, memory policies, and runtime security detection are all built in.

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
val ksafe = KSafe()        // iOS / JVM / WASM / JS / JS

// 2. Store & retrieve with property delegation
var counter by ksafe(0)
counter++  // Auto-encrypted, auto-persisted

// 3. Compose state (read/write, reactive to external changes)
var username by ksafe.mutableStateOf("Guest", scope = viewModelScope)

// 4. Reactive flows — read-only StateFlow or read/write MutableStateFlow
val user: StateFlow<User> by ksafe.asStateFlow(User(), viewModelScope)
private val _state by ksafe.asMutableStateFlow(UiState(), viewModelScope)
val state = _state.asStateFlow()

// 5. Or use suspend API
viewModelScope.launch {
    ksafe.put("user_token", token)
    val token = ksafe.get("user_token", "")
}

// 6. Protect actions with biometrics (optional — add `ksafe-biometrics`)
KSafeBiometrics.verifyBiometricDirect("Confirm payment") { success ->
    if (success) processPayment()
}
```

Data is now AES-256-GCM encrypted — keys in Android Keystore, iOS Keychain, software-backed on JVM, WebCrypto on the browser targets (Kotlin/WASM and Kotlin/JS).

***

## Setup

[![Maven Central](https://img.shields.io/maven-central/v/eu.anifantakis/ksafe.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/eu.anifantakis/ksafe)

### 1 - Add the Dependency

```kotlin
// commonMain or Android-only build.gradle(.kts)
implementation("eu.anifantakis:ksafe:2.0.0-RC1")
implementation("eu.anifantakis:ksafe-compose:2.0.0-RC1")     // ← Compose state (optional)
implementation("eu.anifantakis:ksafe-biometrics:2.0.0-RC1")  // ← Biometric auth (optional)
```

> Skip `ksafe-compose` if you don't use Jetpack Compose or `mutableStateOf` persistence.
>
> Skip `ksafe-biometrics` if you don't need Face ID / Touch ID / Fingerprint verification. The biometrics module is fully independent — it has no dependency on `:ksafe` and can be used on its own to protect any action in your app.

> **Note:** `kotlinx-serialization-json` comes in transitively — don't add it yourself.

### 2 - Apply the kotlinx-serialization plugin

Required only if you store `@Serializable` data classes. Add it to `libs.versions.toml`:
```toml
[versions]
kotlin = "2.2.21"

[plugins]
kotlin-serialization = { id = "org.jetbrains.kotlin.plugin.serialization", version.ref = "kotlin" }
```

then apply it in `build.gradle.kts`:
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

// iOS / JVM / WASM / JS
val ksafe = KSafe()
```

With Koin (recommended for KMP):

```kotlin
// Android
actual val platformModule = module {
    single { KSafe(androidApplication()) }
}

// iOS / JVM / WASM / JS
actual val platformModule = module {
    single { KSafe() }
}
```

Multi-instance setups, web `awaitCacheReady()` (wasmJs + js), and full per-platform Koin examples: [docs/SETUP.md](docs/SETUP.md).


## Basic Usage

A handful of examples cover 95% of real-world use. Full reference (Compose `policy`, cross-screen sync, write modes, nullables, deletion, full ViewModel): **[docs/USAGE.md](docs/USAGE.md)**.

```kotlin
// 1. Property delegate — synchronous, non-blocking, encrypted, persisted
var counter by ksafe(0)
counter++

// 2. Compose state — reactive UI + persistence (requires ksafe-compose)
var username by ksafe.mutableStateOf("Guest")

// 3. Reactive flows — read-only StateFlow and read/write MutableStateFlow
val user: StateFlow<User> by ksafe.asStateFlow(User(), viewModelScope)        // read-only
private val _state by ksafe.asMutableStateFlow(MoviesState(), viewModelScope) // read/write
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

**Per-entry plain / encrypted toggle** via `KSafeWriteMode`:

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

**Complex objects** — just mark them `@Serializable`; JSON and encryption are automatic:

```kotlin
@Serializable
data class AuthInfo(val accessToken: String = "", val refreshToken: String = "")

var authInfo by ksafe(AuthInfo())
authInfo = authInfo.copy(accessToken = "newToken")
```

> **Note:** The property delegate works only with the default KSafe instance. For named instances, use the suspend or direct APIs — see [docs/SETUP.md](docs/SETUP.md#multiple-instances).


## Custom JSON Serialization

For third-party types you can't annotate (`UUID`, `Instant`, `BigDecimal`…), register a `KSerializer` via `KSafeConfig(json = customJson)` and use `@Contextual` fields at the call site. Full walkthrough: **[docs/SERIALIZATION.md](docs/SERIALIZATION.md)**.

***

## Cryptographic Utilities

Two small cross-platform helpers:

```kotlin
// Secure random bytes (SecureRandom / arc4random_buf / WebCrypto)
val nonce = secureRandomBytes(16)

// Generate-or-retrieve a hardware-isolated 256-bit secret (great for DB passphrases)
val passphrase = ksafe.getOrCreateSecret("main.db")
```

Sizes, protection tiers, Room + SQLCipher / SQLDelight examples: **[docs/SECURITY.md#cryptographic-utilities](docs/SECURITY.md#cryptographic-utilities)**.

***

## Why use KSafe?

* **Hardware-backed security** — AES-256-GCM, keys in Android Keystore / iOS Keychain / JVM software / WebCrypto. Per-property control via `KSafeWriteMode` + `KSafeEncryptedProtection` tiers
* **Biometric auth** — Face ID, Touch ID, Fingerprint, with auth caching
* **Root & jailbreak detection** — configurable WARN/BLOCK actions
* **Clean reinstalls** — automatic cleanup on fresh install
* **One code path** — no expect/actual juggling; common code owns the vault
* **Ease of use** — `var launchCount by ksafe(0)`, that is literally it
* **Versatility** — primitives, data classes, sealed hierarchies, lists, sets, nullables
* **Performance** — zero-latency UI reads via hybrid hot cache
* **Desktop & Web** — full JVM/Desktop and browser support on both Kotlin/WASM and Kotlin/JS alongside Android and iOS

***

## How KSafe Compares

| Feature | SharedPrefs | DataStore | multiplatform-settings | KVault | KSafe |
|---------|-------------|-----------|------------------------|--------|-------|
| **Thread safety** | :x: ANRs possible | :white_check_mark: Coroutine-safe | :white_check_mark: Platform-native | :white_check_mark: Thread-safe | :white_check_mark: ConcurrentHashMap + coroutines |
| **Type safety** | :x: Runtime crashes | :white_check_mark: Compile-time | :white_check_mark: Generic API | :white_check_mark: Generic API | :white_check_mark: Reified generics + serialization |
| **Data corruption** | :x: Crash = data loss | :white_check_mark: Atomic | :x: Platform-dependent | :white_check_mark: Atomic | :white_check_mark: Uses DataStore atomicity |
| **API style** | :x: Callbacks | :white_check_mark: Flow | :white_check_mark: Sync | :white_check_mark: Sync | :white_check_mark: Both sync & async |
| **Encryption** | :x: None | :x: None | :x: None | :white_check_mark: Hardware-backed | :white_check_mark: Hardware-backed |
| **Cross-platform** | :x: Android only | :x: Android only | :white_check_mark: KMP | :white_check_mark: KMP | :white_check_mark: Android/iOS/JVM/WASM/JS |
| **Nullable support** | :x: No | :x: No | :white_check_mark: Primitives (`*OrNull` getters) | :white_check_mark: Primitives | :white_check_mark: Primitives + objects + delegates * |
| **Complex types** | :x: Manual | :x: Manual/Proto | :x: Manual | :x: Manual | :white_check_mark: Auto-serialization |
| **Biometric auth** | :x: Manual | :x: Manual | :x: Manual | :x: Manual | :white_check_mark: Built-in |
| **Memory policy** | N/A | N/A | N/A | N/A | :white_check_mark: 3 policies (PLAIN_TEXT / ENCRYPTED / TIMED_CACHE) |
| **Hot cache** | :white_check_mark: Synchronized `HashMap` | :x: No (Flow only) | :white_check_mark: Platform-native cache | :x: No | :white_check_mark: `ConcurrentHashMap` + optimistic writes |
| **Write batching** | :x: No | :x: No | :x: No | :x: No | :white_check_mark: 16ms coalescing |

> **\* "Primitives + objects + delegates"** — nullability flows uniformly through every API shape and every type KSafe stores, not just scalar getters. Specifically:
>
> - **Primitives** — `Boolean?`, `Int?`, `Long?`, `Float?`, `Double?`, `String?` all round-trip through `get` / `put` / `getDirect` / `putDirect` / `getFlow`. `null` is a distinct state, not "missing"; it's preserved on reads and persisted on writes.
>   ```kotlin
>   ksafe.putDirect("nickname", null as String?)   // stored as null, not "default"
>   val nickname: String? = ksafe.getDirect("nickname", "Guest")  // returns null, NOT "Guest"
>   ```
> - **Objects** — any `@Serializable` class can be stored nullably. `null` round-trips through the same encrypted JSON path as the payload; no extra boilerplate.
>   ```kotlin
>   @Serializable data class User(val id: String, val name: String)
>   var currentUser: User? by ksafe(null)          // encrypted, persisted, nullable
>   currentUser = User("u1", "Alice")              // -> encrypted JSON
>   currentUser = null                              // -> null sentinel, round-trips
>   ```
> - **Delegates** — every delegate shape accepts a nullable default, including Compose state and `MutableStateFlow`. The persisted null survives process death and emits correctly through Flow observers.
>   ```kotlin
>   var token: String? by ksafe(null)                              // plain delegate
>   var profile: User? by ksafe.mutableStateOf(null)               // Compose state
>   val user: StateFlow<User?> by ksafe.asStateFlow(null, scope)   // read-only Flow
>   private val _state by ksafe.asMutableStateFlow<User?>(null, scope)  // read/write Flow
>   ```
>
> By contrast, `multiplatform-settings` exposes nullability only through separate `getStringOrNull` / `getIntOrNull` scalar getters — there is no nullable support for custom types, property delegates, or Compose state, because the library has no serialization or delegate layer. KVault is similar: nullable return types on its primitive getters, no object or delegate support.

***

## Performance Benchmarks

| API | Read | Write | Best For |
|-----|------|-------|----------|
| `getDirect`/`putDirect` | 0.007 ms | 0.022 ms | UI, bulk ops, high throughput |
| `get`/`put` (suspend) | 0.010 ms | 22 ms | When you must guarantee persistence |

**vs competitors (encrypted):** 14× faster reads than KVault, 15× faster than EncryptedSharedPreferences. Unencrypted writes match SharedPreferences.

> Measured on representative Android hardware under a synthetic but realistic workload. Real-world numbers depend on device, workload, and data size — see [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for the methodology, full tables, cold-start numbers, and architecture notes.


## Compatibility

| Platform | Minimum Version | Notes |
|----------|-----------------|-------|
| **Android** | API 23 (Android 6.0) | Hardware-backed Keystore on supported devices |
| **iOS** | iOS 13+ | Keychain-backed symmetric keys (protected by device passcode) |
| **JVM/Desktop** | JDK 11+ | Software-backed encryption |
| **Kotlin/WASM (Browser)** | Browsers with WasmGC (Chrome 119+, Firefox 120+, Safari 18+) | WebCrypto API + localStorage |
| **Kotlin/JS (Browser)** | Any modern browser | WebCrypto API + localStorage — use this for older browsers or pre-existing JS builds |

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

A standalone biometric helper (Android + iOS) that can gate **any action** in your app — not just KSafe ops. Ships as the optional `:ksafe-biometrics` artifact and depends on nothing else from KSafe, so apps that need only biometric verification can use it on its own.

**Static API.** No instance, no DI wiring, no `Context` parameter. On Android the library auto-initializes via a `ContentProvider` declared in its merged manifest (the same pattern WorkManager / Firebase use), so consumers don't need to touch their `Application` class.

```kotlin
// Same call shape on every platform — Android, iOS, JVM, web.

// Callback-based
KSafeBiometrics.verifyBiometricDirect("Authenticate to increment") { success ->
    if (success) secureCounter++
}

// Suspend-based
if (KSafeBiometrics.verifyBiometric("Authenticate to increment")) {
    secureCounter++
}
```

Auth caching, scoped sessions, platform setup, complete examples: [docs/BIOMETRICS.md](docs/BIOMETRICS.md).

> **Migrating from KSafe ≤1.x?** Biometric methods used to live on `KSafe` itself. In 2.0 they moved to a separate module. Add `implementation("eu.anifantakis:ksafe-biometrics:2.0.0-RC1")`, change `import eu.anifantakis.lib.ksafe.BiometricAuthorizationDuration` → `import eu.anifantakis.lib.ksafe.biometrics.BiometricAuthorizationDuration`, replace `ksafe.verifyBiometric(...)` with `KSafeBiometrics.verifyBiometric(...)`. Method names and signatures are unchanged. No instance to construct, no DI wiring needed.

***

## Runtime Security Policy

Detect and respond to runtime threats — root/jailbreak, debugger, emulator, debug builds:

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

Preset policies, BLOCK exception handling, Compose stability, detection methods: [docs/SECURITY.md](docs/SECURITY.md).

***

## Memory Security Policy

Trade off performance vs. security for data in RAM:

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

Timed cache details, constructor params, lock-state policies, multi-instance lock policies: [docs/MEMORY.md](docs/MEMORY.md).

***

## Deep-Dive Documentation

Internals, advanced features, reference material:

| Topic | Description |
|-------|-------------|
| [Complete Usage Guide](docs/USAGE.md) | Every API shape: delegates, flow delegates, Compose state, suspend/direct APIs, write modes, nullables, full ViewModel |
| [Setup with Koin](docs/SETUP.md) | Multi-instance setups (prefs vs vault), web `awaitCacheReady()` (wasmJs + js), full platform examples |
| [Custom JSON Serialization](docs/SERIALIZATION.md) | Registering `KSerializer`s for `UUID`, `Instant`, and other third-party types |
| [Performance Benchmarks](docs/BENCHMARKS.md) | Full benchmark tables, cold start numbers, architecture deep-dive |
| [Biometric Authentication](docs/BIOMETRICS.md) | Authorization caching, scoped sessions, platform setup, complete examples |
| [Security](docs/SECURITY.md) | Runtime security policy, encryption internals, threat model, hardware isolation, key storage queries, crypto utilities |
| [Encryption Proof](docs/ENCRYPTION_PROOF.md) | Per-platform automated proof tests + manual commands to inspect the raw stored bytes and see the ciphertext yourself |
| [Memory Policy](docs/MEMORY.md) | Timed cache, constructor parameters, encryption config, device lock-state policies |
| [Architecture](docs/ARCHITECTURE.md) | Hybrid hot cache, optimistic updates, encryption architecture diagram |
| [Testing](docs/TESTING.md) | Running tests, building iOS test app, test features |
| [Migration Guide](docs/MIGRATION.md) | Upgrading from v1.6.x → v1.7.0 and v1.1.x → v1.2.0+ |
| [Alternatives & Comparison](docs/COMPARISON.md) | KSafe vs EncryptedSharedPrefs, KVault, SQLCipher, and more |

***

## Licence

Licensed under the Apache License 2.0 — see http://www.apache.org/licenses/LICENSE-2.0. Distributed "AS IS", without warranties of any kind.
