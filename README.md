# KSafe — Universal Key/Value Persistence for Kotlin Multiplatform and Android

* **Encrypted by default. Plain _(unencrypted)_ when needed.**
* **Persist variables, Compose State, StateFlow, and serializable objects across Android, iOS, macOS, Desktop, and Web**
* **Easy to use by design**

[![Maven Central](https://img.shields.io/maven-central/v/eu.anifantakis/ksafe.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/eu.anifantakis/ksafe)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

![image](https://github.com/user-attachments/assets/e1b396e3-70a7-4473-a703-1ca0f2aa23c2)

## 🤖 KSafe Skill for AI agents

KSafe ships [**KSAFE_SKILL.md**](KSAFE_SKILL.md) — an [agentskills.io](https://agentskills.io)-compatible skill that teaches any AI agent (Claude Code, Codex, Gemini CLI, Copilot CLI, Junie) KSafe's patterns, anti-patterns, and gotchas. Restart your agent session after installing — skills load at session start.

<details>
<summary><b>Install</b> — copy the skill into every supported agent's skills directory</summary>

```bash
for agent in claude codex gemini copilot junie; do
  mkdir -p "$HOME/.$agent/skills/ksafe" && \
    curl -fsSL https://raw.githubusercontent.com/ioannisa/KSafe/main/KSAFE_SKILL.md \
    > "$HOME/.$agent/skills/ksafe/SKILL.md"
done
```

Edit the loop to skip agents you don't use. If you've already cloned this repo, `cp KSAFE_SKILL.md "$HOME/.<agent>/skills/ksafe/SKILL.md"` works too (faster, offline).
</details>

## What is KSafe?

KSafe is a secure-by-default Kotlin Multiplatform key/value persistence library. Persist ordinary Kotlin variables, Compose `MutableState`, `MutableStateFlow`, and `@Serializable` objects across app restarts with **one API** on Android, iOS, macOS, JVM/Desktop, WASM, and Kotlin/JS. **Encrypted (AES-256-GCM) by default; plain per-entry with `mode = KSafeWriteMode.Plain`.**

```kotlin
var counter by ksafe(0)
counter++   // auto-encrypted (AES-256-GCM), auto-persisted, survives process death
```

Read and write it like any normal Kotlin variable — no `suspend`, no `runBlocking`, no DataStore boilerplate, no explicit `encrypt`/`decrypt`. Reads hit a hot in-memory cache (~0.002 ms); writes encrypt and flush in the background — **synchronous, but never blocking**. Reach for the `suspend` API (`get` / `put`) only when *you* want to await the disk flush.

- **Easy?** ✔ one-line setup, property-delegate API
- **Encrypted by default?** ✔ AES-256-GCM, hardware-backed where available
- **Plain storage?** ✔ opt out with one parameter
- **Synchronous?** ✔ non-blocking hot-cache reads
- **Asynchronous?** ✔ full suspend API for guaranteed disk flushes

**Extras when you encrypt:** biometrics (Face ID / Touch ID / Fingerprint — optional standalone `ksafe-biometrics` module) · root/jailbreak detection (WARN/BLOCK + analytics callback) · memory policy (RAM-exposure modes) · a one-line hardware-isolated DB passphrase for SQLCipher / SQLDelight / Room.

## Demo & Videos

KSafe in action across many scenarios: **[KSafeDemo — Compose Multiplatform app](https://github.com/ioannisa/KSafeDemo)**.

| Author's Video | Philipp Lackner's Video | Jimmy Plazas's Video |
|:--------------:|:---------------:|:---------------:|
| [<img width="200" alt="image" src="https://github.com/user-attachments/assets/8c317a36-4baa-491e-8c88-4c44b8545bad" />](https://youtu.be/mFKGx0DMZEA) | [<img width="200" alt="image" src="https://github.com/user-attachments/assets/59cce32b-634e-4b17-bb5f-5e084dff899f" />](https://youtu.be/cLyxWGV6GKg) | [<img width="200" alt="image" src="https://github.com/user-attachments/assets/65dba780-9c80-470c-9ad0-927a86510a26" />](https://youtu.be/M4U06OnAl-I) |
| [KSafe - Kotlin Multiplatform Encrypted DataStore Persistence Library](https://youtu.be/mFKGx0DMZEA) | [How to Encrypt Local Preferences In KMP With KSafe](https://youtu.be/cLyxWGV6GKg) | [Encripta datos localmente en Kotlin Multiplatform con KSafe - Ejemplo + Arquitectura](https://youtu.be/M4U06OnAl-I) |

## Table of Contents

- [🤖 KSafe Skill for AI agents](#ksafe-skill-for-ai-agents) — [KSAFE_SKILL.md](KSAFE_SKILL.md)
- [What is KSafe?](#what-is-ksafe)
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

## Setup

[![Maven Central](https://img.shields.io/maven-central/v/eu.anifantakis/ksafe.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/eu.anifantakis/ksafe)

### 1 - Add the Dependency

```kotlin
// commonMain or Android-only build.gradle(.kts)
implementation("eu.anifantakis:ksafe:2.1.3")
implementation("eu.anifantakis:ksafe-compose:2.1.3")     // ← Compose state (optional)
implementation("eu.anifantakis:ksafe-biometrics:2.1.3")  // ← Biometric auth (optional)
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

// iOS / macOS / JVM / WASM / JS
val ksafe = KSafe()
```

With Koin (recommended for KMP):

```kotlin
// Android
actual val platformModule = module {
    single { KSafe(androidApplication()) }
}

// iOS / macOS / JVM / WASM / JS
actual val platformModule = module {
    single { KSafe() }
}
```

Multi-instance setups, web `awaitCacheReady()` (wasmJs + js), full per-platform Koin examples, the **custom storage directory** option (`baseDir` on JVM/Android, `directory` on iOS / macOS — for example to align with `$XDG_DATA_HOME`, `noBackupFilesDir`, or a sandboxed Mac app's container), and the optional `KSafe.close()` for apps that re-create instances mid-process: [docs/SETUP.md](docs/SETUP.md).

## Basic Usage

A handful of examples cover 95% of real-world use. Full reference (Compose `policy`, cross-screen sync, write modes, nullables, deletion, full ViewModel): **[docs/USAGE.md](docs/USAGE.md)**.

```kotlin
// 1. Property delegate — synchronous, non-blocking, encrypted, persisted
var counter by ksafe(0)
counter++

// 2. Compose state on a ViewModel / class field — reactive UI + persistence (requires ksafe-compose)
var username by ksafe.mutableStateOf("Guest")

// 3. Compose state inside a @Composable body — the rememberSaveable analogue, but persists across app restarts
//    var currentTab by ksafe.rememberKSafeState(Tab.Home)   // key auto-resolves to "currentTab"; no ViewModel needed

// 4. Reactive flows — read-only StateFlow, read/write MutableStateFlow, or read/write Flow without a scope
val user: StateFlow<User> by ksafe.asStateFlow(User(), viewModelScope)         // read-only
private val _state by ksafe.asMutableStateFlow(MoviesState(), viewModelScope)  // read/write, hot
val state = _state.asStateFlow()
val themeMode: WritableKSafeFlow<ThemeMode> by ksafe.asWritableFlow(ThemeMode.DEVICE) // read/write, cold; set() to write

// 5. Suspend API — when you want to await the disk flush
viewModelScope.launch {
    ksafe.put("profile", user)
    val loaded: User = ksafe.get("profile", User())
}

// 6. Direct API — non-suspend, hot-cache reads, background-flushed writes (~1000x faster for bulk ops)
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

> **Note:** The property delegate works with **any** KSafe instance — `var x by myKsafe(default)` makes `myKsafe` the storage backend. The bare `var x by ksafe(default)` form requires an in-scope `ksafe` (the conventional name, typically your default instance). See [docs/SETUP.md](docs/SETUP.md#multiple-instances) for the multi-instance pattern.

## Custom JSON Serialization

For third-party types you can't annotate (`UUID`, `Instant`, `BigDecimal`…), register a `KSerializer` via `KSafeConfig(json = customJson)` and use `@Contextual` fields at the call site. Full walkthrough: **[docs/SERIALIZATION.md](docs/SERIALIZATION.md)**.

## Isolating an app's keys (Desktop / Web)

Android and iOS keystores are OS-sandboxed per app. The **JVM/Desktop** OS secret store (macOS Keychain / Linux Secret Service) is **per-OS-user, shared by every process**, and **Web** IndexedDB/localStorage is shared per browser origin — so two apps using the same `fileName` could collide on the same key. Set a stable, app-unique namespace:

```Kotlin
val ksafe = KSafe(config = KSafeConfig(appNamespace = "com.example.myapp"))
```

Production desktop apps should set it explicitly. Only the key-store destination is namespaced — KSafe ≤ 2.0 data still migrates unchanged. See **[docs/USAGE.md](docs/USAGE.md)**.

## Compose Desktop release builds — strongly recommend `modules("jdk.unsupported")`

For production Compose Desktop release distributables, add these to your `nativeDistributions` block — they give KSafe **OS-backed key custody** (Keychain / DPAPI / Secret Service):

```Kotlin
compose.desktop {
    application {
        nativeDistributions {
            // OS-backed key custody: JNA + DataStore's protobuf need sun.misc.Unsafe (jlink trims it).
            // java.management → only for a non-default KSafeSecurityPolicy.
            modules("jdk.unsupported", "java.management")
        }
    }
}
```

Without it KSafe still persists (at a software key tier) and migrates your data forward when you add the module — the trade-off and the key-file risk are in **[docs/JVM_PROTECTION.md](docs/JVM_PROTECTION.md#compose-desktop-release-distributables-jdkunsupported)**; [KSafeDemo](https://github.com/ioannisa/KSafeDemo) shows it live on its Security screen.

***

## Cryptographic Utilities

Two small cross-platform helpers:

```kotlin
import eu.anifantakis.lib.ksafe.internal.secureRandomBytes

// Secure random bytes (SecureRandom / SecRandomCopyBytes / WebCrypto)
val nonce = secureRandomBytes(16)

// Generate-or-retrieve a hardware-isolated 256-bit secret (great for DB passphrases)
val passphrase = ksafe.getOrCreateSecret("main.db")
```

> `secureRandomBytes` lives under `eu.anifantakis.lib.ksafe.internal` — it's the same primitive KSafe uses internally, exposed for app code that needs a CSPRNG.

Sizes, protection tiers, Room + SQLCipher / SQLDelight examples: **[docs/SECURITY.md#cryptographic-utilities](docs/SECURITY.md#cryptographic-utilities)**.

***

## Why use KSafe?

* **Hardware-backed security** — AES-256-GCM, keys in Android Keystore / Apple Keychain (iOS + macOS) / JVM OS secret store (Windows DPAPI · macOS Keychain · Linux libsecret, software fallback) / non-extractable WebCrypto key in IndexedDB. Per-property control via `KSafeWriteMode` + `KSafeEncryptedProtection` tiers
* **Biometric auth** — Face ID, Touch ID, Fingerprint, with auth caching
* **Root & jailbreak detection** — configurable WARN/BLOCK actions
* **Clean reinstalls** — automatic cleanup on fresh install
* **One code path** — no expect/actual juggling; common code owns the vault
* **Ease of use** — `var launchCount by ksafe(0)`, that is literally it
* **Versatility** — primitives, data classes, sealed hierarchies, lists, sets, nullables
* **Performance** — zero-latency UI reads via hybrid hot cache
* **Desktop & Web** — full JVM/Desktop, native macOS, and browser support on both Kotlin/WASM and Kotlin/JS alongside Android and iOS

***

## How KSafe Compares

| Feature | SharedPrefs | DataStore | multiplatform-settings | KVault | KSafe |
|---------|-------------|-----------|------------------------|--------|-------|
| **Thread safety** | :x: ANRs possible | :white_check_mark: Coroutine-safe | :white_check_mark: Platform-native | :white_check_mark: Thread-safe | :white_check_mark: ConcurrentHashMap + coroutines |
| **Type safety** | :x: Runtime crashes | :white_check_mark: Compile-time | :white_check_mark: Generic API | :white_check_mark: Generic API | :white_check_mark: Reified generics + serialization |
| **Data corruption** | :x: Crash = data loss | :white_check_mark: Atomic | :x: Platform-dependent | :white_check_mark: Atomic | :white_check_mark: Uses DataStore atomicity |
| **API style** | :x: Callbacks | :white_check_mark: Flow | :white_check_mark: Sync | :white_check_mark: Sync | :white_check_mark: Both sync & async |
| **Encryption** | :x: None | :x: None | :x: None | :white_check_mark: Hardware-backed | :white_check_mark: Hardware-backed |
| **Cross-platform** | :x: Android only | :x: Android only | :white_check_mark: KMP | :white_check_mark: KMP | :white_check_mark: Android/iOS/macOS/JVM/WASM/JS |
| **Nullable support** | :x: No | :x: No | :white_check_mark: Primitives (`*OrNull` getters) | :white_check_mark: Primitives | :white_check_mark: Primitives + objects + delegates * |
| **Complex types** | :x: Manual | :x: Manual/Proto | :x: Manual | :x: Manual | :white_check_mark: Auto-serialization |
| **Biometric auth** | :x: Manual | :x: Manual | :x: Manual | :x: Manual | :white_check_mark: Built-in |
| **Memory policy** | N/A | N/A | N/A | N/A | :white_check_mark: 4 policies (LAZY_PLAIN_TEXT / PLAIN_TEXT / ENCRYPTED / ENCRYPTED_WITH_TIMED_CACHE) |
| **Hot cache** | :white_check_mark: Synchronized `HashMap` | :x: No (Flow only) | :white_check_mark: Platform-native cache | :x: No | :white_check_mark: `ConcurrentHashMap` + optimistic writes |
| **Write batching** | :x: No | :x: No | :x: No | :x: No | :white_check_mark: 16ms coalescing |

> **\*** Nullability flows uniformly through every API shape — primitives, `@Serializable` objects, and all delegate / Compose / Flow forms. `null` is a distinct, persisted state, not "missing." Full examples: **[docs/USAGE.md#nullable-values](docs/USAGE.md#nullable-values)**.

***

## Performance Benchmarks

| API | Read | Write | Best For |
|-----|------|-------|----------|
| `getDirect`/`putDirect` | 0.0015 ms | 0.0010 ms | UI, hot cache, fire-and-forget |
| `get`/`put` (suspend) | 0.0024 ms | 0.86 ms | Must guarantee persistence; multiple concurrent callers |

**vs competitors (encrypted):** encrypted reads are **faster than EncryptedSharedPreferences and KVault even decrypting on every read** (~3.4× / ~2.6×), and ~37× / ~28× faster with cached (`PLAIN_TEXT`) memory; encrypted writes are **~31× faster than EncryptedSharedPreferences** and ~383× faster than KVault. Unencrypted `putDirect()` is **~12× faster than SharedPreferences**. Reads are ~9× slower than SharedPreferences in absolute µs (the cost of type-safe generics) — still ~1.5 µs.

> Measured on a **Samsung Galaxy S24 Ultra** (release build, KSafe 2.1.2, 500 iterations). 2.1.2 adds an Android software-DEK fast path: the per-datastore master key stays non-exportable in the TEE and wraps a data-encryption key that is unwrapped once into memory, so per-value AES-GCM runs in userspace — `ENCRYPTED`-memory decrypt-every-read dropped from ~8 ms to ~0.014 ms on real hardware. Suspend-API benchmarks issue all iterations as concurrent coroutines (`GlobalScope.launch` + `joinAll`). Real-world numbers depend on device, workload, and data size — see [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for methodology, full tables, cold-start numbers, and architecture notes.

## Compatibility

| Platform | Minimum Version | Notes |
|----------|-----------------|-------|
| **Android** | API 24 (Android 7.0) | Hardware-backed Keystore on supported devices |
| **iOS** | iOS 13+ | Keychain-backed symmetric keys (protected by device passcode); Secure Enclave on real devices |
| **macOS (native)** | macOS 11+ (`macosArm64`, `macosX64`) | Same Keychain + CryptoKit path as iOS; Secure Enclave on Apple Silicon and T2-equipped Macs |
| **JVM/Desktop** | JDK 11+ | Key in OS secret store — Windows DPAPI / macOS Keychain / Linux Secret Service (libsecret); software fallback + warning when none is available |
| **Kotlin/WASM (Browser)** | Browsers with WasmGC (Chrome 119+, Firefox 120+, Safari 18+) | WebCrypto API; non-extractable key in IndexedDB, values in localStorage |
| **Kotlin/JS (Browser)** | Any modern browser | WebCrypto API; non-extractable key in IndexedDB, values in localStorage — use this for older browsers or pre-existing JS builds |

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

A standalone biometric helper (Android + iOS + macOS) that can gate **any action** in your app — not just KSafe ops. Ships as the optional `:ksafe-biometrics` artifact and depends on nothing else from KSafe, so apps that need only biometric verification can use it on its own.

**Static API.** No instance, no DI wiring, no `Context` parameter. On Android the library auto-initializes via a `ContentProvider` declared in its merged manifest (the same pattern WorkManager / Firebase use), so consumers don't need to touch their `Application` class.

```kotlin
// Same call shape on every platform — Android, iOS, macOS, JVM, web.

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

> **Migrating from KSafe ≤1.x?** Biometric methods used to live on `KSafe` itself. In 2.0 they moved to a separate module. Add `implementation("eu.anifantakis:ksafe-biometrics:2.1.3")`, change `import eu.anifantakis.lib.ksafe.BiometricAuthorizationDuration` → `import eu.anifantakis.lib.ksafe.biometrics.BiometricAuthorizationDuration`, replace `ksafe.verifyBiometric(...)` with `KSafeBiometrics.verifyBiometric(...)`. Method names and signatures are unchanged. No instance to construct, no DI wiring needed.

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

## Key Protection Diagnostics

Find out what key custody this `KSafe` instance **actually** got — including any silent fallback (e.g. JVM dropping from `SANDBOX_PROTECTED` to `SOFTWARE` when no OS vault is reachable):

```kotlin
val info = ksafe.protectionInfo
// info.intendedLevel  = SANDBOX_PROTECTED              // engine baseline
// info.effectiveLevel = SOFTWARE                       // vault self-test failed
// info.custody        = "DataStore (software, ...)"    // human-readable
// info.notes          = ["jvm_os_vault_unavailable"]   // stable code

// Gate startup, drive feature logic, or surface a UX banner
check(info.effectiveLevel >= KSafeProtectionLevel.SANDBOX_PROTECTED)
```

`KSafeProtectionLevel` is a universally-ordered scale — `SOFTWARE < SANDBOX_PROTECTED < HARDWARE_BACKED < HARDWARE_ISOLATED`. One ordinal comparison works across every platform. Per-platform truth table, runtime-decision patterns (gating, tighter re-auth windows, feature disablement, UX honesty banners, intended-vs-effective delta), and all defined `notes` codes: **[docs/PROTECTION_INFO.md](docs/PROTECTION_INFO.md)**.

***

## Memory Security Policy

Trade off performance vs. security for data in RAM:

```Kotlin
val ksafe = KSafe(
    fileName = "secrets",
    memoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT // Default
)
```

| Policy | Best For | RAM Contents | Read Cost | Security |
|--------|----------|-------------|-----------|----------|
| `LAZY_PLAIN_TEXT` (Default) | General-purpose: settings, tokens, app state | Ciphertext at rest; plaintext appears after first read of each key and stays | First read decrypts, then O(1) forever | Low (after first read) — same exposure as `PLAIN_TEXT` for keys you've actually touched |
| `PLAIN_TEXT` (discouraged) | Apps that want decrypt failures surfaced synchronously at startup | Plaintext (forever, eagerly decrypted at cold start) | O(1) lookup | Low — all data exposed in memory; cold start pays $O(n)$ Keystore round-trips up front |
| `ENCRYPTED` | Tokens, passwords, financial data | Ciphertext only | AES-GCM decrypt every read | High — nothing plaintext in RAM |
| `ENCRYPTED_WITH_TIMED_CACHE` | Compose/SwiftUI screens accessing the same encrypted value many times per frame | Ciphertext + short-lived plaintext (TTL) | First read of a window decrypts, then O(1) for TTL | Medium — plaintext only for recently-accessed keys, only for seconds |

Timed cache details, constructor params, lock-state policies, multi-instance lock policies: [docs/MEMORY.md](docs/MEMORY.md).

***

## Deep-Dive Documentation

Internals, advanced features, reference material:

| Topic | Description |
|-------|-------------|
| [KSafe Skill for AI agents](KSAFE_SKILL.md) | Self-contained skill file teaching any agentskills.io-compatible agent (Claude Code, Codex, Gemini CLI, Copilot CLI, Junie, …) the patterns, anti-patterns, and gotchas for KSafe. Install instructions at the top of this README. |
| [Complete Usage Guide](docs/USAGE.md) | Every API shape: delegates, flow delegates, Compose state, suspend/direct APIs, write modes, nullables, full ViewModel |
| [Setup with Koin](docs/SETUP.md) | Multi-instance setups (prefs vs vault), web `awaitCacheReady()` (wasmJs + js), full platform examples, custom storage directory (`baseDir` / `directory`) |
| [Custom JSON Serialization](docs/SERIALIZATION.md) | Registering `KSerializer`s for `UUID`, `Instant`, and other third-party types |
| [Performance Benchmarks](docs/BENCHMARKS.md) | Full benchmark tables, cold start numbers, architecture deep-dive |
| [Biometric Authentication](docs/BIOMETRICS.md) | Authorization caching, scoped sessions, platform setup, complete examples |
| [Security](docs/SECURITY.md) | Runtime security policy, encryption internals, threat model, hardware isolation, key storage queries, crypto utilities |
| [Protection Info](docs/PROTECTION_INFO.md) | Instance-level diagnostic API: `KSafe.protectionInfo`, the cross-platform `KSafeProtectionLevel` scale, per-platform truth table, consumer gating / telemetry / UI patterns |
| [JVM Key Protection](docs/JVM_PROTECTION.md) | Deep dive on how the AES key is held on each JVM host: Windows DPAPI, macOS login Keychain, Linux Secret Service (libsecret), the software fallback, the opt-out, and the per-app namespace |
| [Encryption Proof](docs/ENCRYPTION_PROOF.md) | Per-platform automated proof tests + manual commands to inspect the raw stored bytes and see the ciphertext yourself |
| [Memory Policy](docs/MEMORY.md) | Timed cache, constructor parameters, encryption config, device lock-state policies |
| [Architecture](docs/ARCHITECTURE.md) | The conceptual model: three modules, three rings (public API / `KSafeCore` orchestrator / platform shells), hot cache + write coalescer, the `KSafePlatformStorage` and `KSafeEncryption` interfaces, memory policies, and how 2.0 consolidated ~5,900 lines of duplicated platform logic into ~890 |
| [Source-tree tour](docs/TOUR.md) | File-by-file walkthrough of every Kotlin source file in `:ksafe`: where each behaviour lives and why. Companion to the Architecture doc — Architecture is "the model," TOUR is "the map." |
| [Testing](docs/TESTING.md) | Running tests, building iOS test app, test features |
| [Migration Guide](docs/MIGRATION.md) | Upgrading from v1.x → v2.0 (biometric module extraction, iOS path migration), v1.6.x → v1.7.0 (`encrypted: Boolean` → `KSafeWriteMode`), and v1.1.x → v1.2.0+ |
| [Alternatives & Comparison](docs/COMPARISON.md) | KSafe vs EncryptedSharedPrefs, KVault, SQLCipher, and more |

***

## Licence

Licensed under the Apache License 2.0 — see http://www.apache.org/licenses/LICENSE-2.0. Distributed "AS IS", without warranties of any kind.
