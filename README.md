# KSafe — Universal Key/Value Persistence for Kotlin Multiplatform and Android

* **Encrypted by default. Plain _(unencrypted)_ when needed.**
* **Persist variables, Compose State, StateFlow, and serializable objects across Android, iOS, macOS, Desktop, and Web**
* **Easy to use by design** — plus key rotation, cross-platform biometrics, and an encryption preflight

[![Maven Central](https://img.shields.io/maven-central/v/eu.anifantakis/ksafe.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/eu.anifantakis/ksafe)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Changelog](https://img.shields.io/badge/Changelog-latest-informational.svg)](CHANGELOG.md)

![image](https://github.com/user-attachments/assets/e1b396e3-70a7-4473-a703-1ca0f2aa23c2)

## What is KSafe?

KSafe is a secure-by-default Kotlin Multiplatform key/value persistence library. Persist ordinary Kotlin variables, Compose `MutableState`, `MutableStateFlow`, and `@Serializable` objects across app restarts with **one API** on Android, iOS, macOS, JVM/Desktop, WASM, and Kotlin/JS. **Encrypted (AES-256-GCM) by default; plain per-entry with `mode = KSafeWriteMode.Plain`.**

```kotlin
var counter by ksafe(0)
counter++   // auto-encrypted (AES-256-GCM), auto-persisted, survives process death
```

Read and write it like any normal Kotlin variable — no `suspend`, no `runBlocking`, no DataStore boilerplate, no explicit `encrypt`/`decrypt`. Reads hit a hot in-memory cache; writes encrypt and flush in the background — **synchronous, but never blocking**. Reach for the `suspend` API (`get` / `put`) only when *you* want to await the disk flush.

- **Easy?** ✔ one-line setup, property-delegate API
- **Encrypted by default?** ✔ AES-256-GCM, hardware-backed where available
- **Plain storage?** ✔ opt out with one parameter
- **Synchronous?** ✔ non-blocking hot-cache reads
- **Asynchronous?** ✔ full suspend API for guaranteed disk flushes

**Extras when you encrypt:** biometrics (Face ID / Touch ID / Fingerprint — optional standalone `ksafe-biometrics` module) · root/jailbreak detection (WARN/BLOCK + analytics callback) · memory policy (RAM-exposure modes) · a one-line hardware-isolated DB passphrase for SQLCipher / SQLDelight / Room.

## 🤖 KSafe Skill for AI agents

KSafe ships an [agentskills.io](https://agentskills.io)-compatible skill — [**skills/ksafe/SKILL.md**](skills/ksafe/SKILL.md) — that teaches any AI agent (Claude Code, Codex, Gemini CLI, Copilot CLI, Junie) KSafe's patterns, anti-patterns and gotchas, so the code it writes for you is the code this README describes.

**Claude Code** — run both, in this order, once. Restart the session afterwards; skills load at session start:

```
/plugin marketplace add ioannisa/KSafe    # register this repo as a plugin source
/plugin install ksafe@ksafe               # install the skill from it
```

**Any other agent** — one command, then pick your agents from its prompt:

```bash
npx skills add ioannisa/KSafe
```

Forcing an update, installing without any tooling, and why you should not *also* hand-copy `SKILL.md`: **[docs/AI_AGENTS.md](docs/AI_AGENTS.md)**.

## Demo & Videos

KSafe in action across many scenarios: **[KSafeDemo — Compose Multiplatform app](https://github.com/ioannisa/KSafeDemo)**.

| Author's Video | Philipp Lackner's Video | Jimmy Plazas's Video |
|:--------------:|:---------------:|:---------------:|
| [<img width="200" alt="image" src="https://github.com/user-attachments/assets/8c317a36-4baa-491e-8c88-4c44b8545bad" />](https://youtu.be/mFKGx0DMZEA) | [<img width="200" alt="image" src="https://github.com/user-attachments/assets/59cce32b-634e-4b17-bb5f-5e084dff899f" />](https://youtu.be/cLyxWGV6GKg) | [<img width="200" alt="image" src="https://github.com/user-attachments/assets/65dba780-9c80-470c-9ad0-927a86510a26" />](https://youtu.be/M4U06OnAl-I) |
| [KSafe - Kotlin Multiplatform Encrypted DataStore Persistence Library](https://youtu.be/mFKGx0DMZEA) | [How to Encrypt Local Preferences In KMP With KSafe](https://youtu.be/cLyxWGV6GKg) | [Encripta datos localmente en Kotlin Multiplatform con KSafe - Ejemplo + Arquitectura](https://youtu.be/M4U06OnAl-I) |

***

## Setup

### 1 - Add the Dependency

```kotlin
// commonMain or Android-only build.gradle(.kts)
implementation("eu.anifantakis:ksafe:3.2.0")
implementation("eu.anifantakis:ksafe-compose:3.2.0")     // ← Compose state (optional)
implementation("eu.anifantakis:ksafe-biometrics:3.2.0")  // ← Biometric auth (optional)
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

Multi-instance setups, web `awaitCacheReady()`, custom storage directories, key namespacing for Desktop/Web (`appNamespace`), and AES key-size configuration: **[docs/SETUP.md](docs/SETUP.md)**.

> **Compose Desktop release builds:** add `modules("jdk.unsupported", "java.management")` to `nativeDistributions` for OS-backed key custody — why, and what happens without it: [docs/JVM_PROTECTION.md](docs/JVM_PROTECTION.md#compose-desktop-release-distributables-jdkunsupported).

---

## 🟢 Basic Usage 🟢

There are two ways to reach your data, and they share the same store and the same hot cache, so you can mix them freely. Full reference (Compose `policy`, cross-screen sync, write modes, nullables, deletion, full ViewModel): **[docs/USAGE.md](docs/USAGE.md)**.

### A variable per stored key

You declare one variable per value. KSafe persists it, encrypts it, and keeps it in the hot cache, so reads and writes are synchronous and never suspend.

**Property delegation** — the key is the property name:

```kotlin
var counter by ksafe(0)
counter++
```

**Direct handle (3.2.0+)** — the same call without `by`. Keep the handle in a `val`, pass it around, read and write `.value`. The key must be given explicitly, because there is no property name to infer it from:

```kotlin
val counter = ksafe(0, key = "counter")   // KSafeReference<Int>
counter.value++
```

### Through the KSafe instance

No variable per key. You address any key, at any time, straight on the instance. Each operation comes in two forms: a `suspend` one that waits for the disk flush, and a `Direct` one that returns at once, serves reads from the hot cache and flushes writes in the background (about 1000x faster for bulk work).

```kotlin
// Put
ksafe.put("profile", user)              // suspend — returns after the disk flush
ksafe.putDirect("counter", 42)          // non-suspend — background flush

// Get
val loaded: User = ksafe.get("profile", User())
val n = ksafe.getDirect("counter", 0)

// Delete
ksafe.delete("profile")
ksafe.deleteDirect("counter")

// Wipe the store — every value and the keys that protected them (logout)
ksafe.clearAll()                        // suspend
```

### Flows

Reactive reads that pick up changes made anywhere: another screen, a background sync, a delegate against the same key. Four shapes, and the same two doors as above — the property names the key, or you do:

| Shape | Type | Hot or cold | Writes | Scope | Same thing, key spelled out |
|---|---|---|---|---|---|
| `asFlow` | `Flow<T>` | cold | — | none | `getFlow(key, default)` |
| `asWritableFlow` | `WritableKSafeFlow<T>` | cold | `set(value)` | none | — |
| `asStateFlow` | `StateFlow<T>` | hot, `.value` | — | needed | `getStateFlow(key, default, scope)` |
| `asMutableStateFlow` | `MutableStateFlow<T>` | hot, `.value` | `.value =`, `update {}` | needed | — |

**Cold** — nothing runs until someone collects, so there is no scope to manage:

```kotlin
val toggleMode: Flow<Boolean> by ksafe.asFlow(defaultValue = false)

toggleMode.collect { on -> render(on) }
ksafe.putDirect("toggleMode", true)          // updated from anywhere — the collector above sees true

// Writable: one declaration you both collect and write through
val themeMode: WritableKSafeFlow<ThemeMode> by ksafe.asWritableFlow(ThemeMode.DEVICE)

themeMode.collect { mode -> applyTheme(mode) }
themeMode.set(ThemeMode.DARK)                // persists, and every collector sees it
```

**Hot** — a current value is always there, and that is what the scope pays for. Something has to sit on the store, watch for changes made elsewhere and push them in; that watcher is a coroutine, and it must die with your ViewModel:

```kotlin
val isLoggedIn: StateFlow<Boolean> by ksafe.asStateFlow(true, viewModelScope)

isLoggedIn.value                             // read it any time, with no collector at all
ksafe.putDirect("isLoggedIn", false)         // every collector sees false

// Writable: the _state / state pattern, persisted
private val _count by ksafe.asMutableStateFlow(0, viewModelScope)
val count = _count.asStateFlow()

_count.update { it + 1 }                     // persists
_count.value = 42                            // persists
```

**Without the delegate** — the same shapes and the same types, with the key spelled out. Note that a flow is always bound to one key: unlike `put` or `getDirect`, there is no flow over *any* key.

```kotlin
// Cold: call it inline, as often as you like — a cold Flow starts nothing on its own
ksafe.getFlow("isLoggedIn", defaultValue = true).collect { loggedIn -> render(loggedIn) }

// Hot: call it ONCE and keep the result — every call runs stateIn() and starts its own watcher
val isLoggedIn: StateFlow<Boolean> = ksafe.getStateFlow("isLoggedIn", true, viewModelScope)
```

> [!WARNING]
> **Call `getStateFlow` once and keep the result.** Every call runs `stateIn()` and launches its own
> watcher coroutine in the scope you pass, so calling it inline, in a loop, or inside a composable
> leaks one watcher per call until that scope is cancelled. The `by ksafe.asStateFlow(...)` delegate
> is safe by construction — it builds its `StateFlow` on first read and hands back the same instance
> forever after. `getFlow` is cold and costs nothing: call it as often as you like.

For the cold shapes the two forms are interchangeable — pick whichever reads better.

There is no writable shape without the delegate, and none is needed: to write, use `put` or `putDirect`, and every reader of that key sees it — a delegated flow in a ViewModel, a `getFlow` on another screen, a Compose state. One store, one cache.

### Compose

Persistent state inside a `@Composable` body. The `rememberSaveable` analogue that also survives app restarts; the key resolves to the property name and no ViewModel is needed. `KSafe` is `@Stable`, so it can be passed as a parameter without breaking skipping. The default mode here is `Plain`, because this is UI state, not a secret. Requires `ksafe-compose`.

```kotlin
@Composable
fun TabbedScreen(ksafe: KSafe) {
    var currentTab by ksafe.rememberKSafeState(Tab.Home)
    // ...
}
```

### State

Compose `MutableState` on a ViewModel or any class field. The UI recomposes on change, the value persists, and two screens holding the same key stay in sync. Requires `ksafe-compose`.

```kotlin
var username by ksafe.mutableStateOf("Guest")
```

### Helper classes (3.1.0+)

Every write above takes an optional `KSafeWriteMode`. The default is encrypted; you can step up or step down per entry:

```kotlin
var token by ksafe("")                                                            // encrypted, the default
var token by ksafe("", mode = KSafeWriteMode.Encrypted())                         // the same, spelled out
var pin   by ksafe("", mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)) // step up: StrongBox / Secure Enclave
var theme by ksafe("light", mode = KSafeWriteMode.Plain)                          // step down: no encryption
```

The helper classes freeze that mode at the type level, so no call site can forget it or pick the wrong one. They wrap an existing instance and offer every API shape above — `KSafePlain(ksafe)`, or the accessors `ksafe.plain`, `ksafe.encrypted`, `ksafe.hardwareIsolated`. With Koin:

```kotlin
val appModule = module {
    single<KSafe> { KSafe() }
    single { KSafePlain(get()) }              // every write plain
    single { KSafeEncrypted(get()) }          // every write encrypted
    single { KSafeHardwareIsolated(get()) }   // every write requests StrongBox / Secure Enclave
}

class PreferencesViewModel(
    private val prefs: KSafePlain,
    private val secrets: KSafeEncrypted,
    private val vault: KSafeHardwareIsolated,
) : ViewModel() {
    var counter by prefs(0)                   // delegate, plain
    var pin by vault("0000")                  // delegate, hardware-isolated

    fun save(token: String) = secrets.putDirect("token", token)   // instance API, encrypted
}
```

`KSafeWriteMode.Encrypted(requireUnlockedDevice = true)` additionally binds the key to the lock screen, so the value cannot be read while the device is locked. On Android 9 to 14 without a secure lock screen the key is minted without that binding, and `ksafe.protectionInfo.notes` says so: [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md#known-limitations).

### More in one line

**Complex objects** — mark them `@Serializable`; JSON and encryption are automatic:

```kotlin
@Serializable
data class AuthInfo(val accessToken: String = "", val refreshToken: String = "")

var authInfo by ksafe(AuthInfo())
authInfo = authInfo.copy(accessToken = "newToken")
```

**Nullable values** — `null` is stored as a real value. But a bare `null` default cannot tell Kotlin the type, so name it, on every read shape:

```kotlin
var token: String? by ksafe(null)                          // typed declaration
val token = ksafe.get<String?>("token", null)              // explicit type parameter
ksafe.getFlow<String?>("token", null).collect { … }        // same rule for flows
```

**Key rotation** — re-encrypt everything under fresh keys, on every platform:

```kotlin
val result = ksafe.rotateKeys()   // on demand: rotated / skipped / failed counts + new generation

// …or make it a policy and forget about it
val ksafe = KSafe(config = KSafeConfig(
    keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(90.days)  // rotates in the background at key age 90 days
))
```

Crash-safe and resumable: an interrupted rotation keeps everything readable and finishes on the next KSafe instance. Values never change, only key material does. Details: **[docs/KEY_ROTATION.md](docs/KEY_ROTATION.md)**.

**Encrypted database passphrase** — a stable, hardware-isolated 256-bit secret for SQLCipher / SQLDelight / Room:

```kotlin
val passphrase = ksafe.getOrCreateSecret("main.db")  // generated once, same value on every call after
```

It refuses to overwrite a secret it cannot read back, so it can never silently orphan your database, and key rotation preserves its value. Sizes, protection tiers, full Room + SQLCipher examples: **[docs/SECURITY_MODEL.md#cryptographic-utilities](docs/SECURITY_MODEL.md#cryptographic-utilities)**.

**Biometric gate** — one call raises the platform's own prompt (Face ID, Touch ID, fingerprint, Windows Hello, passkey) from shared code. Requires `ksafe-biometrics`:

```kotlin
if (KSafeBiometrics.verifyBiometric("Unlock your wallet")) showSecrets()
```

Pass `authorizationDuration = BiometricAuthorizationDuration(duration = 60_000L, scope = "payments")` to keep the next minute prompt-free in that scope. Details: **[docs/BIOMETRICS.md](docs/BIOMETRICS.md)**.

**What protection did I actually get** — per store and per key, at runtime:

```kotlin
ksafe.protectionInfo.effectiveLevel           // the tier the store really runs at
ksafe.protectionInfo.isEncryptionOperational  // will encrypted reads and writes succeed right now?
ksafe.getKeyInfo("pin")?.level                // where this one key's material landed
```

Read it off the main thread on Android. Details: **[docs/PROTECTION_INFO.md](docs/PROTECTION_INFO.md)**.

> **Note:** The property delegate and the direct handle work with **any** KSafe instance — `var x by myKsafe(default)` makes `myKsafe` the storage backend. The bare `ksafe(default)` form requires an in-scope `ksafe` (the conventional name, typically your default instance). See [docs/SETUP.md](docs/SETUP.md#multiple-instances) for the multi-instance pattern.

***

## Documentation

Everything else lives in [docs/](docs/). **New here? Start with [USAGE](docs/USAGE.md) and [SETUP](docs/SETUP.md).**

| Topic | What's inside |
|-------|---------------|
| [Complete Usage Guide](docs/USAGE.md) | Every API shape: delegates, flows, Compose state, write modes, mode-typed views, nullables, full ViewModel |
| [Setup](docs/SETUP.md) | Koin per platform, multi-instance, web `awaitCacheReady()`, custom storage directory, `appNamespace` |
| [Custom JSON Serialization](docs/SERIALIZATION.md) | `KSerializer`s for `UUID`, `Instant`, and other third-party types |
| [Biometric Authentication](docs/BIOMETRICS.md) | Face ID / Touch ID / Fingerprint / Windows Hello / WebAuthn — gate any action, auth caching, scoped sessions |
| [Security Model](docs/SECURITY_MODEL.md) | Runtime security policy (root/debugger/emulator), encryption internals, threat model, crypto utilities (`getOrCreateSecret`, `secureRandomBytes`) |
| [Key Rotation](docs/KEY_ROTATION.md) | `rotateKeys()` and the `MaxAge` policy: crash-safe, resumable, compliance notes |
| [Protection Info](docs/PROTECTION_INFO.md) | `KSafe.protectionInfo` diagnostics: effective key custody, `isEncryptionOperational`, gating patterns |
| [JVM Key Protection](docs/JVM_PROTECTION.md) | Windows DPAPI / macOS Keychain / Linux Secret Service, software fallback, `jdk.unsupported` |
| [Memory Policy](docs/MEMORY.md) | RAM-exposure trade-offs: `LAZY_PLAIN_TEXT`, `PLAIN_TEXT`, `ENCRYPTED`, `ENCRYPTED_WITH_TIMED_CACHE` |
| [Encryption Proof](docs/ENCRYPTION_PROOF.md) | Automated proof tests + commands to inspect the raw stored bytes yourself |
| [Performance Benchmarks](docs/BENCHMARKS.md) | Full tables, cold-start numbers, methodology |
| [Alternatives & Comparison](docs/COMPARISON.md) | KSafe vs SharedPrefs, DataStore, multiplatform-settings, KVault, SQLCipher |
| [Architecture](docs/ARCHITECTURE.md) | The conceptual model: modules, rings, hot cache + write coalescer |
| [Source-tree Tour](docs/TOUR.md) | File-by-file walkthrough of `:ksafe` |
| [Testing](docs/TESTING.md) | Running tests, iOS test app |
| [Migration Guide](docs/MIGRATION.md) | Upgrading from older KSafe versions |
| [Skill for AI Agents](docs/AI_AGENTS.md) | Installing the KSafe skill in Claude Code and other agents, updating it, common pitfalls |

**Compatibility:** Android API 24+ · iOS 13+ · macOS 11+ (`macosArm64`/`macosX64`) · JDK 11+ · WasmGC browsers · Kotlin/JS. Kotlin 2.0+.

***

## Community

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening issues or pull requests, and follow the [Code of Conduct](CODE_OF_CONDUCT.md). Release notes live in [CHANGELOG.md](CHANGELOG.md).

Security-sensitive bug reports should follow [SECURITY.md](SECURITY.md), not public GitHub issues.

***

## Licence

Licensed under the Apache License 2.0 — see http://www.apache.org/licenses/LICENSE-2.0. Distributed "AS IS", without warranties of any kind.
