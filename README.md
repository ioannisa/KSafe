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

KSafe ships an [agentskills.io](https://agentskills.io)-compatible skill — [**skills/ksafe/SKILL.md**](skills/ksafe/SKILL.md) — that teaches any AI agent (Claude Code, Codex, Gemini CLI, Copilot CLI, Junie) KSafe's patterns, anti-patterns, and gotchas. Restart your agent session after installing — skills load at session start.

### Claude Code (recommended)
> installs once, updates itself

Run **both** commands, in this order, inside any Claude Code session. It's a one-time setup:

```
/plugin marketplace add ioannisa/KSafe    # 1. register this repo as a plugin source
/plugin install ksafe@ksafe               # 2. install the ksafe skill from it
```

The first command only tells Claude Code where the plugin lives — it installs nothing by
itself. The second does the actual install (the format is `<plugin>@<marketplace>`; both
happen to be named `ksafe` here). Restart the session and the skill is active.

From then on updates are handled for you — but on Claude Code's own schedule, not at the
moment we publish. If you want the newest skill *now* (say, right after a KSafe release),
force it; see below.

<details>
<summary><b>Forcing an update — and why one command isn't always enough</b></summary>

An installed plugin is pinned to a specific commit of this repo, and Claude Code keeps its
own clone of the repo separately. So there are **two** things that can be out of date, and
refreshing only the second one silently does nothing:

| Layer | What it is | Refreshed by |
|---|---|---|
| **Marketplace** | Claude Code's clone of this repo | `marketplace update` |
| **Plugin** | the commit your session actually loads | `update` |

Run them **in this order** — the plugin can only move to a commit the marketplace has
already fetched:

```
/plugin marketplace update ksafe    # 1. fetch the newest commits of this repo
/plugin update ksafe@ksafe          # 2. re-pin the plugin to the newest one
```

Same thing from a terminal, outside any session:

```bash
claude plugin marketplace update ksafe
claude plugin update ksafe@ksafe
```

**Restart the session afterwards** — a running session keeps the skill it loaded at start.

Check what you're actually on at any time:

```bash
claude plugin list
```

The `Version:` shown for `ksafe@ksafe` is the commit hash this repo was at when the plugin
was pinned. If step 2 reports *"already at the latest version"* but you expected something
newer, step 1 hasn't picked up the commit yet — the release may not be pushed, or the
marketplace fetch failed.

</details>

> **Don't also copy `SKILL.md` into `~/.claude/skills/ksafe/`.** That directory holds
> manually-installed skills, which never update and are addressed by the bare name `ksafe`
> — while the plugin is addressed as `ksafe:ksafe`. Keeping both means asking for "the
> ksafe skill" loads the stale hand-copied one. Pick the plugin *or* the plain copy below,
> never both.

### Other agents
> (Codex, Gemini CLI, Copilot, Cursor, Junie, …)
> pick ONE of the two options below

**Option A — the [skills.sh](https://skills.sh) CLI (recommended):** one command installs the
skill into whichever of your agents you select in its prompt (30+ supported):

```bash
npx skills add ioannisa/KSafe
```

There is no auto-update for these agents — re-run the same command whenever you want the
latest skill (e.g. after a KSafe release).

**Option B — plain copy, no tooling:** fetch the file straight into each agent's skills
directory. Edit the agent list to match what you actually use:

```bash
for agent in codex gemini copilot junie; do
  mkdir -p "$HOME/.$agent/skills/ksafe" && \
    curl -fsSL https://raw.githubusercontent.com/ioannisa/KSafe/main/skills/ksafe/SKILL.md \
    > "$HOME/.$agent/skills/ksafe/SKILL.md"
done
```

Re-run it to refresh (again: no auto-update). If you've already cloned this repo,
`cp -r skills/ksafe "$HOME/.<agent>/skills/"` does the same thing offline. Add `claude` to
the list only if you prefer a plain skill over the plugin from the section above — for the
reason why the two don't mix, see the warning at the end of that section.

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
```

### Flows

Reactive reads that pick up changes made anywhere: another screen, a background sync, a delegate against the same key. Four shapes, two read-only and two writable:

| Delegate | Type | Reads | Writes | Scope |
|---|---|---|---|---|
| `asFlow` | `Flow<T>` | cold | no | none |
| `asStateFlow` | `StateFlow<T>` | hot, `.value` | no | needed |
| `asMutableStateFlow` | `MutableStateFlow<T>` | hot, `.value` | `.value = …` persists | needed |
| `asWritableFlow` | `WritableKSafeFlow<T>` | cold | `set(value)` persists | none |

```kotlin
// Observe here, update anywhere: the instance API feeds the flow
val isLoggedIn: StateFlow<Boolean> by ksafe.asStateFlow(true, viewModelScope)
ksafe.putDirect("isLoggedIn", false)                 // every collector sees false

val toggleMode: Flow<Boolean> by ksafe.asFlow(defaultValue = false)   // cold, read-only

// The _state / state pattern, persisted
private val _state by ksafe.asMutableStateFlow(MoviesState(), viewModelScope)
val state = _state.asStateFlow()
```

**WritableFlow** — a writable cold `Flow<T>` with no scope to manage. Collect it like any flow; call `set()` to write. The natural fit for a setting that a screen both shows and edits:

```kotlin
val themeMode: WritableKSafeFlow<ThemeMode> by ksafe.asWritableFlow(ThemeMode.DEVICE)

themeMode.collect { mode -> applyTheme(mode) }   // reacts to every change, from anywhere
themeMode.set(ThemeMode.DARK)                    // persists, and every collector sees it
```

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

The helper classes freeze that mode at the type level, so no call site can forget it or pick the wrong one. They wrap an existing instance and offer every API shape above. With Koin:

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

**Compatibility:** Android API 24+ · iOS 13+ · macOS 11+ (`macosArm64`/`macosX64`) · JDK 11+ · WasmGC browsers · Kotlin/JS. Kotlin 2.0+.

***

## Community

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening issues or pull requests, and follow the [Code of Conduct](CODE_OF_CONDUCT.md). Release notes live in [CHANGELOG.md](CHANGELOG.md).

Security-sensitive bug reports should follow [SECURITY.md](SECURITY.md), not public GitHub issues.

***

## Licence

Licensed under the Apache License 2.0 — see http://www.apache.org/licenses/LICENSE-2.0. Distributed "AS IS", without warranties of any kind.
