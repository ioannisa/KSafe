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

Read and write it like any normal Kotlin variable — no `suspend`, no `runBlocking`, no DataStore boilerplate, no explicit `encrypt`/`decrypt`. Reads hit a hot in-memory cache (~0.002 ms under plaintext policies; `ENCRYPTED` entries run a decrypt on every access — a keystore round-trip on hardware-backed paths — and the very first read after cold start briefly blocks to warm the cache); writes encrypt and flush in the background — **synchronous, but never blocking**. Reach for the `suspend` API (`get` / `put`) only when *you* want to await the disk flush.

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

## Table of Contents

- [What is KSafe?](#what-is-ksafe)
- [🤖 KSafe Skill for AI agents](#-ksafe-skill-for-ai-agents) — [skills/ksafe/SKILL.md](skills/ksafe/SKILL.md)
- [Setup](#setup)
- [Basic Usage](#basic-usage) — full reference in [docs/USAGE.md](docs/USAGE.md)
- [Custom JSON Serialization](#custom-json-serialization) — full guide in [docs/SERIALIZATION.md](docs/SERIALIZATION.md)
- [Isolating an app's keys (Desktop / Web)](#isolating-an-apps-keys-desktop--web) — [docs/SETUP.md](docs/SETUP.md)
- [Compose Desktop release builds](#compose-desktop-release-builds--strongly-recommend-modulesjdkunsupported) — [docs/JVM_PROTECTION.md](docs/JVM_PROTECTION.md)
- [Cryptographic Utilities](#cryptographic-utilities) — full reference in [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)
- [Key Rotation](#key-rotation) — full reference in [docs/KEY_ROTATION.md](docs/KEY_ROTATION.md)
- [Why use KSafe?](#why-use-ksafe)
- [How KSafe Compares](#how-ksafe-compares)
- [Performance Benchmarks](#performance-benchmarks)
- [Compatibility](#compatibility)
- [Biometric Authentication](#biometric-authentication)
- [Runtime Security Policy](#runtime-security-policy)
- [Key Protection Diagnostics](#key-protection-diagnostics) — [docs/PROTECTION_INFO.md](docs/PROTECTION_INFO.md)
- [Memory Security Policy](#memory-security-policy)
- [Deep-Dive Documentation](#deep-dive-documentation)
- [Community](#community)

***

## Setup

[![Maven Central](https://img.shields.io/maven-central/v/eu.anifantakis/ksafe.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/eu.anifantakis/ksafe)

### 1 - Add the Dependency

```kotlin
// commonMain or Android-only build.gradle(.kts)
implementation("eu.anifantakis:ksafe:3.1.0")
implementation("eu.anifantakis:ksafe-compose:3.1.0")     // ← Compose state (optional)
implementation("eu.anifantakis:ksafe-biometrics:3.1.0")  // ← Biometric auth (optional)
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

AES-GCM is intentionally fixed so callers cannot select an unsafe mode. Its key strength is
typed and consistent across every platform:

```kotlin
val ksafe128 = KSafe(
    config = KSafeConfig(aesKeySize = KSafeAesKeySize.BITS_128)
)
// Default: KSafeAesKeySize.BITS_256
```

The setting applies when KSafe creates a key. Existing stores keep their current key size until
`rotateKeys()` mints a new generation.

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
// 1. Property delegate — synchronous, non-suspending, encrypted, persisted
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

// 3.1.0+: or freeze the mode at the TYPE level — no mode parameter exists to forget
val prefs = KSafePlain(ksafe)            // every write plain
val vault = KSafeHardwareIsolated(ksafe) // every write requests StrongBox / Secure Enclave
var theme2 by prefs("light")
vault.put("pin", pin)
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

On **JVM/Desktop** the OS secret store is per-OS-user and shared by every process, and on **Web** IndexedDB/localStorage is shared per browser origin — so two apps using the same `fileName` could collide. Set a stable, app-unique namespace (`KSafeConfig(appNamespace = "com.example.myapp")`); Android/iOS are already OS-sandboxed per app. On JVM an explicit `appNamespace` isolates both the DataStore data directory (the file moves into a namespace subdirectory) and the key-store destination; existing un-namespaced KSafe ≤ 2.0 data is copied forward, not stranded (the `-Dksafe.appNamespace` / env override namespaces only the key store). Details: **[docs/SETUP.md](docs/SETUP.md)**.

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

Sizes, protection tiers, Room + SQLCipher / SQLDelight examples: **[docs/SECURITY_MODEL.md#cryptographic-utilities](docs/SECURITY_MODEL.md#cryptographic-utilities)**.

***

## Key Rotation

Re-encrypt everything under fresh keys — one line, on every platform (3.0.0+):

```kotlin
val result = ksafe.rotateKeys()   // rotated / skipped / failed counts + new generation
```

Or make it a policy and forget about it:

```kotlin
val ksafe = KSafe(config = KSafeConfig(
    keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(90.days), // rotate in the background when the key turns 90 days old
    keyRotationRetryAttempts = 3, // default; 0 disables next-instance retries
))
```

Crash-safe and resumable by design: every entry records which key generation decrypts it. From
3.1.0, a generation bump also carries a durable lifecycle state (`r:1` while active, `r:0`
after completion), so an interrupted rotation leaves a store where **everything stays
readable** and the next KSafe instance automatically resumes that same generation — even with
the default `Never` policy. A 3.0.0 record has no `r` field; the first 3.1.0 startup safely
stamps it `r:0` and does no rotation work in that launch rather than guessing that a released
store crashed. Concurrent writes always win; superseded keys are deleted only when nothing
references them. Values — including `getOrCreateSecret` passphrases — never change; only the
key material and envelopes do.

Automatic crash recovery remains distinct from a normal retry. A pass that returns normally
writes `r:0`; when it reports retryable `skipped` entries it also persists `rp:N`, the number
of automatic next-instance attempts still available (3 by default). The current instance
starts no timer and does not try again in the same app run. Each **new KSafe instance** consumes
at most one attempt and retries the same generation immediately, even under `Never`. The claim
is durable and decrement-first: `r:0,rp:N -> r:1,rp:N-1`, so a crash cannot refill the budget;
`r:1,rp:0` still resumes the last claimed attempt after a crash but cannot schedule another
one. Set `keyRotationRetryAttempts = 0` to disable this automatic retry path. If `MaxAge` is
already due, its fresh rotation takes precedence. `failed` alone never arms the budget: it
denotes a definitive problem that needs investigation.

Rotation also hardens the encryption itself: once rotated, encrypted entries **can't be copied, swapped, or relocated between keys** — tampering that relocates, swaps, or re-tiers an *encrypted* entry breaks its GCM tag, so the read **fails closed to the caller's default** rather than decrypting in the wrong context (the one boundary: rewriting an entry's metadata to *plaintext* reclassifies it, so the read returns the stored bytes verbatim — undecipherable ciphertext, never the underlying secret). A gen-1 (un-rotated) store keeps the exact pre-3.0.0 bytes, so this kicks in at the first `rotateKeys()`.

Semantics, compliance notes, and edge cases: **[docs/KEY_ROTATION.md](docs/KEY_ROTATION.md)**.

***

## Why use KSafe?

* **Hardware-backed security** — AES-256-GCM, keys in Android Keystore / Apple Keychain (iOS + macOS) / JVM OS secret store (Windows DPAPI · macOS Keychain · Linux libsecret, software fallback) / non-extractable WebCrypto key in IndexedDB. Per-property control via `KSafeWriteMode` + `KSafeEncryptedProtection` tiers
* **Biometric auth** — Face ID, Touch ID, Fingerprint, with auth caching
* **Key rotation** — `rotateKeys()` or a declarative `MaxAge` policy; crash-safe, resumable, zero data churn
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

> Measured on a **Samsung Galaxy S24 Ultra** (release build, measured on KSafe 2.1.2; figures current for 3.0.0 — un-rotated generation-1 stores use the same crypto path; 500 iterations). 2.1.2 adds an Android software-DEK fast path: the per-datastore master key stays non-exportable in the TEE and wraps a data-encryption key that is unwrapped once into memory, so per-value AES-GCM runs in userspace — `ENCRYPTED`-memory decrypt-every-read dropped from ~8 ms to ~0.014 ms on real hardware. Suspend-API benchmarks issue all iterations as concurrent coroutines (`GlobalScope.launch` + `joinAll`). Real-world numbers depend on device, workload, and data size — see [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for methodology, full tables, cold-start numbers, and architecture notes.

## Compatibility

| Platform | Minimum Version | Notes |
|----------|-----------------|-------|
| **Android** | API 24 (Android 7.0) | Hardware-backed Keystore on supported devices |
| **iOS** | iOS 13+ | Keychain-backed symmetric keys (protected by device passcode); Secure Enclave on real devices. Entitlement-less Simulators transparently fall back to a sandbox file store (reported `SOFTWARE`); real devices unaffected |
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

A standalone biometric helper (Android + iOS + macOS — and, since 2.2.1, JVM Desktop and web: Touch ID on macOS, Windows Hello on Windows, WebAuthn in the browser) that can gate **any action** in your app — not just KSafe ops. Ships as the optional `:ksafe-biometrics` artifact and depends on nothing else from KSafe, so apps that need only biometric verification can use it on its own.

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

Check availability up front with `KSafeBiometrics.biometricsAvailable()` (2.2.1+) and fall back to your own flow where no real prompt exists. Auth caching, scoped sessions, platform setup, complete examples: [docs/BIOMETRICS.md](docs/BIOMETRICS.md).

> **Migrating from KSafe ≤1.x?** Biometric methods used to live on `KSafe` itself. In 2.0 they moved to a separate module. Add `implementation("eu.anifantakis:ksafe-biometrics:3.0.0")`, change `import eu.anifantakis.lib.ksafe.BiometricAuthorizationDuration` → `import eu.anifantakis.lib.ksafe.biometrics.BiometricAuthorizationDuration`, replace `ksafe.verifyBiometric(...)` with `KSafeBiometrics.verifyBiometric(...)`. Method names and signatures are unchanged. No instance to construct, no DI wiring needed.

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

Preset policies, BLOCK exception handling, Compose stability, detection methods: [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

***

## Key Protection Diagnostics

Find out what key custody this `KSafe` instance **actually** got — including any silent fallback (e.g. JVM dropping from `SANDBOX_PROTECTED` to `SOFTWARE` when no OS vault is reachable):

```kotlin
val info = ksafe.protectionInfo
// info.intendedLevel          = SANDBOX_PROTECTED           // engine baseline
// info.effectiveLevel         = SOFTWARE                    // vault self-test failed
// info.custody                = "DataStore (software, ...)" // human-readable
// info.notes                  = ["jvm_os_vault_unavailable"]// stable code
// info.isEncryptionOperational = true                       // encryption still works
```

There are two independent gates, and they answer different questions:

```kotlin
// 1. Will encrypted writes actually succeed at all? (works even on weaker fallbacks)
if (!info.isEncryptionOperational) blockLoginUntilServedOverHttps()

// 2. Is the key custody strong enough for this feature?
check(info.effectiveLevel >= KSafeProtectionLevel.SANDBOX_PROTECTED)
```

`isEncryptionOperational` (3.0.0) is `true` wherever encryption works — including the weaker-but-working JVM-software and iOS-Simulator fallbacks — and `false` only when an encrypted write genuinely can't run: a web page served outside a secure context (no `crypto.subtle`), or a JVM whose OS vault exists but is unreachable at startup. `effectiveLevel` is a separate question about *strength*: `KSafeProtectionLevel` is a universally-ordered scale — `SOFTWARE < SANDBOX_PROTECTED < HARDWARE_BACKED < HARDWARE_ISOLATED`, one ordinal comparison across every platform.

Per-platform truth table, runtime-decision patterns (gating, tighter re-auth windows, feature disablement, UX honesty banners, intended-vs-effective delta), and all defined `notes` codes: **[docs/PROTECTION_INFO.md](docs/PROTECTION_INFO.md)**.

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
| `PLAIN_TEXT` (discouraged) | Apps that want every value plaintext-resident and O(1) from the very first read (no per-key first-read decrypt latency) | Plaintext (forever, eagerly decrypted at cold start) | O(1) lookup | Low — all data exposed in memory; cold start pays $O(n)$ Keystore round-trips up front |
| `ENCRYPTED` | Tokens, passwords, financial data | Ciphertext only | AES-GCM decrypt every read | High — nothing plaintext in RAM at rest |
| `ENCRYPTED_WITH_TIMED_CACHE` | Compose/SwiftUI screens accessing the same encrypted value many times per frame | Ciphertext + short-lived plaintext (TTL) | First read of a window decrypts, then O(1) for TTL | Medium — plaintext only for recently-accessed keys, reusable only for seconds (the cached copy is ignored, not proactively wiped, after the TTL) |

Timed cache details, constructor params, lock-state policies, multi-instance lock policies: [docs/MEMORY.md](docs/MEMORY.md).

***

## Deep-Dive Documentation

Internals, advanced features, reference material. **New here? Start with [USAGE](docs/USAGE.md) and [SETUP](docs/SETUP.md).**

**Getting started**

| Topic | Description |
|-------|-------------|
| [Complete Usage Guide](docs/USAGE.md) | Every API shape: delegates, flow delegates, Compose state, suspend/direct APIs, write modes, nullables, full ViewModel |
| [Setup with Koin](docs/SETUP.md) | Multi-instance setups (prefs vs vault), web `awaitCacheReady()` (wasmJs + js), full platform examples, custom storage directory (`baseDir` / `directory`) |
| [Custom JSON Serialization](docs/SERIALIZATION.md) | Registering `KSerializer`s for `UUID`, `Instant`, and other third-party types |
| [Biometric Authentication](docs/BIOMETRICS.md) | Authorization caching, scoped sessions, platform setup, complete examples |
| [KSafe Skill for AI agents](skills/ksafe/SKILL.md) | Self-contained skill teaching any agentskills.io-compatible agent (Claude Code, Codex, Gemini CLI, Copilot CLI, Junie, …) the patterns, anti-patterns, and gotchas for KSafe. Install instructions near the top of this README. |

**Security & keys**

| Topic | Description |
|-------|-------------|
| [Security Model](docs/SECURITY_MODEL.md) | Runtime security policy, encryption internals, threat model, hardware isolation, key storage queries, crypto utilities |
| [Key Rotation](docs/KEY_ROTATION.md) | `rotateKeys()` and the `MaxAge` policy: resumable mixed-generation design, concurrency guarantees, compliance notes, observability, edge cases |
| [Protection Info](docs/PROTECTION_INFO.md) | Instance-level diagnostic API: `KSafe.protectionInfo`, `isEncryptionOperational`, the cross-platform `KSafeProtectionLevel` scale, per-platform truth table, consumer gating / telemetry / UI patterns |
| [JVM Key Protection](docs/JVM_PROTECTION.md) | Deep dive on how the AES key is held on each JVM host: Windows DPAPI, macOS login Keychain, Linux Secret Service (libsecret), the software fallback, the opt-out, and the per-app namespace |
| [Memory Policy](docs/MEMORY.md) | Timed cache, constructor parameters, encryption config, device lock-state policies |
| [Encryption Proof](docs/ENCRYPTION_PROOF.md) | Per-platform automated proof tests + manual commands to inspect the raw stored bytes and see the ciphertext yourself |

**Reference & internals**

| Topic | Description |
|-------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | The conceptual model: three modules, three rings (public API / `KSafeCore` orchestrator / platform shells), hot cache + write coalescer, the `KSafePlatformStorage` and `KSafeEncryption` interfaces, memory policies, and how 2.0 consolidated ~5,900 lines of duplicated platform logic into ~890 |
| [Source-tree tour](docs/TOUR.md) | File-by-file walkthrough of every Kotlin source file in `:ksafe`: where each behaviour lives and why. Companion to the Architecture doc — Architecture is "the model," TOUR is "the map." |
| [Performance Benchmarks](docs/BENCHMARKS.md) | Full benchmark tables, cold start numbers, architecture deep-dive |
| [Testing](docs/TESTING.md) | Running tests, building iOS test app, test features |
| [Migration Guide](docs/MIGRATION.md) | Upgrading from v1.x → v2.0 (biometric module extraction, iOS path migration), v1.6.x → v1.7.0 (`encrypted: Boolean` → `KSafeWriteMode`), and v1.1.x → v1.2.0+ |
| [Alternatives & Comparison](docs/COMPARISON.md) | KSafe vs EncryptedSharedPrefs, KVault, SQLCipher, and more |

***

## Community

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening issues or pull requests, and follow the [Code of Conduct](CODE_OF_CONDUCT.md). Release notes live in [CHANGELOG.md](CHANGELOG.md).

Security-sensitive bug reports should follow [SECURITY.md](SECURITY.md), not public GitHub issues.

***

## Licence

Licensed under the Apache License 2.0 — see http://www.apache.org/licenses/LICENSE-2.0. Distributed "AS IS", without warranties of any kind.
