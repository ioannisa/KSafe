---
name: ksafe
description: |
  KSafe — Kotlin Multiplatform encrypted persistence library. Use this skill whenever
  working with persisted preferences, tokens, secrets, encrypted DataStore, or secure
  storage in a Kotlin Multiplatform project (Android, iOS, native macOS, JVM Desktop,
  WasmJS, or Kotlin/JS browsers). Also use for biometric-gated state via the
  :ksafe-biometrics companion module, Compose state that persists across recompositions
  or process death via :ksafe-compose, packaging Compose Desktop release distributables
  that contain KSafe, or migrating to KSafe from EncryptedSharedPreferences /
  DataStore Preferences / KVault / Multiplatform Settings / MMKV.
  Trigger phrases: "KSafe", "ksafe", "by ksafe(", "ksafe.put", "ksafe.get",
  "persist a token", "encrypted preferences", "encrypted DataStore", "secure
  preferences on KMP", "Android Keystore", "Apple Keychain", "Secure Enclave",
  "StrongBox", "DPAPI", "libsecret", "Secret Service", "biometric prompt for
  storage", "BiometricPrompt", "Face ID for storage", "Touch ID for storage",
  "mutableStateOf" with "persist", "KSafe.protectionInfo", "KSafeProtection",
  "KSafeWriteMode", "ksafe-biometrics", "ksafe-compose", "jdk.unsupported"
  in the context of Compose Desktop.
---

# KSafe — Kotlin Multiplatform Encrypted Persistence

You are about to write or modify code that uses **KSafe**: a one-API encrypted key-value
store covering Android, iOS, native macOS, JVM Desktop, Kotlin/WasmJS, and Kotlin/JS.
AES-256-GCM throughout. The AES key always lives in the platform's strongest secure store
(see the matrix below). The on-disk file holds only ciphertext.

This skill teaches you the patterns that work, the patterns that **don't** but look
plausible, and where to escalate to deeper docs when needed. Always prefer the
**property delegate** as the default API.

---

## Key-custody matrix (this is what makes KSafe interesting)

| Platform | Where the AES key lives | How it's hardened | "HARDWARE_ISOLATED" upgrade |
|---|---|---|---|
| Android | Android Keystore | TEE | StrongBox (per-write) |
| iOS / native macOS | Apple Keychain | Per-app sandbox; SEP-gated on modern hardware | Secure Enclave (per-write) |
| JVM Desktop | Windows DPAPI / macOS login Keychain / Linux Secret Service | Bound to OS user login | n/a |
| WasmJS / JS | IndexedDB | Non-extractable WebCrypto `CryptoKey` | n/a |

When a stronger tier isn't available (no StrongBox / no Secure Enclave / headless Linux
without a keyring), KSafe **degrades silently to the next-best path and reports the
degrade** through `KSafe.protectionInfo`. Never silent data loss.

---

## The 80% case — use the property delegate

**KSafe is encrypted by default.** The bare `ksafe(value)` form encrypts and lands the
key in OS-protected custody. You opt *out* with `mode = KSafeWriteMode.Plain` for
non-secret values. The default value is the **first positional argument** (there is no
`default =` or `encrypted =` named parameter — `encrypted` is a deprecated legacy param,
do not generate it).

```kotlin
class AuthViewModel(private val ksafe: KSafe) : ViewModel() {
    // Encrypted by default — key lands in OS-protected custody.
    var authToken by ksafe("")

    // Opt OUT of encryption for non-secret values with mode = Plain.
    var userId by ksafe(0L, mode = KSafeWriteMode.Plain)

    // Any @Serializable type works (encrypted by default).
    var lastSync by ksafe(Instant.EPOCH)
    var session by ksafe(Session())

    // Custom storage key (defaults to the property name otherwise).
    var theme by ksafe(ThemeMode.DEVICE, key = "theme", mode = KSafeWriteMode.Plain)
}
```

What you get for free:
- **Synchronous reads** from an in-memory hot cache (~µs).
- **Coalesced writes** on a background coroutine — never blocks the caller; multiple
  writes within a 16ms window land in one transaction.
- **Reactivity** — observe the same keys as Flows. Two styles, pick either:
  - Delegate (`defaultValue` first, optional `key`):
    `val themeFlow: Flow<String> by ksafe.asFlow("light")` /
    `val theme: StateFlow<String> by ksafe.asStateFlow("light", viewModelScope)`.
  - Direct call: `ksafe.getFlow(key, defaultValue).collect { … }`.
- **Multi-instance support** — the delegate works on any `KSafe` instance, not only a
  "default" one. `var x by myKsafe(value)` makes `myKsafe` the backing store.

---

## Construction

```kotlin
// Android — requires applicationContext (NOT Activity context)
val ksafe = KSafe(applicationContext)

// iOS / macOS / JVM / WasmJS / JS — no context needed
val ksafe = KSafe()
val ksafe = KSafe(fileName = "auth")   // isolated named instance
```

Production-grade construction (Koin example):

```kotlin
// commonMain
expect val platformModule: Module

// androidMain
actual val platformModule = module {
    single { KSafe(androidApplication()) }
}

// iosMain / jvmMain / wasmJsMain / jsMain
actual val platformModule = module {
    single { KSafe() }
}
```

[`docs/SETUP.md`](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/SETUP.md) covers
multi-instance setups, web `awaitCacheReady()`, custom storage directories (`baseDir`
on JVM/Android, `directory` on iOS/macOS), and `KSafe.close()`.

---

## Compose state that persists

```kotlin
// Add `eu.anifantakis:ksafe-compose:<latest>` to your dependencies.
// Like the core delegate, ksafe.mutableStateOf is ENCRYPTED BY DEFAULT.

class CounterViewModel(private val ksafe: KSafe) : ViewModel() {
    // Class-field state: created once, lives for the ViewModel's lifetime.
    // Survives process death, recomposition, and configuration change.
    // Encrypted by default — opt out with mode = KSafeWriteMode.Plain.
    var counter by ksafe.mutableStateOf(0, mode = KSafeWriteMode.Plain)

    // Encrypted (the default) — a secret PIN.
    var pin by ksafe.mutableStateOf("")
}

// In a composable BODY (no ViewModel) use rememberKSafeState — it's an
// EXTENSION on ksafe, default value is the first positional arg.
// (Using mutableStateOf directly in a composable body would re-create on
// every recomposition; rememberKSafeState is remember-scoped.)
@Composable
fun ThemeToggle(ksafe: KSafe) {
    var darkMode by ksafe.rememberKSafeState(false, key = "theme.dark", mode = KSafeWriteMode.Plain)
    Switch(checked = darkMode, onCheckedChange = { darkMode = it })
}
```

---

## Biometric-gated actions (separate module, static API)

The `:ksafe-biometrics` artifact is **independent of `:ksafe`** — call it directly for
any biometric prompt (storage or otherwise). No DI, no `Context`, no init.

```kotlin
// Callback variant — works from anywhere
KSafeBiometrics.verifyBiometricDirect("Unlock balance") { success ->
    if (success) showBalance()
}

// Suspend variant — cleaner async
viewModelScope.launch {
    if (KSafeBiometrics.verifyBiometric("Confirm transaction")) {
        proceed()
    }
}

// Avoid re-prompts within a window
KSafeBiometrics.verifyBiometric(
    reason = "Reauth",
    authorizationDuration = BiometricAuthorizationDuration(
        duration = 60_000L,        // ms
        scope = "MyViewModelScope" // optional: scoped-cache key for invalidation
    )
)

// Hard biometric-only (no PIN/password/Apple-Watch fallback)
KSafeBiometrics.verifyBiometric("Step-up auth", allowDeviceCredentialFallback = false)
```

Android auto-init via `ContentProvider` — no `Application` class changes needed. Requires
`AppCompatActivity`. Full reference: [`docs/BIOMETRICS.md`](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/BIOMETRICS.md).

---

## Diagnostics — `KSafe.protectionInfo` and `KSafe.VERSION`

```kotlin
val info = ksafe.protectionInfo

// Gate startup on the negotiated custody
check(info.effectiveLevel >= KSafeProtectionLevel.SANDBOX_PROTECTED) {
    "App requires sandbox-grade key protection; got ${info.custody}"
}

// Detect any silent fallback
check(info.effectiveLevel >= info.intendedLevel)

// Telemetry — every field is stable, low-cardinality
analytics.log(
    "ksafe_protection",
    "level"       to info.effectiveLevel.name,           // SOFTWARE | SANDBOX_PROTECTED | HARDWARE_BACKED | HARDWARE_ISOLATED
    "custody"     to info.custody,                       // human-readable, never parse
    "notes"       to info.notes.joinToString(","),       // stable lowercase_snake codes
    "ksafe_ver"   to info.kSafeVersion,                  // same as KSafe.VERSION
)
```

**Always check `protectionInfo` before assuming the OS vault is reachable** — especially
on JVM Desktop, where a release distributable's bundled JRE can drop the JDK modules JNA
needs (see below). From 2.1.1+ the property is recomputed per-access, so a runtime
degrade is visible without restarting the app.

For per-key audit (which custody did *this specific key* get?): `ksafe.getKeyInfo(key)`.
Returns `KSafeKeyInfo(protection, storage, level)`. Prefer `.level` — same scale as
`protectionInfo`.

---

## ⚠️ Compose Desktop release distributables — REQUIRED `modules()` lines

This is the single most common KSafe footgun on JVM Desktop. If your project uses
`compose.desktop` and ever runs `runReleaseDistributable` / `packageReleaseDistributable`,
add this:

```kotlin
compose.desktop {
    application {
        nativeDistributions {
            // jdk.unsupported  → JNA needs sun.misc.Unsafe for the OS keyvault path
            //                    (Keychain on macOS / DPAPI on Windows / Secret
            //                    Service on Linux). Without it: KSafe degrades to
            //                    the software vault at runtime (data still saved,
            //                    but no OS-level key protection).
            // java.management  → SecurityChecker.isDebuggerAttached() reads
            //                    java.lang.management.ManagementFactory. Required
            //                    only if you use KSafeSecurityPolicy.WarnOnly /
            //                    Strict / any policy enabling the debugger probe.
            //                    Default policy is IGNORE-everything → omit safely.
            modules("jdk.unsupported", "java.management")
            // …your other settings
        }
    }
}
```

Why: `jlink` builds a custom trimmed JRE that only includes modules it sees referenced
in user bytecode. KSafe's references go through JNA (native) and reflection, which
`jlink` can't statically detect. Dev runs (`./gradlew run`) use your full local JDK, so
they hide this problem — it only bites in release distributables.

Tip: `./gradlew :<your-app>:suggestRuntimeModules` will print the recommended module
list based on your dependency tree. Full background and tracking issue:
[`docs/JVM_PROTECTION.md`](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/JVM_PROTECTION.md)
and [#32](https://github.com/ioannisa/KSafe/issues/32).

---

## Multi-app desktop / web isolation — `appNamespace`

Android and iOS keystores are sandboxed per-app. **JVM Desktop OS secret stores are
per-OS-user (shared across processes)**, and **web IndexedDB is per-origin**. Two
different apps using the same `fileName` will collide on the same key. Always set:

```kotlin
val ksafe = KSafe(config = KSafeConfig(appNamespace = "com.example.myapp"))
```

The legacy ≤ 2.0 layout is not namespaced (it's the frozen migration source), so
namespacing never strands existing data.

---

## Web — `awaitCacheReady()`

WebCrypto is async-only. KSafe forces `KSafeMemoryPolicy.PLAIN_TEXT` internally on web
(decrypts the entire dataset into an in-memory plaintext cache at startup, so synchronous
`getDirect` calls work).

Call `awaitCacheReady()` **once at startup** before the first read of an encrypted key:

```kotlin
suspend fun appStart() {
    ksafe.awaitCacheReady()
    // …safe to call getDirect on encrypted keys
}
```

This is a no-op on Android/iOS/macOS/JVM — they don't need it.

---

## Write modes

The delegate / `mutableStateOf` / `put` all default to encrypted. Use `mode` for fine
control. **Note the enum name:** the `protection` parameter of `KSafeWriteMode.Encrypted`
is `KSafeEncryptedProtection` (write-side), NOT `KSafeProtection` (which is the read-side
detection enum returned by `getKeyInfo`). Using `KSafeProtection` here will not compile.

```kotlin
// Per-entry unlock policy (Apple) — entry inaccessible until first unlock since boot
ksafe.put("token", value, mode = KSafeWriteMode.Encrypted(
    protection = KSafeEncryptedProtection.DEFAULT,
    requireUnlockedDevice = true
))

// HARDWARE_ISOLATED — StrongBox (Android) / Secure Enclave (Apple).
// Per-write per-key Keystore allocation, slower, requires hardware support.
// Use ONLY for high-sensitivity material (master passphrases, identity keys).
ksafe.put("master_passphrase", value, mode = KSafeWriteMode.Encrypted(
    protection = KSafeEncryptedProtection.HARDWARE_ISOLATED
))

// Plain mode — explicit unencrypted write (still goes through KSafe storage)
ksafe.put("theme", "dark", mode = KSafeWriteMode.Plain)
```

---

## Database passphrase (a complete pattern)

`getOrCreateSecret` is a **`suspend`** extension — call it from a coroutine / suspend
function, not synchronously.

```kotlin
// 256-bit hardware-isolated random secret, generated once and persisted.
// Idempotent: subsequent calls return the same bytes.
suspend fun openDatabase(): AppDatabase {
    val passphrase: ByteArray = ksafe.getOrCreateSecret("main.db")   // suspend

    return Room.databaseBuilder(context, AppDatabase::class.java, "main.db")
        .openHelperFactory(SupportFactory(passphrase))
        .build()
}
```

Optional params: `getOrCreateSecret(key, size = 32, protection = KSafeEncryptedProtection.HARDWARE_ISOLATED, requireUnlockedDevice = false)`.
Same one-liner works for SQLDelight + SQLCipher.

---

## Custom serialization

For third-party types you can't annotate:

```kotlin
val json = Json {
    serializersModule = SerializersModule {
        contextual(UUID::class, UUIDSerializer)
        contextual(Instant::class, InstantSerializer)
    }
}
val ksafe = KSafe(config = KSafeConfig(json = json))

@Serializable
data class User(@Contextual val id: UUID, val name: String)
```

Full walkthrough: [`docs/SERIALIZATION.md`](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/SERIALIZATION.md).

---

## ANTI-patterns (common mistakes — DO NOT generate this code)

❌ **Don't use `ksafe(value, encrypted = true)`.** The `encrypted: Boolean` parameter is
   **deprecated**. KSafe is encrypted by default — write `ksafe(value)` to encrypt, and
   `ksafe(value, mode = KSafeWriteMode.Plain)` to opt out. There is no `default =` named
   parameter either; the default value is the first positional argument.

❌ **Don't wrap a delegate in `MutableStateFlow`.** KSafe is already reactive.
   Use `ksafe.asFlow<T>(key)` or `ksafe.asStateFlow<T>(key, scope)` for flow consumers.

❌ **Don't `runBlocking { ksafe.put(...) }`.** Use the delegate, or `putDirect` for
   fire-and-forget, or suspend `put` from a coroutine.

❌ **Don't roll your own `BiometricPrompt` / `LAContext` flow.** Add `:ksafe-biometrics`
   and call `KSafeBiometrics.verifyBiometric(...)` / `verifyBiometricDirect(...)`. Cross-
   platform, with authorization-duration caching and scoped invalidation built in.

❌ **Don't ask for `HARDWARE_ISOLATED` by default.** It's slower and has strict hardware
   requirements. The default encrypted mode (`KSafeEncryptedProtection.DEFAULT`) is
   already TEE/SEP-backed on modern hardware. Reserve `HARDWARE_ISOLATED` for master
   passphrases / identity keys.

❌ **Don't ignore `protectionInfo` when debugging "data not persisted".** Read its
   `notes` first — `jvm_os_vault_unavailable`, `jvm_user_opted_out`, etc. tell you
   exactly what happened.

❌ **Don't pass `Activity` context on Android.** Always `applicationContext`. Activity
   context leaks if held longer than the activity lifecycle.

❌ **Don't forget `appNamespace` on JVM Desktop or web** if multiple apps could share
   the same `fileName`.

---

## "Data isn't persisted" — debugging checklist

1. `println(ksafe.protectionInfo)` — read `effectiveLevel`, `custody`, `notes`.
   - `notes` contains `jvm_os_vault_unavailable` → see Compose Desktop section above.
   - `notes` contains `jvm_user_opted_out` → `-Dksafe.jvm.keyVault=software` is set.
   - `notes` contains `android_strongbox_absent` → only matters for `HARDWARE_ISOLATED`.
   - `notes` contains `apple_secure_enclave_absent` → simulator or pre-T2 Intel Mac.
2. On JVM, check stderr for `KSafe SECURITY WARNING` — printed once when the OS vault
   degrades to the software fallback.
3. Check `ksafe.getKeyInfo(yourKey)`. If it returns `null`, the key was never written.
   If it returns non-null with mismatched `protection` vs `level`, a fallback happened.
4. On Android, verify `applicationContext` (not Activity) and that the device hasn't
   reset the Keystore (rare).
5. On web, verify `awaitCacheReady()` was called before the first `getDirect` on an
   encrypted key.
6. From 2.1.1+, the `KSafeCore` write consumer logs `KSafe SEVERE` on persistent
   `processBatch` failures with the exception class name. Search stderr for it.

---

## Deep-dive references (when this skill isn't enough)

These are **raw-markdown URLs** on the KSafe `main` branch — KSafe is distributed as a
Maven artifact, so its `docs/` folder is not on the user's disk. Fetch any of these
directly with your agent's web-fetch tool (`WebFetch`, `web_search`, etc.) when the
patterns in this skill aren't enough for the task at hand. Each URL returns plain
markdown ready to parse; no HTML chrome to strip.

| Question | Raw-markdown URL on GitHub |
|---|---|
| Full API reference, every write mode, nullable handling, write modes | [USAGE.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/USAGE.md) |
| Setup walkthroughs, Koin DI per platform, multi-instance, `close()`, custom dirs | [SETUP.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/SETUP.md) |
| Cryptographic details, AES-GCM envelope, threat model per platform | [SECURITY.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/SECURITY.md) |
| `KSafe.protectionInfo` model, per-platform truth table, gating patterns | [PROTECTION_INFO.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/PROTECTION_INFO.md) |
| JVM Desktop key custody deep dive, DPAPI/Keychain/libsecret, `jdk.unsupported` | [JVM_PROTECTION.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/JVM_PROTECTION.md) |
| `:ksafe-biometrics` complete reference, scoped auth caching, macOS sandboxing | [BIOMETRICS.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/BIOMETRICS.md) |
| Internals: hot cache, write coalescer, v2 master-key envelope | [ARCHITECTURE.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/ARCHITECTURE.md) |
| Memory policies (`LAZY_PLAIN_TEXT` default vs alternatives) | [MEMORY.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/MEMORY.md) |
| 1.x → 2.0 → 2.1 upgrade notes, on-disk format guarantees | [MIGRATION.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/MIGRATION.md) |
| Custom `KSerializer`, `@Contextual`, third-party types | [SERIALIZATION.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/SERIALIZATION.md) |
| Performance numbers vs MMKV / SharedPreferences / KVault / Multiplatform Settings | [BENCHMARKS.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/BENCHMARKS.md) |
| Testing strategy, gradle test tasks per target | [TESTING.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/TESTING.md) |
| Repo tour, file layout, where to find each subsystem | [TOUR.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/TOUR.md) |
| Reproduce / verify the encryption on disk (Android Studio Database Inspector etc.) | [ENCRYPTION_PROOF.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/docs/ENCRYPTION_PROOF.md) |
| Library README (latest stable version, install snippet, comparisons) | [README.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/README.md) |
| Changelog (per-version detail) | [CHANGELOG.md](https://raw.githubusercontent.com/ioannisa/KSafe/main/CHANGELOG.md) |

---

## Quick reference card

```kotlin
// Construct
val ksafe = KSafe(applicationContext)        // Android
val ksafe = KSafe()                          // everywhere else
val ksafe = KSafe(fileName = "session")      // named instance
val ksafe = KSafe(config = KSafeConfig(appNamespace = "com.example.app"))

// Delegate (preferred — encrypted by default; default value is positional)
var token by ksafe("")                                  // encrypted
var counter by ksafe(0, mode = KSafeWriteMode.Plain)    // opt out of encryption
var theme by ksafe("light", key = "app_theme")          // custom key

// Compose (:ksafe-compose) — also encrypted by default
var pin by ksafe.mutableStateOf("")                            // class field (ViewModel)
@Composable fun X() { var x by ksafe.rememberKSafeState(0, key = "x") }  // composable body

// Suspend (key first, then defaultValue)
val v = ksafe.get(key, defaultValue)
ksafe.put(key, value)                                   // optional: mode = KSafeWriteMode.Plain
ksafe.delete(key)
ksafe.clearAll()

// Direct (fire-and-forget; key first, then defaultValue)
val v = ksafe.getDirect(key, defaultValue)
ksafe.putDirect(key, value)
ksafe.deleteDirect(key)

// Reactive — delegate (defaultValue first) or direct getFlow
val nameFlow: Flow<String> by ksafe.asFlow("Guest")
val nameState: StateFlow<String> by ksafe.asStateFlow("Guest", viewModelScope)
ksafe.getFlow(key, defaultValue).collect { … }

// Diagnostics
ksafe.protectionInfo          // instance-level KSafeProtectionInfo (live, recomputed per access)
ksafe.getKeyInfo(key)         // per-key KSafeKeyInfo (prefer .level)
ksafe.deviceKeyStorages       // set of platform-capability tiers
KSafe.VERSION                 // "x.y.z" of the linked artifact

// Biometrics (separate :ksafe-biometrics module, static API)
suspend fun a() = KSafeBiometrics.verifyBiometric(reason): Boolean
KSafeBiometrics.verifyBiometricDirect(reason) { success -> }

// Secrets — getOrCreateSecret is SUSPEND
suspend fun s() {
    val passphrase: ByteArray = ksafe.getOrCreateSecret("name")   // 256-bit, hw-isolated
}
val nonce: ByteArray = secureRandomBytes(16)                      // platform CSPRNG
```
