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
(see the matrix below); the on-disk file holds only ciphertext.

This skill is self-contained — it covers everything you need to **set up** and **use**
KSafe correctly. Always prefer the **property delegate** as the default API.

**The single most important fact: KSafe is encrypted by default.** `ksafe(value)`
encrypts. You opt *out* for non-secret values with `mode = KSafeWriteMode.Plain`.

---

## Key-custody matrix (this is what makes KSafe interesting)

| Platform | Where the AES key lives | How it's hardened | "HARDWARE_ISOLATED" upgrade |
|---|---|---|---|
| Android | Android Keystore | TEE | StrongBox (per-write) |
| iOS / native macOS | Apple Keychain | Per-app sandbox; SEP-gated on modern hardware | Secure Enclave (per-write) |
| JVM Desktop | Windows DPAPI / macOS login Keychain / Linux Secret Service | Bound to OS user login | n/a |
| WasmJS / JS | IndexedDB | Non-extractable WebCrypto `CryptoKey` | n/a |

When a stronger tier isn't available (no StrongBox / no Secure Enclave / headless Linux
without a keyring), KSafe **degrades to the next-best path and reports the degrade**
through `KSafe.protectionInfo`. Never silent data loss.

---

# SETUP

## Dependencies

```kotlin
// commonMain (or Android-only) build.gradle.kts
implementation("eu.anifantakis:ksafe:<latest>")              // core
implementation("eu.anifantakis:ksafe-compose:<latest>")      // optional: Compose state
implementation("eu.anifantakis:ksafe-biometrics:<latest>")   // optional: biometric prompts
```

`kotlinx-serialization-json` comes transitively — don't add it yourself. If you store
`@Serializable` classes, apply the kotlin-serialization plugin in your app.

## Construction

```kotlin
// Android — pass applicationContext (NOT an Activity context — it leaks)
val ksafe = KSafe(applicationContext)

// iOS / macOS / JVM / WasmJS / JS — no context
val ksafe = KSafe()
val ksafe = KSafe(fileName = "auth")   // isolated named instance
```

Full factory parameters (all platforms except where noted):

```kotlin
KSafe(
    context: Context,                    // Android ONLY — applicationContext
    fileName: String? = null,            // null = default instance; else isolates storage
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    baseDir: File? = null,               // JVM/Android custom dir; iOS uses `directory: String?`
)

KSafeConfig(
    keySize: Int = 256,                  // 128 or 256
    androidAuthValiditySeconds: Int = 30,
    requireUnlockedDevice: Boolean = false,  // default unlock policy for encrypted writes
    json: Json = KSafeDefaults.json,         // custom serialization
    appNamespace: String? = null,            // multi-app isolation (see below)
)
```

## Recommended DI setup (Koin) — the `prefs` / `vault` two-instance pattern

Encryption adds per-write overhead (AES-GCM + Keystore/Keychain round-trip). For
non-secret data — theme, last screen, UI flags — that overhead is wasted. The
recommended pattern is **two named singletons**: a fast plain `prefs` and an encrypted
`vault`.

```kotlin
// commonMain
expect val platformModule: Module

// androidMain
actual val platformModule = module {
    single(named("prefs")) { KSafe(context = androidApplication(), fileName = "prefs") }
    single(named("vault")) { KSafe(context = androidApplication(), fileName = "vault") }
}

// iosMain / jvmMain / wasmJsMain / jsMain (no context)
actual val platformModule = module {
    single(named("prefs")) { KSafe(fileName = "prefs") }
    single(named("vault")) { KSafe(fileName = "vault") }
}
```

```kotlin
class MyViewModel(
    private val prefs: KSafe,   // @Named("prefs") — fast, write Plain
    private val vault: KSafe,   // @Named("vault") — encrypted secrets
) : ViewModel() {
    // UI preferences — opt out of encryption
    var theme      by prefs("dark", mode = KSafeWriteMode.Plain)
    var lastScreen by prefs("home", mode = KSafeWriteMode.Plain)

    // Secrets — encrypted by default
    var authToken    by vault("")
    var userPin      by vault("", mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))
}
```

If your app only stores secrets, a **single default instance** is fine:

```kotlin
actual val platformModule = module { single { KSafe(/* androidApplication() on Android */) } }
```

## Multiple instances — the rules

- **Each `KSafe(fileName=...)` must be a singleton.** Create once (via DI), reuse everywhere.
- **Never create two instances pointing at the same `fileName`** — causes data inconsistency.
- **`fileName` must match `[a-z][a-z0-9_]*`** — start lowercase, then lowercase/digits/underscores.
  Valid: `"userdata"`, `"settings"`, `"data_v2"`. Invalid: spaces, dots, slashes, hyphens, uppercase.

```kotlin
// ✅ Good — singletons via DI
val appModule = module {
    single { KSafe() }                                  // default
    single(named("user")) { KSafe(fileName = "userdata") }
}
// ❌ Bad — two instances, same file
class ScreenA { val prefs = KSafe(fileName = "userdata") }
class ScreenB { val prefs = KSafe(fileName = "userdata") }   // DON'T
```

## Custom storage directory (optional)

Defaults are platform-appropriate (Android app sandbox, iOS `NSApplicationSupportDirectory`,
JVM `~/.eu_anifantakis_ksafe/` at `0700`, web `localStorage`). Override only when needed:

```kotlin
// JVM — e.g. align with XDG
val ksafe = KSafe(fileName = "vault", baseDir = File("$xdgDataHome/myapp/ksafe"))

// Android — e.g. no-backup dir
val ksafe = KSafe(context = context, fileName = "vault", baseDir = File(context.noBackupFilesDir, "ksafe"))

// iOS — absolute path string (note: `directory`, not `baseDir`)
val ksafe = KSafe(fileName = "vault", directory = "/path/to/dir")
```

Web has no directory concept (no `baseDir`). Don't point `baseDir` at external storage for
sensitive data on Android.

## `KSafe.close()` — only when re-creating instances mid-process

The app-lifetime singleton never needs disposal (the OS reclaims everything at exit).
`close()` exists for account/profile switching that changes `fileName`, long-running JVM
services building per-session instances, or dev-time hot-reload. It cancels background
coroutines and releases the DataStore scope/file handle. Idempotent; after `close()` the
instance can't read or write — discard it.

## Web ONLY — `awaitCacheReady()`

WebCrypto is async-only, so on WasmJS/JS KSafe must finish decrypting its cache before the
first synchronous read of an encrypted key. Call `awaitCacheReady()` once at startup.
**No-op on Android/iOS/macOS/JVM.** Placement depends on how you start Koin:

```kotlin
// startKoin (classic) — Koin is up before ComposeViewport, getKoin() works immediately
fun main() {
    startKoin { modules(sharedModule, platformModule) }
    ComposeViewport(document.body!!) {
        var ready by remember { mutableStateOf(false) }
        LaunchedEffect(Unit) { getKoin().get<KSafe>().awaitCacheReady(); ready = true }
        if (ready) App()
    }
}

// KoinMultiplatformApplication (Compose) — awaitCacheReady must go INSIDE the composable
fun main() {
    ComposeViewport(document.body!!) {
        KoinMultiplatformApplication(config = createKoinConfiguration()) {
            var ready by remember { mutableStateOf(false) }
            LaunchedEffect(Unit) { getKoin().get<KSafe>().awaitCacheReady(); ready = true }
            if (ready) AppContent()
        }
    }
}
```

---

# USAGE

## Property delegate — the 80% case (encrypted by default)

Default value is the **first positional argument** (there is no `default =` or
`encrypted =` named parameter — `encrypted` is a deprecated legacy param, never generate
it). Storage key defaults to the property name unless you pass `key`.

```kotlin
class AuthViewModel(private val ksafe: KSafe) : ViewModel() {
    var authToken by ksafe("")                                  // encrypted (default)
    var userId    by ksafe(0L, mode = KSafeWriteMode.Plain)     // opt OUT of encryption
    var lastSync  by ksafe(Instant.EPOCH)                       // any @Serializable type
    var theme     by ksafe(ThemeMode.DEVICE, key = "theme", mode = KSafeWriteMode.Plain)

    init { authToken = "..." }   // just assign — reads sync from hot cache, writes coalesce
}
```

What you get: synchronous reads from an in-memory hot cache (~µs), coalesced background
writes (multiple writes within a 16ms window land in one transaction, never blocks the
caller), and reactivity (see Flows below). The delegate works on **any** `KSafe` instance
— `var x by myKsafe(value)` makes `myKsafe` the backing store.

## Storing complex objects

```kotlin
@Serializable
data class AuthInfo(val accessToken: String = "", val refreshToken: String = "", val expiresIn: Long = 0L)

var authInfo by ksafe(AuthInfo())            // encryption + JSON automatically
authInfo = authInfo.copy(accessToken = "newToken")
```

"Serializer for class X is not found"? Add `@Serializable` and the serialization plugin.

## Nullable values — the reified-`null` trap (IMPORTANT)

KSafe supports nullable types, and `null` is preserved as a distinct state (not
"missing"). **But never pass a bare `null` as the default value** — reified generics have
nothing to infer `T` from, so `T` collapses to `Nothing?` and the call always returns
`null` even when a value is stored.

```kotlin
// ❌ Wrong — always returns null, ignores stored value
val token = ksafe.get("auth_token", null)
var token by ksafe(null)

// ✅ Correct — explicit type parameter
val token = ksafe.get<String?>("auth_token", null)
var token by ksafe<String?>(null)

// ✅ Correct — typed declaration drives inference
val token: String? = ksafe.get("auth_token", null)
var token: String? by ksafe(null)
```

## Suspend vs Direct API

```kotlin
// Suspend — awaits the disk commit. Use when persistence is a precondition
// for the next step (token refresh, payment confirmation). Concurrent callers
// get coalesced, so individual latency drops under load.
suspend fun save() {
    ksafe.put("profile", userProfile)
    val cached: User = ksafe.get("profile", User())
}

// Direct — fire-and-forget (queue + return). Use for UI/hot-cache writes where
// you don't need to know the disk write landed.
ksafe.putDirect("counter", 42)
val n = ksafe.getDirect("counter", 0)
```

Signature order is **key first, then defaultValue**: `get(key, defaultValue)`,
`getDirect(key, defaultValue)`.

## Write modes

The delegate / `mutableStateOf` / `put` all default to encrypted. Use `mode` for control.
**The `protection` param of `KSafeWriteMode.Encrypted` is `KSafeEncryptedProtection`**
(write-side), NOT `KSafeProtection` (the read-side enum from `getKeyInfo`). Using
`KSafeProtection` here will not compile.

```kotlin
// Per-entry unlock policy (Apple) — inaccessible until first unlock since boot
ksafe.put("token", value, mode = KSafeWriteMode.Encrypted(
    protection = KSafeEncryptedProtection.DEFAULT,
    requireUnlockedDevice = true,
))

// HARDWARE_ISOLATED — StrongBox (Android) / Secure Enclave (Apple). Slower,
// per-key Keystore allocation, needs hardware. Reserve for master passphrases /
// identity keys; do NOT use as a default.
ksafe.put("master_passphrase", value, mode = KSafeWriteMode.Encrypted(
    protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
))

// Explicit plaintext
ksafe.putDirect("theme", "dark", mode = KSafeWriteMode.Plain)
```

No-mode writes use encrypted defaults and pick up `KSafeConfig.requireUnlockedDevice`.

## Deleting

```kotlin
ksafe.delete("profile")        // suspend
ksafe.deleteDirect("profile")  // fire-and-forget
ksafe.clearAll()               // suspend — wipes everything (data + keys). Destructive.
```

Deleting removes both the value and its encryption key.

## Reactive reads — Flows and StateFlows

All four are property delegates with `defaultValue` first. All auto-update on writes from
anywhere (another screen, background sync, another delegate on the same key). `asFlow` /
`asStateFlow` are **read-only** (writes go through `put`/`putDirect`); `asWritableFlow` /
`asMutableStateFlow` are writable.

```kotlin
class Repo(private val ksafe: KSafe) {
    // Cold Flow<T> — read-only. Encrypted by default; pass mode = Plain to opt out.
    val username: Flow<String> by ksafe.asFlow("Guest")
    val theme: Flow<String> by ksafe.asFlow("light", key = "app_theme")

    // Writable cold Flow<T> — set() persists, no CoroutineScope needed.
    val themeMode: WritableKSafeFlow<ThemeMode> by ksafe.asWritableFlow(ThemeMode.DEVICE)
    fun setTheme(m: ThemeMode) = themeMode.set(m)
}

class VM(private val ksafe: KSafe) : ViewModel() {
    // Hot StateFlow<T> — read-only. Needs a scope.
    val username: StateFlow<String> by ksafe.asStateFlow("Guest", viewModelScope)

    // Hot MutableStateFlow<T> — .value = / .update {} persist automatically.
    // Drop-in for the standard MutableStateFlow pattern, but persisted + reactive.
    private val _state by ksafe.asMutableStateFlow(MoviesState(), viewModelScope)
    val state = _state.asStateFlow()

    fun load() { _state.update { it.copy(loading = true) } }
}

// Direct (non-delegate) form also exists:
ksafe.getFlow(key, defaultValue).collect { … }
```

Or collect a delegate's flow in Compose: `val name by repo.username.collectAsState()`.

## Compose state — `:ksafe-compose`

Two APIs with **deliberately different default modes**:

```kotlin
// mutableStateOf — ENCRYPTED by default. For class fields (ViewModel/repository):
// created once, lives for the class lifetime.
class CounterViewModel(private val ksafe: KSafe) : ViewModel() {
    var pin by ksafe.mutableStateOf("")                          // encrypted (default)
    var counter by ksafe.mutableStateOf(0, mode = KSafeWriteMode.Plain)  // opt out

    // Optional `scope` = live cross-screen sync (auto-updates when ANY writer changes
    // the key). Without scope: reads once at init, writes persist, but no live sync.
    var username by ksafe.mutableStateOf("Guest", scope = viewModelScope)
}

// rememberKSafeState — PLAIN by default (UI ephemera rarely needs encryption).
// For composable-BODY state (no ViewModel). It's an EXTENSION on ksafe, default value
// first. remember-scoped, so it survives recomposition AND process death.
@Composable
fun TabbedScreen(ksafe: KSafe) {
    var currentTab by ksafe.rememberKSafeState(0)                       // key = "currentTab"
    var draft by ksafe.rememberKSafeState("", key = "screen.draft")     // explicit key
    var pin by ksafe.rememberKSafeState("", mode = KSafeWriteMode.Encrypted())  // opt IN

    // Live cross-screen sync:
    var theme by ksafe.rememberKSafeState(ThemeMode.LIGHT, key = "theme", observeExternalChanges = true)
}
```

Rule of thumb: ViewModel/class property → `mutableStateOf`. Composable-body local state
(tab index, scroll position, draft text, expanded sections) → `rememberKSafeState`.
Domain data shared across screens stays in a ViewModel with `mutableStateOf`.

---

## Memory policy (construction-time tuning)

`KSafe(memoryPolicy = …)` controls how the in-RAM cache holds values. Default is
**`LAZY_PLAIN_TEXT`** — leave it unless you have a specific reason.

| Policy | Behaviour |
|---|---|
| `LAZY_PLAIN_TEXT` (default) | First read of a key decrypts on demand, then caches plaintext permanently. Cold start does no bulk decrypt; steady-state reads are O(1). Best general choice. |
| `ENCRYPTED` | Ciphertext stays in RAM; every read decrypts. Lowest plaintext-in-RAM exposure, highest read cost. |
| `ENCRYPTED_WITH_TIMED_CACHE` | Like `ENCRYPTED`, but decrypted plaintext is side-cached for a TTL window. |
| `PLAIN_TEXT` | Eagerly decrypts everything at startup. Discouraged — pays full cold-start cost; same RAM exposure as `LAZY_PLAIN_TEXT` without the lazy benefit. |

Web forces `PLAIN_TEXT` internally (WebCrypto async-only) — hence `awaitCacheReady()`.

---

## Biometric-gated actions — `:ksafe-biometrics` (independent, static API)

Independent of `:ksafe` — call directly for any biometric prompt. No DI, no `Context`, no
init. Android auto-inits via `ContentProvider` (no `Application` changes); requires
`AppCompatActivity`.

```kotlin
// Callback variant — works anywhere
KSafeBiometrics.verifyBiometricDirect("Unlock balance") { success -> if (success) showBalance() }

// Suspend variant
viewModelScope.launch {
    if (KSafeBiometrics.verifyBiometric("Confirm transaction")) proceed()
}

// Avoid re-prompts within a window
KSafeBiometrics.verifyBiometric(
    reason = "Reauth",
    authorizationDuration = BiometricAuthorizationDuration(duration = 60_000L, scope = "MyScope"),
)

// Hard biometric-only (no PIN/password/Apple-Watch fallback)
KSafeBiometrics.verifyBiometric("Step-up", allowDeviceCredentialFallback = false)
```

`verifyBiometric` is `suspend`; `verifyBiometricDirect` is callback-based. On macOS the
LAPolicy depends on `allowDeviceCredentialFallback`: default `true` →
`LAPolicyDeviceOwnerAuthentication` (always prompts); `false` →
`...WithBiometrics` (Touch ID only, returns false on hardware-less Macs). JVM/JS/WasmJS
return `true` so shared logic compiles.

---

## Database passphrase

`getOrCreateSecret` is a **`suspend`** extension — call from a coroutine.

```kotlin
suspend fun openDatabase(): AppDatabase {
    val passphrase: ByteArray = ksafe.getOrCreateSecret("main.db")   // 256-bit, hw-isolated, idempotent
    return Room.databaseBuilder(context, AppDatabase::class.java, "main.db")
        .openHelperFactory(SupportFactory(passphrase))
        .build()
}
```

Params: `getOrCreateSecret(key, size = 32, protection = KSafeEncryptedProtection.HARDWARE_ISOLATED, requireUnlockedDevice = false)`.
Works the same for SQLDelight + SQLCipher.

---

## Custom serialization

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

---

## Diagnostics — `KSafe.protectionInfo` and `KSafe.VERSION`

```kotlin
val info = ksafe.protectionInfo   // recomputed per access (2.1.1+): a runtime JVM degrade shows up live

check(info.effectiveLevel >= KSafeProtectionLevel.SANDBOX_PROTECTED) {
    "Need sandbox-grade key protection; got ${info.custody}"
}
check(info.effectiveLevel >= info.intendedLevel)   // detect silent fallback

analytics.log("ksafe_protection",
    "level"   to info.effectiveLevel.name,    // SOFTWARE | SANDBOX_PROTECTED | HARDWARE_BACKED | HARDWARE_ISOLATED
    "custody" to info.custody,                // human-readable, never parse
    "notes"   to info.notes.joinToString(","),// stable lowercase_snake codes
    "version" to info.kSafeVersion)           // == KSafe.VERSION
```

Per-key audit: `ksafe.getKeyInfo(key)` → `KSafeKeyInfo(protection, storage, level)`; prefer
`.level` (same scale as `protectionInfo`). Device capability probe: `ksafe.deviceKeyStorages`.

---

## ⚠️ Compose Desktop release distributables — strongly recommend `modules("jdk.unsupported")`

For any production Compose Desktop release build, add this module — it restores **OS-backed
key custody** (Keychain / DPAPI / Secret Service):

```kotlin
compose.desktop {
    application {
        nativeDistributions {
            // STRONGLY RECOMMENDED — restores OS-backed key custody (JNA + DataStore's
            // protobuf both need sun.misc.Unsafe, which jlink trims).
            // java.management → only for a non-default KSafeSecurityPolicy (debugger probe).
            modules("jdk.unsupported", "java.management")
        }
    }
}
```

Without it KSafe doesn't crash — it persists at a software key tier (same DataStore engine +
AES-256-GCM; key in a `0700` file, `protectionInfo.effectiveLevel == SOFTWARE`) and migrates
forward automatically when you add the module. Risk + mechanism: KSafe `docs/JVM_PROTECTION.md`.

---

## Multi-app desktop / web isolation — `appNamespace`

Android/iOS keystores are sandboxed per-app. **JVM Desktop OS secret stores are per-OS-user
(shared across processes)**; **web IndexedDB is per-origin**. Two apps using the same
`fileName` collide on the same key. Set:

```kotlin
val ksafe = KSafe(fileName = "userdata", config = KSafeConfig(appNamespace = "com.example.myapp"))
```

Production desktop apps should set it explicitly. Only the key-store destination is
namespaced — legacy ≤ 2.0 data still migrates unchanged.

---

## ANTI-patterns (common mistakes — DO NOT generate this code)

❌ **Don't use `ksafe(value, encrypted = true)`.** `encrypted: Boolean` is **deprecated**.
   KSafe is encrypted by default: `ksafe(value)` encrypts, `ksafe(value, mode =
   KSafeWriteMode.Plain)` opts out. There is no `default =` named param — the default
   value is the first positional argument.

❌ **Don't pass a bare `null` default.** `ksafe.get("k", null)` / `var x by ksafe(null)`
   always return null (reified `T` collapses to `Nothing?`). Use `get<String?>("k", null)`
   or a typed declaration.

❌ **Don't wrap a delegate in `MutableStateFlow`.** KSafe is already reactive — use
   `ksafe.asMutableStateFlow(default, scope)` (writable) or `ksafe.asStateFlow(default,
   scope)` / `ksafe.asFlow(default)` (read-only).

❌ **Don't `runBlocking { ksafe.put(...) }`.** Use the delegate, `putDirect` for
   fire-and-forget, or suspend `put` from a coroutine.

❌ **Don't use `KSafeProtection` in `KSafeWriteMode.Encrypted(...)`.** That constructor
   takes `KSafeEncryptedProtection`. `KSafeProtection` is the read-side detection enum.

❌ **Don't call `getOrCreateSecret` / `verifyBiometric` / `awaitCacheReady` synchronously.**
   They're `suspend`.

❌ **Don't roll your own `BiometricPrompt` / `LAContext`.** Add `:ksafe-biometrics` and
   call `KSafeBiometrics.verifyBiometric(...)`.

❌ **Don't ask for `HARDWARE_ISOLATED` by default.** Slower, strict hardware requirements.
   The default encrypted mode (`KSafeEncryptedProtection.DEFAULT`) is already TEE/SEP-backed
   on modern hardware. Reserve `HARDWARE_ISOLATED` for master passphrases / identity keys.

❌ **Don't pass `Activity` context on Android.** Always `applicationContext`.

❌ **Don't create two `KSafe` instances for the same `fileName`.** Singletons via DI.

❌ **Don't forget `appNamespace` on JVM Desktop / web** if multiple apps share a `fileName`.

---

## "Data isn't persisted" — debugging checklist

1. `println(ksafe.protectionInfo)` — read `effectiveLevel`, `custody`, `notes`:
   - `jvm_os_vault_unavailable` → JVM OS vault degraded; on Compose Desktop release see the
     `jdk.unsupported` section above.
   - `jvm_user_opted_out` → `-Dksafe.jvm.keyVault=software` is set.
   - `android_strongbox_absent` → only matters for `HARDWARE_ISOLATED`.
   - `apple_secure_enclave_absent` → simulator or pre-T2 Intel Mac.
2. On JVM, check stderr for `KSafe SECURITY WARNING` (printed once on vault degrade).
3. `ksafe.getKeyInfo(key)` — `null` means the key was never written.
4. Android: confirm `applicationContext` (not Activity).
5. Web: confirm `awaitCacheReady()` ran before the first `getDirect` on an encrypted key.
6. Reading null despite a stored value? The reified-`null` trap — see Nullable values.
7. From 2.1.1+, persistent write-consumer failures log `KSafe SEVERE` with the exception
   class. Search stderr.

---

## Further reading (in the KSafe repository's `docs/` folder)

This skill covers setup and usage. For topics it deliberately omits, the repository's
`docs/` folder has: **ARCHITECTURE** / **TOUR** (internals — hot cache, write coalescer,
v2 master-key envelope), **SECURITY** / **PROTECTION_INFO** / **JVM_PROTECTION** (crypto
details, threat models, per-platform key custody deep dive), **BENCHMARKS** (performance vs
MMKV / SharedPreferences / KVault / Multiplatform Settings), **MIGRATION** (version upgrade
notes), **TESTING**, **ENCRYPTION_PROOF**, and **COMPARISON**. Point the user there (or read
them from the project's own checkout) when a question goes beyond setup/usage.

---

## Quick reference card

```kotlin
// Construct
val ksafe = KSafe(applicationContext)        // Android
val ksafe = KSafe()                          // everywhere else
val ksafe = KSafe(fileName = "session")      // named instance
val ksafe = KSafe(config = KSafeConfig(appNamespace = "com.example.app"))

// Delegate (preferred — ENCRYPTED BY DEFAULT; default value is positional)
var token   by ksafe("")                                  // encrypted
var counter by ksafe(0, mode = KSafeWriteMode.Plain)      // opt out
var theme   by ksafe("light", key = "app_theme")          // custom key
var nul: String? by ksafe(null)                           // nullable: type the declaration

// Compose (:ksafe-compose)
var pin by ksafe.mutableStateOf("")                            // class field — ENCRYPTED default
var n   by ksafe.mutableStateOf(0, scope = viewModelScope)     // + live cross-screen sync
@Composable fun X() { var x by ksafe.rememberKSafeState(0, key = "x") }  // body — PLAIN default

// Suspend (key first, then defaultValue)
val v = ksafe.get(key, defaultValue);  ksafe.put(key, value);  ksafe.delete(key);  ksafe.clearAll()

// Direct (fire-and-forget)
val v = ksafe.getDirect(key, defaultValue);  ksafe.putDirect(key, value);  ksafe.deleteDirect(key)

// Reactive (delegates — defaultValue first)
val f:  Flow<String>        by ksafe.asFlow("Guest")
val wf: WritableKSafeFlow<T> by ksafe.asWritableFlow(default)          // .set(v) persists
val sf: StateFlow<String>   by ksafe.asStateFlow("Guest", viewModelScope)
val ms                      by ksafe.asMutableStateFlow(State(), viewModelScope)  // .value=/.update{}
ksafe.getFlow(key, defaultValue).collect { … }

// Diagnostics
ksafe.protectionInfo          // live KSafeProtectionInfo (effectiveLevel, custody, notes, kSafeVersion)
ksafe.getKeyInfo(key)         // per-key KSafeKeyInfo (prefer .level)
ksafe.deviceKeyStorages       // platform capability tiers
KSafe.VERSION                 // linked artifact version

// Biometrics (:ksafe-biometrics — static, suspend verifyBiometric / callback verifyBiometricDirect)
suspend fun a() = KSafeBiometrics.verifyBiometric(reason)            // Boolean
KSafeBiometrics.verifyBiometricDirect(reason) { success -> }

// Secrets — getOrCreateSecret is SUSPEND
suspend fun s() { val pw: ByteArray = ksafe.getOrCreateSecret("name") }   // 256-bit, hw-isolated
val nonce = secureRandomBytes(16)                                          // platform CSPRNG

// Web only
suspend fun boot() { ksafe.awaitCacheReady() }
```
