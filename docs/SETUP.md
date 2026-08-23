# Setup with Koin (Recommended)

> **Install first.** Full install instructions live in the [README](../README.md#setup). The three published artifacts are:
>
> ```kotlin
> implementation("eu.anifantakis:ksafe:3.0.0")
> implementation("eu.anifantakis:ksafe-compose:3.0.0")     // ← Compose persisted state (optional)
> implementation("eu.anifantakis:ksafe-biometrics:3.0.0")  // ← standalone biometric gate (optional)
> ```
>
> `:ksafe-compose` adds `KSafe.mutableStateOf` / `rememberKSafeState`; `:ksafe-biometrics` is an independent process-wide biometric gate (Android, iOS, macOS, JVM Desktop, web) with no dependency on `:ksafe`.

Koin is the defacto DI solution for Kotlin Multiplatform, and is the ideal tool to provide KSafe as a singleton.

> **Performance guidance — "prefs" vs "vault":**
> Encryption adds overhead to every write (AES-GCM + Keystore/Keychain round-trip). For data that doesn't need confidentiality — theme preferences, last-visited screen, UI flags — use `mode = KSafeWriteMode.Plain` to get SharedPreferences-level speed. Reserve encryption for secrets like tokens, passwords, and PII. The easiest way to enforce this is to create **two named singletons**:

```Kotlin
// ──────────────────────────────────────────────
// common
// ──────────────────────────────────────────────
expect val platformModule: Module

// ──────────────────────────────────────────────
// Android
// ──────────────────────────────────────────────
actual val platformModule = module {
    // Fast, plain writes — for everyday preferences
    single(named("prefs")) {
        KSafe(
            context = androidApplication(),
            fileName = "prefs"
        )
    }

    // Encrypted writes — for secrets (tokens, passwords, PII)
    single(named("vault")) {
        KSafe(
            context = androidApplication(),
            fileName = "vault"
        )
    }
}

// ──────────────────────────────────────────────
// iOS / macOS
// ──────────────────────────────────────────────
actual val platformModule = module {
    single(named("prefs")) {
        KSafe(fileName = "prefs")
    }

    single(named("vault")) {
        KSafe(fileName = "vault")
    }
}

// ──────────────────────────────────────────────
// JVM/Desktop
// ──────────────────────────────────────────────
actual val platformModule = module {
    single(named("prefs")) {
        KSafe(fileName = "prefs")
    }

    single(named("vault")) {
        KSafe(fileName = "vault")
    }
}

// ──────────────────────────────────────────────
// Web (Kotlin/WASM + Kotlin/JS) — call ksafe.awaitCacheReady() before first encrypted read (see note below)
// ──────────────────────────────────────────────
actual val platformModule = module {
    single(named("prefs")) {
        KSafe(fileName = "prefs")
    }

    single(named("vault")) {
        KSafe(fileName = "vault")
    }
}
```

Then inject by name in your ViewModels:
```kotlin
class MyViewModel(
    private val prefs: KSafe,  // @Named("prefs") — fast, unencrypted
    private val vault: KSafe   // @Named("vault") — encrypted secrets
) : ViewModel() {

    // UI preferences — no encryption overhead
    var theme      by prefs("dark", mode = KSafeWriteMode.Plain)
    var lastScreen by prefs("home", mode = KSafeWriteMode.Plain)
    var onboarded  by prefs(false, mode = KSafeWriteMode.Plain)

    // Secrets — AES-256-GCM encrypted, hardware-backed keys
    var authToken    by vault("")
    var refreshToken by vault("")
    var userPin      by vault(
        "",
        mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)
    )  // StrongBox / SE
}
```

> Of course, if your app only stores secrets you can use a **single default instance** — the two-instance pattern is a recommendation for apps that mix everyday preferences with sensitive data.

```Kotlin
// Single instance (perfectly fine if everything needs encryption)
// Android
actual val platformModule = module {
    single { KSafe(androidApplication()) }
}

// iOS / JVM / WASM / JS
actual val platformModule = module {
    single { KSafe() }
}
```

### `ksafe.awaitCacheReady()` Required ONLY on the Web Targets (wasmJs + js)

> **Kotlin/WASM and Kotlin/JS:** WebCrypto encryption is async-only, so KSafe must finish decrypting its cache before your UI reads any encrypted values. Call `awaitCacheReady()` before rendering content. The same code works for both `wasmJsMain` and `jsMain` — nothing target-specific here.
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

## Multiple Instances

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
- **Prefer a single instance per file** - On Android, iOS/macOS and JVM/Desktop, co-existing instances on the same file now share one ref-counted storage backend, so they no longer lose data by diverging. A singleton is still recommended to avoid redundant caches and the transient failure a close-then-recreate on the same file can hit during backend teardown.

```Kotlin
// ✅ Good: Singleton instances via DI
val appModule = module {
  single { KSafe() }  // Default instance
  single(named("user")) { KSafe(fileName = "userdata") }
  single(named("cache")) { KSafe(fileName = "cache") }
}

// ⚠️ Non-ideal: Creating multiple instances for the same file
class ScreenA { val prefs = KSafe(fileName = "userdata") }
class ScreenB { val prefs = KSafe(fileName = "userdata") }  // Prefer one shared instance
```

**File Name Requirements:**
- Must match the regex `[a-z][a-z0-9_]*` — start with a lowercase letter, followed by lowercase letters, digits, or underscores
- No spaces, dots, slashes, hyphens, or uppercase letters allowed
- Examples: `"userdata"`, `"settings"`, `"data_v2"`, `"cache"`

### Disposing an instance: `KSafe.close()`

In the singleton-per-process pattern above you never need to call anything to dispose `KSafe` — the OS reclaims everything when the process exits. The optional `close()` method exists for the small set of cases where you actually re-create `KSafe` mid-process:

- **Account or profile switching** that changes the `fileName` (you build a new instance for the new identity and abandon the old one).
- **Long-running JVM services** that build a fresh instance per session, tenant, or request.
- **Dev-time hot-reload** that rebuilds the DI graph and constructs new `KSafe`s on top of the previous ones.

```kotlin
// Raw IDs (UUIDs, hyphenated or mixed-case) violate the fileName rule above.
// Sanitize to [a-z][a-z0-9_]* first (see File Name Requirements), or construction
// throws IllegalArgumentException.
val safeId = userId.lowercase().replace(Regex("[^a-z0-9_]"), "_")
val ksafe = KSafe(fileName = "session_$safeId")
// ... use it ...
ksafe.close()  // cancels background coroutines, releases the DataStore scope and file handle
```

`close()` is idempotent. It does not install a fail-fast closed state, so you must not keep using the instance afterward: cached reads may still return stale values, a `putDirect` will mutate the in-memory cache without ever persisting, and a suspending `put`/`delete` will hang with no consumer to drain it. Always discard the reference and build a new one if you need storage again. Quiesce your own writers first: `close()` cancels the awaiters of writes already queued when it runs, but a suspending write racing `close()` from another coroutine can slip past that one-shot shutdown drain and never complete — await your writes before closing. Calling `close()` on the typical app-lifetime singleton is harmless but achieves nothing the OS won't already do at process exit.

***

## Configuring KSafe (`KSafeConfig`)

Every factory accepts an optional `config = KSafeConfig(...)`. The most important setup
settings are:

```kotlin
val ksafe = KSafe(
    config = KSafeConfig(
        aesKeySize = KSafeAesKeySize.BITS_256,
        appNamespace = "com.example.myapp",
        keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(90.days),
        keyRotationRetryAttempts = 3, // default; 0 disables next-instance retries
    )
)
```

**`aesKeySize`** selects `BITS_128` or `BITS_256` (the default) for newly created AES-GCM
keys on every platform. AES-GCM itself is intentionally fixed; the setting changes key
strength, not the cipher mode. An existing store continues using the size embedded in its
current key until `rotateKeys()` creates a fresh generation.

**`appNamespace`** is the isolation boundary for two apps that share a `fileName`. On **JVM/Desktop** and **Web** the encryption-key destination is shared (one OS secret store / one browser origin), so two apps using the same `fileName` would collide on the same key slot. Setting a distinct `appNamespace` (a reverse-DNS id is ideal) namespaces the key destination. On **JVM/Desktop** an explicit `appNamespace` also isolates the data directory — the DataStore file moves into a namespace subdirectory, and existing un-namespaced data is copied forward rather than stranded. On **Web** it namespaces the `localStorage` data slots too. It has **no effect on Android/iOS**, where the keystore is already per-app. If you leave it `null`, new JVM keys go to a fixed default namespace (`"shared"`), so two apps that share a `fileName` and both leave `appNamespace` null will collide; the old launcher-derived id is no longer a default and survives only as a read-side migration source. You can override the vault namespace via `-Dksafe.appNamespace=` or env `KSAFE_APP_NAMESPACE` (this namespaces only the key store, not the data directory), but setting an explicit `appNamespace` here is best. Web falls back to per-origin isolation.

**`keyRotationPolicy`** controls when KSafe starts a fresh generation. It defaults to
`KSafeKeyRotationPolicy.Never`; set `MaxAge(Duration)` to re-encrypt everything in the
background once the current key exceeds that age (a once-per-startup check that never blocks
startup or reads). On-demand rotation is always available via `ksafe.rotateKeys()`.
Since 3.1.0, passes started with the explicit `r:1` lifecycle state resume automatically at
the same generation on the next instance under every policy, including `Never`. A 3.0.0
generation record has no such field; its first 3.1.0 startup only adopts it as completed and
does no rotation work. A normally completed pass that leaves retryable `skipped` entries
records `rp:N`, a bounded count configured by `keyRotationRetryAttempts` (3 by default,
0 disables it). The current instance does not retry again; each next KSafe instance consumes
at most one attempt and retries the same generation, unless `MaxAge` is already due and the
normal fresh-generation rotation takes precedence. The claim decrements the count durably
before work, so crashes cannot refill it. `failed` alone does not schedule retries. See
[KEY_ROTATION.md](KEY_ROTATION.md) for the full model.

***

## Custom Storage Directory

By default KSafe picks a platform-appropriate location for its DataStore file:

| Platform | Default location |
|----------|-----------------|
| **Android** | `/data/data/<package>/files/datastore/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb` (the app sandbox — recommended) |
| **iOS** | `<NSApplicationSupportDirectory>/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb` |
| **JVM/Desktop** | `~/.eu_anifantakis_ksafe/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb`, POSIX `0700` |
| **Web** | `localStorage`, prefixed `ksafe.<appNamespace@><fileName>:` (e.g. `ksafe.vault:`) — no directory concept |

> Where the encryption **key** lives (OS vault vs. software fallback), how ciphertext is bound to the device, and the trimmed-distributable behaviour are covered in [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY_MODEL.md](SECURITY_MODEL.md), and [JVM_PROTECTION.md](JVM_PROTECTION.md).

Most apps should stick with the default. But on JVM, Android, and iOS you can pass a custom path when you need to control where data lives — for example to align with `$XDG_DATA_HOME` on Linux, store inside `noBackupFilesDir` on Android, or place data in your app's own working directory.

```kotlin
// JVM — store under XDG data home (or %APPDATA% on Windows, your own dir, etc.)
val xdg = System.getenv("XDG_DATA_HOME") ?: "${System.getProperty("user.home")}/.local/share"
val ksafe = KSafe(
    fileName = "vault",
    baseDir = java.io.File("$xdg/myapp/ksafe"),
)
// KSafe creates the directory if missing and applies POSIX 0700.

// Android — store inside no-backup files dir (excluded from auto-backup)
val ksafe = KSafe(
    context = context,
    fileName = "vault",
    baseDir = java.io.File(context.noBackupFilesDir, "ksafe"),
)
// If null, KSafe uses the Context-managed app-private path —
// recommended for most apps because the Android sandbox enforces correct
// permissions there. Do NOT point baseDir at external storage for sensitive data.

// iOS — supply an absolute path string
val ksafe = KSafe(
    fileName = "vault",
    directory = "/path/to/your/dir",
)
// If null, KSafe uses NSApplicationSupportDirectory — the iOS-correct
// location for invisible app data. KSafe doesn't set
// NSURLIsExcludedFromBackupKey on the file (DataStore's atomic-write
// strategy would clobber the xattr on every flush), but the encryption
// keys are device-local, so even an iCloud-Backup of the ciphertext is
// undecryptable on a restored device — effectively device-local data.
```

**Web** doesn't expose a directory concept — `localStorage` is per-origin and KSafe already isolates instances via the `ksafe.<appNamespace@><fileName>:` storage prefix. (The older `ksafe_<fileName>_` prefix is the legacy layout, migrated away from on first construction; it still namespaces the IndexedDB `CryptoKey` records.) There's no `baseDir` parameter on the web factory.

**iOS upgraders:** the default storage path moved from `NSDocumentDirectory` (pre-2.0) to `NSApplicationSupportDirectory`; KSafe migrates the legacy file automatically on first launch. See the [iOS migration section](MIGRATION.md#ios-default-storage-path-moved-from-nsdocumentdirectory-to-nsapplicationsupportdirectory).

***
