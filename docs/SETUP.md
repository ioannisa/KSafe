# Setup with Koin (Recommended)

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
    // Fast, unencrypted — for everyday preferences
    single(named("prefs")) {
        KSafe(
            context = androidApplication(),
            fileName = "prefs",
            memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT
        )
    }

    // Encrypted — for secrets (tokens, passwords, PII)
    single(named("vault")) {
        KSafe(
            context = androidApplication(),
            fileName = "vault"
        )
    }
}

// ──────────────────────────────────────────────
// iOS
// ──────────────────────────────────────────────
actual val platformModule = module {
    single(named("prefs")) {
        KSafe(
            fileName = "prefs",
            memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT
        )
    }

    single(named("vault")) {
        KSafe(
            fileName = "vault"
        )
    }
}

// ──────────────────────────────────────────────
// JVM/Desktop
// ──────────────────────────────────────────────
actual val platformModule = module {
    single(named("prefs")) {
        KSafe(
            fileName = "prefs",
            memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT
        )
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
        KSafe(
            fileName = "prefs",
            memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT
        )
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
- Must match the regex `[a-z][a-z0-9_]*` — start with a lowercase letter, followed by lowercase letters, digits, or underscores
- No spaces, dots, slashes, hyphens, or uppercase letters allowed
- Examples: `"userdata"`, `"settings"`, `"data_v2"`, `"cache"`

### Disposing an instance: `KSafe.close()`

In the singleton-per-process pattern above you never need to call anything to dispose `KSafe` — the OS reclaims everything when the process exits. The optional `close()` method exists for the small set of cases where you actually re-create `KSafe` mid-process:

- **Account or profile switching** that changes the `fileName` (you build a new instance for the new identity and abandon the old one).
- **Long-running JVM services** that build a fresh instance per session, tenant, or request.
- **Dev-time hot-reload** that rebuilds the DI graph and constructs new `KSafe`s on top of the previous ones.

```kotlin
val ksafe = KSafe(fileName = "session_$userId")
// ... use it ...
ksafe.close()  // cancels background coroutines, releases the DataStore scope and file handle
```

`close()` is idempotent. After calling it, the instance can no longer process reads or writes — discard the reference and build a new one if you need storage again. Calling `close()` on the typical app-lifetime singleton is harmless but achieves nothing the OS won't already do at process exit.

***

## Custom Storage Directory

By default KSafe picks a platform-appropriate location for its DataStore file:

| Platform | Default location |
|----------|-----------------|
| **Android** | `/data/data/<package>/files/datastore/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb` (the app sandbox — recommended) |
| **iOS** | `<NSApplicationSupportDirectory>/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb`. Encryption keys are device-local (`…ThisDeviceOnly` Keychain accessibility), so backed-up ciphertext is undecryptable on a restored device — effectively device-local in practice. See migration guide for details. |
| **JVM/Desktop** | `~/.eu_anifantakis_ksafe/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb`, with POSIX `0700` permissions |
| **Web** | `localStorage`, prefixed `ksafe_<fileName>_` (no directory concept) |

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

**Web** doesn't expose a directory concept — `localStorage` is per-origin and KSafe already isolates instances via the `ksafe_<fileName>_` storage prefix. There's no `baseDir` parameter on the web factory.

**iOS upgraders: migration is automatic.** Pre-2.0 KSafe stored its DataStore in `NSDocumentDirectory`. 2.0 moves the default to `NSApplicationSupportDirectory`. When you don't pass `directory` and the new path is empty, KSafe checks for a legacy file at the old location and moves it on first launch — no code changes needed. Details in the [iOS migration section](MIGRATION.md#ios-default-storage-path-moved-from-nsdocumentdirectory-to-nsapplicationsupportdirectory).

***
