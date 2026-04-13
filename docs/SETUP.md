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
// WASM — call ksafe.awaitCacheReady() before first encrypted read (see note below)
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

// iOS / JVM / WASM
actual val platformModule = module {
    single { KSafe() }
}
```

### `ksafe.awaitCacheReady()` Required ONLY at WasmJs

> **WASM/JS:** WebCrypto encryption is async-only, so KSafe must finish decrypting its cache before your UI reads any encrypted values. Call `awaitCacheReady()` before rendering content.
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
