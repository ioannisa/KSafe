# Biometric Authentication

The `:ksafe-biometrics` module provides a **standalone biometric authentication helper** for Android and iOS. It is a general-purpose utility that can protect **any action** in your app — KSafe persistence, API calls, navigation, in-app purchases, anything you want gated behind Face ID / Touch ID / Fingerprint.

The module is **independent of `:ksafe`** — you can use it on its own (no storage library required), or alongside KSafe.

## Setup

### 1 - Add the dependency

```kotlin
// commonMain or Android-only build.gradle(.kts)
implementation("eu.anifantakis:ksafe-biometrics:2.0.0-RC1")
```

That's it — no transitive dependency on `:ksafe`. Apps that don't need biometrics simply don't add this artifact.

### 2 - Instantiate

```kotlin
// Android — pass the application or activity context
val biometrics = KSafeBiometrics(context)

// iOS / JVM / web — no platform deps
val biometrics = KSafeBiometrics()
```

With Koin (recommended for KMP):

```kotlin
// Android
actual val platformBiometricsModule = module {
    single { KSafeBiometrics(androidApplication()) }
}

// iOS / JVM / web
actual val platformBiometricsModule = module {
    single { KSafeBiometrics() }
}
```

### 3 - Platform behaviour

| Platform | What it does |
|----------|--------------|
| Android | Real `BiometricPrompt` — BIOMETRIC_STRONG + DEVICE_CREDENTIAL |
| iOS device | Real `LAContext` — Face ID / Touch ID |
| iOS simulator | Returns `true` (no biometric hardware) |
| JVM, JS, WasmJS | Returns `true` (no biometric hardware) — useful for shared business logic in KMP |

## Two APIs

| Method | Type | Use Case |
|--------|------|----------|
| `verifyBiometricDirect(reason, authorizationDuration?) { success -> }` | Callback-based | Simple, non-blocking, works anywhere |
| `verifyBiometric(reason, authorizationDuration?): Boolean` | Suspend function | Coroutine-based, cleaner async code |

## Basic Usage

```kotlin
class MyViewModel(
    private val biometrics: KSafeBiometrics,
    private val ksafe: KSafe,                  // optional — only if you also use KSafe
) : ViewModel() {

    var secureCounter by ksafe.mutableStateOf(0)
        private set

    // Always prompt (no caching)
    fun incrementWithBiometric() {
        biometrics.verifyBiometricDirect("Authenticate to increment") { success ->
            if (success) secureCounter++
        }
    }

    // Coroutine-based approach
    fun incrementWithBiometricSuspend() {
        viewModelScope.launch {
            if (biometrics.verifyBiometric("Authenticate to increment")) {
                secureCounter++
            }
        }
    }
}
```

## Authorization Duration Caching

Avoid repeated biometric prompts by caching successful authentication:

```kotlin
data class BiometricAuthorizationDuration(
    val duration: Long,       // Duration in milliseconds
    val scope: String? = null // Optional scope identifier (null = global)
)

// Cache for 60 seconds (scoped to this ViewModel)
biometrics.verifyBiometricDirect(
    reason = "Authenticate",
    authorizationDuration = BiometricAuthorizationDuration(
        duration = 60_000L,
        scope = viewModelScope.hashCode().toString()
    )
) { success -> /* ... */ }
```

| Parameter | Meaning |
|-----------|---------|
| `authorizationDuration = null` | Always prompt (no caching) |
| `duration > 0` | Cache auth for this many milliseconds |
| `scope = null` | Global scope - any call benefits from cached auth |
| `scope = "xyz"` | Scoped auth - only calls with same scope benefit |

## Scoped Authorization Use Cases

```kotlin
// ViewModel-scoped: auth invalidates when ViewModel is recreated
BiometricAuthorizationDuration(60_000L, viewModelScope.hashCode().toString())

// User-scoped: auth invalidates on user change
BiometricAuthorizationDuration(300_000L, "user_$userId")

// Flow-scoped: auth shared across a multi-step flow
BiometricAuthorizationDuration(120_000L, "checkout_flow")
```

## Clearing Cached Authorization

```kotlin
biometrics.clearBiometricAuth()              // Clear all cached authorizations
biometrics.clearBiometricAuth("settings")    // Clear specific scope only
```

## Protecting Any Action

```kotlin
// Protect API calls
fun deleteAccount() {
    biometrics.verifyBiometricDirect("Confirm account deletion") { success ->
        if (success) api.deleteAccount()
    }
}

// Protect navigation
fun navigateToSecrets() {
    biometrics.verifyBiometricDirect("Authenticate to view secrets") { success ->
        if (success) navController.navigate("secrets")
    }
}

// Protect a KSafe write — biometrics and storage are completely independent
fun saveSecret(value: String) {
    biometrics.verifyBiometricDirect("Confirm save") { success ->
        if (success) ksafe.putDirect("secret", value)
    }
}
```

## Platform Setup

### Android

**Permission** — Add to `AndroidManifest.xml`:
```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
```

**Activity Requirement** — `BiometricPrompt` requires `FragmentActivity` or `AppCompatActivity`:
```kotlin
// Won't work with biometrics
class MainActivity : ComponentActivity()

// Works with biometrics
class MainActivity : AppCompatActivity()
```

**Early Initialization** — `KSafeBiometrics` must be instantiated before any Activity is created so it can register lifecycle callbacks. The cleanest place is the `Application.onCreate()`:
```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        startKoin {
            androidContext(this@MyApplication)
            modules(appModule)
        }
        get<KSafeBiometrics>()  // Force initialization — registers Activity tracking
    }
}
```

**Customizing the Prompt:**
```kotlin
import eu.anifantakis.lib.ksafe.biometrics.BiometricHelper

BiometricHelper.promptTitle = "Unlock Secure Data"
BiometricHelper.promptSubtitle = "Authenticate to continue"
BiometricHelper.confirmationRequired = true   // false to allow passive face-unlock
```

`BiometricHelper` is in the `eu.anifantakis.lib.ksafe.biometrics` package and ships with `:ksafe-biometrics`.

### iOS

**Info.plist** — Add Face ID usage description:
```xml
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to access secure data</string>
```

**Note:** On the iOS Simulator, biometric verification always returns `true` since there's no biometric hardware.

## Complete Example

```kotlin
class SecureViewModel(
    private val biometrics: KSafeBiometrics,
    private val ksafe: KSafe,
) : ViewModel() {

    // Regular persisted counter (no biometric)
    var counter by ksafe.mutableStateOf(0)
        private set

    // Counter that requires biometric to increment
    var bioCounter by ksafe.mutableStateOf(0)
        private set

    fun incrementCounter() {
        counter++  // No biometric prompt
    }

    // Always prompt
    fun incrementBioCounter() {
        biometrics.verifyBiometricDirect("Authenticate to save") { success ->
            if (success) {
                bioCounter++
            }
        }
    }

    // With 60s duration caching (scoped to this ViewModel instance)
    fun incrementBioCounterCached() {
        biometrics.verifyBiometricDirect(
            reason = "Authenticate to save",
            authorizationDuration = BiometricAuthorizationDuration(
                duration = 60_000L,
                scope = viewModelScope.hashCode().toString()
            )
        ) { success ->
            if (success) {
                bioCounter++
            }
        }
    }

    // Suspend function with caching
    fun incrementBioCounterAsync() {
        viewModelScope.launch {
            val authDuration = BiometricAuthorizationDuration(
                duration = 60_000L,
                scope = viewModelScope.hashCode().toString()
            )
            if (biometrics.verifyBiometric("Authenticate to save", authDuration)) {
                bioCounter++
            }
        }
    }

    // Call on logout to force re-authentication
    fun onLogout() {
        biometrics.clearBiometricAuth()  // Clear all cached auth
    }
}
```

## Migration from KSafe 1.x

Pre-2.0, biometric verification was a member of `KSafe`:

```kotlin
// Before (1.x)
import eu.anifantakis.lib.ksafe.BiometricAuthorizationDuration
ksafe.verifyBiometricDirect(reason, BiometricAuthorizationDuration(60_000L)) { ok -> }
```

In 2.0 it moved to its own module ([issue #14](https://github.com/ioannisa/KSafe/issues/14)):

```kotlin
// After (2.0)
// build.gradle.kts: + implementation("eu.anifantakis:ksafe-biometrics:2.0.0-RC1")
import eu.anifantakis.lib.ksafe.biometrics.KSafeBiometrics
import eu.anifantakis.lib.ksafe.biometrics.BiometricAuthorizationDuration

val biometrics = KSafeBiometrics(context) // Android
biometrics.verifyBiometricDirect(reason, BiometricAuthorizationDuration(60_000L)) { ok -> }
```

Method names and signatures are preserved — only the receiver and import paths change. `BiometricHelper.confirmationRequired` and `BiometricHelper.promptTitle` continue to work the same way, just imported from `eu.anifantakis.lib.ksafe.biometrics` instead of `eu.anifantakis.lib.ksafe`.

**Key Points:**
- Biometrics is a **standalone module** — `:ksafe-biometrics` does not depend on `:ksafe`
- Use it to protect **any action** (persistence, API calls, navigation, etc.)
- Two APIs: callback-based (`verifyBiometricDirect`) and suspend (`verifyBiometric`)
- Optional duration caching with `BiometricAuthorizationDuration`
- Scoped authorization for fine-grained control over cache invalidation
- Works on Android (BiometricPrompt) and iOS (LocalAuthentication); JVM / JS / WasmJS return `true` so shared KMP business logic compiles unchanged
- On Android, requires `AppCompatActivity` and early `KSafeBiometrics` initialization
