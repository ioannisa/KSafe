# Biometric Authentication

The `:ksafe-biometrics` module provides a **standalone biometric authentication helper** with real OS prompts on Android, iOS, macOS, JVM Desktop (macOS Touch ID / Windows Hello), and the web (WebAuthn platform authenticator). It is a general-purpose utility that can protect **any action** in your app — KSafe persistence, API calls, navigation, in-app purchases, anything you want gated behind Face ID / Touch ID / Fingerprint.

The module is **independent of `:ksafe`** — you can use it on its own (no storage library required), or alongside KSafe.

## Setup

### 1 - Add the dependency

```kotlin
// commonMain or Android-only build.gradle(.kts)
implementation("eu.anifantakis:ksafe-biometrics:3.0.0")
```

That's it — no transitive dependency on `:ksafe`. Apps that don't need biometrics simply don't add this artifact.

### 2 - Call it

There is no init step. `KSafeBiometrics` is a static API:

```kotlin
val ok = KSafeBiometrics.verifyBiometric("Authenticate to continue")
```

### Prompt text

Three process-wide defaults, set once at startup, plus per-call overrides on
`verifyBiometric` / `verifyBiometricDirect`:

```kotlin
KSafeBiometrics.defaultTitle = "Commercials Manager"      // app/service name
KSafeBiometrics.defaultReason = "Unlock to continue"      // why you're asking
KSafeBiometrics.defaultCancelLabel = null                 // null -> the platform's localized default

KSafeBiometrics.verifyBiometric()                          // uses the defaults
KSafeBiometrics.verifyBiometric("Confirm transaction")     // per-call reason
KSafeBiometrics.verifyBiometric(title = "Something else")  // per-call title
```

| | `reason` | `title` | `cancelLabel` |
|---|---|---|---|
| Android | prompt subtitle | prompt title (default: the app's launcher label) | negative button of a biometrics-only prompt (default: the platform's translated *Cancel*); a device-credential prompt has no negative button |
| iOS / macOS | `localizedReason` | — (no title in `LAContext`) | `localizedCancelTitle` (default: system) |
| JVM Desktop | Windows Hello / macOS message | — | — |
| Web | — (browser owns the dialog) | **names the passkey** (`rp.name`, `user.name`, `user.displayName`) | — |

> **Web:** the passkey name is written **once**, during the first registration ceremony — what a
> password manager then lists forever. Set `defaultTitle` before the first `verifyBiometric()`
> call (next to `awaitCacheReady()`).

If you rename the app later, inspect what is enrolled and re-enroll **once** — never
unconditionally, or every user re-runs the ceremony on every launch:

```kotlin
KSafeBiometrics.defaultTitle = "Commercials Manager"

if (KSafeBiometricsWeb.isRegistered &&
    KSafeBiometricsWeb.registeredTitle != KSafeBiometrics.defaultTitle
) {
    KSafeBiometricsWeb.resetRegistration()   // next verifyBiometric() enrolls under the new name
}
```

A passkey enrolled by KSafe < 3.0.0 has no recorded title, so `registeredTitle` is `null` and the
condition fires exactly once. Renaming does not rename the existing passkey, but `resetRegistration()`
signals the abandoned credential to the passkey provider (WebAuthn `signalUnknownCredential`), so
browsers that support it drop the stale entry on their own. That signal is advisory and
feature-detected: where it is unsupported or ignored, the old passkey lingers next to the new one and
the user has to delete it in their password manager.

`isRegistered` / `registeredTitle` reflect KSafe's **own local record**, and are never invalidated
automatically. A passkey the user deleted in their password manager keeps reading registered while
every verification fails — KSafe cannot tell that apart from a cancelled prompt, because WebAuthn
deliberately reports both as `NotAllowedError` (otherwise a site could probe for credentials), so
clearing the enrollment on failure would punish a user who merely pressed Cancel.

Recovery is therefore an app decision: surface a **"reset biometric unlock"** action (or offer it
after repeated failures) that calls `resetRegistration()`. Conversely, clearing site data reads
unregistered while the passkey may survive, orphaned, in the password manager.

Same call shape on every platform — no `Context`, no instance, no DI wiring.

On Android, the library auto-initializes via a `ContentProvider` declared in its merged `AndroidManifest.xml` (the same pattern WorkManager / Firebase / AppCompat use). The provider runs at process startup with the application Context and registers the activity-lifecycle observers that `BiometricPrompt` needs. The consumer doesn't have to touch their `Application` class.

### 3 - Platform behaviour

| Platform | `allowDeviceCredentialFallback = true` (default) | `allowDeviceCredentialFallback = false` |
|----------|--------------------------------------------------|----------------------------------------|
| Android | `BiometricPrompt` — BIOMETRIC_STRONG + DEVICE_CREDENTIAL (BIOMETRIC_WEAK + DEVICE_CREDENTIAL on API 28-29, the two levels where androidx rejects the strong pairing) | `BiometricPrompt` — BIOMETRIC_STRONG only (Cancel button shown) |
| iOS device | `LAContext` — Face ID / Touch ID + password | `LAContext` — Face ID / Touch ID only |
| iOS simulator | Returns `true` (no biometric hardware) | Returns `true` |
| macOS | `LAContext` — Touch ID, password, or Apple Watch | `LAContext` — Touch ID only (fails gracefully on Macs without Touch ID) |
| JVM on macOS (2.2.1+) | `LAContext` — Touch ID, password, or Apple Watch | `LAContext` — Touch ID only |
| JVM on Windows (2.2.1+) | Windows Hello — biometrics or Hello PIN | Windows Hello (the Hello PIN cannot be excluded — platform limitation); hard-refuses if Hello is absent |
| JS, WasmJS (2.2.1+) | WebAuthn platform authenticator — Touch ID / Windows Hello / fingerprint | Same prompt (the platform PIN cannot be excluded where the OS treats it as part of the authenticator); hard-refuses if no platform authenticator |
| JVM on Linux | Returns `true` (no portable prompt API) | Returns `true` |

> JVM desktop and web prompts are on by default from 2.2.1. Opt-outs restore the
> pre-2.2.1 always-`true` no-op: `-Dksafe.biometrics.jvm.prompts=off` (or env
> `KSAFE_BIOMETRICS_JVM_PROMPTS=off`) on JVM desktop, `KSafeBiometricsWeb.promptsEnabled
> = false` on the web.
>
> **Web specifics (JS/WasmJS).** The prompt is a WebAuthn *platform authenticator*
> ceremony used as a local re-auth gate (self-generated challenge, no server). The first
> successful call enrolls a platform WebAuthn credential for the origin (non-discoverable —
> KSafe keeps its id in `localStorage` rather than relying on a synced/discoverable passkey)
> — that ceremony itself verifies the user — and later calls verify against it. The `reason` string is **not displayed**
> (WebAuthn dialogs are browser-controlled). Call from a user gesture (e.g. a click
> handler) or the browser may reject the ceremony, and a secure context (HTTPS or
> localhost) is required. If the user removes the credential OS-side, call
> `KSafeBiometricsWeb.resetRegistration()` to force a fresh enrollment.

## Checking availability — `biometricsAvailable()`

Ask up front whether `verifyBiometric` would show a **real** prompt — `false` means the
call would pass through (permissive) or refuse (strict) without gating, so your app can
route to an alternative flow (its own PIN screen, a password) instead:

```kotlin
if (KSafeBiometrics.biometricsAvailable()) {          // suspend; also: biometricsAvailableDirect { }
    if (KSafeBiometrics.verifyBiometric("Unlock")) unlock()
} else {
    showPinScreenInstead()
}
```

The check never shows UI and needs no user gesture. It is `suspend` because the browser
(WebAuthn) and Windows (Hello) can only answer asynchronously — the recommended pattern is
to probe **once at startup** and keep the result in app state (on web, right next to the
`awaitCacheReady()` call you already make):

```kotlin
LaunchedEffect(Unit) {
    ksafe.awaitCacheReady()                                        // web storage readiness
    appState.canUseBiometrics = KSafeBiometrics.biometricsAvailable()
    ready = true
}
```

On Android the answer also depends on a live `FragmentActivity` / `AppCompatActivity` host, so
probe from a composition or an Activity as the sample above does — never from
`Application.onCreate`, where no host exists yet and the cached answer would be a permanent
`false`. `verifyBiometric` waits for that host; this probe does not.

The optional `allowDeviceCredentialFallback` parameter mirrors `verifyBiometric`:
`biometricsAvailable(false)` asks whether a **biometrics-only** prompt is possible.
Reports `false` under the opt-outs, on JVM Linux (no prompt API), and on the iOS
Simulator (where `verifyBiometric` is a pass-through).

## Two APIs

| Method | Type | Use Case |
|--------|------|----------|
| `KSafeBiometrics.verifyBiometricDirect(reason, authorizationDuration?, allowDeviceCredentialFallback = true, title = defaultTitle, cancelLabel = defaultCancelLabel) { success -> }` | Callback-based | Simple, non-blocking, works anywhere |
| `KSafeBiometrics.verifyBiometric(reason, authorizationDuration?, allowDeviceCredentialFallback = true, title = defaultTitle, cancelLabel = defaultCancelLabel): Boolean` | Suspend function | Coroutine-based, cleaner async code |

Set `allowDeviceCredentialFallback = false` to require biometrics only — the system PIN / password / pattern (Android) or login password / Apple Watch (macOS) won't satisfy the prompt. The platform behaviour table above shows what each platform does in each mode.

## Basic Usage

```kotlin
class MyViewModel(
    private val ksafe: KSafe,                  // optional — only if you also use KSafe
) : ViewModel() {

    var secureCounter by ksafe.mutableStateOf(0)
        private set

    // Always prompt (no caching)
    fun incrementWithBiometric() {
        KSafeBiometrics.verifyBiometricDirect("Authenticate to increment") { success ->
            if (success) secureCounter++
        }
    }

    // Coroutine-based approach
    fun incrementWithBiometricSuspend() {
        viewModelScope.launch {
            if (KSafeBiometrics.verifyBiometric("Authenticate to increment")) {
                secureCounter++
            }
        }
    }
}
```

`KSafeBiometrics` is not injected — it's called directly. There is no Koin / Hilt module to add for biometrics.

## Authorization Duration Caching

Avoid repeated biometric prompts by caching successful authentication:

```kotlin
data class BiometricAuthorizationDuration(
    val duration: Long,       // Duration in milliseconds
    val scope: String? = null // Optional scope identifier (null = global)
)

// Cache for 60 seconds (scoped to this ViewModel)
KSafeBiometrics.verifyBiometricDirect(
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
| `scope = null` | Global scope - any call of the same auth strength benefits from cached auth |
| `scope = "xyz"` | Scoped auth - only calls with same scope benefit |

The auth cache is process-wide. Use `scope` to partition it per feature / screen / user / flow.

The cache is also partitioned by authentication strength: an authorization obtained with `allowDeviceCredentialFallback = true` (permissive) does **not** satisfy a later biometrics-only call (`allowDeviceCredentialFallback = false`), even under the same or null/global scope. Each (scope, strength) combination keeps its own timestamp.

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
KSafeBiometrics.clearBiometricAuth()              // Clear all cached authorizations
KSafeBiometrics.clearBiometricAuth("settings")    // Clear specific scope only
```

## Protecting Any Action

```kotlin
// Protect API calls
fun deleteAccount() {
    KSafeBiometrics.verifyBiometricDirect("Confirm account deletion") { success ->
        if (success) api.deleteAccount()
    }
}

// Protect navigation
fun navigateToSecrets() {
    KSafeBiometrics.verifyBiometricDirect("Authenticate to view secrets") { success ->
        if (success) navController.navigate("secrets")
    }
}

// Protect a KSafe write — biometrics and storage are completely independent
fun saveSecret(value: String) {
    KSafeBiometrics.verifyBiometricDirect("Confirm save") { success ->
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

**Auto-init** — `KSafeBiometrics` registers its activity-lifecycle observer automatically via a `ContentProvider` declared in the library's merged manifest. You do **not** need to call any init function in your `Application.onCreate`. The provider's authority is `${applicationId}.ksafe-biometrics-init` so it can't collide with other libraries. If you specifically want to disable auto-init (rare), override the provider in your app's manifest with `tools:node="remove"` — but in nearly every case there's no reason to.

**Customizing the Prompt:** prompt text is set from common code (see [Prompt text](#prompt-text)); only the Android-specific confirmation toggle lives on `BiometricHelper`:

```kotlin
import eu.anifantakis.lib.ksafe.biometrics.BiometricHelper

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

### macOS

No manifest entries or special entitlements are required for basic Touch ID / password authentication via `LocalAuthentication`.

**Sandboxed apps** — if your app is distributed through the Mac App Store (sandboxed), add the `com.apple.security.device.biometrics` entitlement to your entitlements file to enable Touch ID:
```xml
<key>com.apple.security.device.biometrics</key>
<true/>
```

**Unsandboxed apps** — Touch ID and password authentication work without any entitlement. On first Keychain access (when `:ksafe` is also used), macOS may show a system password prompt; suppress it by signing the app with a Keychain access group entitlement.

**Fallback behaviour** — depends on `allowDeviceCredentialFallback`. With the default `true`, KSafe uses `LAPolicyDeviceOwnerAuthentication`, so the system automatically falls back to the macOS login password on machines without Touch ID (Mac mini, Intel MacBooks without T2, etc.) — `verifyBiometric` always produces a real prompt. With `false`, KSafe uses `LAPolicyDeviceOwnerAuthenticationWithBiometrics` (Touch ID only) — on a Mac without Touch ID the policy fails up front and `verifyBiometric` returns `false`. Pick `false` when biometric-grade auth is a hard requirement; pick `true` (default) when you just need to confirm the human at the keyboard.

## Complete Example

```kotlin
class SecureViewModel(
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
        KSafeBiometrics.verifyBiometricDirect("Authenticate to save") { success ->
            if (success) {
                bioCounter++
            }
        }
    }

    // With 60s duration caching (scoped to this ViewModel instance)
    fun incrementBioCounterCached() {
        KSafeBiometrics.verifyBiometricDirect(
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
            if (KSafeBiometrics.verifyBiometric("Authenticate to save", authDuration)) {
                bioCounter++
            }
        }
    }

    // Call on logout to force re-authentication
    fun onLogout() {
        KSafeBiometrics.clearBiometricAuth()  // Clear all cached auth
    }
}
```

## Mocking in tests

`KSafeBiometrics` is a Kotlin `object`, so you can't substitute it through normal constructor injection. The recommended pattern is to wrap calls in your own thin interface that you do inject:

```kotlin
interface BiometricGate {
    suspend fun verify(reason: String): Boolean
}

class DefaultBiometricGate : BiometricGate {
    override suspend fun verify(reason: String): Boolean =
        KSafeBiometrics.verifyBiometric(reason)
}
```

Inject `BiometricGate` into your ViewModels; provide a fake in tests. This keeps the friction-free static call shape for production code while preserving testability where it matters. Mockk can also mock objects directly if you prefer — `mockkObject(KSafeBiometrics)` works.

## Migration from KSafe 1.x

Pre-2.0, biometric verification was a member of `KSafe`:

```kotlin
// Before (1.x)
import eu.anifantakis.lib.ksafe.BiometricAuthorizationDuration
ksafe.verifyBiometricDirect(reason, BiometricAuthorizationDuration(60_000L)) { ok -> }
```

In 2.0 it moved to its own module ([issue #14](https://github.com/ioannisa/KSafe/issues/14)) as a static API:

```kotlin
// After (2.0)
// build.gradle.kts: + implementation("eu.anifantakis:ksafe-biometrics:3.0.0")  // or latest
import eu.anifantakis.lib.ksafe.biometrics.KSafeBiometrics
import eu.anifantakis.lib.ksafe.biometrics.BiometricAuthorizationDuration

KSafeBiometrics.verifyBiometricDirect(reason, BiometricAuthorizationDuration(60_000L)) { ok -> }
```

Method names and signatures are preserved — only the receiver and import paths change. `BiometricHelper.confirmationRequired` continues to work the same way, just imported from `eu.anifantakis.lib.ksafe.biometrics` instead of `eu.anifantakis.lib.ksafe`. (`BiometricHelper.promptTitle` / `promptSubtitle` were removed in 3.0.0 — set `KSafeBiometrics.defaultTitle` / `defaultReason` instead, which are common code; `defaultTitle` is also what names the web passkey, while `defaultReason` is ignored there.)

**Key Points:**
- Biometrics is a **standalone module** — `:ksafe-biometrics` does not depend on `:ksafe`
- **Static API** — call `KSafeBiometrics.verifyBiometric(...)` directly. No DI, no `Context`, no init.
- Use it to protect **any action** (persistence, API calls, navigation, etc.)
- Two APIs: callback-based (`verifyBiometricDirect`) and suspend (`verifyBiometric`)
- Optional duration caching with `BiometricAuthorizationDuration`
- Scoped authorization for fine-grained control over cache invalidation
- Real prompts on Android (BiometricPrompt), iOS (LAContext — Face ID / Touch ID), macOS (LAContext — Touch ID, password, or Apple Watch), JVM Desktop (macOS Touch ID / Windows Hello, on by default from 2.2.1), and the web (WebAuthn platform authenticator, on by default from 2.2.1); JVM on Linux has no portable prompt API and returns `true` so shared KMP business logic compiles unchanged
- On Android, requires `AppCompatActivity`. Auto-init via ContentProvider — no `Application` changes needed.
- On macOS, the LAPolicy depends on `allowDeviceCredentialFallback`: default `true` → `LAPolicyDeviceOwnerAuthentication` (Touch ID + password + Apple Watch, always prompts even without Touch ID); `false` → `LAPolicyDeviceOwnerAuthenticationWithBiometrics` (Touch ID only, returns `false` on hardware-less Macs).
