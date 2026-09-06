# Biometric Authentication

The `:ksafe-biometrics` module provides a **standalone biometric authentication helper** with real OS prompts on Android, iOS, macOS, JVM Desktop (macOS Touch ID / Windows Hello), and the web (WebAuthn platform authenticator). It is a general-purpose utility that can protect **any action** in your app — KSafe persistence, API calls, navigation, in-app purchases, anything you want gated behind Face ID / Touch ID / Fingerprint.

The module is **independent of `:ksafe`** — you can use it on its own (no storage library required), or alongside KSafe.

Names you will meet on this page:

- **`BiometricPrompt`** — Android's system authentication dialog, from the `androidx.biometric` library.
- **`LAContext`** — Apple's equivalent, from the `LocalAuthentication` framework (iOS and macOS).
- **Device credential** — the screen lock itself: a PIN, pattern or password on Android, the passcode on iOS, the login password on a Mac.
- **WebAuthn platform authenticator** — the browser's own authentication dialog, backed by the device's Touch ID, Windows Hello or fingerprint reader.
- **Passkey** — the credential that dialog creates. It is what the user's password manager lists, under the name it was registered with.

## Setup

### 1 - Add the dependency

```kotlin
// commonMain or Android-only build.gradle(.kts)
implementation("eu.anifantakis:ksafe-biometrics:3.1.0")
```

That's it — no transitive dependency on `:ksafe`. Apps that don't need biometrics leave this artifact out.

### 2 - Call it

There is no init step. `KSafeBiometrics` is a static API:

```kotlin
val ok = KSafeBiometrics.verifyBiometric("Authenticate to continue")
```

Same call shape on every platform — no `Context`, no instance, no DI wiring.

On Android, the library auto-initializes via a `ContentProvider` declared in its merged `AndroidManifest.xml` (the same pattern WorkManager / Firebase / AppCompat use). The provider runs at process startup with the application Context and registers the activity-lifecycle observers that `BiometricPrompt` needs. The consumer doesn't have to touch their `Application` class.

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

If you set nothing: `defaultTitle` starts as `null`, so Android shows the app's launcher label and the web names the passkey `KSafe` — which is what the user's password manager will list. `defaultReason` starts as `Authenticate to continue`. Blank text counts as unset — which matters because an empty string is what a missing translation resolves to. A blank `title` or `cancelLabel` falls back to the platform's own default; a blank `reason` falls back to that same built-in `Authenticate to continue`. Neither ever reaches the platform, where an empty prompt string is rejected outright.

The web is the one place where the title outlives the call, because it is baked into the passkey — see [Web (JS / WasmJS)](#web-js--wasmjs).

### 3 - Platform behaviour

Two things decide what the user sees: the platform, and `allowDeviceCredentialFallback`.

- **`true` (the default)** — call this the **permissive** mode. The prompt also accepts what the device accepts instead of a biometric: a PIN, pattern or password, or on a Mac the login password or an Apple Watch.
- **`false`** — call this the **strict** mode. Biometrics only; a PIN or password will not satisfy it.

A third outcome runs underneath both. Where there is nothing to show, the call **passes through**: it returns `true` without asking the user anything, so one piece of shared code compiles and runs on every target. There are two kinds of pass-through:

- **No prompt path at all** — JVM on Linux, the iOS Simulator, or either opt-out below. Both modes pass through and return `true`.
- **A prompt path that cannot be used right now** — the desktop native bridge did not load, Windows Hello is not set up, the browser has no platform authenticator. The permissive mode passes through (`true`); the strict mode refuses (`false`).

Ask [`biometricsAvailable()`](#checking-availability--biometricsavailable) up front if your app must know which case it is in.

| Platform | permissive — `allowDeviceCredentialFallback = true` (default) | strict — `allowDeviceCredentialFallback = false` |
|----------|---------------------------------------------------------------|--------------------------------------------------|
| Android | `BiometricPrompt` — BIOMETRIC_STRONG + DEVICE_CREDENTIAL (BIOMETRIC_WEAK + DEVICE_CREDENTIAL on API 28-29, the two levels where androidx rejects the strong pairing) | `BiometricPrompt` — BIOMETRIC_STRONG only, with a Cancel button |
| iOS device | `LAContext` — Face ID / Touch ID, passcode as fallback | `LAContext` — Face ID / Touch ID only |
| iOS Simulator | passes through — `true`, no prompt | passes through — `true`, no prompt |
| macOS | `LAContext` — Touch ID, login password, or Apple Watch | `LAContext` — Touch ID only; `false` on a Mac without Touch ID |
| JVM on macOS (2.2.1+) | `LAContext` through a native bridge — Touch ID, login password, or Apple Watch | Touch ID only; refuses when Touch ID is absent or the bridge did not load |
| JVM on Windows (2.2.1+) | Windows Hello — biometrics or the Hello PIN. Hello absent, not configured, or disabled by policy: passes through (`true`, no prompt) | Windows Hello (the Hello PIN cannot be excluded — Windows counts it as Hello); refuses when Hello is unusable or the bridge did not load |
| JS, WasmJS (2.2.1+) | WebAuthn platform authenticator — Touch ID / Windows Hello / fingerprint. No platform authenticator, or a page not served over HTTPS or localhost: passes through (`true`, no prompt) | Same prompt (the platform PIN cannot be excluded where the OS treats it as part of the authenticator); refuses when there is no usable platform authenticator |
| JVM on Linux | passes through — `true` (no portable prompt API) | passes through — `true` |

> **Opt-outs.** JVM desktop and web prompts are on by default from 2.2.1. Turning them off restores
> the pre-2.2.1 always-`true` no-op in both modes: `-Dksafe.biometrics.jvm.prompts=off` (or env
> `KSAFE_BIOMETRICS_JVM_PROMPTS=off`) on JVM desktop, `KSafeBiometricsWeb.promptsEnabled = false`
> on the web.
>
> **JVM desktop bridge.** With prompts enabled, the macOS and Windows prompts go through a native
> bridge (the Objective-C runtime / COM, via JNA) that loads on first use. A failed load warns once
> on stderr; from then on the permissive mode passes through, every strict refusal is logged, and
> `biometricsAvailable()` reports `false` in either mode. That is not the Linux case, where no
> prompt path exists at all and both modes pass through.

## Checking availability — `biometricsAvailable()`

Ask up front whether `verifyBiometric` would show a **real** prompt. `false` means the call
would pass through (permissive) or refuse (strict) without gating anything, so your app can
route to an alternative flow — its own PIN screen, a password:

```kotlin
if (KSafeBiometrics.biometricsAvailable()) {          // suspend; also: biometricsAvailableDirect { }
    if (KSafeBiometrics.verifyBiometric("Unlock")) unlock()
} else {
    showPinScreenInstead()
}
```

The check shows no UI and needs no user gesture. It is `suspend` because the browser (WebAuthn)
and Windows (Hello) can only answer asynchronously, so probe **once at startup** and keep the
answer in app state:

```kotlin
// Android / iOS / macOS / JVM Desktop
LaunchedEffect(Unit) {
    appState.canUseBiometrics = KSafeBiometrics.biometricsAvailable()
    ready = true
}

// Web — awaitCacheReady() is a web-only extension on KSafe, visible from jsMain / wasmJsMain
LaunchedEffect(Unit) {
    ksafe.awaitCacheReady()                                        // web storage readiness
    appState.canUseBiometrics = KSafeBiometrics.biometricsAvailable()
    ready = true
}
```

On Android the answer also depends on a live `FragmentActivity` / `AppCompatActivity` host, so
probe from a composition or an Activity as above — never from `Application.onCreate`, where no
host exists yet and the cached answer would be a permanent `false`. `verifyBiometric` waits up
to five seconds for that host; this probe does not wait at all.

`biometricsAvailable(false)` asks the same question about a **biometrics-only** prompt. Android,
iOS/macOS and JVM-on-macOS answer it for real — they probe the strict policy. JVM-on-Windows and
the web accept the argument but cannot narrow their answer, because neither platform can exclude
its own PIN.

It reports `false` under either opt-out, on JVM Linux, on JVM macOS/Windows when the native
bridge did not load or Windows Hello is not set up, on the iOS Simulator, and on Android while
no `FragmentActivity` exists yet. It also reports `false` when the user has enrolled nothing the
prompt would accept — no biometric in the strict mode, and neither a biometric nor a screen lock
in the permissive one.

## Two APIs

Both do the same work. Pick by whether you are already in a coroutine.

```kotlin
object KSafeBiometrics {

    // suspend — resumes when the prompt closes
    suspend fun verifyBiometric(
        reason: String = defaultReason,
        authorizationDuration: BiometricAuthorizationDuration? = null,
        allowDeviceCredentialFallback: Boolean = true,
        title: String? = defaultTitle,
        cancelLabel: String? = defaultCancelLabel,
    ): Boolean

    // callback — for code that is not in a coroutine
    fun verifyBiometricDirect(
        reason: String = defaultReason,
        authorizationDuration: BiometricAuthorizationDuration? = null,
        allowDeviceCredentialFallback: Boolean = true,
        title: String? = defaultTitle,
        cancelLabel: String? = defaultCancelLabel,
        onResult: (Boolean) -> Unit,
    )
}
```

Everything except the callback has a default, so `verifyBiometric()` and
`verifyBiometric("Confirm transaction")` are both complete calls.

What you can rely on:

- **`true`** means one of three things: the user authenticated, a live cached authorization covered the call, or the platform passed through (see the table above). **`false`** means the prompt failed, was dismissed, or was refused.
- **One prompt at a time, per process.** A second call made while a prompt is up waits for it, then re-checks the authorization cache: if the first call seeded a slot this one shares, it skips its own prompt. Two screens asking at once never stack two dialogs.
- **Cancellation is not a `false`.** Cancelling the coroutine that called `verifyBiometric` dismisses the prompt and raises `CancellationException` in the caller, so a `catch`-all around the call must let that through. `verifyBiometricDirect` has no caller to cancel — it runs in the library's own scope and always ends in `onResult`.
- **Callback thread.** `onResult` runs on the main thread on Android and Apple, and on a background thread on JVM Desktop — post to your UI thread there before touching UI. On the web everything runs on the page's single thread.

Set `allowDeviceCredentialFallback = false` to require biometrics only: the system PIN / password / pattern (Android) or login password / Apple Watch (macOS) won't satisfy the prompt. The platform behaviour table above shows what each platform does in each mode.

## Basic Usage

```kotlin
class MyViewModel(
    private val ksafe: KSafe,   // only if you also store values — :ksafe, plus :ksafe-compose for mutableStateOf
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

A successful prompt can be remembered for a while, so a burst of protected actions asks the user once.

```kotlin
data class BiometricAuthorizationDuration(
    val duration: Long,       // milliseconds the authorization stays valid
    val scope: String? = null // which slot it is stored in; null = the global slot
)

// Remember this success for 60 seconds, for the settings screen only
KSafeBiometrics.verifyBiometricDirect(
    reason = "Authenticate",
    authorizationDuration = BiometricAuthorizationDuration(
        duration = 60_000L,
        scope = "settings_screen"
    )
) { success -> /* ... */ }
```

| Argument | What happens |
|-----------|--------------|
| `authorizationDuration = null` (default) | Always prompts |
| `duration` of 0 or less | Always prompts — nothing is cached |
| `duration > 0` | A success is remembered for that many milliseconds |
| `scope = null` | The global slot: any other call with `scope = null` in the same mode skips its prompt |
| `scope = "xyz"` | Only calls passing the same string benefit |

Rules worth knowing before you rely on it:

- The cache lives in memory, in one process. It is empty again after a restart and is never written to disk.
- It is measured on a monotonic clock, so changing the device clock cannot extend an authorization.
- Freshness is judged against the duration of the call asking, not the one that filled the slot. A `300_000L` call can ride on a prompt taken four minutes ago in the same scope; a `10_000L` call in that scope will not.
- Each scope keeps two separate slots, one per mode. An authorization earned in the permissive mode (`allowDeviceCredentialFallback = true`) never satisfies a later strict call, even in the same scope — a PIN success must not open a biometrics-only gate.
- A pass-through where no prompt path exists — Linux, the desktop opt-out, the web with no platform authenticator — returns `true` without asking anyone, and leaves the cache untouched. A desktop pass-through that does have a prompt path — Windows Hello unavailable or not configured, or a native bridge that failed to load — still fills the slot, and so does the iOS Simulator, which returns `true` before any `LAContext` call.

## Scoped Authorization Use Cases

`scope` is only a string used as a cache key. Give it a stable name that says which part of the app
the authorization belongs to:

```kotlin
BiometricAuthorizationDuration(60_000L, "settings_screen")   // one screen
BiometricAuthorizationDuration(300_000L, "user_$userId")     // a different user asks under a different key
BiometricAuthorizationDuration(120_000L, "checkout_flow")    // shared across a multi-step flow
```

A key built from an object's identity — `viewModelScope.hashCode().toString()`, say — works but
misleads: a recreated ViewModel does not invalidate anything, it only asks under a new key and
leaves the old slot to expire on its own, and two unrelated objects that happen to share a hash
code would share one authorization. When you want an authorization gone *now*, call
`clearBiometricAuth(scope)`.

## Clearing Cached Authorization

```kotlin
KSafeBiometrics.clearBiometricAuth()              // Clear all cached authorizations
KSafeBiometrics.clearBiometricAuth("settings")    // Clear specific scope only
```

Clearing a scope drops both of its slots — the permissive one and the biometrics-only one. A
prompt already on screen still returns `true` to the caller waiting on it, but it can no longer
refill the cache, so the next call prompts again. Call this on logout, on lock, and when the
signed-in user changes.

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

**Permission** — nothing to add. `:ksafe-biometrics` depends on `androidx.biometric`, whose own
manifest declares `android.permission.USE_BIOMETRIC`, and the manifest merger copies it into your
app. Declaring it yourself is harmless and changes nothing. Nothing in the library asks for a
runtime permission.

**Activity Requirement** — `BiometricPrompt` is a fragment, so it needs a `FragmentActivity` host.
`AppCompatActivity` is one; the `ComponentActivity` a plain Compose template ships with is not.

```kotlin
// Won't work with biometrics
class MainActivity : ComponentActivity()

// Works with biometrics
class MainActivity : AppCompatActivity()
```

A call made while no such Activity is in the foreground waits up to five seconds for one
(`BiometricHelper.activityWaitTimeoutMs`) and then returns `false`. So does a call whose host
Activity stops before the prompt reaches the screen. The same requirement is why
`biometricsAvailable()` belongs in a composition or an Activity and never in
`Application.onCreate`: unlike `verifyBiometric`, the probe does not wait for a host at all, so
with none in front it answers `false` immediately.

**Auto-init** — `KSafeBiometrics` registers its activity-lifecycle observer automatically via a
`ContentProvider` declared in the library's merged manifest, which Android runs at process start
with the application Context. You do **not** need to call any init function in your
`Application.onCreate`. The provider's authority is `${applicationId}.ksafe-biometrics-init` so it
can't collide with other libraries. If you specifically want to disable auto-init (rare), override
the provider in your app's manifest with `tools:node="remove"` — and then call
`BiometricHelper.init(application)` from `Application.onCreate` yourself. Without one of the two,
the library has no application Context and no tracked Activity, so every `verifyBiometric` returns
`false` and `biometricsAvailable()` reports `false`.

**Android-only knobs** — prompt text is set from common code (see [Prompt text](#prompt-text));
`BiometricHelper` holds what only Android has:

```kotlin
import eu.anifantakis.lib.ksafe.biometrics.BiometricHelper

BiometricHelper.confirmationRequired = true    // false lets a passive face match confirm by itself
BiometricHelper.activityWaitTimeoutMs = 5_000L // how long a call waits for a foreground FragmentActivity
```

It also exposes `getCurrentActivity()`, `hasUsableFragmentActivity()` and the suspending
`authenticate(...)` — the last one shows the same prompt as `verifyBiometric` but throws
`BiometricAuthException` / `BiometricActivityNotFoundException` instead of returning `false`, for
when you want the reason a call failed. `BiometricHelper` is in the `eu.anifantakis.lib.ksafe.biometrics` package and ships
with `:ksafe-biometrics`.

### iOS

**Info.plist** — Add Face ID usage description:
```xml
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to access secure data</string>
```

**Note:** On the iOS Simulator `verifyBiometric` returns `true` without a prompt, in both modes.
KSafe detects the Simulator (the `SIMULATOR_UDID` environment variable) and short-circuits before
`LAContext` is used, so this holds whether or not the Simulator has Face ID enrolled.
`biometricsAvailable()` reports `false` there, so an app can route to its own flow instead.

### macOS

No manifest entries or special entitlements are required for basic Touch ID / password authentication via `LocalAuthentication`.

**Sandboxed apps** — if your app is distributed through the Mac App Store (sandboxed), add the `com.apple.security.device.biometrics` entitlement to your entitlements file to enable Touch ID:
```xml
<key>com.apple.security.device.biometrics</key>
<true/>
```

**Unsandboxed apps** — Touch ID and password authentication work without any entitlement. Separately from biometrics: if you also use `:ksafe`, macOS may show a system password prompt on first Keychain access, which signing the app with a Keychain access group entitlement suppresses. Storage key custody is covered in [SECURITY_MODEL.md](SECURITY_MODEL.md).

**Fallback behaviour** — depends on `allowDeviceCredentialFallback`. With the default `true`, KSafe uses `LAPolicyDeviceOwnerAuthentication`, so the system automatically falls back to the macOS login password on machines without Touch ID (Mac mini, Intel MacBooks without T2, etc.) — `verifyBiometric` always produces a real prompt. With `false`, KSafe uses `LAPolicyDeviceOwnerAuthenticationWithBiometrics` (Touch ID only) — on a Mac without Touch ID the policy fails up front and `verifyBiometric` returns `false`. Pick `false` when biometric-grade auth is a hard requirement; pick `true` (default) when you only need to confirm the human at the keyboard.

### Web (JS / WasmJS)

The web prompt is a WebAuthn **platform authenticator** ceremony — the browser's own dialog,
backed by Touch ID, Windows Hello or a fingerprint reader — used as a local re-auth gate. There is
no server: KSafe generates the challenge itself.

What it needs:

- A **secure context**: HTTPS, or `localhost` while developing. Anywhere else the availability probe answers "insecure context", and a call passes through (`true`) in the permissive mode or refuses (`false`) in the strict one — exactly as on a browser with no platform authenticator.
- A **user gesture**: call it from a click handler. A browser may reject a ceremony that no interaction started.
- `reason` is never shown — the browser writes the dialog text.

The first successful call **registers** a credential for the origin, and that registration ceremony
is itself the user verification, so it counts as a success; later calls verify against it. KSafe
keeps the credential id in `localStorage` and asks for a non-discoverable credential, so it does
not depend on a synced passkey.

`KSafeBiometrics.defaultTitle` names that credential in the user's password manager, and it is
written **once**, at registration. Set it at startup, before the first `verifyBiometric()` call —
if you also use `:ksafe` on the web, right next to the `ksafe.awaitCacheReady()` call.

If you rename the app later, inspect what is enrolled and re-enroll **once** — never
unconditionally, or every user re-runs the ceremony on every launch. `KSafeBiometricsWeb` is
web-only: it is visible from `jsMain` / `wasmJsMain`, not from `commonMain`.

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
after repeated failures) that calls `resetRegistration()`, which also drops every cached
authorization. Conversely, clearing site data reads unregistered while the passkey may survive,
orphaned, in the password manager.

## Complete Example

```kotlin
class SecureViewModel(
    private val ksafe: KSafe,   // :ksafe, plus :ksafe-compose for mutableStateOf
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

    // With 60s duration caching (scoped to this screen)
    fun incrementBioCounterCached() {
        KSafeBiometrics.verifyBiometricDirect(
            reason = "Authenticate to save",
            authorizationDuration = BiometricAuthorizationDuration(
                duration = 60_000L,
                scope = "secure_counter_screen"
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
                scope = "secure_counter_screen"
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

Inject `BiometricGate` into your ViewModels; provide a fake in tests. This keeps the friction-free static call shape for production code while preserving testability where it matters. MockK can mock the object directly on JVM and Android — `mockkObject(KSafeBiometrics)`. MockK is a JVM library, so in `commonTest` (which also compiles for iOS, macOS and the web) the wrapper interface above is the only option.

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
// build.gradle.kts: + implementation("eu.anifantakis:ksafe-biometrics:3.1.0")  // or latest
import eu.anifantakis.lib.ksafe.biometrics.KSafeBiometrics
import eu.anifantakis.lib.ksafe.biometrics.BiometricAuthorizationDuration

KSafeBiometrics.verifyBiometricDirect(reason, BiometricAuthorizationDuration(60_000L)) { ok -> }
```

Method names are preserved and every 1.x call still compiles — only the receiver and the import paths change. 3.0.0 appended two optional parameters, `title` and `cancelLabel`, after the existing ones. `BiometricHelper.confirmationRequired` continues to work the same way; only its import path changed, to `eu.anifantakis.lib.ksafe.biometrics` from `eu.anifantakis.lib.ksafe`. (`BiometricHelper.promptTitle` / `promptSubtitle` were removed in 3.0.0 — set `KSafeBiometrics.defaultTitle` / `defaultReason` instead, which are common code; `defaultTitle` is also what names the web passkey, while `defaultReason` is ignored there.)

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
