# Setup with Koin (Recommended)

> **Install first.** Full install instructions live in the [README](../README.md#setup). The three published artifacts are:
>
> ```kotlin
> implementation("eu.anifantakis:ksafe:3.1.0")
> implementation("eu.anifantakis:ksafe-compose:3.1.0")     // ← Compose persisted state (optional)
> implementation("eu.anifantakis:ksafe-biometrics:3.1.0")  // ← standalone biometric gate (optional)
> ```
>
> `:ksafe-compose` adds `KSafe.mutableStateOf` / `rememberKSafeState`; `:ksafe-biometrics` is an independent process-wide biometric gate (Android, iOS, macOS, JVM Desktop, web) with no dependency on `:ksafe`.

Koin is the most common dependency-injection (DI) library for Kotlin Multiplatform. DI means one
place in your app builds your objects and hands them to whoever needs them. That one place is where
a `KSafe` instance belongs, because every instance should be built once and shared for the life of
the process: each instance keeps its own in-memory cache of your values, and a second instance on
the same file only duplicates that work (see [Multiple Instances](#multiple-instances)).

### One instance (the usual case)

Every platform has its own `KSafe(...)` factory function. Android needs a `Context`; the others need
nothing. Put that platform-specific line in an `expect`/`actual` module — the Kotlin Multiplatform
way to declare something once in shared code and implement it per platform — and share the rest:

```kotlin
// ──────────────────────────────────────────────
// commonMain
// ──────────────────────────────────────────────
expect val platformModule: Module

// ──────────────────────────────────────────────
// androidMain
// ──────────────────────────────────────────────
actual val platformModule = module {
    single { KSafe(androidApplication()) }
}

// ──────────────────────────────────────────────
// iosMain, macosMain, jvmMain, wasmJsMain, jsMain
// (the same body in each of those source sets)
// ──────────────────────────────────────────────
actual val platformModule = module {
    single { KSafe() }
}
```

`single` tells Koin to build the object once and hand out that same object every time. With no
`fileName` you get the default store — KSafe's one unnamed file; passing a `fileName` gives you a
separate file with its own keys. Inject it wherever you need it:

```kotlin
class MyViewModel(private val ksafe: KSafe) : ViewModel() {
    var authToken by ksafe("")                                   // encrypted — the default
    var theme     by ksafe("dark", mode = KSafeWriteMode.Plain)  // stored as-is, not encrypted
}
```

`by ksafe(default)` is a property delegate: reading the property reads the store, assigning to it
writes the store, and the default you pass is what you get back while nothing is stored yet. The
storage key is the property's own name unless you pass one (`ksafe("", key = "auth_token")`).

> **Not everything needs encrypting.** Every write is encrypted unless you say otherwise with
> `mode = KSafeWriteMode.Plain`. The key comes from the platform's key store — Android Keystore,
> Apple Keychain, the desktop OS secret store, a browser-held key on web — but an ordinary
> encrypted write uses a key KSafe already holds, so it costs CPU and no trip back to that store.
> Two cases do go back to it on every write, and only on Android and Apple: a write that asks for
> the device's security chip, and one that ties the value to the lock screen. For data that is not
> secret — theme, last-visited screen, onboarding flags — `Plain` is faster and gives up nothing.
> Keep encryption for secrets: tokens, passwords, and anything that identifies a person.

### Two kinds of data: "prefs" and "vault"

When one app stores both preferences and secrets, a per-call `mode =` argument is easy to forget,
and one forgotten argument silently writes with the wrong protection. Since 3.1.0 the mode-typed
views turn that convention into a compiler rule: `KSafePlain` writes everything plain and
`KSafeEncrypted` writes everything encrypted, and neither has a `mode` parameter anywhere. They wrap
the one instance from above and share its file, its keys and its cache.

```kotlin
val appModule = module {
    single { KSafePlain(get()) }        // "prefs": every write is plain
    single { KSafeEncrypted(get()) }    // "vault": every write is encrypted
    viewModel { MyViewModel(get(), get()) }
}

class MyViewModel(
    private val prefs: KSafePlain,
    private val vault: KSafeEncrypted,
) : ViewModel() {
    var theme      by prefs("dark")   // plain — there is no mode argument to get wrong
    var lastScreen by prefs("home")
    var onboarded  by prefs(false)

    var authToken    by vault("")     // encrypted
    var refreshToken by vault("")
}
```

For the few values that deserve the device's separate security chip — Android StrongBox, Apple
Secure Enclave — `KSafeHardwareIsolated` asks for it on every write. It is a request, not a
guarantee: without that chip the write falls back to the platform's normal key store, and
`ksafe.protectionInfo` reports what you actually got. It is also slower, so keep it for a PIN or a
master passphrase:

```kotlin
single { KSafeHardwareIsolated(get()) }

class PinViewModel(private val hardwareVault: KSafeHardwareIsolated) : ViewModel() {
    var userPin by hardwareVault("")
}
```

The views cover writes only. Reads carry no mode — KSafe detects each entry's protection on its own
— and store-wide operations (`clearAll()`, `rotateKeys()`, `close()`, `protectionInfo`) are
deliberately absent from the views: call those on the underlying instance, which every view exposes
as `view.ksafe`. Full reference:
[USAGE.md](USAGE.md#mode-typed-views-310--ksafeplain--ksafeencrypted--ksafehardwareisolated).

**Two files instead of one?** The views above share one store, so `clearAll()` on it wipes
preferences and secrets together. If you want to wipe the secrets on logout and keep the
preferences, give each kind its own `fileName` and wrap one instance per file — `clearAll()` only
ever touches the file of the instance you call it on:

```kotlin
// androidMain
actual val platformModule = module {
    single(named("prefsStore")) { KSafe(androidApplication(), fileName = "prefs") }
    single(named("vaultStore")) { KSafe(androidApplication(), fileName = "vault") }
}
// the other platforms: the same, with KSafe(fileName = "prefs") / KSafe(fileName = "vault")

// commonMain
val appModule = module {
    single { KSafePlain(get(named("prefsStore"))) }
    single { KSafeEncrypted(get(named("vaultStore"))) }
}
```

`named("…")` is Koin's qualifier: it tells Koin which of two same-typed objects to hand over. On
logout: `vault.ksafe.clearAll()`.

On web, one more call is needed before the first read — next section.

### `ksafe.awaitCacheReady()` Required ONLY on the Web Targets (wasmJs + js)

KSafe keeps every value in an in-memory cache and answers reads from it. On Android, iOS/macOS and
JVM/Desktop that cache is loaded before the first read returns. In the browser it cannot be:
WebCrypto, the browser's encryption API, only works asynchronously, so KSafe cannot make a read wait
while it decrypts. A read that arrives before the cache is ready returns the default value you
passed instead of the stored one — and a write made from that default overwrites the real value.

`awaitCacheReady()` suspends until the cache is loaded and every encrypted value is decrypted. Call
it once at startup, before the first read. It is declared only for the `wasmJs` and `js` targets, so
it goes in your web `main()` (or another web-only source set), not in common code — the same code
serves both `wasmJsMain` and `jsMain`. If you use the mode-typed views, one call on the underlying
instance covers all of them.

> **With `startKoin` (classic):**
> ```kotlin
> fun main() {
>     startKoin {
>         modules(sharedModule, platformModule)
>     }
>
>     val body = document.body ?: return
>     ComposeViewport(body) {
>         // koinInject() is a composable call — it belongs in the composition,
>         // not inside LaunchedEffect (org.koin.compose.koinInject).
>         val ksafe: KSafe = koinInject()
>         var cacheReady by remember { mutableStateOf(false) }
>
>         LaunchedEffect(Unit) {
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
>             val ksafe: KSafe = koinInject()
>             var cacheReady by remember { mutableStateOf(false) }
>
>             LaunchedEffect(Unit) {
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
> With `KoinMultiplatformApplication`, Koin exists only inside that composable, which is why the
> whole block sits inside it. With `startKoin`, Koin is started before `ComposeViewport`, so the
> block can sit at the top level of the viewport.

Now you're ready to inject KSafe into your ViewModels!

***

## Multiple Instances

by [Mark Andrachek](https://github.com/mandrachek)

You can create more than one KSafe instance, each with its own `fileName`, to keep different kinds
of data in separate files. Each file has its own encryption keys and its own `clearAll()`, so you
can wipe one without touching the others.

Register one instance per file. The `KSafe(...)` call is platform-specific — Android needs a
`Context`, the others need nothing — so it belongs in an `expect`/`actual` platform module, not in
common code:

```Kotlin
// androidMain
actual val platformModule = module {
  single { KSafe(androidApplication()) }                                       // default store
  single(named("user"))  { KSafe(androidApplication(), fileName = "userdata") }
  single(named("cache")) { KSafe(androidApplication(), fileName = "cache") }
}
// iosMain, macosMain, jvmMain, wasmJsMain, jsMain: the same without the context —
// KSafe(), KSafe(fileName = "userdata"), KSafe(fileName = "cache")

// commonMain
val appModule = module {
  viewModel { MyViewModel(get(named("user"))) }
}

// Inject the one you need. Delegates, suspend and direct APIs all work on any instance.
class MyViewModel(private val userPrefs: KSafe) : ViewModel() {
  var authToken by userPrefs("")
  suspend fun saveUserToken(token: String) = userPrefs.put("auth_token", token)
}
```

**Important Instance Management Rules:**
- **One instance per file, built once.** Register it in DI and inject it; do not construct `KSafe` inside screens or ViewModels.
- **Why:** every instance keeps its own in-memory cache, so two instances on one file cost twice the memory and twice the work. On Android, iOS/macOS and JVM/Desktop, instances that do share a file share one storage layer underneath, so they do not lose each other's writes, and a `clearAll()` or `rotateKeys()` through one is seen by the others. On web this does not apply: every instance owns its own storage handle, so a second instance on the same file does not see the first one's writes. There the one-instance-per-file rule is a hard requirement, not advice.

```Kotlin
// ✅ Good: one shared instance per file, registered in the platform module
single(named("user")) { KSafe(fileName = "userdata") }

// ⚠️ Non-ideal: a new instance per screen on the same file
class ScreenA { val prefs = KSafe(fileName = "userdata") }
class ScreenB { val prefs = KSafe(fileName = "userdata") }  // Prefer one shared instance
```

**File Name Requirements:**
- Omit `fileName` (or pass `null`) to use the default store.
- Otherwise it must match the regex `[a-z][a-z0-9_]*` — a lowercase letter first, then lowercase letters, digits or underscores. No spaces, dots, slashes, hyphens or uppercase letters. Anything else throws `IllegalArgumentException` when the instance is built.
- Why so strict: the name becomes part of the file name on disk (`eu_anifantakis_ksafe_datastore_<fileName>.preferences_pb`) and part of the key names in the OS key store, so it has to be legal in both.
- Examples: `"userdata"`, `"settings"`, `"data_v2"`, `"cache"`

### Disposing an instance: `KSafe.close()`

In the singleton-per-process pattern above you never need to call anything to dispose `KSafe` — the OS reclaims everything when the process exits, and `close()` on an app-lifetime singleton is harmless but achieves nothing. The optional `close()` method exists for the small set of cases where you actually re-create `KSafe` mid-process:

- **Account or profile switching** that changes the `fileName` (you build a new instance for the new identity and abandon the old one).
- **Long-running JVM services** that build a fresh instance per session, tenant, or request.
- **Dev-time hot-reload** that rebuilds the DI graph and constructs new `KSafe`s on top of the previous ones.

```kotlin
// A raw id (UUID, mixed case, hyphens) breaks the File Name Requirements above, so sanitize
// it first; otherwise construction throws IllegalArgumentException.
val safeId = userId.lowercase().replace(Regex("[^a-z0-9_]"), "_")
val ksafe = KSafe(fileName = "session_$safeId")
// ... use it ...
ksafe.close()
```

**What `close()` does:** it refuses new disk writes, waits — at most a couple of seconds, and not on web, which cannot block — for a write already running, then cancels the background coroutines, hands a `CancellationException` to every write still queued behind it, and releases the file. Calling it twice is safe.

**The rules:**

1. **Finish your writes first.** Await your suspending `put`/`delete` calls before calling `close()`. A write that races `close()` from another coroutine can be queued after the shutdown drain and never complete.
2. **Throw the reference away afterwards.** `close()` does not install a fail-fast closed state, so later calls fail quietly: a `getDirect` may return a stale cached value, a `putDirect` updates the cache but is never written to disk, and a suspending `put`/`delete` waits forever because nothing drains the queue any more. Build a new instance if you need storage again.
3. **Re-creating on the same file immediately can fail once.** On Android, iOS/macOS and JVM the new instance waits up to a second for the old storage to finish tearing down. If that is not enough, the first access reports an error — "multiple DataStores active for the same file", DataStore being the storage engine KSafe uses there — and then self-recovers. Following rule 1 avoids it.

***

## Configuring KSafe (`KSafeConfig`)

Every platform factory accepts an optional `config = KSafeConfig(...)` — on Android the context
still comes first. Every field has a default, so pass only what you change:

```kotlin
import kotlin.time.Duration.Companion.days

val ksafe = KSafe(
    config = KSafeConfig(
        aesKeySize = KSafeAesKeySize.BITS_256,
        appNamespace = "com.example.myapp",
        keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(90.days),
        keyRotationRetryAttempts = 3,
    )
)
```

| Field | Default | What it does | More |
|---|---|---|---|
| `aesKeySize` | `BITS_256` | Key strength for keys KSafe creates from now on: `BITS_128` or `BITS_256`. The cipher is always AES-GCM. | below |
| `requireUnlockedDevice` | `false` | Default unlock policy for encrypted writes that pass no `mode`: `true` ties their key to the lock screen. Android and Apple only. | [MEMORY.md](MEMORY.md#device-lock-state-policy) |
| `json` | `KSafeDefaults.json` | The `kotlinx.serialization` `Json` used for `@Serializable` values. Changing it later can make stored objects unreadable. | [SERIALIZATION.md](SERIALIZATION.md) |
| `appNamespace` | `null` | Keeps two apps that share a `fileName` apart on JVM/Desktop and web. | below |
| `keyRotationPolicy` | `Never` | When KSafe re-encrypts the store under a fresh key on its own. | below |
| `keyRotationRetryAttempts` | `3` | How many later launches may retry entries a rotation could not reach. `0` disables them; a negative value throws. | [KEY_ROTATION.md](KEY_ROTATION.md) |

**`aesKeySize`** selects `BITS_128` or `BITS_256` (the default) for newly created keys on every
platform. The cipher itself — AES-GCM, which both encrypts a value and detects tampering with it —
is intentionally fixed; the setting changes key strength, not the cipher mode. An existing store
keeps using the size embedded in its current key until a rotation creates a fresh one
(`keyRotationPolicy`, below).

**`appNamespace`** — *The problem.* On Android and iOS the OS gives every app its own key store, so
two apps can never see each other's keys. On JVM/Desktop the OS secret store (Windows DPAPI, the
macOS login Keychain, the Linux Secret Service) is shared by every program the same user runs, and
in a browser everything served from one origin shares one storage. Two KSafe apps that both use
`fileName = "vault"` would therefore land on the same key slot and overwrite each other's keys.

*The fix.* Give each app a name nobody else will pick — normally your application id in reverse-DNS
form, `"com.example.myapp"`.

*What it changes.* On JVM the keys are filed under that name **and** the data file moves into a
subdirectory of that name; data that already existed without a namespace is copied forward, so
adding a namespace later loses nothing. On web the name goes into the prefix of both the key records
and the `localStorage` entries. On Android and iOS it does nothing, because the OS already separates
apps. If you leave it `null` on JVM, keys go to the fixed namespace `"shared"` — exactly the
collision above, once a second KSafe app runs for the same user.

The JVM system property `-Dksafe.appNamespace=` and the environment variable `KSAFE_APP_NAMESPACE`
set only the key namespace, not the data directory, so prefer the config field. Details, including
how keys filed under an older namespace are found again:
[JVM_PROTECTION.md](JVM_PROTECTION.md#app-namespace-multi-app-isolation).

**`keyRotationPolicy`** — Rotation means: create a fresh key, re-encrypt every stored value under
it, delete the old key. It is off by default (`Never`), because platform-held keys do not expire.
`MaxAge(90.days)` makes KSafe check once at each startup, in the background, whether the current key
is older than that and rotate if it is; startup and reads never wait for it. `ksafe.rotateKeys()`
does the same on demand. A pass interrupted by a crash finishes on the next launch under any policy,
`Never` included. Entries a pass could not reach — for example an unlock-bound entry while the
device was locked — are retried on later launches, one attempt per new instance, up to
`keyRotationRetryAttempts` times (`3` by default, `0` disables it). The full model, its cost and its
caveats: [KEY_ROTATION.md](KEY_ROTATION.md).

***

## Custom Storage Directory

KSafe keeps each instance's values in one file (Jetpack DataStore on Android, iOS/macOS and
JVM/Desktop; the browser's `localStorage` on web). By default that file goes to the platform's
normal place for private app data:

| Platform | Default location |
|----------|-----------------|
| **Android** | `/data/data/<package>/files/datastore/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb` (the app sandbox — recommended) |
| **iOS / macOS** | `<NSApplicationSupportDirectory>/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb` |
| **JVM/Desktop** | `~/.eu_anifantakis_ksafe/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb`, POSIX `0700`; with an `appNamespace` set, one level deeper: `~/.eu_anifantakis_ksafe/<appNamespace>/…` |
| **Web** | `localStorage`, prefixed `ksafe.<appNamespace@><fileName>:` (e.g. `ksafe.vault:`; the default store is `ksafe.:`) — no directory concept |

> Where the encryption **key** lives (OS key store or software fallback), how ciphertext is tied to the device, and what happens in a Compose Desktop release build whose runtime omits `jdk.unsupported` are covered in [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY_MODEL.md](SECURITY_MODEL.md), and [JVM_PROTECTION.md](JVM_PROTECTION.md#compose-desktop-release-distributables-jdkunsupported).

Most apps should keep the default. On JVM, Android and iOS/macOS you can pass your own directory
when you need to control where the file lives — for example to follow the Linux convention that
user data goes under `$XDG_DATA_HOME`, to keep the file out of Android's automatic cloud backup
(`noBackupFilesDir`), or to put it next to your app's own files.

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

// iOS / macOS — supply an absolute path string
val ksafe = KSafe(
    fileName = "vault",
    directory = "/path/to/your/dir",
)
// If null, KSafe uses NSApplicationSupportDirectory, Apple's location for app data the
// user should not see. The file is not excluded from iCloud Backup, but the encryption
// keys never leave the device, so a restored backup holds unreadable bytes — see
// MIGRATION.md#ksafe-data-on-ios-is-effectively-device-local.
// A custom directory also switches off the automatic move of a pre-2.0 file out of the
// Documents directory (the iOS upgraders note below).
```

**Web** has no directory concept, so there is no `baseDir` parameter on the web factory. Values live
in `localStorage` under the `ksafe.<appNamespace@><fileName>:` prefix; the encryption key is a
non-extractable WebCrypto key kept in the browser's IndexedDB, which is a separate store. (Stores
written by older versions used the `ksafe_<fileName>_` prefix, or `ksafe_default_` for the default
store. Those entries are copied to the new prefix the first time the store is built — and removed
from the old one when no other store shares it — while the old prefix still names the key record in
IndexedDB.)

**iOS upgraders:** the default storage path moved from `NSDocumentDirectory` (pre-2.0) to `NSApplicationSupportDirectory`; KSafe migrates the legacy file automatically on first launch. See the [iOS migration section](MIGRATION.md#ios-default-storage-path-moved-from-nsdocumentdirectory-to-nsapplicationsupportdirectory).

***
