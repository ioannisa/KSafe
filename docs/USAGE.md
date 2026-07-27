# KSafe — Complete Usage Guide

This document is the full reference for every KSafe API shape: property delegates, flow delegates, Compose state, the suspend API, the direct API, per-entry write modes, nullable handling, deletion, and a full ViewModel example.

For the 60-second introduction, see the project [README](../README.md). This page is the deep dive.

## Table of Contents

- [Property Delegation (One Liner)](#property-delegation-one-liner)
- [Flow Delegates (Reactive Reads)](#flow-delegates-reactive-reads)
- [Composable State (One Liner)](#composable-state-one-liner)
- [Suspend API (non-blocking)](#suspend-api-non-blocking)
- [Direct API (Recommended for Performance)](#direct-api-recommended-for-performance)
- [Write Mode API (Per-Entry Unlock Policy)](#write-mode-api-per-entry-unlock-policy)
- [Isolating an app's keys (`appNamespace`)](#isolating-an-apps-keys-ksafeconfigappnamespace)
- [Storing Complex Objects](#storing-complex-objects)
- [Cryptographic Secrets (`getOrCreateSecret`)](#cryptographic-secrets-getorcreatesecret)
- [Key Rotation](#key-rotation)
- [Nullable Values](#nullable-values)
- [Deleting Data](#deleting-data)
- [Collecting Security Violations for the UI](#collecting-security-violations-for-the-ui)
- [Full ViewModel Example](#full-viewmodel-example)

## Property Delegation (One Liner)

```kotlin
var counter by ksafe(0)
```

Parameters:
* `defaultValue` - must be declared (type is inferred from it)
* `key` - if not set, the variable name is used as a key
* `mode` (overload) - `KSafeWriteMode.Plain` or `KSafeWriteMode.Encrypted(...)` for per-entry control

```Kotlin
class MyViewModel(ksafe: KSafe): ViewModel() {
  var counter by ksafe(0)

  init {
    // then just use it as a regular variable
    counter++
  }
}
```

> The property delegate works with any `KSafe` instance — the receiver of `by myKSafe(...)` becomes the storage backend. See [docs/SETUP.md](SETUP.md#multiple-instances) for the named-instance pattern (e.g. `var theme by prefs(...)`, `var token by vault("")`). The variable name is used as the storage key when no explicit `key` is supplied.

## Flow Delegates (Reactive Reads)

KSafe has always offered `getFlow()` and `getStateFlow()` with explicit key strings. These delegates extend the same property-name-as-key pattern from `invoke()` above to Flows and StateFlows — use whichever style you prefer.

**`asFlow`** returns a cold `Flow<T>` — ideal for repositories and data layers:

```kotlin
class UserRepository(private val kSafe: KSafe) {
    val username: Flow<String> by kSafe.asFlow(defaultValue = "Guest")
    val darkMode: Flow<Boolean> by kSafe.asFlow(defaultValue = false)

    // optional: explicit key override
    val theme: Flow<String> by kSafe.asFlow(defaultValue = "light", key = "app_theme")

    // writes use the existing API — the flow emits automatically
    suspend fun updateUsername(name: String) {
        kSafe.put("username", name)
    }
}
```

**`asWritableFlow`** returns a `WritableKSafeFlow<T>` — a cold `Flow<T>` you can also write to via `set()`. Use this when a single declaration should expose both reactive reads and writes, *without* committing to a `MutableStateFlow` or managing a `CoroutineScope`:

```kotlin
@Serializable
enum class ThemeMode { DAY, NIGHT, DEVICE }

class SettingsRepository(ksafe: KSafe) {
    val themeMode: WritableKSafeFlow<ThemeMode> by ksafe.asWritableFlow(ThemeMode.DEVICE)

    fun setThemeMode(mode: ThemeMode) {
        themeMode.set(mode)  // persists; collectors see it on the next emission
    }
}
```

This is the natural fit when you previously had to declare two bindings to the same key — one `asFlow` and one writable property delegate — just to get observability + writability. `WritableKSafeFlow<T>` is a `Flow<T>` (so collectors see persisted changes from any writer), with one extra method:

```kotlin
fun set(value: T)  // calls ksafe.putDirect under the hood; respects the configured KSafeWriteMode
```

`asWritableFlow` defaults to encrypted writes carrying the instance's `KSafeConfig.requireUnlockedDevice` (exposed as `KSafe.defaultWriteMode`) — the same default as the property delegate `ksafe(...)`, `asMutableStateFlow`, and the Compose `mutableStateOf` delegate. Pass `mode = KSafeWriteMode.Plain` for unencrypted persistence. Reads happen only through flow collection — there is no synchronous getter, which keeps the contract identical on every platform (including web cold-start).

**`asStateFlow`** returns a hot `StateFlow<T>` — ideal for ViewModels:

```kotlin
class SettingsViewModel(private val kSafe: KSafe) : ViewModel() {
    val username: StateFlow<String> by kSafe.asStateFlow("Guest", viewModelScope)
    val darkMode: StateFlow<Boolean> by kSafe.asStateFlow(false, viewModelScope)

    fun onNameChanged(name: String) {
        viewModelScope.launch { kSafe.put("username", name) }
    }

    fun toggleDarkMode() {
        kSafe.putDirect("darkMode", !darkMode.value)
    }
}

// Consume in Compose
@Composable
fun SettingsScreen(viewModel: SettingsViewModel) {
    val username by viewModel.username.collectAsState()
    val darkMode by viewModel.darkMode.collectAsState()

    TextField(value = username, onValueChange = { viewModel.onNameChanged(it) })
    Switch(checked = darkMode, onCheckedChange = { viewModel.toggleDarkMode() })
}
```

**`asMutableStateFlow`** returns a read/write `MutableStateFlow<T>` — setting `.value` persists automatically. It's a drop-in replacement for the standard `MutableStateFlow` pattern:

```kotlin
// Standard Kotlin pattern
private val _state = MutableStateFlow(MoviesListState())
val state = _state.asStateFlow()

// KSafe equivalent — same pattern, but persisted + reactive to external changes
private val _state by kSafe.asMutableStateFlow(MoviesListState(), viewModelScope)
val state = _state.asStateFlow()
```

All standard `MutableStateFlow` operations work because we implement the full interface:

```kotlin
// .value = ...  ✅ persists
_state.value = _state.value.copy(loading = true)

// .update {} ✅ persists (uses compareAndSet internally)
_state.update { it.copy(loading = false, movies = list) }

// .asStateFlow() ✅ works (it's a real MutableStateFlow)
val state = _state.asStateFlow()

// collectAsState() ✅ works
val state by viewModel.state.collectAsState()
```

Full ViewModel example:

```kotlin
@Serializable
data class MoviesListState(
    val loading: Boolean = false,
    val movies: List<Movie> = emptyList(),
    val error: String? = null
)

class MoviesViewModel(private val kSafe: KSafe, private val api: MoviesApi) : ViewModel() {
    private val _state by kSafe.asMutableStateFlow(MoviesListState(), viewModelScope)
    val state = _state.asStateFlow()

    fun loadMovies() {
        _state.update { it.copy(loading = true) }
        viewModelScope.launch {
            try {
                val movies = api.getMovies()
                _state.update { it.copy(loading = false, movies = movies) }
            } catch (e: Exception) {
                _state.update { it.copy(loading = false, error = e.message) }
            }
        }
    }
}

@Composable
fun MoviesScreen(viewModel: MoviesViewModel) {
    val state by viewModel.state.collectAsState()

    when {
        state.loading -> CircularProgressIndicator()
        state.error != null -> Text("Error: ${state.error}")
        else -> LazyColumn {
            items(state.movies) { movie -> MovieItem(movie) }
        }
    }
}
```

> `asFlow` and `asStateFlow` are **read-only** — writes go through `put`/`putDirect`. `asWritableFlow` gives you a writable cold `Flow<T>` (`set(value)`) without any scope; `asMutableStateFlow` gives you a hot `MutableStateFlow<T>` (`.value = ...`) with a scope. All four automatically pick up changes made anywhere — KSafe writes from another screen, background sync, or another delegate against the same key.

## Composable State (One Liner)

```kotlin
var counter by ksafe.mutableStateOf(0)
```

Recomposition-proof and survives process death with zero boilerplate. Requires the `ksafe-compose` dependency.

```Kotlin
class MyViewModel(ksafe: KSafe): ViewModel() {
  var counter by ksafe.mutableStateOf(0)
    private set

  init {
    counter++
  }
}
```

When you need custom Compose equality semantics, use the advanced overload with `policy`:

```kotlin
import androidx.compose.runtime.neverEqualPolicy
import androidx.compose.runtime.referentialEqualityPolicy

// Default (recommended): structural equality
var profile by ksafe.mutableStateOf(Profile())

// Persist/recompose only when reference changes
var uiModel by ksafe.mutableStateOf(
    defaultValue = UiModel(),
    policy = referentialEqualityPolicy()
)

// Always treat assignment as a change (always persists)
var ticks by ksafe.mutableStateOf(
    defaultValue = 0,
    policy = neverEqualPolicy()
)
```

### Reactive `mutableStateOf` with Cross-Screen Sync

The existing `mutableStateOf` (available since v1.0.0) now accepts an optional `scope` parameter.

**Without `scope`** — the state reads from cache at initialization and persists on write, but it's **isolated**. If another ViewModel or a background `put()` writes to the same key, this state won't see the change until the ViewModel is destroyed and recreated.

**With `scope`** — the state continuously observes the underlying flow. Changes from **any source** (another screen, another ViewModel, a background coroutine) are reflected **in real-time**.

```kotlin
// Without scope — isolated: reads once at init, writes persist, but no live sync
var username by ksafe.mutableStateOf("Guest")

// With scope — live subscription: auto-updates when ANY writer changes this key
var username by ksafe.mutableStateOf("Guest", scope = viewModelScope)
```

> If you only ever read/write from a single ViewModel, both behave identically. The `scope` parameter only matters when **multiple writers** exist for the same key.

This is especially useful when multiple screens share the same data:

```kotlin
class DashboardViewModel(kSafe: KSafe) : ViewModel() {
    // These auto-reflect changes made from other screens
    var username by kSafe.mutableStateOf("Guest", scope = viewModelScope)
    var notificationsEnabled by kSafe.mutableStateOf(false, scope = viewModelScope)
}

class SettingsViewModel(kSafe: KSafe) : ViewModel() {
    var username by kSafe.mutableStateOf("Guest", scope = viewModelScope)
    var notificationsEnabled by kSafe.mutableStateOf(false, scope = viewModelScope)
}

// When SettingsScreen writes, DashboardScreen auto-updates — no manual refresh
@Composable
fun DashboardScreen(viewModel: DashboardViewModel) {
    Text("Welcome, ${viewModel.username}")
    if (viewModel.notificationsEnabled) Text("Notifications ON")
}

@Composable
fun SettingsScreen(viewModel: SettingsViewModel) {
    TextField(value = viewModel.username, onValueChange = { viewModel.username = it })
    Switch(
        checked = viewModel.notificationsEnabled,
        onCheckedChange = { viewModel.notificationsEnabled = it }
    )
}
```

### `rememberKSafeState` — composable-body persistent state, no ViewModel required

`mutableStateOf` is the right tool for persisted state on a **class field** (ViewModel, repository): the property delegate is created once when the class is constructed and lives for the class's lifetime. Used directly inside a `@Composable` function body it would re-create itself on every recomposition, so for that case use `rememberKSafeState`:

```kotlin
@Composable
fun TabbedScreen(ksafe: KSafe) {
    var currentlySelectedIndex by ksafe.rememberKSafeState(0)   // key auto-resolves to "currentlySelectedIndex"
    var draftMessage by ksafe.rememberKSafeState("")            // key auto-resolves to "draftMessage"

    // Both survive process death AND every recomposition cleanly.
}
```

This is the KSafe analogue of `rememberSaveable { mutableStateOf(...) }`, with stronger guarantees: `rememberSaveable` survives configuration changes and (via the saveable state registry) process death for `Bundle`-friendly types on Android only — state is cleared on a cold app launch. `rememberKSafeState` survives **app restart**, on every supported target (Android, iOS, JVM, Web), with optional encryption.

#### When the value naturally lives in the composable, not in a ViewModel

The bottom-tab index of the demo app is a textbook fit. Before:

```kotlin
@Composable
fun AppContent() {
    var currentScreen by remember { mutableStateOf(Screen.Storage) }
    // … bottom bar + screen dispatch …
}
```

That state is wiped on every cold launch — the user never re-opens the app on the tab they were last viewing. The "correct" Android answer used to be: build a `MainViewModel`, expose `currentScreen`, inject it via `koinViewModel()`, save the value through KSafe inside the VM, observe a flow back into the composable. Five files of plumbing for a single integer.

`rememberKSafeState` collapses that to one line:

```kotlin
@Composable
fun AppContent(ksafe: KSafe) {
    var currentScreen by ksafe.rememberKSafeState(Screen.Storage)
    // … bottom bar + screen dispatch …
}
```

The key auto-resolves to `"currentScreen"` from the property name, the value persists across app restarts, and there's no ViewModel to construct, inject, observe, or test. Reach for it whenever the state is naturally local to the composable — bottom-tab index, scroll position, expanded/collapsed sections, draft form input, last-selected sort order, "show advanced settings" toggles. State that *belongs in a ViewModel* (because it's domain data, shared across screens, or driven by business logic) still belongs in a ViewModel — `mutableStateOf` is still the right tool there.

#### How it works

Under the hood the factory returns a `KSafeComposeStateProvider<T>`. The `provideDelegate` operator on that provider is `@Composable`, which is what lets the property name fall through to the storage key when `by` is used — same mechanism as `mutableStateOf`, just composable-aware. The provider materialises a `KSafeComposeState<T>` (which is both a `MutableState<T>` and a `ReadWriteProperty`) wrapped in `remember(key, instance, mode, policy, defaultValue)`, so the state survives recomposition and is disposed when the composition leaves. The optional self-heal coroutine (the WASM cold-start case where the cache is still warming up when first composition runs) and the optional `observeExternalChanges` collector are both launched inside a `LaunchedEffect(key, instance, mode, policy, defaultValue, observeExternalChanges)` — every value the memoized state bakes in participates in the keys, so a swapped instance/mode/policy/default rebuilds it with correctly-bound lambdas, and cancellation tracks the composition's lifetime — **no detached coroutines**, even when called at recomposition rate.

```kotlin
inline fun <reified T> KSafe.rememberKSafeState(
    defaultValue: T,
    key: String? = null,                                              // optional — defaults to property name
    mode: KSafeWriteMode = KSafeWriteMode.Plain,                      // UI state usually doesn't need encryption
    observeExternalChanges: Boolean = false,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): KSafeComposeStateProvider<T>
```

Defaults differ from `mutableStateOf` deliberately:
- **`mode = KSafeWriteMode.Plain`** — the typical compose-body use case is UI ephemera (selected tab, scroll position, draft text). Pass `mode = KSafeWriteMode.Encrypted(...)` to opt in if the value is sensitive.
- **`key` is optional** — when omitted, the storage key is inferred from the property name on the `var x by` declaration (same convention as `ksafe.mutableStateOf`). Pass an explicit `key` when you want to namespace (`key = "screen.draft"`) or share a key across multiple `var` declarations.

When to reach for which:

| Use case                       | API                                                                |
| ------------------------------ | ------------------------------------------------------------------ |
| ViewModel / class property     | `var x by ksafe.mutableStateOf(default)`                           |
| Composable-body local state    | `var x by ksafe.rememberKSafeState(default)`                       |

Cross-screen live sync still works the same way you'd expect — set `observeExternalChanges = true`:

```kotlin
@Composable
fun DashboardScreen(ksafe: KSafe) {
    var theme by ksafe.rememberKSafeState(
        defaultValue = ThemeMode.LIGHT,
        key = "theme",                           // explicit when sharing the key with other places
        observeExternalChanges = true,           // see writes from other screens / VMs
    )
    // …
}
```

## Suspend API (non-blocking)

```Kotlin
// inside coroutine / suspend fn
ksafe.put("profile", userProfile)          // encrypt & persist
val cached: User = ksafe.get("profile", User())
```

## Direct API (Recommended for Performance)

```Kotlin
ksafe.putDirect("counter", 42)
val n = ksafe.getDirect("counter", 0)
```

> **Performance Note:** Both APIs are competitive when used in their natural patterns. The Direct API is fire-and-forget (queue + return); use it when you don't need to know that the disk write committed. The Coroutine API awaits the disk commit; use it when persistence is a precondition for the next step (auth-token refresh, payment confirmation). When called from multiple concurrent coroutines (login flow saving 5 tokens, repository fan-out, etc.) the suspend API's coalescer batches the writes and individual call latency drops dramatically.

| API | Read | Write | Best For |
|-----|------|-------|----------|
| `getDirect`/`putDirect` | 0.0015 ms | 0.0010 ms | UI thread, fire-and-forget, hot cache |
| `get`/`put` (suspend) | 0.0024 ms | 0.86 ms | Guaranteed persistence; multiple concurrent callers |

> Numbers from the unencrypted-operations table in [BENCHMARKS.md](BENCHMARKS.md) (Direct API row, rounded; Samsung Galaxy S24 Ultra). Measured on KSafe 2.1.2; the figures are current for 3.0.0 — an un-rotated (generation-1) store uses the same byte-for-byte crypto path. See that doc for methodology, hardware, and the full table.

## Write Mode API (Per-Entry Unlock Policy)

Use `KSafeWriteMode` when you need encrypted-only options like `requireUnlockedDevice`:

```kotlin
// Direct API
ksafe.putDirect(
    "token",
    token,
    mode = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.DEFAULT,
        requireUnlockedDevice = true
    )
)

// Suspend API
ksafe.put(
    "pin",
    pin,
    mode = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
        requireUnlockedDevice = true
    )
)

// Explicit plaintext write
ksafe.putDirect("theme", "dark", mode = KSafeWriteMode.Plain)
```

No-mode writes (`put`/`putDirect` without `mode`) use encrypted defaults and pick up `KSafeConfig.requireUnlockedDevice` as the default unlock policy.

> To check up front whether an encrypted write will actually succeed on the current device — as opposed to how *strong* the protection is — read `protectionInfo.isEncryptionOperational`. See **[docs/PROTECTION_INFO.md](PROTECTION_INFO.md)**.

## Isolating an app's keys (`KSafeConfig.appNamespace`)

On **Android and iOS** the OS sandboxes each app's keystore, so different apps can never see each other's keys. On **JVM/Desktop** the OS secret store (macOS Keychain / Linux Secret Service) is **per-OS-user and shared by every process**, and on **Web** IndexedDB/localStorage is shared within a browser origin. Two different apps (or two KSafe setups) that use the same `fileName` would therefore collide on — and could overwrite — each other's encryption keys.

Set a stable, app-unique `appNamespace` to isolate the key-store destination:

```Kotlin
val ksafe = KSafe(
    fileName = "userdata",
    config = KSafeConfig(appNamespace = "com.example.myapp")
)
```

If left `null`, new JVM keys go to a fixed default namespace (`"shared"`), so two apps that share a `fileName` and both leave `appNamespace` null will collide; the old launcher-derived id is no longer a default and survives only as a read-side migration source. Override the vault namespace via `-Dksafe.appNamespace=…` / env `KSAFE_APP_NAMESPACE`, or — best — set an explicit `KSafeConfig.appNamespace`; Web relies on its built-in per-origin isolation. **Production desktop apps should set it explicitly** so the namespace is stable across run modes and packaging. On JVM an explicit `appNamespace` isolates both the data directory (the DataStore file moves into a namespace subdirectory) and the key-store *destination*; existing un-namespaced data is copied forward, not stranded. (The `-Dksafe.appNamespace`/env override namespaces only the key store, not the data directory.)

## Storing Complex Objects

```Kotlin
@Serializable
data class AuthInfo(
  val accessToken: String = "",
  val refreshToken: String = "",
  val expiresIn: Long = 0L
)

var authInfo by ksafe(AuthInfo())   // encryption + JSON automatically

// Update
authInfo = authInfo.copy(accessToken = "newToken")
```

> Seeing "Serializer for class X' is not found"? Add `@Serializable` and make sure you have added the Serialization plugin to your app.

### Example: Ktor bearer auth with zero encryption boilerplate

Persisting a whole auth-token object is one line — it's encrypted, persisted, and JSON-serialized for you. Reads come from the hot cache (~0.002 ms; no disk, no `suspend`):

```Kotlin
@Serializable
data class AuthTokens(val accessToken: String = "", val refreshToken: String = "")

var tokens by ksafe(AuthTokens())   // one line: encrypt + persist + serialize

install(Auth) {
  bearer {
    loadTokens {
      BearerTokens(tokens.accessToken, tokens.refreshToken)
    }
    refreshTokens {
      val newInfo = api.refreshAuth(tokens.refreshToken)
      // Atomic update: encrypts & persists as JSON in the background
      tokens = AuthTokens(newInfo.accessToken, newInfo.refreshToken)
      BearerTokens(tokens.accessToken, tokens.refreshToken)
    }
  }
}
```

## Cryptographic Secrets (`getOrCreateSecret`)

Generate-once, read-forever random secrets — ideal for a database passphrase (SQLCipher / SQLDelight / Room), an HMAC key, or an API signing key. On the first call KSafe mints a cryptographically secure random `ByteArray` and stores it encrypted; every later call returns the same bytes.

```kotlin
// 32-byte (256-bit) secret, HARDWARE_ISOLATED — one line
val passphrase = ksafe.getOrCreateSecret("main.db")

// Customise size / protection / unlock policy
val signingKey = ksafe.getOrCreateSecret(
    key = "api_signing_key",
    size = 64,                                                // bytes (default 32)
    protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,  // default
    requireUnlockedDevice = false                             // default
)
```

Defaults: 32 bytes, `HARDWARE_ISOLATED` protection (StrongBox on Android, Secure Enclave on iOS/macOS), device-unlock not required.

> **The value is sacred.** A stored secret is *never* silently rotated: if it exists but can't be read back (backing key invalidated, vault temporarily locked, stored value corrupt) `getOrCreateSecret` **throws** instead of minting a fresh one — overwriting would permanently orphan everything encrypted under the old secret (your SQLCipher database would become unreadable). Resolve the vault/key problem and retry, or `delete` the key to deliberately rotate it. `rotateKeys()` re-wraps a secret's storage key for the same reason — it preserves the value.

### Example: Room + SQLCipher

```kotlin
val passphrase = ksafe.getOrCreateSecret("main.db")
val factory = SupportFactory(passphrase)

Room.databaseBuilder(context, AppDatabase::class.java, "main.db")
    .openHelperFactory(factory)
    .build()
```

### Example: SQLDelight (cross-platform)

```kotlin
val passphrase = ksafe.getOrCreateSecret("app.db")
// pass to your platform-specific SqlDriver configuration
```

## Key Rotation

`rotateKeys()` re-encrypts every entry under a fresh key generation and sweeps the superseded keys — values, defaults, and the on-disk layout are untouched:

```kotlin
val result: KSafeRotationResult = ksafe.rotateKeys()
// result.rotated / result.skipped / result.failed / result.keyGeneration
```

It is crash-safe, resumable, never blocks startup or reads, and can also run automatically in the background via a policy:

```kotlin
val ksafe = KSafe(config = KSafeConfig(
    keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(90.days)  // rotate once the keys turn 90 days old
))
```

The full model, guarantees, and the policy API live in **[docs/KEY_ROTATION.md](KEY_ROTATION.md)**.

## Nullable Values

KSafe fully supports nullable types:

```Kotlin
// Store null values
val token: String? = null
ksafe.put("auth_token", token)

// Retrieve null values (returns null, not defaultValue)
val retrieved: String? = ksafe.get("auth_token", "default")
// retrieved == null ✓

// Nullable fields in serializable classes
@Serializable
data class UserProfile(
    val id: Int,
    val nickname: String?,
    val bio: String?
)
```

> ⚠️ **Important:** Do **not** pass a bare `null` as the `defaultValue` argument (e.g. `ksafe.get("auth_token", null)`). KSafe relies on `reified` generics to infer the type `T`, and a bare `null` gives the compiler nothing to infer from — `T` collapses to `Nothing?` and the call always returns `null`, even if the key has a stored value.
>
> If you want a nullable type with a `null` default, make the type explicit so inference has something to work with:
>
> ```Kotlin
> // ❌ Wrong — always returns null
> val token = ksafe.get("auth_token", null)
>
> // ✅ Correct — explicit type parameter
> val token = ksafe.get<String?>("auth_token", null)
>
> // ✅ Correct — typed variable drives inference
> val token: String? = ksafe.get("auth_token", null)
> ```
>
> The same rule applies to the property delegate (`ksafe(...)`), which also relies on reified generics:
>
> ```Kotlin
> // ❌ Wrong — T collapses to Nothing?
> var token by ksafe(null)
>
> // ✅ Correct — explicit type parameter
> var token by ksafe<String?>(null)
>
> // ✅ Correct — typed property drives inference
> var token: String? by ksafe(null)
> ```

Nullability flows through **every** delegate shape — Compose state and Flows included, not just `get`/`put`. The persisted `null` survives process death and emits correctly through Flow observers (give each an explicit type so reified inference has something to work with):

```Kotlin
var token: String? by ksafe(null)                                       // plain delegate
var profile: User? by ksafe.mutableStateOf(null)                        // Compose state
val user: StateFlow<User?> by ksafe.asStateFlow(null, scope)            // read-only StateFlow
private val _state by ksafe.asMutableStateFlow<User?>(null, scope)      // read/write MutableStateFlow
val theme: WritableKSafeFlow<ThemeMode?> by ksafe.asWritableFlow(null)  // read/write Flow, no scope
```

## Deleting Data

```Kotlin
ksafe.delete("profile")       // suspend — awaits the durable delete
ksafe.deleteDirect("profile") // non-suspending; cache cleared immediately, delete persisted in the background
```

When you delete a value, its data and metadata are removed from the store, and any per-entry encryption key is deleted (best-effort). Note that `DEFAULT` entries — the default protection — share one master key: deleting a single entry does **not** delete that master, because it still encrypts your other entries. The master key is removed only by `clearAll()`, or when a rotation drops a generation that no entry references any more.

To wipe **everything** in an instance at once:

```Kotlin
ksafe.clearAll()   // suspend — removes every entry AND its encryption key
```

`clearAll()` is destructive and irreversible: it clears all data for this instance and deletes every associated key from the OS key store. The data wipe fails loudly; the key deletions are best-effort — a platform-vault failure is logged rather than thrown, since the values are already gone and surviving key material only matters to out-of-store ciphertext copies (backups, quarantine files).

## Collecting Security Violations for the UI

KSafe runs its root/jailbreak checks during construction — before your ViewModels exist. To surface any `SecurityViolation` in the UI, collect them from the policy's `onViolation` callback into a holder, then read that holder once the UI is up:

```kotlin
// 1. Collect violations as KSafe initialises
object SecurityViolationsHolder {
    private val _violations = mutableListOf<SecurityViolation>()
    val violations: List<SecurityViolation> get() = _violations.toList()

    fun add(violation: SecurityViolation) {
        if (violation !in _violations) _violations.add(violation)
    }
}

// 2. Wire the callback
val ksafe = KSafe(
    context = context,
    securityPolicy = KSafeSecurityPolicy.Strict.copy(
        onViolation = { SecurityViolationsHolder.add(it) }
    )
)

// 3. Read them once a ViewModel exists
class SecurityViewModel : ViewModel() {
    val violations = mutableStateListOf<UiSecurityViolation>()

    init {
        SecurityViolationsHolder.violations.forEach { violations.add(UiSecurityViolation(it)) }
    }
}
```

The `ksafe-compose` module ships `UiSecurityViolation` — an `@Immutable` wrapper around `SecurityViolation` — so Compose can skip recomposition; prefer it over the raw enum in composable state. The policy actions (`WARN`/`BLOCK`), preset policies, and detection methods are documented in **[docs/SECURITY_MODEL.md](SECURITY_MODEL.md)**.

## Full ViewModel Example

```Kotlin
class CounterViewModel(ksafe: KSafe) : ViewModel() {
  // regular Compose state (not persisted)
  var volatile by mutableStateOf(0)
    private set

  // persisted Compose state (AES encrypted)
  var persisted by ksafe.mutableStateOf(100)
    private set

  // persisted Compose state + flow observation (auto-updates from external changes)
  var shared by ksafe.mutableStateOf(0, scope = viewModelScope)
    private set

  // plain property-delegate preference
  var hits by ksafe(0)

  // reactive read-only StateFlow (key = "score")
  val score: StateFlow<Int> by ksafe.asStateFlow(0, viewModelScope)

  // reactive read/write MutableStateFlow (key = "level")
  val level: MutableStateFlow<Int> by ksafe.asMutableStateFlow(1, viewModelScope)

  fun inc() {
    volatile++
    persisted++
    shared++
    hits++
  }
}
```
