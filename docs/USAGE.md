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
- [Mode-Typed Views (3.1.0+)](#mode-typed-views-310--ksafeplain--ksafeencrypted--ksafehardwareisolated)
- [Isolating an app's keys (`appNamespace`)](#isolating-an-apps-keys-ksafeconfigappnamespace)
- [Storing Complex Objects](#storing-complex-objects)
- [Cryptographic Secrets (`getOrCreateSecret`)](#cryptographic-secrets-getorcreatesecret)
- [Key Rotation](#key-rotation)
- [Nullable Values](#nullable-values)
- [Deleting Data](#deleting-data)
- [Collecting Security Violations for the UI](#collecting-security-violations-for-the-ui)
- [Full ViewModel Example](#full-viewmodel-example)

## Property Delegation (One Liner)

`ksafe` below is a `KSafe` instance built by the platform factory (see [docs/SETUP.md](SETUP.md)).
Kotlin's `by` hands the property over to KSafe, so reading and writing the variable *is* reading
and writing the store:

```kotlin
var counter by ksafe(0)
```

Parameters:
* `defaultValue` — required; the type is inferred from it, and it is what you read while nothing readable is stored under the key.
* `key` — optional; when omitted, the property name is the storage key (`"counter"` above).
* `mode` — optional; `KSafeWriteMode.Plain` or `KSafeWriteMode.Encrypted(...)` for per-entry control (see [Write Mode API](#write-mode-api-per-entry-unlock-policy)). When omitted, writes use `KSafe.defaultWriteMode`: encrypted, with the instance's unlock policy.

Reads come from the in-memory cache; writes update that cache at once and reach disk in the
background, and a write that fails in the background is rolled back and logged.

```Kotlin
class MyViewModel(ksafe: KSafe): ViewModel() {
  var counter by ksafe(0)

  init {
    // then use it as a regular variable
    counter++
  }
}
```

> The property delegate works with any `KSafe` instance — the receiver of `by myKSafe(...)` is the store the value lives in. With several instances (see [docs/SETUP.md](SETUP.md#multiple-instances) for how to create and inject them) each one gets its own delegates: `var theme by prefs("light")`, `var token by vault("")`.

**Prefer no delegation at all? Hold the handle directly (3.2.0+).** The same call that backs
`by` returns a `KSafeReference<T>` — keep it in a normal `val` and read/write `.value`. Direct
access needs an explicit `key`: with `by`, Kotlin passes the property (and so its name) to the
delegate, while a plain `=` assignment involves no property at all, so there is no name KSafe
could use. A key-less handle stays delegate-only, and `.value` on it throws
`IllegalStateException`.

```kotlin
val counter = ksafe(0, key = "counter")   // KSafeReference<Int>
counter.value++                           // read + write, no `by`
```

It works on the mode-typed views too — `ksafe.plain(0, key = "theme")`, or the same call on a
[`KSafePlain`](#mode-typed-views-310--ksafeplain--ksafeencrypted--ksafehardwareisolated) you
already hold — where writes use the view's frozen mode.

`.value` is plain storage access: changing it recomposes nothing. Inside Compose use
[`rememberKSafeState`](#rememberksafestate--composable-body-persistent-state-no-viewmodel-required) from `:ksafe-compose`, or collect a flow (see
[Flow Delegates](#flow-delegates-reactive-reads) below).

## Flow Delegates (Reactive Reads)

KSafe has always offered `getFlow()` and `getStateFlow()` with explicit key strings. These delegates extend the same property-name-as-key pattern from the `ksafe(...)` delegate above to Flows and StateFlows — use whichever style you prefer.

**`asFlow`** returns a cold `Flow<T>` — *cold* means nothing runs until someone collects it, so
it needs no `CoroutineScope` and costs nothing while unused — ideal for repositories and data
layers:

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

Why does this one need no scope, when the StateFlow variants below do? A hot flow has to be kept collecting by someone, and the scope is who does that; a cold flow is collected only by whoever reads it. The missing synchronous getter above is the price of that freedom.

**`asStateFlow`** returns a hot `StateFlow<T>` — *hot* means it always holds a current value you
can read synchronously with `.value`, which is why it needs a `CoroutineScope` to keep it alive —
ideal for ViewModels:

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

Picking one:

| Delegate | Returns | Needs a scope | Read | Write |
|---|---|---|---|---|
| `asFlow` | cold `Flow<T>` | no | collect | — (use `put`/`putDirect`) |
| `asWritableFlow` | `WritableKSafeFlow<T>` (cold) | no | collect | `set(value)` |
| `asStateFlow` | hot `StateFlow<T>` | yes | `.value` or collect | — (use `put`/`putDirect`) |
| `asMutableStateFlow` | hot `MutableStateFlow<T>` | yes | `.value` or collect | `.value = …`, `update {}` |

All four use the property name as the storage key unless you pass `key`, and the writable ones use `KSafe.defaultWriteMode` unless you pass `mode`.

> All four automatically pick up changes made anywhere in the process — KSafe writes from another screen, background sync, or another delegate against the same key. One limit: on Web a flow only sees writes made through the *same* `KSafe` instance, so keep one instance per store there (the singleton rule in [docs/SETUP.md](SETUP.md#multiple-instances)).

## Composable State (One Liner)

```kotlin
var counter by ksafe.mutableStateOf(0)
```

The value is Compose state — changing it recomposes whatever reads it — and it is persisted, so
it is still there after the OS kills and restarts the app (*process death*, in Android's
vocabulary). Requires the `ksafe-compose` dependency.

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

`mutableStateOf` has been in KSafe since v1.0.0; since 1.8.0 it takes an optional `scope` parameter.

**Without `scope`** — the state reads from the cache when the delegate is created and persists on write, but it is **isolated**: if another ViewModel or a background `put()` writes the same key later, this state does not see it until the ViewModel is destroyed and recreated. (One exception: if that first read returned the default because the value was not readable yet — the cache still loading on Web, a locked device elsewhere — the state applies the stored value once, when it arrives.)

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

This is the KSafe analogue of `rememberSaveable { mutableStateOf(...) }`, with stronger guarantees: `rememberSaveable` survives configuration changes and (via the saveable state registry) process death for `Bundle`-friendly types on Android only — state is cleared on a cold app launch. `rememberKSafeState` survives **app restart**, on every supported target (Android, iOS, macOS, JVM Desktop, Web), with optional encryption.

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

`rememberKSafeState` returns a `KSafeComposeStateProvider<T>`. Its `provideDelegate` operator is
`@Composable`, which is how the property name reaches KSafe as the storage key when you write
`by` — the same mechanism as `mutableStateOf`, made composable-aware.

The provider builds a `KSafeComposeState<T>` — both a Compose `MutableState<T>` and a property
delegate — inside `remember(key, instance, mode, policy, defaultValue)`, so the state survives
recomposition and is dropped when the composable leaves the composition.

Storage observation runs in a `LaunchedEffect` keyed on those same values plus
`observeExternalChanges`. If the first read returned the default because the value was not
readable yet (WebCrypto still decrypting on Web, a locked device elsewhere), a one-shot self-heal
applies the stored value once it arrives, waiting up to 5 seconds. With
`observeExternalChanges = true` the effect keeps collecting for as long as the composable lives.
Changing the instance, mode, policy or default rebuilds the state with correctly bound lambdas,
and leaving the composition cancels everything — **no detached coroutines**, even when called at
recomposition rate.

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

`put` returns only once the value is committed to disk; `get` suspends instead of blocking while
the cache loads. The [Direct API](#direct-api-recommended-for-performance) below is the
non-suspending counterpart, and the note there says when to prefer which.

## Direct API (Recommended for Performance)

```Kotlin
ksafe.putDirect("counter", 42)
val n = ksafe.getDirect("counter", 0)
```

> **Which one when?** Both APIs are fast when used in their natural patterns.
>
> - `putDirect` is *fire-and-forget*: it updates the in-memory cache and queues the disk write, then returns. Use it when you do not need to know that the value reached disk (UI state, counters, preferences). A write that fails in the background is rolled back and logged; use the `putDirect(key, value, mode, onWriteFailed)` overload if you need to hear about it.
> - `put` *suspends until the write is committed to disk*. Use it when the next step must not run before the value is durable — an auth-token refresh, a payment confirmation.
> - Reads: `getDirect` serves from the in-memory cache without touching disk (it blocks once if the cache is still doing its first load; on Web, which cannot block, it returns the default until that load finishes — call `awaitCacheReady()` at startup there). `get` suspends instead of blocking.
>
> Writes that are queued at the same moment — a login flow saving five tokens, a repository fan-out — are committed together in one batch, so they share a single disk commit instead of paying one each. A suspending `put` never waits for the batching window: it closes the batch, so it completes in one round trip.

| API | Read | Write | Best For |
|-----|------|-------|----------|
| `getDirect`/`putDirect` | 0.0015 ms | 0.0010 ms | UI thread, fire-and-forget, cache reads |
| `get`/`put` (suspend) | 0.0024 ms | 0.86 ms | Guaranteed persistence; multiple concurrent callers |

> Numbers from the unencrypted-operations table in [BENCHMARKS.md](BENCHMARKS.md) (Direct API row, rounded; Samsung Galaxy S24 Ultra), measured on KSafe 2.1.2. That document states which later versions the figures still describe, and gives the methodology, the hardware, and the full table.

## Write Mode API (Per-Entry Unlock Policy)

Every write carries a *mode* that says how the value is stored:

- `KSafeWriteMode.Plain` — stored unencrypted; no key store is involved. For values that are not secret (theme, selected tab).
- `KSafeWriteMode.Encrypted(protection, requireUnlockedDevice)` — encrypted with AES-GCM under a key KSafe keeps in the platform key store. This is the default.
  - `protection = KSafeEncryptedProtection.DEFAULT` — the platform's normal key store: Android Keystore, Apple Keychain, the OS vault on JVM Desktop, a browser-origin key on Web.
  - `protection = KSafeEncryptedProtection.HARDWARE_ISOLATED` — asks for the device's dedicated security chip (StrongBox on Android, Secure Enclave on Apple). A request, not a guarantee: where that hardware is missing the write lands in the same store as `DEFAULT`. To see which happened, read `getKeyInfo(key)?.level` for one entry, or `protectionInfo` for the custody the whole instance negotiated.
  - `requireUnlockedDevice = true` — the entry's key is usable only while the device is unlocked. Enforced on Android and Apple; JVM and Web have no device lock and store an ordinary encrypted entry. On Android 28–34, removing the lock screen can silently delete such keys (the value then reads back as its default), so treat it as hardening, not a portable guarantee.

Reads take no mode: KSafe records how each entry was written and decrypts it accordingly.

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

A write without `mode` uses `KSafe.defaultWriteMode`: `Encrypted` at the `DEFAULT` tier, with `requireUnlockedDevice` taken from `KSafeConfig.requireUnlockedDevice` (`false` unless you set it). The property delegate, the flow delegates and the Compose `mutableStateOf` delegate share that default; `rememberKSafeState` is the one exception — it defaults to `Plain`, because composable-body state is usually UI ephemera.

> To check up front whether an encrypted write will actually succeed on the current device — as opposed to how *strong* the protection is — read `protectionInfo.isEncryptionOperational`. See **[docs/PROTECTION_INFO.md](PROTECTION_INFO.md)**.

## Mode-Typed Views (3.1.0+) — `KSafePlain` / `KSafeEncrypted` / `KSafeHardwareIsolated`

When one store holds both preferences and secrets, the per-call `mode =` argument is a
convention — and one forgotten argument silently writes with the wrong protection. The three
view types turn the convention into a compiler rule: each wraps an **existing** `KSafe`
instance and freezes the write mode at construction, so no member of the type takes a `mode`
parameter at all.

```kotlin
val prefs = KSafePlain(ksafe)            // or: ksafe.plain
val vault = KSafeHardwareIsolated(ksafe) // or: ksafe.hardwareIsolated

prefs.putDirect("theme", "dark")         // always Plain — nothing to forget
vault.put("master_key", secret)          // always requests the device's security chip

var theme by prefs("dark")               // delegate: key = property name, writes Plain
val pin by vault.asWritableFlow("", key = "pin")   // .set() writes hardware-isolated
```

The full write surface is covered — `put`/`putDirect`, the `by view(...)` delegate (whose
result, given an explicit `key`, is also a direct no-`by` `.value` handle — 3.2.0+),
`asFlow`/`asWritableFlow`/`asStateFlow`/`asMutableStateFlow`/`getStateFlow`, and (via
`:ksafe-compose`) `mutableStateOf` and `rememberKSafeState` — so the type guarantee has no
gap where writes actually happen.

**In Koin, the types replace string qualifiers.** Instead of registering one `KSafe` three times under `named("prefs")`, `named("vault")` … and hoping every injection site spells the string right, register each view once and let the type do the matching. One store, three injectable views:

```kotlin
single { KSafe(context = androidApplication(), fileName = "app") }
single { KSafePlain(get()) }
single { KSafeHardwareIsolated(get()) }

class SettingsRepository(private val prefs: KSafePlain)          // writes are always Plain
class AuthRepository(private val vault: KSafeHardwareIsolated)   // writes always request StrongBox / Secure Enclave
```

Every view shares the underlying store — same file, same key namespace, same cache, one
`awaitCacheReady()` on web — so mixed-mode entries in one store keep working, and a value
written through one view is immediately visible through any other.

Three honest boundaries:

- **The guarantee is write-side only.** KSafe records how each entry was written and decrypts it
  accordingly, so reads take no mode at all — `KSafePlain.get()` happily reads a value some other
  handle wrote encrypted.
- **`KSafeHardwareIsolated` requests, it does not guarantee.** Where the device has no security
  chip the write falls back to the platform's normal key store — the same one `DEFAULT` uses —
  and reports what it actually got via `protectionInfo` / `getKeyInfo`.
- **Store-scoped operations are deliberately absent** (`rotateKeys`, `clearAll`, `close`,
  `protectionInfo`, `getKeyInfo`, `awaitCacheReady`, `getOrCreateSecret`) — they concern the
  whole store, not a mode view. Call them on the underlying instance, exposed as `view.ksafe`.

`KSafeEncrypted` and `KSafeHardwareIsolated` also freeze the unlock policy:
`KSafeEncrypted(ksafe, requireUnlockedDevice = true)` makes every write through that view
strict, while the default constructor inherits the instance's configured policy
(`KSafe.defaultWriteMode`) — a default-constructed `KSafeEncrypted(ksafe)` writes exactly
like a modeless `ksafe.put`.

## Isolating an app's keys (`KSafeConfig.appNamespace`)

KSafe stores two things: your values (in a store file, or in browser storage on Web) and the
encryption keys that protect them (in the platform's key store — the OS service that holds key
material for you). Whether anything else on the machine can reach them depends on the platform:

- **Android and iOS/macOS** — the OS gives every app its own sandbox for both. Nothing to configure; `appNamespace` has no effect there.
- **JVM/Desktop** — the OS secret store (macOS Keychain, Windows DPAPI, Linux Secret Service) is per OS user and shared by every process that user runs. Two desktop apps — or two builds of the same app — that use the same `fileName` would reach the same keys and could overwrite each other's.
- **Web** — `localStorage` and IndexedDB (the browser's own storage) are shared by everything on the same browser origin. Two KSafe stores on one origin that share a `fileName` would collide the same way.

On JVM and Web, set a stable, app-unique `appNamespace` (reverse-DNS works well):

```Kotlin
val ksafe = KSafe(
    fileName = "userdata",
    config = KSafeConfig(appNamespace = "com.example.myapp")
)
```

What it does:

- **JVM** — the store file moves into a subdirectory named after the namespace, and the keys are stored under that namespace in the OS secret store. Data that already existed without a namespace is copied forward on the first launch, so nothing is stranded.
- **Web** — the namespace becomes part of the storage prefix for both the stored values and the encryption-key record, so same-origin stores stay apart.

Leave it `null` on JVM and new keys go to a fixed default namespace called `"shared"` — so two
apps that share a `fileName` and both leave it unset will collide. The namespace can also be set
from outside the app, with `-Dksafe.appNamespace=…` or the `KSAFE_APP_NAMESPACE` environment
variable, but those move only the key store, not the data directory; production desktop apps
should set `KSafeConfig.appNamespace` explicitly so the namespace is stable across run modes and
packaging. Pick the value once and do not change it: it is part of where your data and keys live.
Storage-layout changes between KSafe versions are listed in [docs/MIGRATION.md](MIGRATION.md).

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

> Seeing "Serializer for class X is not found"? Add `@Serializable` to the class, and make sure the kotlinx-serialization Gradle plugin is applied — it is step 2 of the install in the [README](../README.md). For a type you cannot annotate because you don't own it (`java.util.UUID`, a value type from a library), see [docs/SERIALIZATION.md](SERIALIZATION.md).

### Example: Ktor bearer auth with zero encryption boilerplate

Persisting a whole auth-token object is one line — it's encrypted, persisted, and JSON-serialized for you. Reads come from the in-memory cache (~0.002 ms; no disk, no `suspend`):

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

Some values have to be random, secret, and reproduced exactly for the life of the app: a database
passphrase (SQLCipher / SQLDelight / Room), an HMAC key, an API signing key. `getOrCreateSecret`
is for those. On the first call KSafe generates cryptographically secure random bytes and stores
them encrypted; every later call returns the same bytes.

It is a `suspend` function — call it from a coroutine (a suspending database factory,
`viewModelScope.launch`, or a `runBlocking` in your DI module at startup):

```kotlin
// 32-byte (256-bit) secret, HARDWARE_ISOLATED — one line
val passphrase: ByteArray = ksafe.getOrCreateSecret("main.db")

// Customise size / protection / unlock policy
val signingKey = ksafe.getOrCreateSecret(
    key = "api_signing_key",
    size = 64,                                                // bytes (default 32)
    protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,  // default
    requireUnlockedDevice = false                             // default
)
```

Defaults: 32 bytes, `HARDWARE_ISOLATED` protection (the device's security chip — StrongBox on
Android, Secure Enclave on iOS/macOS — where there is one, otherwise the platform's normal key
store), device-unlock not required. `key` must not be blank and `size` must be positive; a call
that breaks either rule throws `IllegalArgumentException`.

> **The value is never silently replaced.** If a secret exists but cannot be read back — its backing key was invalidated, the OS key vault is temporarily locked, the stored value is corrupt — `getOrCreateSecret` **throws** `IllegalStateException` instead of minting a fresh one. Overwriting would permanently orphan everything encrypted under the old secret: your SQLCipher database would never open again. Fix the vault or key problem and retry. To discard the secret on purpose, delete the storage slot named in the exception message — KSafe keeps secrets in reserved slots, not under the key you passed — and call `getOrCreateSecret` again. `rotateKeys()` keeps the value for the same reason: it only re-wraps the key that encrypts it.

### Example: Room + SQLCipher

```kotlin
// inside a coroutine — e.g. a suspending database factory
val passphrase = ksafe.getOrCreateSecret("main.db")
val factory = SupportFactory(passphrase)

Room.databaseBuilder(context, AppDatabase::class.java, "main.db")
    .openHelperFactory(factory)
    .build()
```

### Example: SQLDelight (cross-platform)

```kotlin
val passphrase = ksafe.getOrCreateSecret("app.db")   // suspend — call from a coroutine
// pass to your platform-specific SqlDriver configuration
```

## Key Rotation

Every encrypted value is protected by a key KSafe holds in the platform key store. A *key
generation* is a number, starting at 1, that names the set of keys a store currently writes under.
`rotateKeys()` raises that number by one, mints fresh keys for the new generation, re-encrypts
every encrypted entry under them, and deletes the keys it supersedes. Your values, your defaults
and the on-disk layout do not change (plaintext entries are untouched — they have no key):

```kotlin
val result: KSafeRotationResult = ksafe.rotateKeys()
// result.rotated       — entries re-encrypted under the new generation
// result.skipped       — entries left on the previous generation for now (a device-unlock entry
//                        read while locked, or one a concurrent write won); still readable
// result.failed        — entries whose decrypt or re-encrypt failed outright
// result.keyGeneration — the store's generation after this pass; new writes use it
```

Rotation is opt-in and off by default (`KSafeKeyRotationPolicy.Never`). Platform-held keys do not
expire, so starting a new generation is a hygiene and compliance control rather than a security
necessity, and most apps never call it. It never blocks startup or reads, and it is crash-safe: if
the process dies mid-pass, the next `KSafe` instance finishes that same generation — also under
`Never`. A pass that had to skip retryable entries is retried by later instances, one attempt
each, up to `keyRotationRetryAttempts` (3 by default; `0` disables it). `rotateKeys()` throws
`IllegalStateException`, leaving the store untouched, if a rotation is already running on the
instance.

To rotate on a schedule, set a policy:

```kotlin
val ksafe = KSafe(config = KSafeConfig(
    keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(90.days), // rotate in the background once the keys are older than this
    keyRotationRetryAttempts = 3,                               // default; set 0 to disable next-instance retries
))
```

The full model, the guarantees, the retry budget, the upgrade behaviour from older stores and the
edge cases live in **[docs/KEY_ROTATION.md](KEY_ROTATION.md)**.

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

> ⚠️ **Important:** Do **not** pass a bare `null` as the `defaultValue` argument (e.g. `ksafe.get("auth_token", null)`). KSafe has to know the value's type at the call site — that is what `reified` generics give it: the type argument is kept at runtime, so KSafe can pick the right serializer. A bare `null` gives the compiler nothing to infer from — `T` collapses to `Nothing?` and the call always returns `null`, even when the key has a stored value.
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

When you delete a value, its data and its metadata are removed from the store. What happens to key material depends on how the entry was written. Encrypted entries at the `DEFAULT` protection tier share one key per store — the *master key*; on Android and Apple, where `requireUnlockedDevice` is enforced, entries written with it ride a second master of their own. Entries written `HARDWARE_ISOLATED` each get a key of their own, a *per-entry key*. Deleting an entry removes its per-entry key (best-effort) but never a master, because that master still encrypts your other entries. A master is removed only by `clearAll()`, or when a rotation drops a key generation that no entry references any more (see [Key Rotation](#key-rotation)).

To wipe **everything** in an instance at once:

```Kotlin
ksafe.clearAll()   // suspend — removes every entry AND its encryption key
```

`clearAll()` is destructive and irreversible: it clears the whole store — disk plus the caches of every live instance on this file (on web each instance still owns its own store handle) — and deletes every associated key from the OS key store. The data wipe fails loudly; the key deletions are best-effort — a platform-vault failure is logged rather than thrown, since the values are already gone and surviving key material only matters to out-of-store ciphertext copies (backups, quarantine files).

## Collecting Security Violations for the UI

KSafe can check whether the device is rooted or jailbroken, whether a debugger is attached to the
process, whether this is a debug build, and whether it is running on an emulator or simulator —
the four `SecurityViolation` values `RootedDevice`, `DebuggerAttached`, `DebugBuild` and
`Emulator` (Web detects none). Every check is off (`IGNORE`) unless your `KSafeSecurityPolicy`
turns it on.

The checks run inside the `KSafe(...)` factory call — before your ViewModels exist — so to surface
a violation in the UI, collect them from the policy's `onViolation` callback into a holder, then
read that holder once the UI is up:

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

The `ksafe-compose` module ships `UiSecurityViolation` — an `@Immutable` wrapper around `SecurityViolation` — so Compose can skip recomposition; prefer it over the raw enum in composable state. The policy actions (`IGNORE` — the default, where the check never runs — `WARN`, and `BLOCK`, which throws from the factory call), the preset policies, and the detection methods are documented in **[docs/SECURITY_MODEL.md](SECURITY_MODEL.md)**.

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
