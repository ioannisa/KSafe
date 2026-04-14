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
- [Storing Complex Objects](#storing-complex-objects)
- [Nullable Values](#nullable-values)
- [Deleting Data](#deleting-data)
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

> **Important:** The property delegate can ONLY use the default KSafe instance. If you need to use multiple KSafe instances with different file names, you must use the suspend or direct APIs.

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

> `asFlow` and `asStateFlow` are **read-only** — writes go through `put`/`putDirect`. Use `asMutableStateFlow` when you want read/write + reactivity without Compose. All three automatically pick up changes made anywhere.

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

> **Performance Note:** For bulk or concurrent operations, **always use the Direct API**. The Coroutine API waits for DataStore persistence on each call (~22 ms), while the Direct API returns immediately from the hot cache (~0.022 ms) — that's **~1000x faster**.

| API | Read | Write | Best For |
|-----|------|-------|----------|
| `getDirect`/`putDirect` | 0.007 ms | 0.022 ms | UI, bulk ops, high throughput |
| `get`/`put` (suspend) | 0.010 ms | 22 ms | When you must guarantee persistence |

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

## Deleting Data

```Kotlin
ksafe.delete("profile")       // suspend (non-blocking)
ksafe.deleteDirect("profile") // blocking
```

When you delete a value, both the data and its associated encryption key are removed from secure storage.

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
