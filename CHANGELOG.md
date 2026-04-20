# Changelog

All notable changes to KSafe will be documented in this file.

## [1.9.0] - 2026-04-19

### Added

#### Kotlin/JS (IR) target — browser support beyond WasmGC

KSafe now publishes a dedicated Kotlin/JS (IR) artifact alongside the existing Kotlin/WASM target. Projects that build for the legacy JS toolchain — or that need to ship to browsers without WasmGC (anything older than Chrome 119 / Firefox 120 / Safari 18) — are no longer dead-ended.

```kotlin
kotlin {
    js(IR) { browser() }

    // existing
    @OptIn(ExperimentalWasmDsl::class)
    wasmJs { browser() }

    sourceSets {
        // no extra work — :ksafe and :ksafe-compose expose the JS variant automatically
    }
}
```

Behaviour is identical to the wasmJs target:
- AES-256-GCM via WebCrypto through `cryptography-kotlin`.
- Persistence to browser `localStorage` with the same key layout, so switching a project between the two targets reads the same data back.
- Async-only crypto, `PLAIN_TEXT` internal memory policy, biometric calls return `true`, security checks are no-ops.

The JS implementation is a thin `actual` over `kotlinx.browser.localStorage`, `kotlin.js.Date.now()`, and a direct `crypto.getRandomValues()` binding — no Base64 round-trip for random bytes, unlike the WASM actual.

#### Shared `webMain` / `webTest` source sets

The bulk of the previous `wasmJsMain` implementation — `KSafe`, the WebCrypto-backed encryption engine, the `SecurityChecker` no-ops — moved into a new intermediate `webMain` source set shared between `jsMain` and `wasmJsMain`. Each target keeps only a small `WebInterop` actual file (`@JsFun` bindings for wasmJs; plain `external` + `kotlinx.browser` for js). The full `KSafeTest` suite now runs on **both** targets via a shared `webTest/WebKSafeTest.kt`.

A new `WebInteropSmokeTest` runs on both targets and asserts the per-target actuals: `localStorage` round-trip, `localStorage` enumeration, `currentTimeMillisWeb()` plausibility, and `secureRandomBytes()` non-determinism. This guards against Long / Int / Float conversion regressions specific to either target.

### Fixed

#### Kotlin/JS: Float / Double reads collapsing into the Int branch

On Kotlin/JS, `Float` and `Double` share a single runtime representation with `Int` (`0f is Int` returns `true` because JS stores `0f` as the integer `0`). The internal `convertStoredValueRaw` dispatch on the **runtime type of the default value** therefore routed Float / Double reads into the Int branch, returning the default (`0`) instead of the stored value — visible as `testPutAndGetUnencryptedFloat`, `testPutAndGetUnencryptedDouble`, and `testNegativeNumbers` failures on the js target.

Dispatch now goes through a new `primitiveKindOrNull(serializer)` helper that reads the `PrimitiveKind` off the serializer's descriptor, which preserves the declared type regardless of how the runtime represents the value. This path is only hit on the web targets — JVM / Android / iOS continue to use DataStore's typed preferences and are unaffected.

### Changed

#### `wasmJsMain` is now minimal

`KSafe.wasmJs.kt`, `WasmSoftwareEncryption.kt`, `SecurityChecker.wasmJs.kt`, and `LocalStorage.kt` no longer exist. Their contents live in `webMain` as `KSafe.web.kt`, `WebSoftwareEncryption.kt`, `SecurityChecker.web.kt`, and `WebInterop.kt` respectively. The only wasmJs-specific file is `WebInterop.wasmJs.kt` (which still uses `@JsFun` / `ExperimentalWasmJsInterop`) plus the existing `KSafeSecureRandom.wasmJs.kt`. No public API changes; no migration required.

---

## [1.8.1] - 2026-04-17

### Added

#### Android: `BiometricHelper.confirmationRequired` ([#11](https://github.com/ioannisa/KSafe/pull/11) — thanks @HansHolz09)

Added a `confirmationRequired: Boolean = true` property on `BiometricHelper` that wraps `BiometricPrompt.PromptInfo.Builder.setConfirmationRequired(...)`. Keep the default for sensitive actions — the prompt only resolves after an explicit user confirmation. Set to `false` for passive flows where the biometric match itself should be sufficient.

```kotlin
BiometricHelper.confirmationRequired = false // allow passive face-unlock
```

Note: this flag only affects weak/passive biometric modalities (e.g. face). For `BIOMETRIC_STRONG` modalities like fingerprint, the physical action is the confirmation and this flag has no effect.

### Fixed

#### iOS: Keychain NSString Memory Leak on Background Threads ([#22](https://github.com/ioannisa/KSafe/issues/22))

Fixed a memory leak in `IosKeychainEncryption` where Kotlin → NSString bridging conversions (e.g. inside `CFBridgingRetain(keyId)`) accumulated indefinitely when keychain operations ran on coroutine worker threads. The root cause is that Kotlin/Native emits autorelease-convention NSString allocations for string bridging, and `Dispatchers.Default` / SKIE-bridged Swift `async` worker threads do not have an ambient ObjC autorelease pool to drain them. Over time this surfaced as continuously growing memory in Instruments, dominated by `Kotlin_ObjCExport_CreateRetainedNSStringFromKString` allocations attributed to `IosKeychainEncryption#getExistingKeychainKey` and related paths.

The fix wraps the `memScoped { ... }` body of every keychain-touching internal method in `kotlinx.cinterop.autoreleasepool { ... }` so autoreleased bridged NSStrings drain promptly regardless of which thread the caller is on. No public API changes.

Affected methods (all internal): `createSecureEnclaveKey`, `getSecureEnclaveKey`, `deleteSecureEnclaveKey`, `updateSecureEnclaveKeyAccessibility`, `getExistingKeychainKeyRaw`, `getExistingKeychainKeyPlain`, `getOrCreateKeychainKeyPlain`, `storeInKeychain`, `updateKeychainItemAccessibility`, `deleteFromKeychain`.

A regression test (`IosKeychainEncryptionLeakTest`) was added that runs 5,000 keychain operations on `Dispatchers.Default` and asserts peak RSS growth stays under 2 MB via `getrusage(RUSAGE_SELF)`. Pre-fix the test reports ~7 MB of growth; post-fix it stays within allocator slack.

---

## [1.8.0] - 2026-04-14

### Added

#### Cryptographic Utilities: `secureRandomBytes` & `getOrCreateSecret`

**`secureRandomBytes(size: Int): ByteArray`** — A cross-platform cryptographically secure random byte generator, delegating to each platform's strongest CSPRNG (`java.security.SecureRandom` on Android/JVM, `arc4random_buf` on iOS, `crypto.getRandomValues()` on WASM). This is now also used internally by KSafe's own encryption engines for IV and key generation.

```kotlin
val nonce = secureRandomBytes(16)
val aesKey = secureRandomBytes(32)
```

**`KSafe.getOrCreateSecret(key, size, protection, requireUnlockedDevice): ByteArray`** — A suspend extension that generates a cryptographically secure random secret on first call and retrieves it on subsequent calls. Stored with hardware-backed encryption (`HARDWARE_ISOLATED` by default). Ideal for database encryption passphrases, API signing keys, HMAC keys, or any persistent secret.

```kotlin
// Database passphrase — one line, hardware-backed, generated once
val passphrase = ksafe.getOrCreateSecret("main.db")

// Custom size + protection
val apiKey = ksafe.getOrCreateSecret("api_key", size = 64)
```

#### Flow & StateFlow Property Delegates ([#20](https://github.com/ioannisa/KSafe/issues/20))

Since v1.0.0, KSafe offered `var counter by ksafe(0)` (plain delegates) and `var counter by ksafe.mutableStateOf(0)` (Compose state). Version 1.8.0 adds **`MutableStateFlow` delegates** (`asMutableStateFlow`) as a drop-in replacement for the standard `_state`/`state` pattern, **read-only flow delegates** (`asStateFlow` / `asFlow`), and **cross-screen sync** via `mutableStateOf(scope=)`. All new delegates derive their storage key from the property name (with an optional `key` override), staying consistent with the existing `invoke()` delegate — and the explicit-key `getStateFlow()` / `getFlow()` APIs remain fully supported.

**Core Module — flow delegates**

**1. `asMutableStateFlow` (Read / Write)**

Implements the full `MutableStateFlow` interface — all standard atomic operations work out of the box, persisting to encrypted storage instantly.

```kotlin
// Standard Kotlin pattern
private val _state = MutableStateFlow(MoviesListState())
val state = _state.asStateFlow()

// KSafe equivalent — same pattern, but persisted + reactive to external changes
private val _state by kSafe.asMutableStateFlow(MoviesListState(), viewModelScope)
val state = _state.asStateFlow()
```

```kotlin
@Serializable
data class MoviesListState(
    val loading: Boolean = false,
    val movies: List<Movie> = emptyList(),
    val error: String? = null
)

class MoviesViewModel(private val kSafe: KSafe, private val api: MoviesApi) : ViewModel() {
    // Acts exactly like a standard MutableStateFlow, but fully persisted
    private val _state by kSafe.asMutableStateFlow(MoviesListState(), viewModelScope)
    val state = _state.asStateFlow()

    fun loadMovies() {
        // .update {} persists securely (uses compareAndSet internally)
        _state.update { it.copy(loading = true) }

        viewModelScope.launch {
            try {
                val movies = api.getMovies()
                // .value = ... also persists instantly
                _state.value = _state.value.copy(loading = false, movies = movies)
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

**2. `asStateFlow` & `asFlow` (Read-Only)**

If you only need to read data (or update it manually via `kSafe.put()`), you can use read-only flow delegates.

```kotlin
class SettingsViewModel(private val kSafe: KSafe) : ViewModel() {
    // Hot flow tied to viewModelScope
    val username: StateFlow<String> by kSafe.asStateFlow("Guest", viewModelScope)

    // Cold flow
    val darkMode: Flow<Boolean> by kSafe.asFlow(defaultValue = false)

    // Optional: explicitly override the storage key
    val theme: Flow<String> by kSafe.asFlow(defaultValue = "light", key = "app_theme")

    fun onNameChanged(name: String) {
        viewModelScope.launch { kSafe.put("username", name) }
    }
}
```

**Compose Module — cross-screen reactivity**

The existing `mutableStateOf` now accepts an optional `scope` parameter.

**Without `scope`** (existing behavior) — the state reads from cache at init and persists on write, but it's isolated. If another ViewModel or a background `put()` writes to the same key, this state won't update until the ViewModel is recreated.

**With `scope`** — the state continuously observes the underlying flow. Changes from any source (another screen, another ViewModel, a background coroutine) are reflected in real-time. No manual refreshes or event buses required.

> If you only read/write from a single ViewModel, both behave identically. The `scope` parameter matters when **multiple writers** exist for the same key.

```kotlin
// Dashboard Screen — auto-reflects changes made from other screens
class DashboardViewModel(private val kSafe: KSafe) : ViewModel() {
    var username by kSafe.mutableStateOf("Guest", scope = viewModelScope)
    var notificationsEnabled by kSafe.mutableStateOf(false, scope = viewModelScope)
}

// Settings Screen — writes to the same KSafe instance
class SettingsViewModel(private val kSafe: KSafe) : ViewModel() {
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

**API summary**

| Module | Function | Type | Returns |
|--------|----------|------|---------|
| core | `asFlow(defaultValue, key?)` | Read-only | `Flow<T>` delegate |
| core | `asStateFlow(defaultValue, scope, key?)` | Read-only | `StateFlow<T>` delegate |
| core | `asMutableStateFlow(defaultValue, scope, key?, mode?)` | Read/write + Reactive | `MutableStateFlow<T>` delegate |
| compose | `mutableStateOf(..., scope?)` | Read/write + Reactive | `MutableState<T>` w/ flow observation |

## [1.7.1] - 2025-03-17

### Added

#### Custom JSON Serialization ([#19](https://github.com/ioannisa/KSafe/issues/19))

`KSafeConfig` now accepts a `json` parameter — a fully configured `Json` instance used for all user-payload serialization. This enables support for `@Contextual` types (e.g., `UUID`, `Instant`, `BigDecimal`) and custom `SerializersModule` registration.

```kotlin
val customJson = Json {
    ignoreUnknownKeys = true
    serializersModule = SerializersModule {
        contextual(UUIDSerializer)
        contextual(InstantSerializer)
    }
}

val ksafe = KSafe(
    config = KSafeConfig(json = customJson)
)
```

- Serializers are registered once at the instance level and apply to all operations (`putDirect`, `getDirect`, `put`, `get`, `getFlow`, delegates)
- Internal metadata serialization is unaffected — it uses its own private codec
- Default remains `Json { ignoreUnknownKeys = true }` via `KSafeDefaults.json` — no changes needed for existing code
- `kotlinx-serialization-json` is declared in the library as a **transitive dependency** (`api` scope) — no need to add it manually in your project
- **Note:** Changing the `Json` configuration for an existing `fileName` namespace may make previously stored non-primitive values unreadable

### Fixed

#### WASM: Encrypted `mutableStateOf` Delegates Return Defaults on Page Reload

Fixed a race condition on WASM where `mutableStateOf` Compose delegates could return the default value instead of the persisted encrypted value after a browser refresh. This occurred because WASM's WebCrypto decryption is async-only — if a KSafe instance was created and immediately read from in the same synchronous frame (e.g., via Koin lazy singleton injection into a ViewModel), the cache hadn't loaded yet.

The fix adds reactive self-healing to `KSafeComposeState`: when `getDirect` returns the default, a lightweight coroutine observes `getFlow` and updates the Compose state when the real decrypted value arrives. A `userHasWritten` guard ensures user writes are never overwritten by late-arriving cache data.

This bug was latent since WASM support was added but only surfaced when using multiple KSafe instances (e.g., a second instance with custom JSON serialization), where the second instance had no head start for its async cache loading.

#### Inline Bytecode Bloat ([#16](https://github.com/ioannisa/KSafe/issues/16))

Reduced bytecode generated at each KSafe call site by extracting non-reified logic from `inline` functions into `@PublishedApi internal` helpers. Previously, every `getDirect`/`putDirect` delegate expansion could produce thousands of bytecode instructions because the entire function body was inlined. Now only the `serializer<T>()` call is inlined; the rest is a regular function call to the `*Raw` variant.

#### Relaxed `fileName` Validation

The `fileName` parameter now accepts lowercase letters, digits, and underscores (must start with a letter). Previously only `[a-z]+` was allowed, which was unnecessarily restrictive. The regex is now `[a-z][a-z0-9_]*` across all platforms. Dots, slashes, and uppercase remain forbidden to prevent path traversal and case-sensitivity issues.


---

## [1.7.0] - 2025-03-03

### Added

#### StrongBox Opt-In (Android)

New `useStrongBox: Boolean = false` parameter on the Android `KSafe` constructor. When enabled, AES keys are generated inside the device's StrongBox security chip — a physically separate, tamper-resistant hardware module (available on Pixel 3+, some Samsung flagships, and other devices with StrongBox support).

> **Note:** This constructor parameter is `@Deprecated` — prefer per-property `KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)` instead. See [Deprecated](#deprecated) section.

```kotlin
val ksafe = KSafe(
    context = context,
    useStrongBox = true  // request StrongBox; falls back to TEE if unavailable
)
```

- **Automatic TEE fallback:** If the device lacks StrongBox, `StrongBoxUnavailableException` is caught and the key is regenerated in the standard TEE — no code changes or user-facing errors
- **Existing keys unaffected:** `useStrongBox` only applies to new key generation (`KeyGenParameterSpec.Builder`). Keys already stored in the Keystore are loaded from wherever they were originally generated (TEE or StrongBox) regardless of this setting. This means enabling `useStrongBox = true` on an existing installation won't migrate previously-generated TEE keys to StrongBox — those keys continue working in TEE. To migrate existing data to StrongBox-backed keys, delete the KSafe data (or the specific keys) and reinitialize — new keys will be generated in StrongBox
- **Performance trade-off:** StrongBox key generation is slower (1–5s vs 50–200ms for TEE) and per-operation latency is higher (~10–50ms vs <1ms). KSafe's memory policies mitigate read-side latency since most reads come from the hot cache

#### Secure Enclave Opt-In (iOS)

New `useSecureEnclave: Boolean = false` parameter on the iOS `KSafe` constructor. When enabled, AES encryption keys are wrapped (encrypted) by an EC P-256 key pair that lives inside the Secure Enclave hardware — Apple's dedicated security coprocessor.

> **Note:** This constructor parameter is `@Deprecated` — prefer per-property `KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)` instead. See [Deprecated](#deprecated) section.

```kotlin
val ksafe = KSafe(
    useSecureEnclave = true  // request SE envelope encryption; falls back to plain Keychain if unavailable
)
```

**Envelope encryption architecture:** The Secure Enclave only supports asymmetric keys (EC P-256), not AES. KSafe bridges this gap with envelope encryption:

1. An EC P-256 key pair is created inside the Secure Enclave hardware
2. The AES-256 symmetric key is wrapped (encrypted) by the SE public key using ECIES (`ECIESEncryptionCofactorX963SHA256AESGCM`)
3. The wrapped AES key is stored in the Keychain as a generic-password item
4. On decrypt, the SE private key unwraps the AES key, which then decrypts data via CryptoKit as before

This means the raw AES key bytes are only exposed in app memory during the actual CryptoKit encrypt/decrypt call — they can no longer be extracted directly from the Keychain.

- **Automatic Keychain fallback:** If the Secure Enclave is unavailable (simulator, older device without SE), KSafe catches the error and falls back to plain Keychain storage — same pattern as Android's StrongBox fallback
- **Existing keys unaffected:** `useSecureEnclave` only applies to new key creation. Pre-existing plain Keychain keys are still readable — KSafe checks for legacy (unwrapped) keys before creating new SE-wrapped keys. No automatic migration
- **Memory-safe:** All `SecKeyRef` references from Core Foundation are properly released via `try/finally { CFRelease() }` to prevent memory leaks
- **Performance trade-off:** The SE wrapping/unwrapping step adds latency to key retrieval. KSafe's memory policies and hot cache mitigate this since most reads come from the in-memory cache, not from repeated key unwrapping

#### Type-Safe Write Modes (`KSafeWriteMode`) & Hardware Isolation
The `encrypted: Boolean` parameter on public APIs is deprecated in favor of a strictly type-safe write model:

- `KSafeWriteMode.Plain` — unencrypted persistence
- `KSafeWriteMode.Encrypted(...)` — encrypted persistence with optional hardware isolation and per-entry unlock policy

```kotlin
// Plaintext (no encryption)
var theme by ksafe("dark", mode = KSafeWriteMode.Plain)

// Default encryption
var token by ksafe(
    "",
    mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.DEFAULT)
)

// Hardware isolation + per-entry unlock policy
var pin by ksafe(
    "",
    mode = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
        requireUnlockedDevice = true
    )
)
```

Write APIs now support:
- `putDirect(key, value, mode: KSafeWriteMode)`
- `put(key, value, mode: KSafeWriteMode)`
- delegate/Compose mode overloads

**`HARDWARE_ISOLATED` behavior by platform:**

| Platform | Behavior |
|----------|----------|
| **Android** | Generates AES key in StrongBox (dedicated security chip). Falls back to TEE if StrongBox unavailable. |
| **iOS** | Uses Secure Enclave envelope encryption (SE EC P-256 wraps AES key). Falls back to plain Keychain if SE unavailable. |
| **JVM** | Ignored — always software-backed. |
| **WASM** | Ignored — always WebCrypto. |

**Compose and delegate support:**

```kotlin
// Property delegation (protection applies to writes; reads auto-detect)
var secret by ksafe("", mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))

// Compose state (requires ksafe-compose)
var secret by ksafe.mutableStateOf("", mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))
```

#### Smart Auto-Detecting Reads
Read APIs (`getDirect`, `get`, `getFlow`, `getStateFlow`) no longer require mode/encrypted parameters. KSafe auto-detects encrypted vs plaintext values from persisted metadata, with legacy fallbacks when needed.

```kotlin
// Writes specify protection level
ksafe.putDirect("token", value)                                     // DEFAULT (encrypted)
ksafe.putDirect("setting", value, mode = KSafeWriteMode.Plain)     // unencrypted

// Reads auto-detect — just provide key + default
val token = ksafe.getDirect("token", "")      // auto-detects encrypted
val setting = ksafe.getDirect("setting", "")  // auto-detects unencrypted
val flow = ksafe.getFlow("token", "")         // auto-detects per emission
```

This eliminates the risk of mismatched put/get protection levels and simplifies the read API.

#### Automatic Protection Tier Migration

When the protection level for a key changes between app versions (e.g., upgrading from `DEFAULT` to `HARDWARE_ISOLATED`, or from `Plain` to `Encrypted`), KSafe transparently migrates the data:

- **`getDirect` / `get`**: If the key is not found at the expected storage location, `migrateProtectionInline` checks the alternate location (encrypted ↔ plaintext), reads the value, writes it to the new location at the new protection level, and cleans up the old data — all inline during the read.
- **`putDirect` / `put`**: Before writing, the alternate storage location is cleaned up (old data, old encryption keys) so stale entries don't accumulate.
- **`DEFAULT` ↔ `HARDWARE_ISOLATED`**: Both use the same encrypted storage key, so migration deletes the old encryption key and re-encrypts with a new one at the correct hardware tier.

This means changing a property's protection level in code "just works" — no manual migration step required.

#### Device Key Storage Query API

New read-only properties and methods on `KSafe` that let app code query the hardware security capabilities of the device and inspect both the protection tier and storage location of individual keys:

```kotlin
val ksafe = KSafe(context)

// Device-level: what hardware is available?
ksafe.deviceKeyStorages  // e.g. {HARDWARE_BACKED, HARDWARE_ISOLATED}
ksafe.deviceKeyStorages.max()  // HARDWARE_ISOLATED (highest available)

// Per-key: what protection was requested and where is the key actually stored?
val info = ksafe.getKeyInfo("auth_token")
// info?.protection  → KSafeProtection.DEFAULT (what the caller requested)
// info?.storage     → KSafeKeyStorage.HARDWARE_BACKED (where the key lives)
```

- **`KSafeKeyInfo`** — data class combining `protection: KSafeProtection?` (the tier used when the key was stored, or `null` for plaintext entries) and `storage: KSafeKeyStorage` (where the encryption key material actually resides on this device).
- **`KSafeProtection`** enum: `DEFAULT`, `HARDWARE_ISOLATED` — the read-time protection tier (internal counterpart to `KSafeEncryptedProtection` used in write APIs).
- **`deviceKeyStorages: Set<KSafeKeyStorage>`** — the set of key storage levels the current device supports. Always contains at least one element. Use `deviceKeyStorages.max()` to get the highest available level.
- **`getKeyInfo(key: String): KSafeKeyInfo?`** — returns the protection tier and actual storage location of a specific key, or `null` if the key doesn't exist. On Android/iOS, encrypted keys return `HARDWARE_BACKED` (or `HARDWARE_ISOLATED` if written with `HARDWARE_ISOLATED` and the device supports it). On JVM/WASM, storage is always `SOFTWARE`. Unencrypted keys return `KSafeKeyInfo(null, SOFTWARE)`.

New `KSafeKeyStorage` enum with natural ordinal ordering (`SOFTWARE < HARDWARE_BACKED < HARDWARE_ISOLATED`):

| Value | Meaning | Platforms |
|-------|---------|-----------|
| `SOFTWARE` | Software-only encryption | JVM, WASM |
| `HARDWARE_BACKED` | On-chip hardware (TEE / Keychain) | Android, iOS |
| `HARDWARE_ISOLATED` | Dedicated security chip (StrongBox / Secure Enclave) | Android (if available), iOS (real devices) |

**Platform behavior:**

| Platform | `deviceKeyStorages` |
|----------|---------------------|
| **Android** | Always `{HARDWARE_BACKED}`. Adds `HARDWARE_ISOLATED` if `PackageManager.FEATURE_STRONGBOX_KEYSTORE` is present (API 28+). |
| **iOS** | Always `{HARDWARE_BACKED}`. Adds `HARDWARE_ISOLATED` on real devices (not simulator). |
| **JVM** | `{SOFTWARE}` |
| **WASM** | `{SOFTWARE}` |

Instance-level (not static/companion) because Android needs `Context` for StrongBox detection via `PackageManager`.

#### Centralized Metadata Management (`KeySafeMetadataManager`)

New internal object that centralizes storage key naming, metadata parsing, and legacy format migration across all four platforms:

- **Canonical key format:** values stored at `__ksafe_value_{key}`, metadata at `__ksafe_meta_{key}__` (JSON: `{"v":1,"p":"DEFAULT","u":"unlocked"}`)
- **Legacy compatibility:** reads remain backward-compatible with `encrypted_{key}`, bare `{key}`, and `__ksafe_prot_{key}__` metadata; touched keys are migrated on write/delete
- Handles `classifyStorageEntry()`, `collectMetadata()`, `parseProtection()`, `buildMetadataJson()` for all platforms

### Changed

- **Canonical storage keys:** values are now written under `__ksafe_value_{key}` on all platforms.
- **Single JSON metadata entry per key:** metadata is written under `__ksafe_meta_{key}__`.
- **Legacy compatibility:** reads remain backward-compatible with `encrypted_{key}`, bare `{key}`, and legacy metadata keys; touched keys are migrated/cleaned on write/delete.
- **Per-entry unlock policy:** `requireUnlockedDevice` is now per encrypted write mode (`KSafeWriteMode.Encrypted(...)`), while `KSafeConfig.requireUnlockedDevice` is the default for no-mode encrypted writes.
- **Global access-policy migration removed:** per-instance access-policy marker flow is no longer used.
- **`protectionMap` stores literal strings instead of raw JSON:** `detectProtection()` is called on every `getDirect`/`get` read to determine if a key is encrypted or plaintext. Previously, `protectionMap` stored raw JSON metadata strings, causing `parseProtection()` to parse JSON on every read. Now stores literal strings (`"DEFAULT"`, `"NONE"`, `"HARDWARE_ISOLATED"`) via `protectionToLiteral()` at write time and `extractProtectionLiteral()` at cache load time. Reads always hit `parseProtection()`'s fast-path `when` check — no JSON parsing on the hot path. Applied on all four platforms (Android, JVM, iOS, WASM). Resulted in ~40% improvement in unencrypted read performance.
- **iOS Secure Enclave error messages now include CFError details:** `createSecureEnclaveKeyPair()` and `wrapAesKey()` now include the `NSError.localizedDescription` from the underlying `CFError` in their exception messages. This prevents the string-based fallback logic in `getOrCreateKeychainKey()` from misclassifying transient SE failures (e.g., device locked, interaction not allowed) as "SE unavailable" and silently downgrading to plain Keychain storage. The fallback check also now re-throws errors containing "interaction" (matching `errSecInteractionNotAllowed` from CFError descriptions).
- **Per-key protection metadata for migration safety and auto-detection:** Every write now persists metadata alongside the data, recording the protection level. This metadata serves two purposes: (1) auto-detection on reads — read APIs use it to determine whether to decrypt without caller input, and (2) migration safety — `requireUnlockedDevice` migration uses it to re-encrypt each key at its original hardware isolation level.
- **Dirty-key guard for protectionMap on all platforms:** `updateCache()` (DataStore platforms: Android, JVM, iOS) now skips overwriting `protectionMap` entries for keys with pending writes (dirty keys). On WASM, `loadCacheFromStorage()` skips `protectionMap` entries that were already set by optimistic `putDirect` writes. This prevents stale emissions from clobbering metadata set during the optimistic write window.
- **Android access-policy migration preserves StrongBox backing:** `migrateAccessPolicyIfNeeded()` now reads per-key protection metadata when re-encrypting keys during `requireUnlockedDevice` policy changes. Each key is re-encrypted at its original hardware isolation level. Pre-1.7.0 keys without metadata default to `DEFAULT` (TEE) since hardware isolation was not available before 1.7.0.

### Removed

- **`iosTestApp/`** — iOS test app that imported `ksafe` but never instantiated `KSafe`. Used a plain Swift `Dictionary` instead. Added by an external contributor; superseded by the Kotlin test suite in `ksafe/src/iosTest/` and the [KSafeDemo](https://github.com/ioannisa/KSafeDemo) app
- **`KoinInit.kt`** — Placeholder function (`initKoin()` with a `println`) in `iosMain` that shipped with the iOS framework to all consumers. No functionality
- **`ExampleInstrumentedTest.kt`** — Default Android Studio template test in `ksafe-compose` that only asserted the package name. No KSafe coverage
- **`IosDebugTest.kt`** — Debug-oriented iOS test with `println` hex dumps. All meaningful assertions already covered by `IosKSafeTest` (which extends the shared `KSafeTest` suite)
- **`ACCESS_POLICY_KEY` / `ACCESS_POLICY_UNLOCKED` / `ACCESS_POLICY_DEFAULT` constants** — Replaced by per-key JSON metadata

### Documentation

- Updated README performance benchmarks with v1.7.0 numbers measured on realistic cold-start conditions (disk I/O, not DataStore singleton cache). Updated all performance claims to reflect accurate ratios.

### Deprecated

#### `encrypted: Boolean` parameter (WARNING level)
`encrypted: Boolean` overloads remain available at `DeprecationLevel.WARNING` with IDE `ReplaceWith` guidance to `KSafeWriteMode`.

```kotlin
// Old (deprecated)
ksafe.put("key", value, encrypted = true)

// New
ksafe.put("key", value, mode = KSafeWriteMode.Encrypted())
ksafe.put("key", value, mode = KSafeWriteMode.Plain)
```

Affected APIs: `getDirect`, `putDirect`, `get`, `put`, `getFlow`, `getStateFlow`, property delegation `invoke`, and Compose `mutableStateOf`.

#### `useStrongBox` / `useSecureEnclave` constructor parameters
The instance-level constructor flags `useStrongBox: Boolean` (Android) and `useSecureEnclave: Boolean` (iOS) are `@Deprecated` in favor of per-property `KSafeEncryptedProtection.HARDWARE_ISOLATED` via `KSafeWriteMode`. When set to `true`, they promote all `DEFAULT` encryptions to `HARDWARE_ISOLATED` at the instance level.

### Added (Testing)

- `KSafeProtectionTest` (common) — tests for `KSafeProtection` enum values and `KSafeKeyStorage` ordinal ordering
- `KSafeKeyStorageTest` (JVM) — tests for the Key Storage Query API: `deviceKeyStorages_returnsOnlySoftware`, `enumOrdinalOrdering`, `getKeyInfo_returnsNullForNonExistentKey`, `getKeyInfo_returnsNoneProtectionAndSoftwareForUnencryptedKey`, `getKeyInfo_returnsDefaultProtectionAndSoftwareForEncryptedKey`, `getKeyInfo_protectionMatchesStoredMetadata`
- `IosKeychainEncryptionTest` (iOS) — tests for `keychainLookupOrder()`, `isTransientUnwrapFailure()`, SE tag prefix constants, plus Secure Enclave tests:
  - `testSecureEnclaveThrowsInTestEnvironment` — verifies SE encrypt falls back and throws in entitlement-less test runner
  - `testSecureEnclaveDeleteDoesNotThrow` — verifies SE delete is permissive
  - `documentSecureEnclaveBehavior` — documents envelope encryption architecture and manual test steps
- All existing test suites updated to use new `KSafeWriteMode` API (removed `encrypted: Boolean` parameter from all test calls)

### Build

- Added `kotlin.kmp.isolated-projects.support=auto` to `gradle.properties`

### Fixed

- **`getStateFlow()` brief incorrect emission ([#15](https://github.com/ioannisa/KSafe/issues/15)):** `getStateFlow()` used `defaultValue` as the initial `StateFlow` value, causing a brief emission of the default before the actual stored value arrived from `getFlow()`. Now uses `getDirect(key, defaultValue)` to synchronously resolve the initial value from the memory cache, so the `StateFlow` starts with the correct stored value immediately. *(Thanks @dhng22)*
- **Typed key cleanup correctness:** DataStore cleanup now uses type-agnostic key-name removal (`removeByKeyName`) to reliably remove stale typed legacy entries.
- **iOS Secure Enclave error propagation:** improved CFError forwarding avoids accidental fallback on lock-state related failures.
- **Race-safety and migration robustness:** batch/metadata migration behavior has been hardened for concurrent and legacy upgrade scenarios.
- **Biometric prompt never showing when KSafe is lazily initialized** (e.g. via Koin `single`, Hilt `@Singleton`). `BiometricHelper` relied solely on `ActivityLifecycleCallbacks` to track the current `FragmentActivity`, but when KSafe was created after the Activity had already reached RESUMED state, the callbacks never fired and `waitForFragmentActivity()` timed out after 5 seconds returning `false`. Added `findCurrentActivity()` reflection fallback that discovers the current resumed `FragmentActivity` via `ActivityThread`. The reflection is wrapped in a try-catch and degrades gracefully on non-standard Android builds.
- **`verifyBiometricDirect` dispatcher changed from `Dispatchers.Main` to `Dispatchers.Default`** to avoid calling `BiometricHelper.authenticate()` from the main thread, which its documentation explicitly prohibits.

---

## [1.6.0] - 2025-02-16

### Added

#### WASM/JS Target

KSafe now runs in the browser. New platform source sets (`wasmJsMain`, `wasmJsTest`) and a `ksafe-compose` WASM target bring encrypted key-value storage to Kotlin/WASM.

- **Storage:** Browser `localStorage` via `@JsFun` externals (in `LocalStorage.kt`)
- **Encryption:** WebCrypto AES-256-GCM via `cryptography-provider-webcrypto`
- **Memory policy:** Always `PLAIN_TEXT` internally — WebCrypto is async-only, so all values are decrypted at init and held as plaintext in a `HashMap`
- **Key namespace:** `ksafe_{fileName}_{key}` for data, `ksafe_key_{alias}` for encryption keys
- **Mutex-protected key generation** to prevent race conditions in single-threaded coroutine environments
- **Per-operation error isolation** in batch writes — a single failed operation doesn't discard the entire batch
- **`yield()`-based StateFlow propagation** — required because WASM is single-threaded and has no implicit suspension points like JVM's DataStore I/O
- **No** `runBlocking`, `ConcurrentHashMap`, `Dispatchers.IO`, or `AtomicBoolean` — all replaced with WASM-compatible equivalents
- New WASM-specific `actual` implementations: `KSafe.wasmJs.kt`, `WasmSoftwareEncryption.kt`, `LocalStorage.kt`, `SecurityChecker.wasmJs.kt`

#### StateFlow API

New reactive API for observing KSafe values as flows, available on all four platforms:

- `getFlow(key, defaultValue, encrypted)` — returns a cold `Flow<T>` that emits whenever the underlying value changes
- `getStateFlow(key, defaultValue, encrypted, scope)` — convenience extension that converts the cold flow into a hot `StateFlow<T>` using `stateIn(scope, SharingStarted.Eagerly, defaultValue)`
- Works with both encrypted and unencrypted values
- On DataStore platforms (Android, JVM, iOS), backed by `DataStore.data.map {}` with `distinctUntilChanged()`
- On WASM, backed by a `MutableStateFlow` that is updated on writes

#### ksafe-compose WASM Target

The `ksafe-compose` module now includes a `wasmJs` target, enabling `mutableStateOf` persistence in Compose for Web.

### Fixed

#### Android: DataStore "multiple active instances" crash on DI re-initialization

When using Koin Compose Multiplatform (`KoinMultiplatformApplication {}`), the Koin application context can be recreated on Activity restart (configuration changes such as rotation, locale change, or dark mode toggle). This causes all `single {}` definitions to be re-instantiated, including KSafe. Each new KSafe instance created a new DataStore for the same file, triggering:

```
IllegalStateException: There are multiple DataStores active for the same file
```

**Root cause:** Each `KSafe` constructor eagerly created its own `DataStore` instance. DataStore enforces a single-instance-per-file invariant. When Koin re-created KSafe with the same `fileName`, a second DataStore was created for the same file.

**Fix:** Added a process-level `ConcurrentHashMap<String, DataStore<Preferences>>` cache in the Android `companion object`. If a DataStore already exists for a given file name, it is reused instead of creating a new one. This fix is Android-only because configuration changes (Activity recreation) are an Android-specific lifecycle concept — iOS, JVM, and WASM do not re-initialize their DI containers during normal operation.

#### Key generation race condition (JVM)

Concurrent `putEncrypted` calls for the same key alias could trigger parallel key generation in `JvmSoftwareEncryption`, producing different AES keys. One key would be stored in DataStore while a different one was used to encrypt data, causing permanent data loss on the next read.

**Fix:** Added a `ConcurrentHashMap<String, SecretKey>` in-memory key cache and per-alias `synchronized` locks to `JvmSoftwareEncryption.getOrCreateSecretKey()`. The first caller generates and caches the key; subsequent callers return the cached key immediately.

#### deleteKey race with key cache repopulation (Android + JVM)

`deleteKey()` removed the key from the Keystore/DataStore but not from the in-memory cache (Android) or had no cache at all (JVM). A concurrent `encrypt()` call could re-cache the stale key before the delete completed, causing subsequent encryptions to use a key that no longer existed in persistent storage.

**Fix:** `deleteKey()` now holds the same per-alias lock as `getOrCreateKey()` and removes the key from both the persistent store and the in-memory cache atomically. Applied to both `AndroidKeystoreEncryption` and `JvmSoftwareEncryption`.

#### Replaced `intern()` lock strategy with dedicated lock map (Android + JVM)

Both `AndroidKeystoreEncryption` and `JvmSoftwareEncryption` used `synchronized(identifier.intern())` for per-alias locking. `String.intern()` adds strings to the JVM's permanent string pool, which is never garbage collected. With dynamic key aliases (e.g., per-user keys), this caused unbounded memory growth.

**Fix:** Replaced with `ConcurrentHashMap<String, Any>` lock maps and a `lockFor(alias)` helper. Lock objects are scoped to the encryption engine instance and eligible for GC when the engine is collected.

### Removed

- **`IntegrityChecker`** — Removed from all platforms (Android, iOS, JVM, WASM). This was a wrapper around Google Play Integrity (Android) and Apple DeviceCheck (iOS) that generated tokens for server-side device verification. It had no connection to KSafe's core encrypted storage functionality and added transitive dependencies (`play-integrity`, `play-services-base`) to every consumer. Client-side root/jailbreak detection remains available via `SecurityChecker` and `KSafeSecurityPolicy`.
- Removed `play-integrity` and `play-services-base` dependencies from Android

### Changed

- `datastore-preferences-core` dependency moved from `commonMain` to per-platform source sets (Android, JVM, iOS) — WASM uses `localStorage` and does not depend on DataStore

### Added (Testing)

- `Jvm160FixesTest` — 9 new JVM tests covering the three encryption engine fixes:
  - `testConcurrentEncryptedWritesSameKey_noDataLoss` — verifies concurrent encrypted writes to the same key all produce readable values
  - `testConcurrentEncryptedWritesDifferentKeys_allReadable` — verifies concurrent writes to different keys don't interfere
  - `testKeyGenerationRaceStress` — stress test with 20 threads writing to the same key
  - `testDeleteKeyDoesNotLeaveStaleCache` — verifies deleted keys return default on re-read
  - `testDeleteKeyRaceWithConcurrentEncryption` — verifies delete + encrypt race doesn't corrupt data
  - `testRepeatedDeleteAndRewriteCycles` — 50 cycles of delete + rewrite with integrity checks
  - `testManyUniqueAliasesWork` — 100 unique aliases to verify lock map scalability
  - `testLockMapSerializesPerAlias` — verifies per-alias serialization with concurrent readers/writers
  - `testDynamicStringAliasesShareLock` — verifies dynamically constructed alias strings share the same lock
- `WasmJsKSafeTest` — WASM test suite extending `KSafeTest` with `FakeEncryption` (WebCrypto requires browser)

### Dependencies

- Added `cryptography-provider-webcrypto` for WASM target

---

## [1.5.0] - 2025-02-09

### Added

#### Configurable Device Lock-State Policy: `requireUnlockedDevice`

New `KSafeConfig.requireUnlockedDevice: Boolean = false` property that controls whether encrypted data should only be accessible when the device is unlocked.

| Platform | `false` (default) | `true` |
|----------|-------------------|--------|
| **Android** | Keys accessible at any time | Keys created with `setUnlockedDeviceRequired(true)` (API 28+) |
| **iOS** | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |
| **JVM** | No effect (software-backed keys) | No effect (software-backed keys) |

**Automatic migration:** Changing this value in either direction triggers a one-time migration on the next KSafe initialization:
- **Android:** Existing encrypted values are decrypted with the old key, the old Keystore key is deleted, and values are re-encrypted with a new key that has the updated policy. This applies in both directions (`false→true` and `true→false`). Migration is atomic — the policy marker is only written on success, so a crash safely retries.
- **iOS:** Existing Keychain items have their `kSecAttrAccessible` attribute updated in-place via `SecItemUpdate` (no re-encryption needed). The migration marker is only written if all key updates succeed — if any fail (e.g., device is locked), migration retries on next launch.
- **JVM:** Only the policy marker is written (no lock concept on JVM).

```kotlin
// Require device to be unlocked for all encrypted data access
val ksafe = KSafe(
    context = context,
    config = KSafeConfig(requireUnlockedDevice = true)
)
```

**Breaking change (iOS default behavior):** Previously, iOS always used `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, meaning Keychain items were only accessible when the device was unlocked. With `requireUnlockedDevice = false` (the new default), iOS now uses `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, making items accessible after the first unlock — matching Android's existing behavior and enabling background access patterns.

- New `KSafeEncryption.updateKeyAccessibility()` interface method (default no-op, overridden on iOS)
- Migration marker `__ksafe_access_policy__` stored in DataStore (skipped by `updateCache()` on all platforms)

**Error behavior when locked:** When `requireUnlockedDevice = true` and the device is locked, encrypted reads (`getDirect`, `get`, `getFlow`) and suspend writes (`put`) throw `IllegalStateException` instead of silently returning default values. `putDirect` does not throw — the background write consumer logs the error and drops the batch while staying alive for future writes. On Android, `InvalidKeyException` from `Cipher.init()` is wrapped as `IllegalStateException("device is locked")` and propagated through `resolveFromCache` and `getEncryptedFlow`. Apps can catch this exception to detect and handle locked-device scenarios.

#### New Memory Policy: `ENCRYPTED_WITH_TIMED_CACHE`

A third memory policy that balances security and performance. The primary `memoryCache` still holds ciphertext (like `ENCRYPTED`), but a secondary plaintext cache stores recently-decrypted values for a configurable TTL.

**Why this matters:** Under `ENCRYPTED` policy, every read triggers AES-GCM decryption. In UI frameworks like Jetpack Compose or SwiftUI, the same encrypted property may be read multiple times during a single recomposition/re-render cycle. This causes redundant crypto operations that waste CPU and can drop frames on lower-end devices.

`ENCRYPTED_WITH_TIMED_CACHE` eliminates this: only the first read decrypts; subsequent reads within the TTL window are pure memory lookups. After the TTL expires, the plaintext is evicted and the next read decrypts again.

```kotlin
// Android
val ksafe = KSafe(
    context = context,
    memoryPolicy = KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE,
    plaintextCacheTtl = 5.seconds  // default
)

// JVM
val ksafe = KSafe(
    memoryPolicy = KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE,
    plaintextCacheTtl = 10.seconds
)

// iOS
val ksafe = KSafe(
    memoryPolicy = KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE,
    plaintextCacheTtl = 3.seconds
)
```

**How the three policies compare:**

| Policy | RAM contents | Read cost | Security |
|--------|-------------|-----------|----------|
| `PLAIN_TEXT` | Plaintext (forever) | O(1) lookup | Low — all data exposed in memory |
| `ENCRYPTED` | Ciphertext | AES-GCM decrypt every read | High — nothing plaintext in RAM |
| `ENCRYPTED_WITH_TIMED_CACHE` | Ciphertext + short-lived plaintext | First read decrypts, then O(1) for TTL | Medium — plaintext only for recently-accessed keys, only for seconds |

**Race condition safety:** Reads capture a local reference to the cached entry atomically. There is no background sweeper — expired entries are simply ignored on the next access. Even under concurrent reads and writes, the worst case is a single extra decryption, never a crash or data corruption.

- New `plaintextCacheTtl: Duration` constructor parameter (default: 5 seconds) on all platforms
- Uses `kotlin.time.TimeSource.Monotonic` for cross-platform monotonic timestamps
- Thread-safe: `ConcurrentHashMap` on Android/JVM, `AtomicReference<Map>` on iOS

#### Orphaned Ciphertext Cleanup on Startup

After uninstalling an app and reinstalling, Android Auto Backup restores the DataStore file (containing ciphertext) but **not** the Android Keystore keys (hardware-bound). This leaves orphaned ciphertext that wastes space and creates confusion — encrypted values silently return defaults because the key is gone. On iOS, a similar scenario occurs if Keychain entries are cleared during a device reset.

KSafe now proactively detects and removes orphaned ciphertext on startup. A new `cleanupOrphanedCiphertext()` method runs once in `startBackgroundCollector()` after migration and before the DataStore `collect`:

```kotlin
private fun startBackgroundCollector() {
    CoroutineScope(Dispatchers.Default + SupervisorJob()).launch {
        migrateAccessPolicyIfNeeded()
        cleanupOrphanedCiphertext()   // ← NEW
        dataStore.data.collect { updateCache(it) }
    }
}
```

**How it works:**
1. Reads all DataStore entries with the `encrypted_` prefix
2. Attempts to decrypt each entry using the platform's encryption engine
3. If decryption permanently fails (key gone, invalidated, or wrong key) → marks for removal
4. If decryption temporarily fails (device is locked) → skips, retries next launch
5. Atomically removes all orphaned entries from DataStore and memory cache

**Error classification by platform:**
- **Android:** "device is locked" → skip (temporary). `KeyPermanentlyInvalidatedException`, `AEADBadTagException`, "No encryption key found" → orphaned.
- **iOS:** "device is locked" or "Keychain" errors → skip (temporary). All others → orphaned.
- **JVM:** All decrypt failures → orphaned (no device lock concept).

> **Note on unencrypted values:** This cleanup targets only encrypted entries (those with the `encrypted_` prefix in DataStore). Unencrypted values (`encrypted = false`) are not affected. On Android, if `android:allowBackup="true"` is set in the manifest, Auto Backup may restore unencrypted DataStore entries after reinstall with stale values from the last backup snapshot.

### Fixed

#### iOS Keychain operations now check return values

- `storeInKeychain()` now checks the `SecItemAdd` return value — previously it was silently ignored, meaning key storage could fail without any error
- `updateKeyAccessibility()` now checks the `SecItemUpdate` return value and throws on failure

#### Suspend API no longer blocks the calling dispatcher during encryption/decryption

The suspend functions `put(encrypted = true)` and `get(encrypted = true)` previously called `engine.encrypt()`/`engine.decrypt()` directly on the caller's coroutine dispatcher. If called from `Dispatchers.Main` (e.g., inside `viewModelScope.launch`), the blocking AES-GCM operation would run on the main thread. On Android, first-time Keystore key generation can take 50–200ms — enough to drop frames.

**Before (broken):**
```kotlin
// In ViewModel — encryption runs on Main thread!
viewModelScope.launch {
    ksafe.put("token", myToken, encrypted = true)
}
```

**After (fixed):**
- `putEncrypted` now wraps `engine.encrypt()` in `withContext(Dispatchers.Default)`
- `getEncrypted` now wraps `resolveFromCache()` in `withContext(Dispatchers.Default)`
- Applied consistently across all three platforms (Android, JVM, iOS)
- `Dispatchers.Default` is correct because encryption is CPU-bound, not I/O-bound

**Note:** `putDirect` was already safe — it defers encryption to `processBatch()` on a background scope. This fix brings the suspend API (`put`/`get`) to the same level of thread safety.

#### ENCRYPTED mode plaintext leak via Direct API

`putDirect()` stored plaintext JSON in `memoryCache` for instant read-back, but `processBatch()` never replaced it with ciphertext after encryption completed. Because dirty keys are permanent (by design), `updateCache()` couldn't fix this either. Result: `ENCRYPTED` mode advertised "ciphertext in RAM" but Direct API writes left plaintext in RAM permanently.

**Fixed:** After `processBatch()` encrypts and persists data to DataStore, it now atomically replaces plaintext with ciphertext in the memory cache using compare-and-swap (CAS):
- **Android/JVM**: `ConcurrentHashMap.replace(key, oldValue, newValue)` — atomic, no-op if a newer `putDirect()` wrote a different value
- **iOS**: `AtomicReference.compareAndSet` loop with same "skip if newer write" semantics

A brief plaintext window (~16ms write coalescing) remains inherent to deferred encryption — it keeps `putDirect()` at ~13μs instead of 4-6ms. The suspend API (`put()`) does not have this window; it encrypts immediately via `withContext(Dispatchers.Default)`.

#### Long values silently stored as Int in unencrypted suspend writes (Android + iOS)

`putUnencrypted` coerced small Long values (those fitting in Int range) to Int before storing. On Android, this created a type mismatch — `getUnencryptedKey` correctly selected `longPreferencesKey` but the stored value was an Int. On iOS, both key selection and value were coerced to Int, silently changing the stored type. The in-memory cache masked the issue during runtime (because `resolveFromCache` handles Int-to-Long conversion), but DataStore's typed key system could not round-trip the value correctly from disk after a restart.

**Fixed:** All primitives are now stored as their declared type — a Long stays a Long, an Int stays an Int. No `Number` coercion. JVM was already correct. Existing data is safe: `resolveFromCache` already handles Int-to-Long conversion on read, so old values stored as Int will still be read correctly as Long through the cache layer.

#### Redundant serialization and cache write in `putDirect`

The encrypted branch of `putDirect()` previously called `json.encodeToString()` twice and `updateMemoryCache()` twice with the same value. The shared `toCache` computation was wasted for encrypted writes because the encrypted branch recomputed it independently. Restructured so encrypted and unencrypted branches are fully independent — each computes its own cache value and calls `updateMemoryCache()` once. Applied across all three platforms.

#### Stale comment in `updateCache` (Android + JVM)

A comment in `updateCache()` incorrectly stated "Dirty flags are cleared in processBatch after successful persistence." In reality, dirty flags are intentionally kept permanently to prevent race conditions. Updated the comment to reflect the actual behavior.

#### Background write consumer dies on encryption failure

If `processBatch()` threw an exception (e.g., device locked with `requireUnlockedDevice = true`), the Channel consumer coroutine would crash and never restart — all future `putDirect` writes would silently queue up and never persist. Now `processBatch()` is wrapped in a try-catch: the failed batch is dropped with a log message, and the consumer stays alive for future writes after the device is unlocked.

#### Nullable primitive retrieval returns default instead of stored value (all platforms)

When retrieving an unencrypted primitive with a nullable type and `null` default (e.g., `get<String?>(key, defaultValue = null, encrypted = false)`), KSafe always returned `null` even when a value was stored. The `when(defaultValue)` dispatch in `convertStoredValue` matched `null` against `is String` — which fails because `null` is not a `String` instance — falling through to the `else` branch that attempted JSON deserialization on a plain string like `"hello"`. Since `"hello"` is not valid JSON, deserialization silently failed and the catch returned `null`.

**Fixed:** The `else` branch now tries a direct cast (`storedValue as T`) before JSON deserialization. For primitives (String, Int, Boolean, etc.), the cast succeeds and the value is returned immediately. JSON deserialization is only attempted as a fallback for complex types (data classes). Applied on Android, iOS, and JVM.

#### Cache cleanup evicts newly-written keys (all platforms)

`updateCache()` removed any key from `memoryCache` that wasn't present in the DataStore snapshot. But between `putDirect()` and `processBatch()` flushing to DataStore, newly-written keys exist only in the cache — the DataStore snapshot doesn't contain them yet. A concurrent `updateCache()` would evict these keys, causing the next `getDirect()` to return the default value instead of the just-written value.

**Fixed:** The key-removal filter in `updateCache()` now also checks `dirtyKeys`, preserving any key that has a pending write. Applied on Android, iOS, and JVM.

### Added (Testing)

- `testNewKeysSurviveCacheCleanup` — stress test: 10 writers × 200 iterations verifying that `putDirect` + immediate `getDirect` never returns default (targets the cache cleanup race condition)
- `testOrphanedCiphertextIsCleanedUpOnStartup` — uses a togglable fake engine to simulate lost encryption keys after backup restore; verifies orphaned ciphertext is detected and that unencrypted data is left untouched
- `testValidCiphertextIsNotCleanedUp` — verifies that valid encrypted entries survive the startup cleanup
- `testEncryptedPutGetNeverReturnsDefault` — 5 concurrent readers + writers verifying encrypted values never transiently return defaults

### Dependencies

- `play-services-base` 18.9.0 → 18.10.0
- `vanniktech-mavenPublish` 0.35.0 → 0.36.0

---

## [1.4.2] - 2025-01-26

### Fixed

- **Critical iOS data loss on upgrade from v1.2.0** - Removed erroneous `clearAllKeychainEntriesSync()` function that was wiping all Keychain entries on first launch
  - **Root cause**: The function was based on a flawed premise that v1.2.0 stored "biometric-protected" Keychain entries that needed cleanup
  - **Reality**: v1.2.0 used `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` which is NOT biometric protection—it simply means "accessible when device is unlocked"
  - **Impact**: Users upgrading from v1.2.0 to v1.3.0+ lost all their encrypted data unnecessarily
  - **Fix**: Removed the one-time cleanup that ran on startup. The legitimate `cleanupOrphanedKeychainEntries()` function (which removes Keychain keys without matching DataStore entries after app reinstall) remains intact
  - **Who was affected**: Only users who upgraded FROM v1.2.0 TO any version between v1.3.0–v1.4.1. Users who started fresh on v1.3.0+ or upgraded between v1.3.x/v1.4.x versions were NOT affected
  - **Why in-between upgrades were safe**: The cleanup used NSUserDefaults to track execution via `BIOMETRIC_CLEANUP_KEY`. Once it ran (on first launch after upgrading from v1.2.0), the flag was set and subsequent version upgrades (e.g., v1.3.0→v1.4.0→v1.4.1) skipped the cleanup entirely. The damage only occurred on that single first upgrade from v1.2.0

### Removed

- `clearAllKeychainEntriesSync()` - iOS function that unnecessarily deleted all Keychain entries
- `BIOMETRIC_CLEANUP_KEY` constant - No longer needed without the erroneous cleanup

---

## [1.4.1] - 2025-01-21

### Performance Improvements

KSafe 1.4.1 delivers **massive performance improvements**, making it faster than EncryptedSharedPreferences and KVault for encrypted operations while maintaining hardware-backed security.

#### Benchmark Results (1.4.0 → 1.4.1)

| Metric | 1.4.0 | 1.4.1 | Improvement |
|--------|-------|-------|-------------|
| Unencrypted Write | 0.23 ms | 0.0115 ms | **20x faster** |
| Encrypted Write (ENCRYPTED mem) | 0.44 ms | 0.053 ms | **8x faster** |
| Encrypted Write (PLAIN_TEXT mem) | 0.70 ms | 0.012 ms | **58x faster** |
| Encrypted Write vs ESP | 2.4x slower | **17x faster** | Now beats ESP! |
| DataStore Write Acceleration | 20x | 327x | **16x more** |

#### Comparison with Other Libraries (Unencrypted)

| Library | Read | Write | Notes |
|---------|------|-------|-------|
| SharedPreferences | 0.0006 ms | 0.0152 ms | Android only, no encryption |
| MMKV | 0.0007 ms | 0.0577 ms | Fast, but no KMP, no hardware encryption |
| Multiplatform Settings | 0.0009 ms | 0.0192 ms | KMP, but no encryption |
| **KSafe 1.4.1** | **0.0016 ms** | **0.0115 ms** | KMP + encryption + biometrics |
| DataStore | 1.10 ms | 3.76 ms | Safe but slow |

> **Note:** KSafe unencrypted writes are now **faster than SharedPreferences**!

#### Comparison with Other Libraries (Encrypted)

| Library | Read | Write | vs KSafe |
|---------|------|-------|----------|
| **KSafe (PLAIN_TEXT memory)** | **0.0058 ms** | **0.0123 ms** | — |
| KSafe (ENCRYPTED memory) | 0.0276 ms | 0.0531 ms | *(decrypts on-demand)* |
| KVault | 0.6003 ms | 1.05 ms | KSafe is **103x/85x faster** |
| EncryptedSharedPrefs | 0.6817 ms | 0.2064 ms | KSafe is **117x/17x faster** |

**vs KVault (encrypted KMP storage):**
- **103x faster encrypted reads** (0.60 ms → 0.0058 ms with PLAIN_TEXT memory)
- **85x faster encrypted writes** (1.05 ms → 0.0123 ms)

**vs multiplatform-settings (Russell Wolf):**
- **1.7x faster writes** (0.0192 ms → 0.0115 ms)
- Similar read performance (0.0016 ms vs 0.0009 ms)
- KSafe adds: hardware-backed encryption, biometric auth, auto-serialization

#### Cold Start / Reinitialization Performance

| Library | Keys | Time |
|---------|------|------|
| SharedPreferences | 201 | 0.0315 ms |
| Multiplatform Settings | 201 | 0.0400 ms |
| MMKV | 201 | 0.0402 ms |
| DataStore | 201 | 0.4901 ms |
| **KSafe (ENCRYPTED)** | 603 | **1.26 ms** |
| KVault | 320 | 4.77 ms |
| EncryptedSharedPrefs | 201 | 6.41 ms |
| KSafe (PLAIN_TEXT) | 1206 | 6.49 ms |

> **Note:** KSafe ENCRYPTED mode is **5x faster** to cold-start than PLAIN_TEXT mode (defers decryption until access).

#### Optimizations Implemented

1. **ConcurrentHashMap for Hot Cache**
   - Replaced `AtomicReference<Map>` with `ConcurrentHashMap`
   - O(1) per-key updates instead of copy-on-write
   - Eliminates full map copy on every write

2. **ConcurrentHashMap for Dirty Keys**
   - Replaced `AtomicReference` with CAS loops with `ConcurrentHashMap.newKeySet()`
   - O(1) add/remove operations for tracking pending writes
   - Prevents stale data overwrites during async persistence

3. **Write Coalescing**
   - New `Channel<WriteOperation>` for queuing writes
   - Single consumer coroutine batches operations within 16ms window
   - Multiple writes coalesced into single `DataStore.edit{}` call
   - Reduces disk I/O overhead significantly

4. **Deferred Encryption**
   - Encryption moved from UI thread to background batch processor
   - `putDirect()` queues plaintext, returns immediately
   - `processBatch()` encrypts all pending operations before DataStore write
   - UI thread no longer blocked by Android Keystore operations

5. **SecretKey Caching (Android)**
   - Added `ConcurrentHashMap<String, SecretKey>` cache in `AndroidKeystoreEncryption`
   - Avoids repeated Android Keystore lookups
   - Double-checked locking with `synchronized(keyAlias.intern())`
   - Cache cleared when keys are deleted

6. **Shared Write Scope**
   - Reuses single `CoroutineScope(Dispatchers.IO + SupervisorJob())` for all write operations
   - Avoids object allocation overhead of creating new scope per `putDirect()` call

7. **Simplified Cache Updates**
   - `updateMemoryCache()` now uses O(1) direct `ConcurrentHashMap` operations
   - Eliminated CAS loops and map copying previously required with `AtomicReference<Map>`

### Technical Details

**Write Flow Before (1.4.0):**
```
putDirect() → encrypt (BLOCKING) → launch coroutine → DataStore.edit()
             ↑ 4-6ms on UI thread!
```

**Write Flow After (1.4.1):**
```
putDirect() → update cache → queue WriteOperation → return (~13µs)
                                     ↓
Background: collect 16ms window → encrypt all → single DataStore.edit()
```

### Fixed

- **Critical Data Integrity Fix (Hot Cache)** - Fixed a bug where plaintext values like `"true"`, `"false"`, or numbers (which are valid Base64) were incorrectly attempted to be decrypted during optimistic reads.
  - Previously, "decrypting" these values produced garbage which failed JSON parsing outside the recovery block.
  - Now validates JSON structure post-decryption; invalid results trigger the correct plaintext fallback.
  - Fixes potential read failures for specific primitive values immediately after writing.

- **ConcurrentHashMap iteration race condition (JVM)** - Fixed `NoSuchElementException` crash during rapid concurrent writes

- **HashMap concurrency crash (iOS)** - Fixed `IllegalStateException` ("Have object hashCodes changed?") crash during concurrent cache access
  - Kotlin/Native's HashMap is not thread-safe unlike JVM's ConcurrentHashMap
  - Implemented proper copy-on-write semantics with AtomicReference for all cache mutations
  - Added synchronized access to dirty keys set
  - Background collector can no longer corrupt cache while UI reads values

- **Dirty keys race condition** - Fixed cache corruption where keys could be removed prematurely
  - Dirty flags are now intentionally NOT cleared after persistence
  - Prevents stale DataStore snapshots from overwriting optimistic cache values
  - Trade-off: Small memory overhead (~10KB for 1000 keys) for guaranteed correctness

- **Self-Healing Key Recovery (Android)** - Fixed rare crash when Android Keystore keys become invalidated
  - **This is rare**: KSafe keys are configured WITHOUT these flags:
    - `setUserAuthenticationRequired(true)` - NOT set (keys usable without unlocking device)
    - `setInvalidatedByBiometricEnrollment(true)` - NOT set (keys survive biometric changes)
  - This means KSafe keys are stable and always accessible
  - Invalidation only occurs in edge cases: factory reset, OEM Keystore bugs, or system corruption
  - Now catches `KeyPermanentlyInvalidatedException` during encrypt/decrypt operations
  - **Self-healing behavior**: Automatically deletes invalidated key and regenerates a fresh one
  - Encryption: Seamlessly retries with new key (data preserved)
  - Decryption: Returns default value (old encrypted data cannot be recovered with destroyed key)

- **iOS Keychain error handling** - Improved error handling to prevent silent data loss
  - `errSecItemNotFound` → Creates new key (correct - key doesn't exist)
  - `errSecInteractionNotAllowed` → Throws error (device locked - key exists but inaccessible)
  - Other errors → Throws error with status code (prevents silent key regeneration)
  - Previously, ANY error would silently create a new key, potentially causing data loss

### Added (Testing)

- **Concurrency stress tests** in `JvmKSafeTest`:
  - `testConcurrentPutDirectStress` - 10 writers × 500 iterations
  - `testConcurrentEncryptedPutDirectStress` - 5 writers × 100 encrypted iterations
  - `testConcurrentReadWriteStress` - Simultaneous read/write on shared keys
  - `testDirtyKeysStress` - 20 writers × 1000 iterations targeting dirty key mechanism
- **iOS Keychain error handling tests** in `IosKeychainEncryptionTest`:
  - `testThrowsOnKeychainErrorInTestEnvironment` - Verifies errors throw (not silently create keys)
  - `testDecryptThrowsOnKeychainError` - Verifies decrypt fails safely
  - `testDeleteKeyDoesNotThrow` - Verifies delete is safe (no data loss risk)
  - `testCustomConfigIsAccepted` - Verifies 128-bit and 256-bit config
  - Documentation tests for error codes and device-locked scenario

### Changed

- `WriteOperation.Encrypted` now carries plaintext + keyAlias instead of pre-computed ciphertext
- Encryption happens in `processBatch()` instead of `putDirect()`
- All three platforms (Android, iOS, JVM) use consistent write coalescing architecture

### Documentation

- **Added Direct API recommendation** for bulk/concurrent operations (~950x faster than Coroutine API)
- Added Cold Start / Reinitialization benchmark results
- Added comprehensive comparison table (KSafe vs SharedPreferences vs DataStore vs KVault)
- Added performance benchmarks section with detailed results including KVault
- Added explanation of hot cache architecture
- Updated "Alternatives & Comparison" section with KVault

---

## [1.4.0] - 2025-01-11

### Added

#### Runtime Security Policy
- **New `KSafeSecurityPolicy`** for detecting runtime security threats
- **Configurable actions** - `IGNORE`, `WARN`, or `BLOCK` for each security check:
  - `IGNORE` - No detection performed, no callback invoked
  - `WARN` - Detection runs, callback invoked, app continues normally
  - `BLOCK` - Detection runs, callback invoked, throws `SecurityViolationException`
- **Preset policies** - `Default`, `Strict`, `WarnOnly` for common configurations
  ```kotlin
  val ksafe = KSafe(
      context = context,
      securityPolicy = KSafeSecurityPolicy.Strict
  )
  ```

#### Root & Jailbreak Detection
- **Enhanced Android root detection**:
  - su binary paths (`/system/bin/su`, `/system/xbin/su`, etc.)
  - Magisk paths (`/sbin/.magisk`, `/data/adb/magisk`, etc.)
  - BusyBox installation paths
  - Xposed Framework (files + stack trace detection)
  - Root management apps (Magisk Manager, SuperSU, LSPosed, KingRoot, etc.)
  - Build tags (`test-keys`) and dangerous system properties
- **iOS jailbreak detection**:
  - Cydia, Sileo, and other jailbreak app paths
  - System write access test (fails on non-jailbroken devices)
  - Common jailbreak tool paths (`/bin/bash`, `/usr/sbin/sshd`, etc.)
- ⚠️ **Limitation**: Sophisticated root-hiding tools (Magisk DenyList, Shamiko, Zygisk) may bypass detection

#### Debugger & Emulator Detection
- **Debugger detection** - Detect attached debuggers on all platforms
- **Emulator detection** - Detect emulators/simulators (Android & iOS)
- **Debug build detection** - Detect debug builds

#### Compose Support
- **New `UiSecurityViolation`** - Immutable wrapper for `SecurityViolation` ensuring Compose stability
  ```kotlin
  @Immutable
  data class UiSecurityViolation(val violation: SecurityViolation)
  ```
  - Allows `ImmutableList<UiSecurityViolation>` to skip unnecessary recompositions
  - Located in `ksafe-compose` module

### Added (Testing)
- **Comprehensive test suite** for new security features:
  - `KSafeSecurityPolicyTest` - SecurityAction, SecurityViolation, presets
  - `BiometricAuthorizationDurationTest` - Duration and scope patterns
  - `KSafeMemoryPolicyTest` - Memory policy enum
  - `JvmSecurityCheckerTest` - JVM-specific security behavior
- **ksafe-compose module tests**:
  - `KSafeComposeStateTest` - Compose state integration tests
  - `KSafeMutableStateOfTest` - MutableState behavior tests
  - `AndroidKSafeMutableStateOfTest` - Android instrumented tests
  - `JvmKSafeMutableStateOfTest` - JVM-specific tests

### Changed
- **iOS Simulator uses real Keychain** - Removed `MockKeychain` in favor of actual iOS Keychain APIs
  - Simulator: Software-backed Keychain
  - Real device: Hardware-encrypted Keychain (protected by device passcode)
  - Added threat model and security boundaries
  - Added compatibility matrix
  - Added GCM (Galois/Counter Mode) explanation
  - Added detailed Actions behavior documentation with examples
  - Added non-GMS device compatibility notes
  - Added root detection methods documentation

### Removed
- **`MockKeychain.kt`** - iOS Simulator now uses real Keychain APIs instead of UserDefaults-based mock
- **Irrelevant images** - Removed unnecessary publishing screenshots from repository

---

## [1.3.0] - 2025-12-31

### Added

#### Standalone Biometric Authentication
- **New `verifyBiometric()` suspend function** - Coroutine-based biometric verification
- **New `verifyBiometricDirect()` callback function** - Non-blocking biometric verification for any context
- **Biometric authentication is now decoupled from storage** - Use it to protect any action (API calls, navigation, data display), not just KSafe operations

#### Authorization Duration Caching
- **New `BiometricAuthorizationDuration` data class** for configuring cached authentication:
  ```kotlin
  data class BiometricAuthorizationDuration(
      val duration: Long,       // Duration in milliseconds
      val scope: String? = null // Optional scope identifier
  )
  ```
- **Duration caching** - Avoid repeated biometric prompts by caching successful auth for a specified duration
- **Scoped authorization** - Different scopes maintain separate auth timestamps for fine-grained control
- **Recommended pattern**: Use `viewModelScope.hashCode().toString()` for ViewModel-scoped auth that auto-invalidates when the ViewModel is recreated

#### Authorization Management
- **New `clearBiometricAuth()` function** - Force re-authentication by clearing cached auth
  - `clearBiometricAuth()` - Clear all cached authorizations
  - `clearBiometricAuth(scope)` - Clear only a specific scope

#### Configurable Encryption
- **New `KSafeConfig` data class** for encryption customization
- Configurable AES key size: 128-bit or 256-bit (default)
  ```kotlin
  // Default (AES-256)
  val ksafe = KSafe(context)

  // Custom key size (AES-128)
  val ksafe128 = KSafe(context, config = KSafeConfig(keySize = 128))
  ```

### Changed
- **iOS thread safety improvements** - Biometric callbacks now always execute on Main thread
- **License consistency** - Fixed Maven POM metadata to use Apache-2.0 (matching repository)

---

## [1.2.0] - 2025-01-15

### Added
- **Hybrid "Hot Cache" Architecture** - Zero-latency UI reads with async preloading
- **Memory Security Policy** - Choose between `ENCRYPTED` (max security) or `PLAIN_TEXT` (max performance)
- **Nullable value support** - Correctly store and retrieve `null` values
- **Multiple KSafe instances** - Create separate instances with different file names
- **JVM/Desktop support** - Full support alongside Android and iOS
- **KSafeConfig** - Configurable encryption parameters (key size)
- **Lazy loading option** - Defer data loading until first access

### Changed
- `getDirect()` now performs atomic memory lookup (O(1)) instead of blocking disk read
- `putDirect()` uses optimistic updates - immediate cache update with background persistence
- Eager preloading on initialization by default (use `lazyLoad = true` to defer)

---

## [1.1.0] - 2024-12-01

### Added
- Initial release with encrypted persistence
- Property delegation (`by ksafe(defaultValue)`)
- Compose state support (`by ksafe.mutableStateOf(defaultValue)`)
- Android Keystore and iOS Keychain integration
- Suspend and Direct APIs





:tada: KSafe 1.8.0 is out — Kotlin Multiplatform key-value persistence for Android / iOS / JVM / WASM.

If you haven't seen it: think DataStore, but with a hot in-memory cache in front. That gives you a fully synchronous API (getDirect / putDirect) when you don't want
coroutines, plus suspend get / put when you do. AES-256-GCM with hardware-backed keys by default (Keystore / Keychain / StrongBox / Secure Enclave) — or opt out with a     
single parameter and use KSafe as a fast general-purpose persistence library for plain data.

var token   by ksafe("")                                                           // plain delegate                                                                        
var counter by ksafe.mutableStateOf(0)                                             // Compose state                                                                         
val user:  StateFlow<User>           by ksafe.asStateFlow(User(), scope)           // read-only flow                                                                        
val state: MutableStateFlow<UiState> by ksafe.asMutableStateFlow(UiState(), scope) // read/write flow

What's new in 1.8.0:

• asMutableStateFlow — drop-in for the classic _state / state pattern, persisted + encrypted transparently:                                                                 
private val _state by ksafe.asMutableStateFlow(UiState(), viewModelScope)
val state = _state.asStateFlow()                                                                                                                                            
.update { }, .value = …, compareAndSet all behave exactly as you'd expect — persistence is invisible, and it survives process death.

• getOrCreateSecret("main.db") — one line to get a 256-bit passphrase for Room / SQLCipher / SQLDelight (or an API signing key). Generated once, stored hardware-isolated   
(StrongBox on Android, Secure Enclave on iOS). No more "check if exists, else create and save" boilerplate.

• secureRandomBytes(16) — cryptographically secure random bytes with one API across every target.

• Cross-screen Compose sync via ksafe.mutableStateOf(scope = viewModelScope) — a write in one ViewModel auto-reflects in another.

GitHub: https://github.com/ioannisa/KSafe                                                                                                                                   
Changelog: https://github.com/ioannisa/KSafe/blob/main/CHANGELOG.md