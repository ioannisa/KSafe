# KSafe — a tour of the source tree

This is a walk-through of every source file in the `ksafe` module. The intent is to give a new contributor (or future-you) enough orientation to know *where* a given behaviour lives and *why* it lives there, without re-reading every line.

## Sister modules

KSafe ships as three independent artifacts. This tour focuses on `:ksafe`. The other two are mentioned only where they're relevant:

| Module | What it owns | Depends on |
|---|---|---|
| **`:ksafe`** | Storage core: `KSafe` class, hot cache, write coalescer, encryption engines, DataStore / localStorage adapters | nothing else in the project |
| **`:ksafe-compose`** | `KSafe.mutableStateOf(...)` Compose state delegates | `:ksafe` |
| **`:ksafe-biometrics`** | `KSafeBiometrics` static API for biometric verification (Face ID / Touch ID / Fingerprint), `BiometricAuthorizationDuration`, Android `BiometricHelper`, auto-init `ContentProvider` | nothing else in the project |

If you're chasing biometric verification code, you're in the wrong module — see `:ksafe-biometrics`. Pre-2.0, biometrics lived inside `:ksafe`; in 2.0 it was extracted ([issue #14](https://github.com/ioannisa/KSafe/issues/14)).

## Architecture overview

`:ksafe` splits into three rings:

1. A **public API** in `commonMain` — everything a consumer imports, defined exactly once.
2. An **internal orchestrator** in `commonMain/internal/` — the shared logic that implements the public API once.
3. Per-platform **thin factory shells** in `{android,ios,jvm,web}Main` that wire the orchestrator to a DataStore, a keystore, and the platform's crypto engine.

The architectural rule is that **the orchestrator lives in common code and the platform shells are construction-only adapters**. Android, iOS, and JVM additionally share a `datastoreMain` intermediate source set because all three back onto Jetpack DataStore Preferences.

A consequence of this: `KSafe` itself is **not** an `expect class`. It is a regular class declared once in `commonMain`, with all members — including the inline reified `getDirect/put/get/putDirect/getFlow` — defined a single time. Each platform shell exposes a top-level **factory function** named `KSafe(...)` that builds the platform-specific dependencies and returns a `KSafe` instance. Kotlin treats `KSafe(context, ...)` and `KSafe(...)` identically at the call site whether the resolution target is a constructor or a same-named top-level function, so the consumer-visible API didn't change when this happened.

The tour starts in `commonMain`. Each platform file only gets a section for the things that differ from — or extend — what the common equivalent already describes.

---

## Source layout at a glance

```
ksafe/src/
├── commonMain/                         (public API + shared orchestrator)
│   └── kotlin/eu/anifantakis/lib/ksafe/
│       ├── KSafe.kt                    (public class — defined ONCE in commonMain)
│       ├── KSafeConfig.kt
│       ├── KSafeDelegate.kt
│       ├── KSafeKeyInfo.kt
│       ├── KSafeKeyStorage.kt
│       ├── KSafeProtection.kt
│       ├── KSafeSecret.kt
│       ├── KSafeSecurityPolicy.kt
│       ├── KSafeWriteMode.kt
│       └── internal/
│           ├── KSafeCore.kt
│           ├── KSafePlatformStorage.kt
│           ├── KSafeEncryption.kt
│           ├── KSafeConcurrent.kt
│           ├── KSafeSecureRandom.kt
│           ├── KSafeSerializerUtil.kt
│           ├── KeySafeMetadataManager.kt
│           └── SecurityChecker.kt
│
├── datastoreMain/                      (shared by Android + iOS + JVM)
│   └── …/internal/DataStoreStorage.kt
│
├── androidMain/
│   ├── KSafe.android.kt                (top-level `fun KSafe(context, ...)` factory)
│   └── internal/
│       ├── AndroidKeystoreEncryption.kt
│       ├── KSafeConcurrent.android.kt
│       ├── KSafeSecureRandom.android.kt
│       └── SecurityChecker.android.kt
│
├── iosMain/
│   ├── KSafe.ios.kt                    (top-level `fun KSafe(...)` factory)
│   └── internal/
│       ├── IosKeychainEncryption.kt
│       ├── KeychainOrphanCleanup.kt
│       ├── KSafeConcurrent.ios.kt
│       ├── KSafeSecureRandom.ios.kt
│       └── SecurityChecker.ios.kt
│
├── jvmMain/
│   ├── KSafe.jvm.kt                    (top-level `fun KSafe(...)` factory + test extensions)
│   └── internal/
│       ├── JvmSoftwareEncryption.kt
│       ├── KSafeConcurrent.jvm.kt
│       ├── KSafeSecureRandom.jvm.kt
│       └── SecurityChecker.jvm.kt
│
├── webMain/                            (shared by js + wasmJs)
│   ├── KSafe.web.kt                    (top-level `fun KSafe(...)` factory + awaitCacheReady ext)
│   └── internal/
│       ├── LocalStorageStorage.kt
│       ├── WebSoftwareEncryption.kt
│       ├── WebInterop.kt               (expect)
│       ├── KSafeConcurrent.web.kt
│       └── SecurityChecker.web.kt
│
├── jsMain/…/internal/
│   ├── KSafeSecureRandom.js.kt
│   └── WebInterop.js.kt
│
└── wasmJsMain/…/internal/
    ├── KSafeSecureRandom.wasmJs.kt
    └── WebInterop.wasmJs.kt
```

Note what's *not* there anymore: `BiometricHelper.kt` used to live in `androidMain`. In 2.0 it moved to `:ksafe-biometrics`.

---

# Part 1 — `commonMain`: the public API

Everything in this section is visible to consumers. Import paths are `eu.anifantakis.lib.ksafe.*`.

## `KSafe.kt` — entry point

The single regular `class KSafe` that consumers instantiate, with all storage methods defined once.

**Key declarations:**

- `class KSafe @PublishedApi internal constructor(core, deviceKeyStorages, onClearAllCleanup)` — the public class. Constructor is `internal` so consumers always go through a per-platform factory function (see Part 4); they never see the raw `KSafeCore` they need to build.
- Members defined once for every platform:
  - `val deviceKeyStorages: Set<KSafeKeyStorage>` — what tiers the current device supports. Populated by the platform factory.
  - `fun getKeyInfo(key): KSafeKeyInfo?` — protection tier + storage location for a specific key. Forwards to `core.getKeyInfo`.
  - `fun deleteDirect(key)` / `suspend fun delete(key)` — async + suspend deletion. Forward to `core`.
  - `suspend fun clearAll()` — wipes the core, then runs `onClearAllCleanup` (used by JVM to also delete the physical `.preferences_pb` file).
  - `inline fun <reified T> getDirect/put/get/putDirect/getFlow(...)` — the public read/write surface. Each is a one-or-two-line member that calls `serializer<T>()` and forwards into the corresponding non-inline `core.*Raw(...)` method. Bodies live exactly once here in commonMain.
  - Deprecated `encrypted: Boolean` overloads of all of the above — preserved for source compat; they delegate to the new `KSafeWriteMode`-parameterised forms.
  - `@PublishedApi internal val core: KSafeCore` — the orchestrator. Exposed at this visibility because inline reified members and inline delegate factories need to reach it from consumer bytecode without a synthetic accessor on the hot path.
- `enum class KSafeMemoryPolicy` — `PLAIN_TEXT`, `ENCRYPTED`, `ENCRYPTED_WITH_TIMED_CACHE`.
- `getStateFlow(key, default, scope)` — extension that hooks `getFlow(...)` into `stateIn(scope, Eagerly, initial)` so consumers get a `StateFlow<T>` with a known synchronous initial value. Uses `core.getFlowRaw` / `core.getDirectRaw` directly.

**What's *not* here anymore (compared to 1.x):**
- No `expect class KSafe` declaration. Construction lives in per-platform factory functions.
- No `*Raw` methods on `KSafe`. They live on `KSafeCore` only — the inline reified members forward to `core.getDirectRaw(...)` / `core.putDirectRaw(...)` etc. directly.
- No biometric methods — extracted to `:ksafe-biometrics`.
- No `BiometricAuthorizationDuration` data class — moved to `:ksafe-biometrics`.

**Why this shape:** making `KSafe` a regular common class lets the inline reified bodies live in one place. The platform-specific concerns (engine wiring, hardware detection, file paths) are all construction-time, so they live in factory functions in the platform source sets. The runtime call after inlining is one hop: `core.getDirectRaw(...)`.

## `KSafeConfig.kt` — instance configuration

Data class of non-cryptographic knobs that users can pass to the `KSafe` factory.

**Key declarations:**

- `data class KSafeConfig(keySize, androidAuthValiditySeconds, requireUnlockedDevice, json)`.
- `object KSafeDefaults { val json }` — the default `Json` instance (`ignoreUnknownKeys = true`), used when the caller doesn't supply their own. `Json` is declared `api` in the build script so consumers can pass a custom one without declaring `kotlinx-serialization-json` themselves.

**Why:** centralises the "things you configure once at construction time" — key size, the default unlock policy, and the `Json` instance for `@Serializable` types. Separating config into its own class keeps the factory signatures readable, and it lets users swap in a `Json` with `@Contextual` serializers for `UUID`, `Instant`, etc.

## `KSafeWriteMode.kt` — how writes are parameterised

Sealed interface describing the three ways to write a value.

**Key declarations:**

- `sealed interface KSafeWriteMode`:
  - `object Plain` — unencrypted.
  - `data class Encrypted(protection, requireUnlockedDevice)` — everything else.
- `enum class KSafeEncryptedProtection { DEFAULT, HARDWARE_ISOLATED }` — only the encrypted write needs a protection tier; `Plain` can't have one.
- `internal fun KSafeWriteMode.toProtection(): KSafeProtection?` — maps the mode to the tier stored in metadata.

**Why:** "`encrypted: Boolean` + `protection: KSafeProtection` + `requireUnlockedDevice: Boolean`" was the old shape and it allowed nonsense combinations like "plain write with `HARDWARE_ISOLATED`". Modelling writes as a sealed hierarchy makes invalid combinations unrepresentable.

## `KSafeProtection.kt` — encryption tier tags

A two-valued enum used throughout the internals.

**Key declarations:**

- `enum class KSafeProtection { DEFAULT, HARDWARE_ISOLATED }` — also `null` for "plaintext", which is why nearly every function signature uses `KSafeProtection?`.

**Why:** single source of truth for the protection tags that (a) get serialised into per-key metadata on disk, and (b) feed `KSafeKeyInfo.protection`. Kept separate from `KSafeWriteMode` because reads don't have a "mode" — the tier is auto-detected from metadata.

## `KSafeKeyStorage.kt` / `KSafeKeyInfo.kt` — "where does this key actually live?"

Two small files that together form the `getKeyInfo(key)` API surface.

- `enum class KSafeKeyStorage { SOFTWARE, HARDWARE_BACKED, HARDWARE_ISOLATED }` — the actual backing store, which may be different from the *requested* tier on a device that lacks the hardware. E.g. a `HARDWARE_ISOLATED` write on a phone without StrongBox/Secure Enclave silently lands in `HARDWARE_BACKED`.
- `data class KSafeKeyInfo(protection: KSafeProtection?, storage: KSafeKeyStorage)` — what `ksafe.getKeyInfo("my_key")` returns.

**Why:** honesty. A caller who wrote with `HARDWARE_ISOLATED` may want to tell the user "stored in hardware-isolated chip" — but only if that's what actually happened. `getKeyInfo` lets the UI reflect reality instead of hardcoding assumptions.

## `KSafeSecurityPolicy.kt` — runtime security checks

Per-instance declaration of what the library should do on detecting a rooted device, a debugger, a debug build, or an emulator.

**Key declarations:**

- `data class KSafeSecurityPolicy(rootedDevice, debuggerAttached, debugBuild, emulator, onViolation)` — each check is a `SecurityAction` (`IGNORE` / `WARN` / `BLOCK`). Three preset companion values: `Default` (all `IGNORE`), `Strict` (`BLOCK` on root/debugger, `WARN` on debug/emulator), `WarnOnly` (everything `WARN`).
- `enum class SecurityViolation { RootedDevice, DebuggerAttached, DebugBuild, Emulator }`.
- `class SecurityViolationException` — thrown when a `BLOCK` check fails.
- `internal fun validateSecurityPolicy(policy: KSafeSecurityPolicy)` — runs the checks at `KSafe` construction by delegating to the platform-specific `SecurityChecker` object.

**Why:** a consumer can opt into bank-app behaviour (`BLOCK` on root) without the library forcing that choice on everyone. Checks run *once* at construction because root/debugger detection is expensive and defeated by determined attackers anyway — it raises the floor, not the ceiling.

## `KSafeDelegate.kt` — `var counter by ksafe(0)` and friends

The property-delegate layer that sits on top of the public `get/put` API so consumers can treat a persistent value like a regular `var`.

**Key declarations:**

- `class KSafeDelegate<T>` — the backing object for `by ksafe(default)`. Calls `ksafe.core.getDirectRaw` in `getValue` and `ksafe.core.putDirectRaw` in `setValue`, using the Kotlin property name as the storage key (or an explicit `key` override).
- `operator fun <reified T> KSafe.invoke(...)` — the factory that makes `by ksafe(0)` syntactically work.
- `class KSafeFlowDelegate<T>` — observer-side delegate backed by a `Flow<T>` derived from `core.getFlowRaw`.
- `class KSafeMutableStateFlowDelegate<T>` — a full `MutableStateFlow<T>` implementation persisted through KSafe; drops into the canonical Android `_state` / `state` pattern.

**Why it's public (not internal):** delegates are how the library is used in the "feels like a local variable" sense. `KSafeDelegate` is an ordinary class so a consumer can reference it in their DI or, unusually, pass it around.

**Why it talks to `core` directly:** these delegates work with a non-reified `KSerializer<T>` captured at creation time, so they can't go through the inline reified `KSafe.getDirect(...)` API. They reach into `ksafe.core.getDirectRaw` directly — cheaper than the `KSafe` member layer, which exists only for the reified-T entry point.

## `KSafeSecret.kt` — `getOrCreateSecret`

A single extension function added in 1.8.0 that embodies the library's architecture as a one-liner.

**Key declaration:**

- `suspend fun KSafe.getOrCreateSecret(key, size = 32, protection = HARDWARE_ISOLATED, requireUnlockedDevice = false): ByteArray` — retrieves a stored secret if it exists, otherwise generates a cryptographically-random one (via `secureRandomBytes` from the internal package) and persists it.

**Why:** the "generate on first run, store hardware-backed, retrieve thereafter" pattern is exactly what database-passphrase code needs for SQLCipher / SQLDelight / Room. A guarded mutex in the file prevents two concurrent first-time callers from writing different secrets.

---

# Part 2 — `commonMain/internal`: the orchestrator

Everything under `internal/` is `@PublishedApi internal` or plain `internal` — not consumer-facing. This is where the library's logic lives.

## `KSafePlatformStorage.kt` — the storage contract

Defines the narrow interface `KSafeCore` uses to talk to whatever on-disk backend a platform provides.

**Key declarations:**

- `interface KSafePlatformStorage`:
  - `suspend fun snapshot(): Map<String, StoredValue>` — read all entries once (cold-start preload + orphan cleanup).
  - `fun snapshotFlow(): Flow<Map<String, StoredValue>>` — reactive change stream. Drives both the hot cache and single-key `Flow` APIs.
  - `suspend fun applyBatch(ops: List<StorageOp>)` — transactional write. The write-coalescer emits one batch per 16 ms window.
  - `suspend fun clear()` — full wipe.
- `sealed interface StoredValue` — `IntVal`, `LongVal`, `FloatVal`, `DoubleVal`, `BoolVal`, `Text`. One tagged variant per DataStore native type; the web adapter collapses everything to `Text`.
- `sealed interface StorageOp` — `Put(rawKey, StoredValue)` and `Delete(rawKey)`.
- `internal fun StoredValue.toCacheValue(): Any` — unwraps the typed variant back into the raw Kotlin value (Int, Long, …). Used when populating the hot cache.
- `internal fun primitiveToStoredValue(value: Any): StoredValue` — inverse: wraps a primitive in the appropriate typed variant on write.

**Why an interface:** before this abstraction, each platform's `KSafe.{platform}.kt` reached into DataStore (or localStorage) directly, which meant the coalescer, hot cache, and orphan cleanup were re-implemented four times. Splitting the storage concern from the orchestration concern lets both sides be tested in isolation.

## `KSafeEncryption.kt` — the crypto contract

Interface implemented by the four per-platform encryption engines.

**Key declarations:**

- `interface KSafeEncryption`:
  - Blocking `encrypt` / `decrypt` / `deleteKey` — original contract. Android/iOS/JVM implement these directly.
  - Suspend `encryptSuspend` / `decryptSuspend` / `deleteKeySuspend` — default bodies delegate to the blocking variants. `WebSoftwareEncryption` overrides these with real WebCrypto calls (and keeps the blocking variants throwing `UnsupportedOperationException`).
  - `updateKeyAccessibility(identifier, requireUnlocked)` — default no-op. Only iOS's Keychain actually implements this (to move keys between accessibility tiers via `SecItemUpdate`).

**Why both blocking and suspend:** Android/iOS/JVM crypto is synchronous and integrates cleanly with `Cipher.init(...)`-style APIs. Web's WebCrypto is Promise-based — there's no way to call it blockingly. Rather than break the Android/iOS/JVM engines by forcing them into suspend-everywhere, the interface provides both and `KSafeCore` prefers `*Suspend` from every coroutine-context code path (write coalescer, preload, updateCache). The one remaining blocking decrypt site is `resolveFromCache` (called from sync `getDirect`), and web avoids it by running exclusively in `PLAIN_TEXT` memory policy where the cache holds pre-decrypted strings.

## `KSafeCore.kt` — the orchestrator

The big one. Takes a `KSafePlatformStorage`, a `KSafeEncryption`, a `KSafeConfig`, and a few platform-callable lambdas; exposes the `*Raw` methods that `KSafe` (and the property delegates, and `getStateFlow`) forward into.

**Constructor parameters worth highlighting:**

- `storage: KSafePlatformStorage` — exposed as `@PublishedApi internal val` so platform extensions in jvmMain can reach into the underlying `DataStore` for whitebox tests.
- `engineProvider: () -> KSafeEncryption` — a provider, not the engine itself, so a `testEngine` can be slotted in by the platform factory before the engine is first dereferenced. The lazy property `engine` materialises it once, exposed as `@PublishedApi internal val` for the same test-extension reason as `storage`.
- `resolveKeyStorage: (userKey, protection) -> KSafeKeyStorage` — Android inspects the Keystore for StrongBox; iOS inspects the Keychain for Secure Enclave; JVM/web always return `SOFTWARE`.
- `migrateAccessPolicy: suspend () -> Unit = {}` — runs once before orphan cleanup. iOS uses it to call the standalone `cleanupOrphanedKeychainEntries` helper; the others are no-ops.
- `keyAlias: (userKey) -> String` — exposed `@PublishedApi internal` because tests reach for it to reconstruct the disk-side alias for whitebox assertions. Android: `"$KEY_ALIAS_PREFIX.$fileName?.$key"`. iOS: `"$KEY_PREFIX.$fileName?.$key"`. JVM/web: `"$fileName?:$key"`.
- `legacyEncryptedPrefix` / `legacyEncryptedKeyFor` — pre-1.8 iOS overrode these to read entries written under `"{fileName}_{key}"`.
- `modeTransformer: (KSafeWriteMode) -> KSafeWriteMode = { it }` — applied at the top of `putDirectRaw` and `putRaw`. Android passes `::promoteMode` (honors the deprecated `useStrongBox` flag); iOS passes its `::promoteMode` (honors `useSecureEnclave`); JVM/web pass the identity default. This is what made it possible to remove `*Raw` trampolines from the platform shells in 2.0.

**Key state:**

- `memoryCache: KSafeConcurrentMap<Any>` — the hot cache. Stores plaintext in `PLAIN_TEXT` mode, Base64 ciphertext in `ENCRYPTED` / `ENCRYPTED_WITH_TIMED_CACHE`. Keyed by the *cache key*: user key for plain entries, `"encrypted_<key>"` (legacy pattern) for encrypted ones.
- `protectionMap: KSafeConcurrentMap<String>` — per-user-key protection literal, populated from `__ksafe_meta_*__` entries on disk.
- `plaintextCache: KSafeConcurrentMap<CachedPlaintext>` — TTL-bounded plaintext for `ENCRYPTED_WITH_TIMED_CACHE`.
- `cacheInitialized: KSafeAtomicFlag` — cold-start signal.
- `dirtyKeys: KSafeConcurrentSet<String>` — keys with in-flight writes; the background collector refuses to stomp these.
- `writeChannel: Channel<PendingWrite>` — unbounded queue feeding the coalescer.

**Key methods:**

- `defaultEncryptedMode(): KSafeWriteMode` — `KSafeWriteMode.Encrypted(requireUnlockedDevice = config.requireUnlockedDevice)`. Used by the no-mode `put`/`putDirect` overloads on `KSafe`. Lives on `KSafeCore` (not `KSafe`) because it reads `config`, which is a `KSafeCore` constructor param.
- `startBackgroundCollector()` — launches the collector coroutine that runs `migrateAccessPolicy()`, then `cleanupOrphanedCiphertext()`, then `storage.snapshotFlow().collect { updateCache(it) }`.
- `suspend updateCache(snapshot)` — the workhorse that merges an on-disk snapshot into `memoryCache`. Handles dirty-key skipping, legacy-format classification (via `KeySafeMetadataManager.classifyStorageEntry`), and — on non-`ENCRYPTED` memory policy — decrypts every encrypted entry through `engine.decryptSuspend`.
- `processBatch(batch)` — write-coalescer body. Encrypts every `PendingWrite.Encrypted` via `engine.encryptSuspend`, builds the full `List<StorageOp>` (including metadata + legacy-key deletes), calls `storage.applyBatch(ops)`, then deletes removed keys from the engine. For `ENCRYPTED` memory policy, uses a CAS (`memoryCache.replaceIf`) to swap plaintext for ciphertext without clobbering a newer in-flight write.
- `cleanupOrphanedCiphertext()` — probes every encrypted entry; removes from storage any whose decryption fails with a "key not found" message (but not "device is locked").
- `resolveFromCache(key, default, protection, serializer)` — the read hot-path called from both `getDirectRaw` (sync) and `getRaw` (suspend). Uses the timed plaintext cache when applicable, decrypts via blocking `engine.decrypt` in `ENCRYPTED` mode, and ultimately calls `convertStoredValue` to reconcile the stored type with the requested one.
- `convertStoredValue(storedValue, default, serializer)` — the cross-type dispatcher. Uses `primitiveKindOrNull(serializer)` to route Int/Long/Float/Double/Boolean/String lookups. Handles both typed DataStore values (Android/iOS/JVM) *and* string-stored primitives (web localStorage), plus `@Serializable` types via JSON. Also handles Int↔Long cross-type migration (widening / range-checked narrowing).
- `getDirectRaw` / `putDirectRaw` / `getRaw` / `putRaw` / `getFlowRaw` — the non-inline, non-reified entry points that everything in the library funnels through. `putDirectRaw` and `putRaw` shadow their `mode` parameter with `modeTransformer(mode)` at the very top.
- `deleteDirect` / `delete` / `clearAll` / `getKeyInfo` — straightforward.
- `isTransientDecryptFailure(e)` — shared "device locked / Keystore inaccessible" check. Used to distinguish "should retry" from "orphaned ciphertext, clean up".

**Why it's a class (not an object):** one `KSafeCore` per `KSafe` instance, so an app with `prefs` + `vault` instances gets two independent caches/coalescers.

## `KeySafeMetadataManager.kt` — on-disk key layout

A stateless helper object that owns the string-scheme for how user keys map to DataStore/localStorage raw keys.

**Key declarations:**

- Constants: `VALUE_PREFIX = "__ksafe_value_"`, `META_PREFIX = "__ksafe_meta_"`, `META_SUFFIX = "__"`, plus legacy equivalents `LEGACY_ENCRYPTED_PREFIX = "encrypted_"` and `LEGACY_PROTECTION_PREFIX = "__ksafe_prot_"`.
- `valueRawKey(userKey)` / `metadataRawKey(userKey)` — current format.
- `legacyEncryptedRawKey(userKey)` / `legacyProtectionRawKey(userKey)` — pre-1.7 format, still read for backwards compat.
- `tryExtractCanonicalValueKey(rawKey)` / `tryExtractCanonicalMetadataKey(rawKey)` / `tryExtractLegacyProtectionKey(rawKey)` / `tryExtractLegacyEncryptedKey(rawKey)` — reverse helpers.
- `isInternalStorageKey(rawKey)` — `true` for anything starting with `"__ksafe_"` or `"ksafe_"`. `classifyStorageEntry` uses this to skip internal housekeeping entries when building the cache.
- `collectMetadata(entries, accept)` — merges canonical + legacy metadata across a snapshot; canonical wins on conflict.
- `classifyStorageEntry(rawKey, legacyEncryptedPrefix, encryptedCacheKeyForUser, stagedMetadata, existingMetadata): ClassifiedStorageEntry?` — the algorithm that turns a raw on-disk key into `(userKey, cacheKey, encrypted)`. Handles both the canonical `__ksafe_value_` prefix and the pre-1.7 `encrypted_<key>` / bare-userKey variants.
- `buildMetadataJson(protection, accessPolicy)` — compact JSON like `{"v":1,"p":"DEFAULT","u":"unlocked"}`.
- `parseProtection(raw)` / `parseAccessPolicy(raw)` / `extractProtectionLiteral(raw)` — read-side parsers.
- `protectionToLiteral(protection): String` — write-side.

**Why centralised:** every platform shell and `KSafeCore` used to duplicate these string constants and parsers. Pulling them into one object means the on-disk format is defined exactly once.

## `KSafeSerializerUtil.kt` — JSON + serializer-kind helpers

Three small functions used by the read/write paths.

**Key declarations:**

- `jsonEncode(json, serializer, value)` / `jsonDecode(json, serializer, jsonString)` — `kotlinx-serialization-json` helpers that work with type-erased `KSerializer<*>`. Used by the non-inline `*Raw` methods.
- `primitiveKindOrNull(serializer)` — returns the `PrimitiveKind` from a serializer's descriptor, unwrapping nullable markers (so `Int?`'s serializer still returns `INT`). The backbone of `convertStoredValue`'s dispatch.
- `isStringSerializer(serializer)` — convenience wrapper. *Currently unused* after the 2.0 refactor; slated for removal in 2.1.

## `KSafeConcurrent.kt` — common concurrency primitives

Thin `expect` abstractions so `KSafeCore` can use a thread-safe map/set/flag without knowing how it's implemented.

**Key declarations:**

- `expect class KSafeAtomicFlag(initial: Boolean)` — atomic boolean.
- `expect class KSafeConcurrentMap<V : Any>()` — thread-safe `String`-keyed map with `get` / `set` / `remove` / `containsKey` / `clear` / `snapshot()` / `replaceIf(key, expected, new)` (CAS).
- `expect class KSafeConcurrentSet<T : Any>()` — thread-safe set.
- `expect fun <T> runBlockingOnPlatform(block: suspend () -> T): T` — `runBlocking` on Android/iOS/JVM, error on web (browsers can't block their main thread).

**Why `expect`:** JVM/Android use `ConcurrentHashMap` / `AtomicBoolean`; iOS uses copy-on-write `AtomicReference`; web is single-threaded so it uses plain `HashMap`. `KSafeCore` compiles unchanged against all three. (This and `KSafeSecureRandom` are the only `expect/actual` declarations in the storage module — `KSafe` itself is no longer one.)

## `KSafeSecureRandom.kt` — cross-platform CSPRNG

Single `expect fun secureRandomBytes(size: Int): ByteArray`. Used everywhere a random IV, a new AES key, or a secret body is needed.

## `SecurityChecker.kt` — runtime security probes

Platform-specific root/debugger/emulator detection, abstracted behind a common `expect object`.

**Key declaration:**

- `expect object SecurityChecker`:
  - `isDeviceRooted(): Boolean`
  - `isDebuggerAttached(): Boolean`
  - `isAppDebuggable(): Boolean`
  - `isEmulator(): Boolean`

**Why an `object`:** there's only ever one checker per platform, and the consumer never instantiates it. Called once from `validateSecurityPolicy` at `KSafe` construction.

---

# Part 3 — `datastoreMain`: the DataStore adapter

Android + iOS + JVM all use Jetpack DataStore Preferences. Rather than duplicate the adapter three times, KSafe defines a `datastoreMain` intermediate source set that the three actuals all depend on.

## `datastoreMain/internal/DataStoreStorage.kt`

The sole file in this source set. Implements `KSafePlatformStorage` on top of `DataStore<Preferences>`.

**Key logic:**

- The constructor takes the `DataStore<Preferences>` as `@PublishedApi internal val dataStore` — exposed at this visibility so the JVM platform-extension `KSafe.dataStore` (used by JVM whitebox tests) can read it back through `core.storage as DataStoreStorage`.
- `snapshot()` → `dataStore.data.first().toStoredMap()` — reads every preference once, maps each `Preferences.Key<*>` to its matching `StoredValue` variant (Int → `IntVal`, Boolean → `BoolVal`, String → `Text`, etc.).
- `snapshotFlow()` → `dataStore.data.map(::toStoredMap)` — change stream.
- `applyBatch(ops)` → a single `dataStore.edit { … }` block that processes every `StorageOp` in order, using typed `intPreferencesKey` / `longPreferencesKey` / … for writes and a name-based removal helper for deletes.
- `clear()` → `dataStore.edit { it.clear() }`.

**Why one adapter for three platforms:** DataStore is a KMP library. Android uses `datastore-preferences`; iOS/JVM use `datastore-preferences-core`. The typed-Preferences API we rely on is identical across all three. Writing the adapter once is the whole reason for the intermediate source set.

---

# Part 4 — platform shells

Each platform shell is a single file that exposes a top-level `fun KSafe(...)` factory plus any genuinely platform-specific helpers. The factories are what consumers actually call. Internally, each calls a `private fun buildXxxKSafe(...)` that does the construction work and ends in `return KSafe(core, deviceKeyStorages, onClearAllCleanup)`.

Every platform also exposes an `@PublishedApi internal fun KSafe(..., testEngine: KSafeEncryption)` overload — same params plus an injectable engine for tests. Pre-2.0 this was a secondary `internal constructor` on `actual class KSafe`; option C turned it into a same-name overload, which test call sites can use unchanged because they always pass `testEngine =` as a named argument.

## Android

### `KSafe.android.kt` — the factory

~176 lines (down from ~1,584 pre-2.0). Owns:

- **Top-level `KSafe(context: Context, fileName: String? = null, ..., useStrongBox: Boolean = false, baseDir: File? = null): KSafe`** — public factory.
- **Top-level `@PublishedApi internal fun KSafe(..., baseDir: File? = null, testEngine: KSafeEncryption)`** — test overload.
- **`private val dataStoreCache: ConcurrentHashMap<String, DataStore<Preferences>>`** — top-level cache (not in a companion anymore). Caches the `DataStore` per absolute file path (not per-filename, as it was pre-`baseDir`) so two `KSafe` instances pointing at different `baseDir`s get separate DataStores instead of conflicting on the same fileName, and two pointing at the same path correctly share one DataStore (avoiding DataStore's "multiple active instances" error).
- **`const val KEY_ALIAS_PREFIX = "eu.anifantakis.ksafe"`** — top-level public constant. Used to build the Keystore alias passed to `KSafeCore`.
- **StrongBox detection** inside `buildAndroidKSafe`. `Build.VERSION.SDK_INT >= P && context.packageManager.hasSystemFeature(FEATURE_STRONGBOX_KEYSTORE)`. Drives `deviceKeyStorages`.
- **DataStore file resolution.** If `baseDir == null` (recommended), uses `context.preferencesDataStoreFile(name)` — Context-managed app-private path under `/data/data/<package>/files/datastore/...`, where the Android sandbox enforces correct permissions. If a custom `baseDir` is supplied, KSafe creates the directory if missing and uses `File(baseDir, "$baseFileName.preferences_pb")`. Doc warns against external storage for sensitive data.
- **`promoteMode(KSafeWriteMode)`** — local helper inside `buildAndroidKSafe`. Honors the deprecated `useStrongBox` constructor flag by promoting `KSafeEncryptedProtection.DEFAULT` to `HARDWARE_ISOLATED`. Passed to `KSafeCore` as `modeTransformer = ::promoteMode`.
- **`resolveKeyStorageTier(userKey, protection)`** — local helper. Returns `HARDWARE_ISOLATED` when protection is HARDWARE_ISOLATED *and* the device has StrongBox; otherwise `HARDWARE_BACKED`. Passed to `KSafeCore` as `resolveKeyStorage = ::resolveKeyStorageTier`.
- **`SecurityChecker.applicationContext = context.applicationContext`** — wired in the factory before `validateSecurityPolicy(securityPolicy)` runs.

What's *not* here anymore: biometric integration. Pre-2.0 the Android shell owned `BiometricHelper.init(application)`, a per-scope session cache (`AtomicReference<Map<String, Long>>`), and `verifyBiometric{,Direct}` methods. All of that moved to `:ksafe-biometrics` in 2.0.

### `internal/AndroidKeystoreEncryption.kt` — the engine

Implements `KSafeEncryption` via `javax.crypto` talking to the `"AndroidKeyStore"` JCA provider. Notable specifics:

- `KeyGenerator.getInstance("AES", "AndroidKeyStore")` + a `KeyGenParameterSpec` carrying `setIsStrongBoxBacked(true)` when `hardwareIsolated` is requested, and `setUnlockedDeviceRequired(true)` (API 28+) when `requireUnlockedDevice` is set.
- Returns a `SecretKey` that's actually a *handle* — the key bytes never leave the TEE / StrongBox.
- `deleteKey(alias)` removes the Keystore entry; idempotent on missing aliases.

### `internal/KSafeConcurrent.android.kt` / `internal/KSafeSecureRandom.android.kt` / `internal/SecurityChecker.android.kt`

- `KSafeConcurrent` — `actual` via `java.util.concurrent.ConcurrentHashMap` and `java.util.concurrent.atomic.AtomicBoolean`.
- `KSafeSecureRandom` — `java.security.SecureRandom.nextBytes(...)`.
- `SecurityChecker` — reads `BuildConfig.DEBUG`, probes for root binaries / Magisk, checks `Debug.isDebuggerConnected()`, detects emulator via build fingerprints + the standard `goldfish` / `sdk` heuristics.

## iOS

### `KSafe.ios.kt` — the factory

~225 lines (down from ~1,938 pre-2.0). Owns:

- **Top-level `KSafe(fileName: String? = null, ..., useSecureEnclave: Boolean = false, directory: String? = null): KSafe`** — public factory.
- **Top-level `@PublishedApi internal fun KSafe(..., directory: String? = null, testEngine: KSafeEncryption)`** — test overload.
- **`@PublishedApi internal const val KEY_PREFIX = "eu.anifantakis.ksafe"`** — top-level constant. Used to build the Keychain alias passed to `KSafeCore`.
- **CryptoKit registration + AES.GCM retention** inside `buildIosKSafe`. Kotlin/Native's dead-code elimination can strip CryptoKit bindings if nothing references them statically. The factory body references `CryptographyProvider.CryptoKit` and captures `AES.GCM` into a `@Suppress("UNUSED_VARIABLE")` val.
- **Secure Enclave detection** via `isSimulator()` (top-level helper). Returns `true` on Simulator (no hardware); every real device has an SEP. Drives `deviceKeyStorages`.
- **Legacy encrypted-key format override.** Pre-1.8 iOS builds wrote encrypted entries under `"{fileName}_{key}"` rather than the common `"encrypted_{key}"`. Local helpers `iosLegacyEncryptedKey(userKey)` / `iosLegacyEncryptedPrefix()` are passed to `KSafeCore`, which uses them throughout its legacy-read paths so upgraders never lose data.
- **`useSecureEnclave` deprecated flag.** Same role as Android's `useStrongBox`: promoted via local `promoteMode` helper passed as `modeTransformer = ::promoteMode`.
- **`cleanupOrphanedKeychainEntriesSafe()`** — local suspend helper passed as `migrateAccessPolicy = { cleanupOrphanedKeychainEntriesSafe() }`. Delegates to `internal/KeychainOrphanCleanup.kt`.
- **DataStore directory resolution.** If `directory == null` (default), uses `NSFileManager.URLForDirectory(NSApplicationSupportDirectory, NSUserDomainMask, create = true)` — the Apple-recommended location for invisible app data. If a custom path is supplied, it's used as-is. Either way the directory is `mkdir`ed via `createDirectoryAtPath(withIntermediateDirectories = true)` and the resolved file path is `"$dir/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb"`.
- **1.x → 2.0 auto-migration from `NSDocumentDirectory`.** Pre-2.0 iOS stored the DataStore in `NSDocumentDirectory` — the wrong place (user-visible via iTunes File Sharing if `UIFileSharingEnabled`, iCloud-syncable by default). 2.0 moves the default to `NSApplicationSupportDirectory`. To avoid forcing 1.x consumers to write migration code, the factory checks: when `directory == null` AND the new path is empty AND a legacy file exists at `"$NSDocumentDirectory/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb"`, it calls `NSFileManager.moveItemAtPath` to relocate the file. Idempotent (only triggers when the new location is empty) and best-effort (a failed move logs a recovery message and leaves the legacy file alone — the consumer can recover by passing `directory = "<old Documents path>"`). Apps bumping the dep from 1.x to 2.0 keep their data with zero code changes.
- **No file-level `NSURLIsExcludedFromBackupKey` setting.** An earlier draft set the attribute unconditionally, but DataStore's atomic-write strategy (write-to-temp then rename) creates a new inode on every flush and clobbers the xattr — making the setting unreliable in practice. The actual security guarantee comes from key locality: encryption keys live in the Keychain with `…ThisDeviceOnly` accessibility (and Secure Enclave keys never leave the device for `HARDWARE_ISOLATED` writes), so a backed-up ciphertext is undecryptable on a restored device — effectively device-local even when the bytes themselves traverse iCloud. Apps that need a hard file-level exclusion can do it themselves on the resolved path or use a per-instance subdirectory layout.
- **`fun obtainAesGcm(): AES.GCM`** — public top-level helper retained from pre-refactor for external Swift callers that warm up the cipher.

What's *not* here anymore: `verifyBiometric` / `verifyBiometricDirect` / `clearBiometricAuth`, the LAContext glue, and the `biometricAuthSessions` map. All moved to `:ksafe-biometrics`.

### `internal/IosKeychainEncryption.kt` — the engine

Implements `KSafeEncryption` using `cryptography-kotlin`'s CryptoKit provider for AES-GCM, and the raw Apple Security framework (`SecItemAdd`, `SecItemCopyMatching`, `SecKeyCreateRandomKey`) for key persistence. At ~640 lines it's still the biggest engine — raw `platform.Security.*` cinterop has no JCA-style shortcut — but it's built on a small helper layer so the same boilerplate doesn't repeat.

**Key behaviours:**

- Plain `DEFAULT` writes store a raw AES key as a `kSecClassGenericPassword` item with service = `"eu.anifantakis.ksafe"` and account = `"eu.anifantakis.ksafe.<fileName>.<userKey>"`.
- `HARDWARE_ISOLATED` writes use ECIES: an EC private key is created in the Secure Enclave (`kSecAttrTokenIDSecureEnclave`), and the AES key is wrapped with its public key and stored as a `kSecClassGenericPassword` item under `"se.<prefix>.<userKey>"`.
- `updateKeyAccessibility(identifier, requireUnlocked)` — the only engine that actually implements this, via `SecItemUpdate`.
- Every `memScoped` body is wrapped in `kotlinx.cinterop.autoreleasepool { … }` (fix from 1.8.1) to drain Kotlin→NSString bridging allocations on worker threads that lack an ambient Objective-C autorelease pool.

**Internal helper layer** (top of the class, above the `KSafeEncryption` interface impls):

- `accessibleAttr(Boolean)` — maps the unlock-policy boolean to the right `kSecAttrAccessible*` CFString. Previously an `if/else` re-written in four places.
- `tagAsNSData(String)` — encodes an SE application-tag as UTF-8 NSData. Previously duplicated in `createSecureEnclaveKey`, `getSecureEnclaveKey`, `deleteSecureEnclaveKey`, `updateSecureEnclaveKeyAccessibility`.
- `cfErrorDescription(CFErrorRefVar)` — reads a localized description out of a `CFError` with a stable fallback message. Previously duplicated in `createSecureEnclaveKey`, `wrapAesKey`, `unwrapAesKey`.
- `usingPasswordQuery(account, configure, block)` / `usingSeKeyQuery(tagData, configure, block)` — `inline` helpers that build a `CFDictionary` with the base class/service/account (or class/keyType/applicationTag for SE) attributes pre-populated, let the caller add class-specific attrs via `configure`, run `block` with the dict, and `CFRelease` it on every exit path. Previously each `SecItemCopyMatching` / `SecItemAdd` / `SecItemUpdate` / `SecItemDelete` call-site built and released its own dict.
- `copyKeychainBytes(account)` — single unified "find this item's bytes or return null / throw" routine used by every lookup path.
- `cryptWithSeKey(key, input, wrap: Boolean)` — one shared ECIES-encrypt/decrypt implementation, with `wrap: Boolean` choosing `SecKeyCreateEncryptedData` vs `SecKeyCreateDecryptedData`.
- `runItemUpdate(query, requireUnlocked)` / `handleAccessibilityUpdateStatus(status, what)` — shared between the two `update*Accessibility` methods (SE EC private key and generic-password item), which previously duplicated the update-dictionary build and the `errSecSuccess` / `errSecItemNotFound` / `errSecInteractionNotAllowed` switch.

### `internal/KeychainOrphanCleanup.kt`

Standalone suspend function `cleanupOrphanedKeychainEntries(storage, engine, serviceName, keyPrefix, fileName, legacyEncryptedPrefix, seKeyTagPrefix)`.

- Reads `storage.snapshot()` to compute the set of user keys with live DataStore entries.
- Scans Keychain generic-password items (plain keys + SE-wrapped blobs) via `SecItemCopyMatching`; compares `kSecAttrAccount` against the valid-keys set.
- Scans `kSecClassKey` EC private keys separately — catches SE keys that exist without a matching generic-password item (e.g. after a crash between SE-key creation and wrapped-AES-key storage).
- Deletes orphans by calling `engine.deleteKeySuspend(fullIdentifier)`, which unconditionally removes plain + SE-wrapped + SE EC artifacts for the same identifier.

**Why separate from `IosKeychainEncryption`:** the sweep needs both the `KSafePlatformStorage` snapshot (to know what's valid) and the `KSafeEncryption` engine (to delete). Keeping it as a standalone function lets it be unit-tested against fakes of both.

### `internal/KSafeConcurrent.ios.kt` / `internal/KSafeSecureRandom.ios.kt` / `internal/SecurityChecker.ios.kt`

- `KSafeConcurrent` — `actual` via `kotlin.concurrent.AtomicReference` with copy-on-write semantics (Kotlin/Native lacks `ConcurrentHashMap`). `KSafeAtomicFlag` is backed by `AtomicInt` (0/1) rather than `AtomicReference<Boolean>` because boxed `Boolean` doesn't have stable reference identity on Kotlin/Native.
- `KSafeSecureRandom` — `arc4random_buf` via `kotlinx.cinterop`.
- `SecurityChecker` — jailbreak detection (probes for `/Applications/Cydia.app`, `/bin/bash`, etc.), debugger check via `sysctl(CTL_KERN, KERN_PROC, …)` and `P_TRACED`, simulator via `NSProcessInfo.processInfo.environment["SIMULATOR_UDID"]`.

## JVM

### `KSafe.jvm.kt` — the factory + test extensions

~212 lines (down from ~1,360 pre-2.0). Owns:

- **Top-level `KSafe(fileName: String? = null, ..., baseDir: File? = null): KSafe`** — public factory.
- **Top-level `@PublishedApi internal fun KSafe(..., baseDir: File? = null, testEngine: KSafeEncryption)`** — test overload.
- **DataStore directory resolution.** If `baseDir == null` (default), uses `~/.eu_anifantakis_ksafe`. If a custom `baseDir` is supplied (e.g. `$XDG_DATA_HOME/myapp`, `%APPDATA%`, a per-test temp dir), KSafe uses that. Either way the directory is `mkdir`ed if missing and the local `secureDirectory(File)` helper applies POSIX `0700` permissions — the user-supplied path is hardened the same way as the default (this was the security fix on top of [PR #25](https://github.com/ioannisa/KSafe/pull/25)). The resolved file path is `"$baseDir/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb"`.
- **Public top-level `encodeBase64(bytes)`** helper. Kept public (not `@PublishedApi internal`) because test assertions use it.
- **`onClearAllCleanup` callback** passed into `KSafe(...)`. Captures the same resolved `datastoreFile` used by the `produceFile` lambda and deletes it after `core.clearAll()` (DataStore's `edit { clear() }` leaves an empty protobuf behind and some tests assert on file absence). The pre-2.0 PR #25 merge had a bug here — it hardcoded the home dir, so `clearAll()` silently failed to delete the file when `baseDir` was set; that's fixed.
- **Test-surface extensions** at the bottom of the file:
  - `@PublishedApi internal val KSafe.dataStore: DataStore<Preferences>` — extension property; reaches in via `(core.storage as DataStoreStorage).dataStore`. Used by `JvmKSafeTest` for whitebox DataStore access.
  - `@PublishedApi internal val KSafe.engine: KSafeEncryption` — extension property; just `core.engine`.
  - `@PublishedApi internal fun KSafe.updateCache(prefs: Preferences)` — extension function. Lets `JvmKSafeTest` deterministically merge a DataStore snapshot into the core's cache. Wraps `core.updateCache(...)` in `runBlocking`. (Pre-2.0 this was a member of `actual class KSafe`; option C couldn't keep it there because `KSafe` is now in commonMain.)

### `internal/JvmSoftwareEncryption.kt` — the engine

Implements `KSafeEncryption` via `javax.crypto` (`Cipher.getInstance("AES/GCM/NoPadding")`). Notable specifics:

- AES keys stored as Base64 strings in the *same* DataStore as the encrypted data, under `"ksafe_key_<alias>"` entries. The DataStore file's `0700` perm is the perimeter.
- In-memory key cache (`ConcurrentHashMap<String, SecretKey>`) avoids repeated Base64 decode + key import on every call.
- A per-alias mutex (via `ConcurrentHashMap<String, Any>` for lock objects) prevents concurrent first-time key generation under the same alias from racing.

### `internal/KSafeConcurrent.jvm.kt` / `internal/KSafeSecureRandom.jvm.kt` / `internal/SecurityChecker.jvm.kt`

- `KSafeConcurrent` — `ConcurrentHashMap` + `AtomicBoolean` — same as Android.
- `KSafeSecureRandom` — `java.security.SecureRandom.nextBytes(...)`.
- `SecurityChecker` — `isDeviceRooted()` and `isEmulator()` are no-ops (return `false`) because they don't map to desktop and pretending they did would be dishonest. `isDebuggerAttached()` and `isDebugBuild()` are real implementations: the former scans `ManagementFactory.getRuntimeMXBean().inputArguments` for `-agentlib:jdwp` / `-Xdebug` / `-Xrunjdwp`; the latter probes whether assertions are enabled via the `assert` keyword.

## Web (js + wasmJs)

### `KSafe.web.kt` — the shared factory

~128 lines (down from ~1,052 pre-2.0), lives in `webMain` (shared by both `jsMain` and `wasmJsMain`). Owns:

- **Top-level `KSafe(fileName: String? = null, ...): KSafe`** — public factory. The `memoryPolicy` parameter is accepted for API parity but ignored — see below.
- **Top-level `@PublishedApi internal fun KSafe(..., testEngine: KSafeEncryption)`** — test overload.
- **`memoryPolicy` is forced to `PLAIN_TEXT`.** WebCrypto is async-only, so decrypting from the sync `getDirect` path is impossible — the cache has to hold pre-decrypted strings. The factory passes `memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT` to `KSafeCore` regardless of what the consumer passed.
- **Storage prefix.** Every localStorage entry is prefixed with `"ksafe_<fileName>_"` (or `"ksafe_default_"`). Isolates multiple `KSafe` instances in the same origin.
- **`suspend fun KSafe.awaitCacheReady()`** — top-level extension function. Delegates to `core.ensureCacheReadySuspend()`. Apps that want a deterministic first `getDirect` call it once at startup before rendering. Defined as an extension because `awaitCacheReady` is web-only — JVM/Android/iOS preload synchronously and don't need it.

### `internal/LocalStorageStorage.kt` — the storage adapter

Implements `KSafePlatformStorage` on top of localStorage.

- **Strings only.** `applyBatch` flattens every `StoredValue` variant to `.toString()` and writes via `localStorage.setItem`. On read, everything comes back as `StoredValue.Text`. `KSafeCore.convertStoredValue` reconstitutes the typed primitive using the request's `KSerializer` (the `primitiveKindOrNull` dispatch path).
- **Change notification.** localStorage's `storage` event only fires for *other* tabs, so this adapter maintains a `MutableStateFlow<Map<String, StoredValue>>` that it re-emits after every `applyBatch` or `clear`. `snapshotFlow()` returns that flow.
- **`yield()` after each batch.** Browsers are single-threaded; without yielding, downstream collectors don't see the new snapshot before the caller's suspend function returns. This was the fix for a flaky `testStateFlowUnencrypted` caught during the web port.

### `internal/WebSoftwareEncryption.kt` — the engine

Implements `KSafeEncryption` via `cryptography-kotlin`'s WebCrypto provider. Overrides only the suspend variants; the blocking `encrypt` / `decrypt` throw `UnsupportedOperationException` with a message pointing at the suspend versions. Keys are Base64 AES-key bytes stored in localStorage under `"<storagePrefix>ksafe_key_<alias>"`.

### `internal/WebInterop.kt` — expect/actual for localStorage

Single file of `expect fun` declarations: `localStorageGet/Set/Remove/Length/Key`, `currentTimeMillisWeb`. The `LocalStorageStorage` adapter and the engine are the only callers.

Why expect/actual: `jsMain` and `wasmJsMain` both need to call localStorage but through slightly different interop (plain `external` + `kotlinx.browser` on js; `@JsFun`-annotated externals on wasmJs).

### `internal/KSafeConcurrent.web.kt` / `internal/SecurityChecker.web.kt`

- `KSafeConcurrent` — plain `HashMap` / `HashSet` / `var value: Boolean`. Browsers are single-threaded; these never need locks. `runBlockingOnPlatform` throws — the one place it's called (`KSafeCore.ensureCacheReadyBlocking`) catches the throw, so a getDirect that races the async preload returns `defaultValue` rather than blocking.
- `SecurityChecker` — no-ops, same reasoning as JVM.

### `jsMain/internal/` and `wasmJsMain/internal/`

Two files per target, both thin:

- **`KSafeSecureRandom.{js,wasmJs}.kt`** — `actual fun secureRandomBytes(size)` via `crypto.getRandomValues(Uint8Array(size))`. js uses direct DOM bindings; wasmJs uses an `@JsFun`-bridged equivalent.
- **`WebInterop.{js,wasmJs}.kt`** — target-specific `actual` bindings for localStorage + time.

Nothing platform-specific beyond binding style; behaviour on both targets is identical.

---

# Part 5 — where key features live

Quick lookup table: if you're tracking down a specific behaviour, this is the file you want.

| Feature | File |
|---|---|
| `KSafe` class itself (members defined once) | `commonMain/KSafe.kt` |
| Per-platform factory functions | `{android,ios,jvm,web}Main/KSafe.{platform}.kt` |
| Custom storage directory (`baseDir` / `directory`) | `{android,ios,jvm}Main/KSafe.{platform}.kt` factories |
| iOS 1.x → 2.0 path migration (`NSDocumentDirectory` → `NSApplicationSupportDirectory`) | `iosMain/KSafe.ios.kt` (`buildIosKSafe`) |
| iOS forced backup-exclusion (`NSURLIsExcludedFromBackupKey`) | `iosMain/KSafe.ios.kt` (`buildIosKSafe`) |
| Hot cache + write coalescing | `commonMain/internal/KSafeCore.kt` |
| `modeTransformer` callback (honors `useStrongBox` / `useSecureEnclave`) | `commonMain/internal/KSafeCore.kt` (constructor) — set per-platform in the factories |
| Orphan-ciphertext cleanup (DataStore side) | `commonMain/internal/KSafeCore.kt` (`cleanupOrphanedCiphertext`) |
| Orphan-key cleanup (iOS Keychain side) | `iosMain/internal/KeychainOrphanCleanup.kt` |
| On-disk key naming | `commonMain/internal/KeySafeMetadataManager.kt` |
| Int ↔ Long cross-type migration | `commonMain/internal/KSafeCore.kt` (`convertStoredValue`) |
| Legacy-format read path | `commonMain/internal/KeySafeMetadataManager.kt` (`classifyStorageEntry`) |
| `ENCRYPTED_WITH_TIMED_CACHE` TTL | `commonMain/internal/KSafeCore.kt` (`plaintextCache`) |
| WebCrypto suspend crypto | `webMain/internal/WebSoftwareEncryption.kt` |
| StrongBox request wiring | `androidMain/internal/AndroidKeystoreEncryption.kt` |
| Secure Enclave ECIES wrapping | `iosMain/internal/IosKeychainEncryption.kt` |
| `var x by ksafe(0)` | `commonMain/KSafeDelegate.kt` |
| `getOrCreateSecret` | `commonMain/KSafeSecret.kt` |
| Root/debugger/emulator checks | `*Main/internal/SecurityChecker.*.kt` |
| `secureRandomBytes` CSPRNG | `*Main/internal/KSafeSecureRandom.*.kt` |
| `encrypted: Boolean` deprecated overloads | `commonMain/KSafe.kt` (members of `class KSafe`) |
| JVM whitebox test access (`ksafe.dataStore`, `ksafe.engine`, `ksafe.updateCache`) | `jvmMain/KSafe.jvm.kt` (extension functions/properties) |
| Web `ksafe.awaitCacheReady()` | `webMain/KSafe.web.kt` (extension function) |
| Biometric verification | **`:ksafe-biometrics` module** (separate artifact) |

---

# Part 6 — test source sets

Not exhaustively covered, but briefly:

- **`commonTest/`** — abstract base + cross-platform tests:
  - `KSafeTest.kt` — abstract base with every test that runs on every platform. Each platform's test source set has its own `fooKSafeTest : KSafeTest()` that supplies `createKSafe(...)` (often forwarding a `testEngine` to the internal `KSafe(..., testEngine = ...)` factory overload).
  - `KSafeConfigTest`, `KSafeMemoryPolicyTest`, `KSafeProtectionTest`, `KSafeSecurityPolicyTest` — value-class tests.
  - `FakeEncryption.kt`, `TestData.kt`, `ByteArraySearch.kt` — shared helpers.
  - Note: `BiometricAuthorizationDurationTest` is **not** here in 2.0 — it lives in `:ksafe-biometrics/commonTest/` along with the rest of biometric.
- **`jvmTest/`** — JVM-specific tests: `JvmKSafeTest` (extends common), `Jvm160FixesTest` (regression suite for the v1.6.0 key-generation race fix), `JvmCustomJsonTest`, `JvmEncryptionProofTest` (verifies AES output round-trips), `JvmNullFilenameTest`, `JvmFileNameTest` (includes the 2.0 `baseDir_storesFileInProvidedDirectory` and `baseDir_clearAll_removesFileFromProvidedDirectory` tests for the custom-storage-directory feature), `JvmSecurityCheckerTest`, `KSafeKeyStorageTest`. `JvmKSafeTest` is the heaviest user of the platform-extension test surface (`ksafe.dataStore`, `ksafe.engine`, `ksafe.updateCache`).
- **`iosTest/`** — `IosKSafeTest`, `IosEncryptionProofTest`, `IosKeychainEncryptionTest`, `IosKeychainEncryptionLeakTest` (`ru_maxrss`-based memory-leak regression for the 1.8.1 NSString-bridging fix), `IosNullFilenameTest`, **`IosStorageLocationTest`** (locks in the 2.0 storage-location behaviour: `directory` parameter routing, the 1.x → 2.0 auto-migration from `NSDocumentDirectory` to `NSApplicationSupportDirectory`, and the explicit-`directory` migration-skip).
- **`webTest/`** (shared by js + wasmJs) — `WebKSafeTest`, `WebEncryptionProofTest`, `WebInteropSmokeTest`. The smoke test asserts per-target `actual` correctness: `localStorage` round-trip, `localStorage` enumeration, `currentTimeMillisWeb()` plausibility, and `secureRandomBytes()` non-determinism.
- **`androidInstrumentedTest/`** — `AndroidKSafeTest`, `AndroidEncryptionProofTest`, `AndroidConcurrencyTest`, `NullFilenameTest`, **`AndroidStorageLocationTest`** (locks in the 2.0 cache-key change: same `fileName` + different `baseDir` → isolated DataStores instead of DataStore's "multiple active instances" crash). Require a device or emulator.

### Sister-module tests

- **`:ksafe-biometrics/commonTest/`** — `BiometricAuthorizationDurationTest` (the data class).
- **`:ksafe-biometrics/jvmTest/`** — `KSafeBiometricsJvmTest` pins the no-op contract on JVM/JS/WasmJS (`verifyBiometric` returns `true`, `verifyBiometricDirect` callback fires with `true`, `clearBiometricAuth` doesn't throw, `KSafeBiometrics` is a singleton object). The same `actual fun`s back JS/WasmJS, so JVM coverage is sufficient for those targets too.
- **`:ksafe-compose/commonTest/`** — `KSafeComposeStateTest`, `KSafeMutableStateOfTest`. The latter's `mutableStateOf_encryptsByDefault` / `mutableStateOf_canStoreUnencrypted` tests use `getKeyInfo(...).protection` to verify encryption — the 2.0-correct way, since the deprecated `encrypted: Boolean` parameter on reads is auto-detected and ignored.

---

# Appendix — how to read the code when chasing a bug

After the 2.0 refactor, the call chain through the library is short:

1. **Consumer call site.** E.g., `ksafe.put("k", 42)`.
2. **Inline reified body** in `commonMain/KSafe.kt` — the body is `core.putRaw(key, value, core.defaultEncryptedMode(), serializer<T>())`. This whole expression is inlined into the consumer's compiled bytecode at the call site, so at runtime there's no `KSafe` method frame at all.
3. **`KSafeCore`** in `commonMain/internal/KSafeCore.kt` — `putRaw` shadows `mode` with `modeTransformer(mode)` (no-op on JVM/web; `promoteMode` on Android/iOS), then runs the actual write.
4. **`KSafePlatformStorage`** (`DataStoreStorage` / `LocalStorageStorage`) — what touches disk.
5. **`KSafeEncryption`** implementation — what touches the keystore / keychain / WebCrypto.

Almost every bug hunt in KSafe ends in `KSafeCore` or one of the four encryption engines. The platform shells are construction-only; once a `KSafe` is built, no platform-specific code runs on the read/write hot path — except the `modeTransformer` for puts on Android/iOS, and the `resolveKeyStorage` callback that `getKeyInfo` uses.

For property-delegate paths (`var x by ksafe(0)`, `ksafe.mutableStateOf(...)`, the flow delegates), the chain skips step 2 — the delegates work with a non-reified `KSerializer<T>` captured at creation time and call `ksafe.core.getDirectRaw` / `core.putDirectRaw` directly from `commonMain/KSafeDelegate.kt`.

For biometric verification, you're in the wrong module — see `:ksafe-biometrics`.
