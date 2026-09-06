# KSafe — a tour of the source tree

This is a walk-through of the `ksafe` module. The tree below lists every source file in it; the sections after it explain what each one holds and why it lives there, so a new contributor (or future-you) can find *where* a given behaviour lives without re-reading every line. A few one-purpose helpers are named only where their caller is described.

This document assumes you know what KSafe does from a caller's side. If you don't, read **[docs/ARCHITECTURE.md](ARCHITECTURE.md)** first — the same library described as concepts rather than files — and **[docs/USAGE.md](USAGE.md)** for the API you would actually call. This tour maps those concepts onto paths.

## Sister modules

KSafe ships as three independent artifacts. This tour focuses on `:ksafe`. The other two are mentioned only where they're relevant:

| Module | What it owns | Depends on |
|---|---|---|
| **`:ksafe`** | Storage core: `KSafe` class, hot cache, write coalescer, encryption engines, DataStore / localStorage adapters | nothing else in the project |
| **`:ksafe-compose`** | Compose state on top of a `KSafe`: `mutableStateOf(...)` / `rememberKSafeState(...)`, on the instance and on each mode view | `:ksafe` |
| **`:ksafe-biometrics`** | `KSafeBiometrics` static API — a process-wide biometric gate with real OS prompts on Android, iOS, macOS, JVM Desktop (macOS Touch ID / Windows Hello) and web (WebAuthn); `BiometricAuthorizationDuration`, `biometricsAvailable()`, Android `BiometricHelper`, auto-init `ContentProvider` | nothing else in the project |

If you're chasing biometric verification code, you're in the wrong module — see `:ksafe-biometrics`. Pre-2.0, biometrics lived inside `:ksafe`; in 2.0 it was extracted ([issue #14](https://github.com/ioannisa/KSafe/issues/14)).

## Architecture overview

`:ksafe` splits into three rings:

1. A **public API** in `commonMain` — everything a consumer imports, defined exactly once.
2. An **internal orchestrator** in `commonMain/internal/` — the shared logic that implements the public API once.
3. Per-platform **thin factory shells** in `{android,apple,jvm,web}Main` that wire the orchestrator to a DataStore, a keystore, and the platform's crypto engine.

The architectural rule is that **the orchestrator lives in common code and the platform shells are construction-only adapters**. Two intermediate source sets sit between common and the targets: `datastoreMain` (Android + Apple + JVM), because all three back onto Jetpack DataStore Preferences, and `jvmSharedMain` (Android + JVM), which hosts the concurrency and CSPRNG actuals those two share — `java.*` and kotlinx code with no Android API in it. `jvmSharedMain` can't be folded into `datastoreMain`: Apple shares that set and has its own actuals for those.

A consequence of this: `KSafe` itself is **not** an `expect class`. It is a regular class declared once in `commonMain`, with all members — including the inline reified `getDirect/put/get/putDirect/getFlow` — defined a single time. Each platform shell exposes a top-level **factory function** named `KSafe(...)` that builds the platform-specific dependencies and returns a `KSafe` instance. Kotlin treats `KSafe(context, ...)` and `KSafe(...)` identically at the call site whether the resolution target is a constructor or a same-named top-level function, so the consumer-visible API didn't change when this happened.

The tour starts in `commonMain`. Each platform file only gets a section for the things that differ from — or extend — what the common equivalent already describes.

## Vocabulary

These words recur throughout the tour. Each is defined once, here.

| Term | What it means here |
|---|---|
| **engine** | The per-platform `KSafeEncryption` implementation. It encrypts and decrypts bytes and owns the key material; it knows nothing about caching, metadata, or the user keys a caller reads and writes. |
| **alias** | The name the engine files a key under — a Keystore alias, a Keychain account, a JVM vault entry name. Derived from the store's `fileName` and the user key. |
| **master alias** | One shared key per store that every ordinary `DEFAULT` encrypted entry rides. Only `HARDWARE_ISOLATED` entries get a key of their own. Android and Apple keep two masters, one per unlock policy; JVM and web have one. |
| **envelope version** | A number in each entry's metadata saying how to route its decrypt: v1 (pre-2.x, per-entry alias), v2 (master key, no associated data), v3 (v2 routing plus an authenticated envelope). An entry upgrades only when it is overwritten or rotated. |
| **AAD** (associated data) | Bytes that travel in the clear but are covered by the AES-GCM authentication tag. Decryption must present exactly the same bytes or it fails. KSafe puts the entry's routing in there, so ciphertext copied to another key or another store fails to open instead of decrypting into the wrong place. |
| **KEK / DEK** | Key-encrypting key and data-encrypting key. On Android the KEK stays inside the TEE and never leaves; it wraps a DEK that is unwrapped once into process memory, after which per-value AES-GCM is ordinary CPU work. |
| **TEE** | The Trusted Execution Environment — a protected mode of the main chip, where Android Keystore keys live. |
| **StrongBox / Secure Enclave** | A separate security chip, on Android and Apple respectively. Stronger than the TEE, requested per write, and absent on many devices. |
| **coalescer** | The single coroutine that drains the write queue and turns a burst of writes into one storage transaction. |
| **CAS** | Compare-and-set: replace a value only if it still equals what you last saw. KSafe uses it so a background task never overwrites a newer in-flight write. |
| **`expect` / `actual`** | Kotlin Multiplatform's mechanism for one declaration in common code and one implementation per target. |
| **`@PublishedApi internal`** | Invisible to consumer *source*, but present in the compiled artifact — a public `inline` function's body is copied into the caller and must still be able to name what it touches. Such a declaration is part of the binary contract even though nobody can import it. |
| **ABI dump / klib dump** | The checked-in files describing that binary contract: `ksafe/api/{android,jvm}/ksafe.api` for the JVM-bytecode targets and `ksafe/api/ksafe.klib.api` for the native and web ones. `apiCheck` fails the build when a change would break already-compiled callers. |
| **orphan** | Ciphertext whose decryption key is definitively gone, or a key with no ciphertext left to open. The startup sweeps reclaim both — carefully, because the two failure modes look alike. |
| **sentinel** | A reserved name KSafe uses in its own alias plane (`__ksafe_master__` and friends). A user key that would collide with one is rejected. |

---

## Source layout at a glance

```
ksafe/src/
├── commonMain/                         (public API + shared orchestrator)
│   └── kotlin/eu/anifantakis/lib/ksafe/
│       ├── KSafe.kt                    (public class — defined ONCE in commonMain)
│       ├── KSafeBase64.kt              (internal codec, one spelling for every target)
│       ├── KSafeConfig.kt
│       ├── KSafeDelegate.kt
│       ├── KSafeKeyInfo.kt
│       ├── KSafeKeyRotationPolicy.kt    (3.0.0+: Never | MaxAge auto-rotation policy)
│       ├── KSafeKeyStorage.kt
│       ├── KSafeModeViews.kt               (3.1.0+: KSafePlain / KSafeEncrypted / KSafeHardwareIsolated views)
│       ├── KSafeProtection.kt
│       ├── KSafeProtectionInfo.kt          (2.1.0+: instance diagnostic — see KSafe.protectionInfo; 3.0.0+ isEncryptionOperational)
│       ├── KSafeProtectionLevel.kt         (2.1.0+: universally-ordered scale)
│       ├── KSafeReference.kt               (3.2.0+: the handle `ksafe(default, key)` returns)
│       ├── KSafeRotationResult.kt          (3.0.0+: rotateKeys() outcome counts)
│       ├── KSafeSecret.kt
│       ├── KSafeSecurityPolicy.kt
│       ├── KSafeWriteMode.kt
│       └── internal/
│           ├── KSafeCore.kt              (the class: constructor, state, PendingWrite, companion)
│           ├── coreparts/                (KSafeCore's logic, one file per concern)
│           │   ├── KSafeCoreRouting.kt       (alias/AAD routing + the one decryptEntry)
│           │   ├── KSafeCoreRead.kt          (resolveFromCache, ensureCacheReadyBlocking)
│           │   ├── KSafeCoreValues.kt        (convertStoredValue — cross-type dispatch)
│           │   ├── KSafeCoreCacheMerge.kt    (updateCacheOnce — snapshot → cache)
│           │   ├── KSafeCoreStartup.kt       (collector, one-time cleanup, prewarm, orphan sweep)
│           │   ├── KSafeCoreWriteConsumer.kt (coalescer loop, batch wrapper, rollback)
│           │   ├── KSafeCoreCommit.kt        (processWrites — dedup, encrypt fan-out, StorageOps)
│           │   ├── KSafeCorePutSuspend.kt    (write staging + suspend put/delete)
│           │   ├── KSafeCoreClearAll.kt      (performClearAll + the sibling-instance wipe)
│           │   ├── KSafeCoreFailureClassification.kt  (transient vs definitive decrypt failure)
│           │   └── KSafeCoreSupport.kt       (small shared helpers: clock, channel drain, backoff)
│           ├── KSafePlatformStorage.kt
│           ├── KSafeEncryption.kt
│           ├── KSafeEngineMessage.kt     (the engine↔core message protocol, spelled once)
│           ├── KSafeFactoryShared.kt     (KSafeReservedKeys, KSafeAliasGrammar, KSafeAliasFormat, shared factory logic)
│           ├── KSafeConcurrent.kt
│           ├── KSafeLog.kt               (expect: severity-routed diagnostic log)
│           ├── KSafeSecureRandom.kt
│           ├── KSafeSerializerUtil.kt
│           ├── KSafeHex.kt
│           ├── KSafeProtectionNotes.kt   (the protectionInfo `notes` vocabulary)
│           ├── KSafeSnapshotProtection.kt (user key → protection, off a raw snapshot)
│           ├── CorruptStoreSweep.kt      (quarantine naming + the clearAll sweep)
│           ├── NamespaceTokens.kt        (canonical appNamespace normalization)
│           ├── LegacyNamespaceTokens.kt  (the frozen pre-canonicalization spelling)
│           ├── SiblingRegistry.kt        (the live cores of one physical store)
│           ├── KeySafeMetadataManager.kt
│           ├── KeychainOrphanClassification.kt  (pure Apple-orphan decision — unit-testable)
│           └── SecurityChecker.kt
│
├── datastoreMain/                      (shared by Android + Apple + JVM)
│   └── …/internal/
│       ├── DataStoreStorage.kt
│       ├── DataStoreCommitRelay.kt      (the shared read side: `.data` merged with local commits)
│       ├── SharedStoreBackend.kt        (per-file storage/engine/scope sharing)
│       ├── StoreLocation.kt             (file naming + store identity)
│       ├── TransientRenameRetry.kt      (retries a store rewrite whose rename lost to another program)
│       └── KSafeLog.datastore.kt        (actual: `println` — the non-web target set)
│
├── jvmSharedMain/                      (shared by Android + JVM — the two JVM-bytecode targets)
│   └── …/internal/
│       ├── KSafeConcurrent.jvmShared.kt
│       ├── KSafeSecureRandom.jvmShared.kt
│       ├── JvmSharedCrypto.kt           (JvmAesGcm — the frozen AES-GCM layout)
│       ├── OneShotWarning.kt            (a degradation notice that prints once, on System.err)
│       └── CorruptStoreQuarantine.kt    (java.io half of the quarantine write + sweep)
│
├── androidMain/
│   ├── KSafe.android.kt                (top-level `fun KSafe(context, ...)` factory)
│   └── internal/
│       ├── AndroidKeystoreEncryption.kt
│       ├── AndroidLockScreen.kt         (API 28-34 unlock-binding relaxation + its persisted marker)
│       ├── WrappedDekStore.kt           (DataStore-backed wrapped-DEK slot — software-DEK fast path)
│       └── SecurityChecker.android.kt
│
├── appleMain/                          (shared by iosX64/iosArm64/iosSimulatorArm64 + macosX64/macosArm64)
│   ├── KSafe.apple.kt                  (top-level `fun KSafe(...)` factory)
│   ├── internal/
│   │   ├── AppleAesGcm.kt                  (frozen nonce(12)||ct||tag(16) framing over the CryptoKit bridge)
│   │   ├── AppleKeychainEncryption.kt
│   │   ├── KeychainOrphanCleanup.kt
│   │   ├── SimulatorKeychainFallback.kt    (Simulator sandbox-file store for errSecMissingEntitlement -34018)
│   │   ├── KSafeConcurrent.apple.kt
│   │   ├── KSafeSecureRandom.apple.kt
│   │   └── SecurityChecker.apple.kt
│   └── swift/
│       └── KSafeCryptoKitBridge.swift      (the bundled CryptoKit bridge the build compiles in;
│                                            its .def/.h live in ksafe/src/nativeInterop/cinterop/)
│
├── jvmMain/
│   ├── KSafe.jvm.kt                    (top-level `fun KSafe(...)` factory + test extensions)
│   └── internal/
│       ├── JvmSoftwareEncryption.kt
│       ├── DataStoreJsonStorage.kt      (no-`sun.misc.Unsafe` JSON storage fallback)
│       ├── JvmFallbackMigration.kt      (JSON-fallback → OS-backed forward migration)
│       ├── keyvault/                   (OS secret-store abstraction — JNA)
│       │   ├── JvmKeyVault.kt          (iface + DataStoreKeyVault + provider)
│       │   ├── WindowsDpapiKeyVault.kt
│       │   ├── MacosKeychainKeyVault.kt
│       │   ├── LinuxSecretServiceKeyVault.kt
│       │   ├── FileKeyVault.kt         (software vault for the no-`Unsafe` fallback)
│       │   └── KeyVaultFailures.kt     ("vault unavailable" — the protocol phrase, once)
│       └── SecurityChecker.jvm.kt
│
├── webMain/                            (shared by js + wasmJs)
│   ├── KSafe.web.kt                    (top-level `fun KSafe(...)` factory + awaitCacheReady ext)
│   └── internal/
│       ├── LocalStorageStorage.kt
│       ├── WebSoftwareEncryption.kt
│       ├── WebKeyStore.kt              (expect — SubtleCrypto + IndexedDB)
│       ├── WebKeyStoreJsSource.kt      (the IndexedDB/WebCrypto JS, written once for both targets)
│       ├── WebKeyStoreOps.kt           (the op tokens both bindings and the JS dispatcher share)
│       ├── WebInterop.kt               (expect — localStorage)
│       ├── WebNamespaceTokens.kt       (the frozen web appNamespace spelling)
│       ├── KSafeSecureRandom.web.kt    (the shared chunking; only the chunk copy is per-target)
│       ├── KSafeConcurrent.web.kt
│       └── SecurityChecker.web.kt
│
├── jsMain/…/internal/
│   ├── KSafeSecureRandom.js.kt
│   ├── KSafeLog.js.kt
│   ├── WebKeyStore.js.kt
│   └── WebInterop.js.kt
│
└── wasmJsMain/…/internal/
    ├── KSafeSecureRandom.wasmJs.kt
    ├── KSafeLog.wasmJs.kt
    ├── WebKeyStore.wasmJs.kt
    └── WebInterop.wasmJs.kt
```

Note what's *not* there anymore: `BiometricHelper.kt` used to live in `androidMain`. In 2.0 it moved to `:ksafe-biometrics`. The per-target `KSafeConcurrent.{android,jvm}.kt` and `KSafeSecureRandom.{android,jvm}.kt` pairs were byte-identical, so they collapsed into `jvmSharedMain`; `KSafeLog.{android,apple,jvm}.kt` were all the same `println` and collapsed into `datastoreMain`, whose target set (Android + Apple + JVM) is exactly the non-web one.

---

# Part 1 — `commonMain`: the public API

Everything in this section is visible to consumers. Import paths are `eu.anifantakis.lib.ksafe.*`.

## `KSafe.kt` — entry point

The single regular `class KSafe` that consumers instantiate, with all storage methods defined once.

**Key declarations:**

- `class KSafe @PublishedApi internal constructor(core, deviceKeyStorages, protectionInfoProvider, onClearAllCleanup)` — the public class. The constructor is `internal` so consumers always go through a per-platform factory function (see Part 4); they never see the raw `KSafeCore` they would have to build. `protectionInfoProvider: () -> KSafeProtectionInfo` is invoked on every read of the public `protectionInfo` property, and every shell passes a live closure rather than a fixed value: Android re-probes the lock screen and whether the current master was minted without its unlock binding, Apple re-checks whether the Simulator Keychain fallback has engaged, Web re-checks `crypto.subtle`, and JVM re-reads the engine's vault state so a runtime degrade shows on the next read. Only the values a shell *chooses between* are precomputed snapshots.
- Members defined once for every platform:
  - `val deviceKeyStorages: Set<KSafeKeyStorage>` — which tiers this device can hold keys in, never empty. Populated by the platform factory. What this instance is actually running at is `protectionInfo`.
  - `val defaultWriteMode: KSafeWriteMode` — the mode a `put` / `putDirect` without one uses: `Encrypted` at the `DEFAULT` tier with the instance's `requireUnlockedDevice`. Reads `core.defaultEncryptedMode()`.
  - `fun getKeyInfo(key): KSafeKeyInfo?` — protection tier and key custody for one key, or `null` if it doesn't exist. Forwards to `core.getKeyInfo`.
  - `fun deleteDirect(key)` / `suspend fun delete(key)` — async + suspend deletion. Forward to `core`.
  - `suspend fun clearAll()` — wipes the core, then runs `onClearAllCleanup`. Android, Apple and JVM all pass one: each deletes the `.corrupt` quarantine copies its corruption handler set aside, because those still hold decryptable ciphertext (and on Android the wrapped DEK too). JVM additionally sweeps the `<base>.ksafe*` JSON-fallback residue. The active `.preferences_pb` is deliberately left in place as an emptied store — `core.clearAll()` already wiped its contents, and a raw delete on the caller thread would race the write consumer.
  - `suspend fun rotateKeys(): KSafeRotationResult` (3.0.0+) — re-encrypts every entry under a fresh store-wide key generation. Whole-store, not per-key; forwards to `core.rotateKeys()`. See `KSafeRotationResult.kt` and the `KSafeCore` write-op discussion below.
  - `fun close()` — releases this instance's background coroutines so it can be collected, and on the DataStore targets drops its share of the per-file backend. Forwards to `core.cancel()`. Needed only when re-creating a `KSafe` mid-process; the instance is unusable afterwards.
  - `inline fun <reified T> getDirect/put/get/putDirect/getFlow(...)` — the public read/write surface. Each is a one-or-two-line member that calls `serializer<T>()` and forwards into the corresponding non-inline `core.*Raw(...)` method. Bodies live exactly once here in commonMain. `putDirect` has a third overload taking `onWriteFailed: (Throwable) -> Unit` — the only way a fire-and-forget caller hears that a background persist failed and the optimistic cache was rolled back.
  - Deprecated `encrypted: Boolean` overloads of all of the above — preserved for source compat; they delegate to the new `KSafeWriteMode`-parameterised forms.
  - `companion object { val VERSION }` — the published artifact version, also surfaced as `KSafeProtectionInfo.kSafeVersion`.
  - `@PublishedApi internal val core: KSafeCore` — the orchestrator. Exposed at this visibility because inline reified members and inline delegate factories need to reach it from consumer bytecode without a synthetic accessor on the hot path.
- `enum class KSafeMemoryPolicy` — `PLAIN_TEXT` (eager-decrypt-everything; discouraged due to cold-start cost), `ENCRYPTED` (decrypt every read), `ENCRYPTED_WITH_TIMED_CACHE` (TTL-bounded plaintext side cache), `LAZY_PLAIN_TEXT` (default; first read decrypts, plaintext cached permanently in the side cache).
- `getStateFlow(key, default, scope)` — extension that hooks `getFlow(...)` into `stateIn(scope, Eagerly, initial)` so consumers get a `StateFlow<T>` with a known synchronous initial value. Its non-inline half, `getStateFlowRaw`, uses `core.getFlowRaw` / `core.getDirectRaw` directly.

**What's *not* here anymore (compared to 1.x):**
- No `expect class KSafe` declaration. Construction lives in per-platform factory functions.
- No `*Raw` methods on `KSafe`. They live on `KSafeCore` only — the inline reified members forward to `core.getDirectRaw(...)` / `core.putDirectRaw(...)` etc. directly.
- No biometric methods — extracted to `:ksafe-biometrics`.
- No `BiometricAuthorizationDuration` data class — moved to `:ksafe-biometrics`.

**Why this shape:** making `KSafe` a regular common class lets the inline reified bodies live in one place. The platform-specific concerns (engine wiring, hardware detection, file paths) are all construction-time, so they live in factory functions in the platform source sets. The runtime call after inlining is one hop: `core.getDirectRaw(...)`.

## `KSafeConfig.kt` — instance configuration

Data class of instance-level knobs that users can pass to the `KSafe` factory.

**Key declarations:**

- `enum class KSafeAesKeySize { BITS_128, BITS_256 }` — the only accepted AES key
  strengths. AES-GCM itself remains deliberately fixed.
- `data class KSafeConfig(aesKeySize, requireUnlockedDevice, json, appNamespace, keyRotationPolicy, keyRotationRetryAttempts)`.
- `aesKeySize: KSafeAesKeySize = BITS_256` — used whenever any platform creates a new
  key. An existing generation retains its inherent size until `rotateKeys()` replaces it.
- `object KSafeDefaults { val json }` — the default `Json` instance (`ignoreUnknownKeys = true`, `allowSpecialFloatingPointValues = true`, so `NaN` and `±Infinity` round-trip through an encrypted write as they already do through a plain one), used when the caller doesn't supply their own. `Json` is declared `api` in the build script so consumers can pass a custom one without declaring `kotlinx-serialization-json` themselves.
- `appNamespace: String? = null` — per-app isolation for the **JVM/Desktop and Web** key store. Android and iOS keystores are already OS-sandboxed per app; the desktop OS secret store (macOS Keychain, Linux Secret Service) is **per-OS-user and shared by every process**, and Web IndexedDB/localStorage is shared within an origin. Without a namespace, two apps using the same `fileName` reach the same key.

  | Setting | JVM key store | JVM data directory | Web |
  |---|---|---|---|
  | `appNamespace = "com.acme.app"` | that namespace | a subdirectory of the same name; existing un-namespaced data is copied forward | that namespace |
  | `appNamespace = null` | the fixed default `"shared"` — **two apps sharing a `fileName` collide** | the base directory | the browser origin |
  | `-Dksafe.appNamespace=` / env `KSAFE_APP_NAMESPACE` | that namespace | **unchanged** — the override does not move data | n/a |

  Setting an explicit `KSafeConfig.appNamespace` is the reliable option. The old launcher-derived id is no longer a default and survives only as a read-side migration source, and the system property is a recovery lever rather than a configuration one. Keys written by KSafe ≤ 2.0 still migrate unchanged.
- `keyRotationPolicy: KSafeKeyRotationPolicy = KSafeKeyRotationPolicy.Never` (3.0.0+) — when to start a **fresh** rotation automatically. `Never` (default) means fresh rotations are on-demand only (`ksafe.rotateKeys()`); `MaxAge(Duration)` runs one background age check shortly after startup. Since 3.1.0, finishing a pass the application already started is independent of this policy — see the lifecycle table under `rotateKeys` in Part 2 for the states and who acts on them. None of these paths blocks startup or reads. See `KSafeKeyRotationPolicy.kt`.
- `keyRotationRetryAttempts: Int = 3` (3.1.0+) — bounded automatic attempts for normally completed passes that left retryable `skipped` entries. One newly created KSafe instance consumes at most one attempt; `0` disables this path. The remaining count is persisted and decremented before work, so a crash never refills it. Definitive `failed` entries do not arm the budget.

**Why:** centralises the "things you configure once at construction time" — typed key strength, the default unlock policy, the `Json` instance for `@Serializable` types, the app namespace that keeps one app's desktop/web keys from colliding with another's in the shared per-user secret store, and the automatic key-rotation/retry policy. Separating config into its own class keeps the factory signatures readable, and it lets users swap in a `Json` with `@Contextual` serializers for `UUID`, `Instant`, etc.

## `KSafeKeyRotationPolicy.kt` — when to auto-rotate (3.0.0)

Sealed interface selecting the automatic key-rotation schedule; the value of `KSafeConfig.keyRotationPolicy`.

**Key declarations:**

- `sealed interface KSafeKeyRotationPolicy`:
  - `data object Never` — the default. No automatic **new** generation; rotate on demand with `ksafe.rotateKeys()`. Since 3.1.0, an interrupted pass still resumes and a completed-with-skips pass can still consume its bounded retry under `Never` — neither creates another generation. See the lifecycle table under `rotateKeys` in Part 2.
  - `data class MaxAge(val maxAge: Duration)` — a background check runs once shortly after startup; if the current key generation is older than `maxAge` (measured from the last rotation, or from the first launch under this policy for a never-rotated store), a full rotation is scheduled on the background scope. `init` requires a positive `maxAge`.

**Why:** key material on every KSafe platform is hardware- or OS-protected and doesn't expire, so starting fresh generations automatically is an opt-in hygiene/compliance policy rather than a security necessity — hence `Never` by default. Repairing a pass the application already started is a lifecycle guarantee, not a policy choice, so it runs under `Never` too. The work stays in the background; entries a pass normally reports `skipped` remain readable and, since 3.1.0, can arm a bounded next-instance retry budget. `failed` alone does not arm that retry.

## `KSafeRotationResult.kt` — outcome of a rotation pass (3.0.0)

`data class KSafeRotationResult(rotated, skipped, failed, keyGeneration)` — what `rotateKeys()` returns.

- `rotated` — entries re-encrypted under the new generation.
- `skipped` — entries left on their previous generation this pass: a strict (`requireUnlockedDevice`) entry while the device is locked, or an entry a concurrent write superseded mid-rotation (the newer write wins). A transient key-store outage counts here, not as `failed`.
- `failed` — entries whose decrypt or re-encrypt failed outright.
- `keyGeneration` — the store's generation after the pass; new writes encrypt under it.

**Why:** rotation is not all-or-nothing. A `skipped` entry keeps decrypting under the generation recorded in its own metadata (that key is retained until nothing references it), so a partial pass leaves a readable mixed-generation store rather than a broken one. Since 3.1.0 the store records what the pass achieved, and the next KSafe instance finishes the job — see the lifecycle table under `rotateKeys` in Part 2.

## `KSafeWriteMode.kt` — how writes are parameterised

Sealed interface describing the three ways to write a value.

**Key declarations:**

- `sealed interface KSafeWriteMode`:
  - `data object Plain` — unencrypted.
  - `data class Encrypted(protection = DEFAULT, requireUnlockedDevice = false)` — everything else.
- `enum class KSafeEncryptedProtection { DEFAULT, HARDWARE_ISOLATED }` — only the encrypted write needs a protection tier; `Plain` can't have one.
- `internal fun KSafeWriteMode.toProtection(): KSafeProtection?` — maps the mode to the tier stored in metadata.

**Why:** "`encrypted: Boolean` + `protection: KSafeProtection` + `requireUnlockedDevice: Boolean`" was the old shape and it allowed nonsense combinations like "plain write with `HARDWARE_ISOLATED`". Modelling writes as a sealed hierarchy makes invalid combinations unrepresentable.

## `KSafeModeViews.kt` — write modes frozen into a type (3.1.0)

Three thin wrappers over an existing `KSafe` that fix the write mode at construction, so a call site has no `mode` argument left to get wrong.

**Key declarations:**

- `class KSafePlain(ksafe)`, `class KSafeEncrypted(ksafe, requireUnlockedDevice = …)`, `class KSafeHardwareIsolated(ksafe, requireUnlockedDevice = …)` — each exposes a `val mode` and the whole write surface with the mode already applied: `put` / `putDirect` (including the `onWriteFailed` overload), `invoke` (so `var flag by view(false)` works, returning a `KSafeReference`), `asFlow` / `asWritableFlow` / `asStateFlow` / `asMutableStateFlow`. The mode-free members — `get` / `getDirect` / `getFlow` / `getStateFlow` / `delete` / `deleteDirect` — are forwarded unchanged for convenience. The two encrypted views also freeze the unlock policy, defaulting to the instance's own, so a default-constructed view writes exactly like a modeless `ksafe.put`.
- `val KSafe.plain` / `val KSafe.encrypted` / `val KSafe.hardwareIsolated` — one-line accessors returning a fresh view each time.

**Why write-side only:** reads carry no mode at all — each entry's protection is auto-detected from its metadata — so a view's `get` returns values any other handle wrote, in whatever mode. Store-wide operations (`rotateKeys`, `clearAll`, `close`, `protectionInfo`, `getKeyInfo`, `getOrCreateSecret`) are deliberately absent from the views; each exposes its instance as `val ksafe` for those. All views over one instance share its file, key namespace and cache.

## `KSafeProtection.kt` — encryption tier tags

A two-valued enum used throughout the internals.

Protection tiers are spelled in four overlapping vocabularies across this and the next two sections: `KSafeEncryptedProtection` (what a write asks for), `KSafeProtection` (what got recorded), `KSafeKeyStorage` (the legacy three-value answer) and `KSafeProtectionLevel` (the ordered answer). `KSafeProtectionLevel.kt` / `KSafeProtectionInfo.kt` below walks one write through all four.

**Key declarations:**

- `enum class KSafeProtection { DEFAULT, HARDWARE_ISOLATED }` — also `null` for "plaintext", which is why nearly every function signature uses `KSafeProtection?`.

**Why:** single source of truth for the protection tags that (a) get serialised into per-key metadata on disk, and (b) feed `KSafeKeyInfo.protection`. Kept separate from `KSafeWriteMode` because reads don't have a "mode" — the tier is auto-detected from metadata.

## `KSafeKeyStorage.kt` / `KSafeKeyInfo.kt` — "where does this key actually live?"

Two small files that together form the `getKeyInfo(key)` API surface.

- `enum class KSafeKeyStorage { SOFTWARE, HARDWARE_BACKED, HARDWARE_ISOLATED }` — the actual backing store, which may be different from the *requested* tier on a device that lacks the hardware. E.g. a `HARDWARE_ISOLATED` write on a phone without StrongBox/Secure Enclave silently lands in `HARDWARE_BACKED`.
- `data class KSafeKeyInfo(protection: KSafeProtection?, storage: KSafeKeyStorage, level: KSafeProtectionLevel, keyGeneration: Int = 1)` — what `ksafe.getKeyInfo("my_key")` returns. `storage` is the legacy three-value vocabulary (now `@Deprecated` in favour of the finer-grained `level` on the universally-ordered `KSafeProtectionLevel` scale); `keyGeneration` (3.0.0+) is which key generation decrypts this entry — `1` for a never-rotated entry, higher after `rotateKeys()`, always `1` for plaintext.

**Why:** honesty. A caller who wrote with `HARDWARE_ISOLATED` may want to tell the user "stored in hardware-isolated chip" — but only if that's what actually happened. `getKeyInfo` lets the UI reflect reality instead of hardcoding assumptions.

## `KSafeProtectionLevel.kt` / `KSafeProtectionInfo.kt` — the ordered answer, per entry and per instance

Where the encryption **key** lives after runtime negotiation. Both files describe the key, never the payload — the payload is always AES-GCM.

**Key declarations:**

- `enum class KSafeProtectionLevel { SOFTWARE, SANDBOX_PROTECTED, HARDWARE_BACKED, HARDWARE_ISOLATED }` (2.1.0+) — one scale, ordered the same way on every platform: a higher ordinal is harder to recover the key from. `SOFTWARE` = key bytes in a plain file behind OS permissions; `SANDBOX_PROTECTED` = protected by the surrounding sandbox (a browser origin, or an OS user account via DPAPI / login Keychain / libsecret); `HARDWARE_BACKED` = on-chip secure hardware; `HARDWARE_ISOLATED` = a separate security chip. Reported per entry as `KSafeKeyInfo.level` and per instance inside `KSafeProtectionInfo`.
- `data class KSafeProtectionInfo(intendedLevel, effectiveLevel, custody, notes, kSafeVersion)` (2.1.0+) — what `ksafe.protectionInfo` returns, about the **instance**, not any one entry. `intendedLevel` is the platform's baseline target and is never `HARDWARE_ISOLATED` (that level is reached per write, not as a baseline); `effectiveLevel` is what was actually negotiated, so the two differing means "weaker than intended", not "broken". `custody` is a human-readable sentence — safe to log, never parse. `notes` are stable `lowercase_snake` codes (`android_strongbox_absent`, `apple_secure_enclave_absent`, `jvm_os_vault_degraded`, `web_crypto_subtle_unavailable`, …); new codes may appear, so ignore unknown ones.
- `val isEncryptionOperational: Boolean` (3.0.0+) — computed from `notes`: `false` only for a code that marks the engine unable to encrypt or decrypt at all (`web_crypto_subtle_unavailable`, `jvm_os_vault_degraded`). A weaker-but-working fallback still reads `true`.

**One write through all four vocabularies.** `putDirect("token", v, KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))` on an Android phone with no StrongBox records `KSafeProtection.HARDWARE_ISOLATED` in the entry's metadata — that is what the write *asked for*, and it is what a later rotation must reproduce. But `getKeyInfo("token")` answers `storage = HARDWARE_BACKED` and `level = HARDWARE_BACKED`, because that is where the key actually landed. `ksafe.protectionInfo` describes the instance rather than the entry, and carries `android_strongbox_absent` in its `notes`.

**Why two answers:** `KSafeKeyStorage` is the older three-value vocabulary and cannot express "sandbox-protected", which is the honest answer on JVM and web. `KSafeProtectionLevel` was added beside it rather than replacing it, so existing `getKeyInfo` callers keep compiling.

## `KSafeSecurityPolicy.kt` — runtime security checks

Per-instance declaration of what the library should do on detecting a rooted device, a debugger, a debug build, or an emulator.

**Key declarations:**

- `data class KSafeSecurityPolicy(rootedDevice, debuggerAttached, debugBuild, emulator, onViolation)` — each check is a `SecurityAction` (`IGNORE` / `WARN` / `BLOCK`). Three preset companion values: `Default` (all `IGNORE`), `Strict` (`BLOCK` on root/debugger, `WARN` on debug/emulator), `WarnOnly` (everything `WARN`).
- `enum class SecurityViolation { RootedDevice, DebuggerAttached, DebugBuild, Emulator }`.
- `class SecurityViolationException` — thrown when a `BLOCK` check fails.
- `internal fun validateSecurityPolicy(policy: KSafeSecurityPolicy)` — runs the checks at `KSafe` construction by delegating to the platform-specific `SecurityChecker` object.

**Why:** a consumer can opt into bank-app behaviour (`BLOCK` on root) without the library forcing that choice on everyone. Checks run *once* at construction because root/debugger detection is expensive and defeated by determined attackers anyway — it raises the floor, not the ceiling.

## `KSafeReference.kt` — the handle `ksafe(default, key)` returns

**Key declaration:**

- `class KSafeReference<T>` (3.2.0+) — what `ksafe(default, key)` returns, and what backs `by ksafe(default)`. It implements `ReadWriteProperty`, so `var token by ksafe("")` works and the delegated property's *name* becomes the storage key. Kept in a `val` instead, its `value` property reads and writes the store — and then the explicit `key` is required, because a plain assignment carries no property name Kotlin could supply. `.value` on a key-less handle throws `IllegalStateException` with a message saying exactly that. Reads go to `ksafe.core.getDirectRaw`, writes to `ksafe.core.putDirectRaw` in the `KSafeWriteMode` captured when the handle was created.

```kotlin
var counter by ksafe(0)          // delegate: the property name becomes the key
counter++

val hits = ksafe(0, key = "hits")  // handle: the key must be explicit
hits.value++
```

**Why it's public:** a handle can be injected, held in a field, and passed around, not only used with `by`. The mode-typed views' `invoke` (`ksafe.encrypted(…)`, see `KSafeModeViews.kt`) returns the same type with their frozen mode.

## `KSafeDelegate.kt` — `var counter by ksafe(0)` and friends

The layer above the public `get`/`put` API that lets a stored value be used as an ordinary `var`, a `Flow`, or a `MutableStateFlow`.

**Key declarations:**

- `inline operator fun <reified T> KSafe.invoke(defaultValue, key = null, mode = core.defaultEncryptedMode()): KSafeReference<T>` — the factory that makes both `by ksafe(0)` and `ksafe(0, key = "counter")` work. A deprecated `encrypted: Boolean` form forwards to it, but is declared as returning the plain `ReadWriteProperty`, so `.value` is out of reach through that one — it is a `by` delegate only.
- Four observer-side extensions, each returning a `ReadOnlyProperty` so they are used with `by`:
  - `asFlow(defaultValue, key = null)` — a cold `Flow<T>` of the value and its updates.
  - `asWritableFlow(defaultValue, key = null, mode = core.defaultEncryptedMode())` — a `WritableKSafeFlow<T>`: collect it to observe, call `set(v)` to persist. Needs no scope, since the flow is cold and the write is fire-and-forget.
  - `asStateFlow(defaultValue, scope, key = null)` — the hot `StateFlow<T>` of `getStateFlow`, shared eagerly in `scope`.
  - `asMutableStateFlow(defaultValue, scope, key = null, mode = core.defaultEncryptedMode())` — a full `MutableStateFlow<T>` persisted through KSafe; drops into the canonical `_state` / `state` pattern.
- `class WritableKSafeFlow<T>` — the only other public type in the file: it delegates `Flow<T>` to the source flow and adds `set`. There is deliberately no synchronous getter, because on web a read before the cache has loaded would answer the default.
- The classes behind those extensions — `KSafeFlowDelegate`, `KSafeWritableFlowDelegate`, `KSafeStateFlowDelegate`, `KSafeMutableStateFlowDelegate`, and the `MutableStateFlow` implementation `KSafeMutableStateFlow` — are all `@PublishedApi internal`: reachable from the inline factories' bytecode, never from consumer source.
- `class KSafeDelegate<T>` is `@PublishedApi internal` and superseded by `KSafeReference`. It is kept so code compiled against older releases keeps linking; nothing in the library calls it.

**Why the flow delegates stay internal:** nobody needs to name them — each extension's return type is the Kotlin interface (`ReadOnlyProperty<Any?, Flow<T>>` and friends), so the implementation class never appears in consumer source.

**Why they talk to `core` directly:** they hold a non-reified `KSerializer<T>` captured at creation time, so they can't go through the inline reified `KSafe.getDirect(...)` API. They call `ksafe.core.getDirectRaw` / `core.putDirectRaw` — one hop fewer than the `KSafe` member layer, which exists only for the reified-T entry point.

## `KSafeSecret.kt` — `getOrCreateSecret`

A single extension function added in 1.8.0 that embodies the library's architecture as a one-liner.

**Key declaration:**

- `suspend fun KSafe.getOrCreateSecret(key = "main_db", size = 32, protection = HARDWARE_ISOLATED, requireUnlockedDevice = false): ByteArray` — retrieves a stored secret if it exists, otherwise generates a cryptographically-random one (via `secureRandomBytes` from the internal package) and persists it. Every parameter has a default, `key` included.

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
  - `suspend fun applyBatch(ops: List<StorageOp>)` — batched write, atomic on the DataStore backends; the web localStorage adapter orders metadata-before-value and rolls back synchronous failures, but is not crash-atomic. The write-coalescer batches bursts within a 16 ms window, which it skips entirely when a caller is awaiting the commit — see `startWriteConsumer` below.
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
  - Blocking `encrypt` / `decrypt` / `deleteKey` — original contract. Android/iOS/JVM implement these directly. `encrypt` / `decrypt` take a trailing `aad: ByteArray? = null` (3.0.0+) — *associated data*: bytes that travel in the clear but are covered by the AES-GCM authentication tag, so decryption must present exactly the same bytes or it fails. KSafe puts the entry's routing (which store, which key, which tier, which generation) in there, so ciphertext copied to another key or another store fails to open instead of decrypting into the wrong place. `KSafeCore` passes the v3 AAD from `KeySafeMetadataManager.aadFor(...)` for generation ≥ 2 entries and `null` otherwise, so v2 ciphertext stays byte-compatible.
  - Suspend `encryptSuspend` / `decryptSuspend` / `deleteKeySuspend` — default bodies delegate to the blocking variants (forwarding `aad`). `WebSoftwareEncryption` overrides these with real WebCrypto calls (and keeps the blocking variants throwing `UnsupportedOperationException`).
  - `updateKeyAccessibility(identifier, requireUnlocked)` — default no-op. Only the Apple engine actually implements it — on iOS and macOS alike, since both share `appleMain` — to move keys between Keychain accessibility tiers via `SecItemUpdate`.
  - `onStoreCleared()` — default no-op; a hook `clearAll()` calls so an engine can drop in-memory key/DEK caches (Android's software-DEK engine uses it).
  - `prewarmKey(...)` / `prewarmDekReadIfPresent(...)` — give an engine a chance to warm its key/DEK off the caller (potentially UI) thread. `prewarmKey`'s default body is a throwaway encrypt of empty bytes, which is enough to mint the key; the Android engine overrides it to create only the wrapping KEK, never a DEK, so a safe with no encrypted entries writes nothing. `prewarmDekReadIfPresent` defaults to a genuine no-op and reads an existing DEK only, never creating or persisting one.
  - `migrateLegacyKeysSuspend()` — default no-op; the startup legacy-key sweep (see `startBackgroundCollector`).

**Why both blocking and suspend:** Android/iOS/JVM crypto is synchronous and integrates cleanly with `Cipher.init(...)`-style APIs. Web's WebCrypto is Promise-based — there's no way to call it blockingly. Rather than break the Android/iOS/JVM engines by forcing them into suspend-everywhere, the interface provides both and `KSafeCore` prefers `*Suspend` from every coroutine-context code path (write coalescer, preload, updateCache). The one remaining blocking decrypt site is `resolveFromCache` (called from sync `getDirect`), and web avoids it by running exclusively in `PLAIN_TEXT` memory policy where the cache holds pre-decrypted strings.

## `KSafeCore.kt` and the `coreparts` package — the orchestrator

The big one. Takes a `KSafePlatformStorage`, a `KSafeEncryption`, a `KSafeConfig`, and a few platform-callable lambdas; exposes the `*Raw` methods that `KSafe` (and the property delegates, and `getStateFlow`) forward into.

`KSafeCore.kt` holds the class itself — constructor, state, the `PendingWrite` hierarchy, the read/write entry points and the companion's alias/AAD primitives. The rest of its behaviour is spread across the files of the **`internal.coreparts` sub-package**, as extension functions on `KSafeCore`:

| File | What it holds |
|---|---|
| `KSafeCoreRouting.kt` | alias + AAD derivation per entry, and the one `decryptEntry` (plus a blocking twin) that bundles the envelope-version check, alias resolution, the gated AAD and the legacy-identity retry |
| `KSafeCoreRead.kt` | `resolveFromCache`, `ensureCacheReadyBlocking` |
| `KSafeCoreValues.kt` | `convertStoredValue` |
| `KSafeCoreCacheMerge.kt` | `updateCacheOnce` — the snapshot→cache merge |
| `KSafeCoreStartup.kt` | `prewarmMasterKeys`, `startBackgroundCollector`, `runOneTimeStartupCleanup`, `cleanupOrphanedCiphertext` |
| `KSafeCoreWriteConsumer.kt` | `startWriteConsumer`, `processBatch` / `processBatchBody`, optimistic rollback |
| `KSafeCoreCommit.kt` | `processWrites` — dedup, parallel encrypt, `StorageOp` building, the rotation CAS |
| `KSafeCorePutSuspend.kt` | write staging (`stagePlainWrite` / `stageEncryptedWrite` / `stageDelete`, shared by the fire-and-forget and the awaiting paths) plus `putPlainSuspend` / `putEncryptedSuspend` |
| `KSafeCoreClearAll.kt` | `performClearAll`, and `onSiblingClearAll` — how a wipe reaches every other live instance on the same file |
| `KSafeCoreFailureClassification.kt` | `isTransientDecryptFailure` / `isRotationRetryable` (top-level, not members) |
| `KSafeCoreSupport.kt` | small shared helpers — epoch clock, channel drain, collector backoff |

`KSafeCore` itself stays in `internal` while its parts moved down into `internal.coreparts`. That asymmetry is deliberate. `@PublishedApi internal` means: invisible to consumer *source*, but present in the compiled artifact, because a public `inline` function's body is copied into the caller and must still be able to name what it touches — which makes such a declaration part of the binary contract even though nobody can import it. `KSafeCore` is `@PublishedApi internal` and appears in the published ABI — `KSafe`'s public inline functions bake its fully-qualified name into consumer bytecode — so moving it into a sub-package would be a runtime break for apps compiled against 2.2.x. The parts are plain `internal`, appear in neither ABI dump, and move freely.

**Constructor parameters worth highlighting:**

- `storage: KSafePlatformStorage` — exposed as `@PublishedApi internal val` so platform extensions in jvmMain can reach into the underlying `DataStore` for whitebox tests.
- `engineProvider: () -> KSafeEncryption` — a provider, not the engine itself, so a `testEngine` can be slotted in by the platform factory before the engine is first dereferenced. The lazy property `engine` materialises it once, exposed as `@PublishedApi internal val` for the same test-extension reason as `storage`.
- `resolveKeyStorage: (userKey, protection, engineAlias) -> KSafeKeyStorage` (and its `resolveKeyLevel` twin, same shape) — Android inspects the Keystore for StrongBox; Apple answers from the Secure Enclave presence its factory probed at construction; JVM and web report a sandbox tier, degraded to `SOFTWARE` when the OS vault is unavailable or `crypto.subtle` is absent. `engineAlias` is the alias the entry's *recorded* envelope decrypts under (null for plain entries), so a shell that can inspect the live key reports its actual custody instead of inferring from the requested tier. Both come from one `KSafeKeyTier` answer per shell, projected into the two vocabularies.
- `migrateAccessPolicy: suspend (isUserKeyDirty: (String) -> Boolean) -> Unit = {}` — runs once after the first `snapshotFlow` emission (so the cache is populated before the lambda fires). The Apple-platform factory uses it to call the standalone `cleanupOrphanedKeychainEntries` helper, passing the dirty-key predicate so the sweep can't reap a key whose write is still in flight; Android, JVM and web pass the default no-op.
- `keyAlias: (userKey) -> String` — exposed `@PublishedApi internal` because tests reach for it to reconstruct the disk-side alias for whitebox assertions. Android and Apple: `"eu.anifantakis.ksafe[.<fileName>].<key>"`. JVM and web: `"[<fileName>:]<key>"`. Both spellings come from `KSafeAliasFormat` in `KSafeFactoryShared.kt`, never from a local string in the shell.
- `masterAlias: (requireUnlockedDevice) -> String` — the counterpart to `keyAlias`: the shared key a v2 `DEFAULT` entry encrypts under. `HARDWARE_ISOLATED` entries use `keyAlias` instead. Android and Apple return two distinct aliases (`__ksafe_master__` / `__ksafe_master_locked__`), one per unlock policy; JVM and web have no device lock, so both policies collapse onto the one `__ksafe_master__`.
- `storeIdentity` / `fallbackStoreIdentity` — the store's stable, home-relative identity that the v3 AAD binds ciphertext to, plus the older spelling a decrypt retries under before giving up. Home-relative rather than absolute because the container path moves (an iOS app update, Android adoptable storage) while the keys survive.
- `commitMutex: Mutex` — supplied by the shared per-file backend, so two cores on one physical file cannot interleave each other's snapshot → commit sequence.
- `legacyEncryptedPrefix` / `legacyEncryptedKeyFor` — pre-1.8 iOS overrode these to read entries written under `"{fileName}_{key}"`.
- `modeTransformer: (KSafeWriteMode) -> KSafeWriteMode = { it }` — applied at the top of `putDirectRaw` and `putRaw`. Android and Apple both pass the shared `promoteDefaultToIsolated(mode, enabled)`, bound to the deprecated `useStrongBox` / `useSecureEnclave` flag respectively (the two used to be identical local `promoteMode` helpers). Web passes one too, clearing `requireUnlockedDevice` on an encrypted write — a strict entry routes to a blocking decrypt WebCrypto cannot serve, so keeping the flag would make the value unreadable. Only JVM passes the identity default. This is what made it possible to remove `*Raw` trampolines from the platform shells in 2.0.
- `onCancel: () -> Unit = {}` — run from `cancel()`, which `KSafe.close()` calls. The three DataStore targets release their share of the per-file backend here; web passes the default no-op.

**Key state:**

- `memoryCache: KSafeConcurrentMap<Any>` — the hot cache. Stores plaintext in `PLAIN_TEXT` mode, Base64 ciphertext in `ENCRYPTED` / `ENCRYPTED_WITH_TIMED_CACHE` / `LAZY_PLAIN_TEXT`. Keyed by the *cache key*: user key for plain entries, `"encrypted_<key>"` for encrypted ones — except on Apple platforms with a non-null `fileName`, where pre-1.8 builds used `"{fileName}_{key}"` and KSafeCore still recognises that legacy form via the `legacyEncryptedKeyFor` constructor parameter.
- `protectionMap: KSafeConcurrentMap<String>` — per-user-key protection literal, populated from `__ksafe_meta_*__` entries on disk.
- `encMetaMap: KSafeConcurrentMap<EncMeta>` — per-encrypted-key routing record: envelope version, unlock policy, key generation, and whether the entry uses the strict alias variant. Plain entries are never present. This is what the read path resolves an alias and an AAD from, so an entry whose record disagrees with what is on disk reads back as the caller's default — the first place to look for a "reads back as its default" bug.
- `plaintextCache: KSafeConcurrentMap<CachedPlaintext>` — secondary plaintext cache used by `ENCRYPTED_WITH_TIMED_CACHE` (TTL-bounded) and `LAZY_PLAIN_TEXT` (permanent — TTL check is short-circuited). Filled lazily on first read of each key.
- Two predicates derived from `memoryPolicy` at construction: `cacheHoldsCiphertext` (true for `ENCRYPTED`/`ENCRYPTED_WITH_TIMED_CACHE`/`LAZY_PLAIN_TEXT`) and `usesPlaintextSideCache` (true for `ENCRYPTED_WITH_TIMED_CACHE`/`LAZY_PLAIN_TEXT`). The cache layer branches on these, not on individual policy values, so adding a new policy is one enum entry plus the predicate updates. (They are `internal` rather than `private` only because the `coreparts` files above read them.)
- `cacheInitialized: KSafeAtomicFlag` — cold-start signal.
- `dirtyKeys: KSafeConcurrentSet<String>` — keys with in-flight writes; the background collector refuses to stomp these.
- `writeChannel: Channel<PendingWrite>` — unbounded queue feeding the coalescer. `PendingWrite` has eight variants: the three user writes (`Plain`, `Encrypted`, `Delete`), whose `completion: CompletableDeferred<Unit>?` is null for fire-and-forget `putDirect` / `deleteDirect` and non-null for the suspend `put` / `delete` that await the disk commit; the four rotation/lifecycle ops (`Rotate`, `SetKeyGeneration`, `CompleteKeyRotation`, `SweepSupersededMasters`), which always carry one because their issuers always await; and `ClearAll`, handled as a batch boundary. Every variant carries a `writeToken` — the identity the rollback checks before undoing an optimistic cache change — and the two put variants carry the optional `onWriteFailed` callback.
- `hasAnyEncryptedKey: KSafeAtomicFlag` — monotonic; flips true the first time an encrypted write is seen (in `processBatch`, `putEncryptedSuspend`, or during `updateCache` classification). When false, `detectProtection` short-circuits the `protectionMap` lookup, so plain-only stores pay zero per-read overhead for the auto-detect feature.
- `currentKeyGeneration: KSafeAtomicInt` (3.0.0+) — the store-wide key generation new writes encrypt under (`1` until the first rotation). Bumped by `rotateKeys()` and kept in sync from the persisted `KeySafeMetadataManager.KEYGEN_RAW_KEY` entry on every snapshot merge, so a co-existing instance's rotation propagates here. Each entry's alias generation comes from its *own* recorded metadata, never the store's current value — a not-yet-rotated entry keeps decrypting under its old generation.

**Key methods:**

- `defaultEncryptedMode(): KSafeWriteMode` — `KSafeWriteMode.Encrypted(requireUnlockedDevice = config.requireUnlockedDevice)`. Used by the no-mode `put`/`putDirect` overloads on `KSafe`. Lives on `KSafeCore` (not `KSafe`) because it reads `config`, which is a `KSafeCore` constructor param.
- `startBackgroundCollector()` — launches the collector coroutine that subscribes to `storage.snapshotFlow()`. Every emission refreshes the cache through `updateCache(snapshot)`; on the **first emission only**, and *after* that merge has populated the cache, `runOneTimeStartupCleanup()` runs four steps in order:

  1. `migrateAccessPolicy()` — the per-platform hook. Apple passes the Keychain orphan sweep here; Android, JVM and web pass a no-op.
  2. `cleanupOrphanedCiphertext()` — reclaims ciphertext whose key is definitively gone.
  3. `engine.migrateLegacyKeysSuspend()` (2.1.0+) — sweeps any remaining pre-2.1 raw keys out of weak locations (the JVM DataStore file, web localStorage) into the secure store. A no-op where there is no safer destination (software fallback, opt-out).
  4. `maybeScheduleKeyRotation()` (3.0.0+) — reads the `__ksafe_keygen__` lifecycle record and decides whether to resume, retry, or start a rotation. See the lifecycle table under `rotateKeys` below for the states.

  All of it is background work; none of it blocks startup or reads. A `lazyLoad` instance has no collector, so the same cleanup is triggered on first access instead, guarded by `startupCleanupDone`.

  **The "first emission first" ordering is load-bearing on Apple.** `migrateAccessPolicy` there is `cleanupOrphanedKeychainEntries`, which reads `storage.snapshot()` to decide which Keychain entries are orphaned. Run before DataStore's first emission, it would see an empty snapshot during the 1.x → 2.0 path-migration window and destroy every Secure Enclave EC private key in the store. See the `### Fixed` block in CHANGELOG 2.0.0 for the walk-through; `KSafeCoreStartupOrderingTest` in `jvmTest` locks the order in.
- `suspend updateCache(snapshot)` — the workhorse that merges an on-disk snapshot into `memoryCache`. Handles dirty-key skipping, legacy-format classification (via `KeySafeMetadataManager.classifyStorageEntry`), and — only when `cacheHoldsCiphertext` is false (i.e. the explicit `PLAIN_TEXT` policy or the Web-forced equivalent) — decrypts every encrypted entry through `engine.decryptSuspend`. Two-pass structure: classification + plain entries + ciphertext stashing run sequentially (they mutate `validCacheKeys` and `protectionByKey`); the bulk-decrypt pass for `PLAIN_TEXT` is deferred into a `pendingDecrypts` list and flushed concurrently inside a `coroutineScope { … }` with a `Semaphore(8)` cap. Under the new default `LAZY_PLAIN_TEXT` (and under `ENCRYPTED` / `ENCRYPTED_WITH_TIMED_CACHE`), this pass is skipped entirely — encrypted entries land in the cache as ciphertext and decryption is deferred to read time. Skipping that pass is what makes the default policy's cold start independent of how much ciphertext the store holds: nothing is decrypted until a key is actually read. For measured cold-start figures see **[docs/BENCHMARKS.md](BENCHMARKS.md)**.
- `startWriteConsumer()` — the coalescer coroutine. Two-phase loop: (1) `receive()` the first write to suspend until something arrives, then **greedy-drain** via `tryReceive()` until the channel is empty or `maxBatchSize` is reached — this coalesces a burst into batches of up to `maxBatchSize` (200) writes instead of one `applyBatch` per `receive()`; a burst larger than 200 splits into successive 200-op batches; (2) **conditional 16 ms window** that opens *only* when no write in the current batch has a `completion`. If even one caller is awaiting their commit, the window is skipped and the batch flushes immediately. The window also exits early the moment a write with a `completion` arrives mid-window. Net effect: a single sequential `ksafe.put(...)` completes in roughly one `applyBatch` round-trip; bursty `putDirect` traffic still coalesces into one transaction per frame.
- `processBatch(batch)` — wraps `processBatchBody(batch)` in a try/catch so that the `CompletableDeferred`s of any awaiting callers always resolve: `complete(Unit)` on success, `completeExceptionally(failure)` on a thrown error (which is then re-raised so `startWriteConsumer`'s `runCatching` can log it), and `cancel(e)` on `CancellationException` (re-thrown to honour structured concurrency). Without this wrapper, a thrown error in the body would leave every awaiting `suspend put` caller hanging forever.
- `processBatchBody(batch)` — splits the batch at the last `ClearAll` (everything before it is wiped by `performClearAll`, only later writes survive), then hands the remainder to `processWrites`.
- `processWrites(batch)` (in `KSafeCoreCommit.kt`) — the actual work. Deduplicates the batch by user-key across ALL write types (plain, encrypted, delete, rotate) — building a `finalByKey` map that keeps the last pending write per key, with a Rotate never displacing a same-batch user write — then encrypts the surviving encrypted writes concurrently via `coroutineScope { batch.map { async { gate.withPermit { engine.encryptSuspend(...) } } }.awaitAll() }` with a `Semaphore(8)` cap — hardware-keystore IPC pipelines instead of running serially. Then builds the full `List<StorageOp>` (including metadata + legacy-key deletes) iterating the deduplicated `finalByKey.values` so each surviving key emits its cleanup deletes and last-applied-wins is preserved, calls `storage.applyBatch(ops)`, then deletes removed keys from the engine. When `cacheHoldsCiphertext` is true (i.e. `ENCRYPTED`, `ENCRYPTED_WITH_TIMED_CACHE`, or `LAZY_PLAIN_TEXT`), uses a CAS (`memoryCache.replaceIf`) to swap optimistic plaintext for ciphertext without clobbering a newer in-flight write.
- `putPlainSuspend` / `putEncryptedSuspend` / `delete` (suspend) — apply optimistic in-memory state (matches the `*Direct` siblings), enqueue a `PendingWrite.*` carrying a `CompletableDeferred<Unit>`, then `await()` it. Concurrent suspend callers from independent coroutines coalesce into the same `processBatch` invocation as fire-and-forget `putDirect` traffic, so a burst of 500 `suspend put` calls amortises into a small number of `applyBatch` transactions instead of 500.
- `cleanupOrphanedCiphertext()` — probes every encrypted entry except a `getOrCreateSecret` slot; removes from storage any whose decrypt fails with a **definitive key miss** — one of `No encryption key found`, `key not found` or `web key missing`, and only when it appears behind the `KSafe: ` brand every engine throws with. An error phrased in the platform's own wording is deliberately left alone, so a user key whose name happens to read like one of those phrases cannot condemn its own entry. A transient failure (`device is locked`, a busy Keystore or Keychain) never counts. Probes run concurrently inside a `coroutineScope { … }` with a `Semaphore(8)` cap (same fan-out budget as `processBatch` and `updateCache`), then orphan deletes are applied sequentially after all probes complete. A 1500-key sweep finishes in milliseconds rather than seconds because the Keystore IPC pipelines instead of stalling on each probe.
- `rotateKeys(): KSafeRotationResult` (3.0.0+; automatic resume/retry state in 3.1.0+) — the whole-store rotation. Single-flighted via `rotationInFlight`; a second concurrent call fails fast. Persists the generation bump **and its `r:1` recovery marker first** through the write consumer (so every later write already uses the new generation), then re-encrypts each older-generation or legacy entry via a per-entry `PendingWrite.Rotate` that commits under a ciphertext CAS — a concurrent user write always wins. After `SweepSupersededMasters`, `CompleteKeyRotation` changes `r:1` to `r:0`, but only if the store is still at that target generation; if the pass left retryable skips it also writes the configured `rp:N` retry budget. No per-entry journal or rollback log is needed, because every step is idempotent.

  This is the authoritative description of the `__ksafe_keygen__` lifecycle. What a freshly constructed KSafe instance does with the record it finds:

  | Recorded state | What the next instance does |
  |---|---|
  | no `r` field | a released 3.0.0 record; adopted as `r:0`, with no rotation work of any kind |
  | `r:1` | a pass was interrupted; resume it at the **same** generation, under any policy including `Never` |
  | `r:0` | complete; the normal `keyRotationPolicy` check applies |
  | `r:0,rp:N` | complete but with retryable skips; claim one attempt by durably writing `r:1,rp:N-1` **before** any work, so a crash cannot refill the budget |
  | anything else | unknown to this build; preserved as written and rejected |

  A `MaxAge` that has already come due supersedes a pending **retry claim** with a fresh generation — but never a resume: an interrupted pass finishes at its persisted generation whatever the policy says, because that is a recovery guarantee rather than a policy choice. A `failed` entry never arms the retry budget; only `skipped` does.
- `resolveFromCache(key, default, protection, serializer)` — the read hot-path called from both `getDirectRaw` (sync) and `getRaw` (suspend). Uses the timed plaintext cache when applicable, decrypts via blocking `engine.decrypt` in `ENCRYPTED` mode, and ultimately calls `convertStoredValue` to reconcile the stored type with the requested one.
- `convertStoredValue(storedValue, default, serializer)` — the cross-type dispatcher. Uses `builtInPrimitiveKindOrNull(serializer)` to route Int/Long/Float/Double/Boolean/String lookups — built-ins only, because a custom serializer with a primitive descriptor was written as JSON and must decode in the fallback branch. Handles both typed DataStore values (Android/iOS/JVM) *and* string-stored primitives (web localStorage), plus `@Serializable` types via JSON. Also handles Int↔Long cross-type migration (widening / range-checked narrowing).
- `getDirectRaw` / `putDirectRaw` / `getRaw` / `putRaw` / `getFlowRaw` — the non-inline, non-reified entry points that everything in the library funnels through. `putDirectRaw` and `putRaw` shadow their `mode` parameter with `modeTransformer(mode)` at the very top.
- `deleteDirect` / `delete` / `clearAll` / `getKeyInfo` — straightforward.
- `isTransientDecryptFailure(e)` — shared "device locked / Keystore inaccessible" check. Used to distinguish "should retry" from "orphaned ciphertext, clean up". A top-level function in `KSafeCoreFailureClassification.kt` rather than a `KSafeCore` member, next to its rotation-scoped sibling `isRotationRetryable` (which additionally retries a temporarily unreachable key store, so an outage is counted `skipped` and never `failed`). Both match phrases from the `KSafeEngineMessage` registry that every engine throws from, so an engine can't word a failure the classifier doesn't recognise.

**Why it's a class (not an object):** one `KSafeCore` per `KSafe` instance, so an app with `prefs` + `vault` instances gets two independent caches/coalescers.

## `KeySafeMetadataManager.kt` — on-disk key layout

A stateless helper object that owns the string-scheme for how user keys map to DataStore/localStorage raw keys.

**Key declarations:**

- Constants: `VALUE_PREFIX = "__ksafe_value_"`, `META_PREFIX = "__ksafe_meta_"`, `META_SUFFIX = "__"`, plus legacy equivalents `LEGACY_ENCRYPTED_PREFIX = "encrypted_"` and `LEGACY_PROTECTION_PREFIX = "__ksafe_prot_"`.
- `valueRawKey(userKey)` / `metadataRawKey(userKey)` — current format.
- `legacyEncryptedRawKey(userKey)` / `legacyProtectionRawKey(userKey)` — pre-1.7 format, still read for backwards compat.
- `tryExtractCanonicalValueKey(rawKey)` / `tryExtractCanonicalMetadataKey(rawKey)` / `tryExtractLegacyProtectionKey(rawKey)` / `tryExtractLegacyEncryptedKey(rawKey)` — reverse helpers.
- `isInternalStorageKey(rawKey)` — `true` for anything starting with `"__ksafe_"` (the reserved namespace) or `"ksafe_key_"` (the web engine's legacy localStorage key store). A blanket `"ksafe_"` is deliberately NOT matched, so a user key like `ksafe_token` is treated as normal data. `classifyStorageEntry` uses this to skip internal housekeeping entries when building the cache.
- `collectMetadata(entries, accept)` — merges canonical + legacy metadata across a snapshot; canonical wins on conflict.
- `classifyStorageEntry(rawKey, legacyEncryptedPrefix, encryptedCacheKeyForUser, stagedMetadata, existingMetadata): ClassifiedStorageEntry?` — the algorithm that turns a raw on-disk key into `(userKey, cacheKey, encrypted)`. Handles both the canonical `__ksafe_value_` prefix and the pre-1.7 `encrypted_<key>` / bare-userKey variants.
- `buildMetadataJson(protection, accessPolicy, envelopeVersion = ENVELOPE_VERSION_LATEST, keyGeneration = 1, strictAliasVariant = false)` — compact JSON like `{"v":2,"p":"DEFAULT","u":"unlocked"}`. `ENVELOPE_VERSION_LATEST` is `2`. Two fields are written **only when they leave their default**: `g` (generation) when `keyGeneration > 1`, and `sa` (strict alias variant — a `HARDWARE_ISOLATED` entry that *also* requires an unlocked device, which keys under its own alias spelling) when true. So an ordinary generation-1 entry stays byte-identical to a pre-3.0.0 v2 entry. Legacy pre-2.0 builds carry `"v":1` (or a bare protection literal) and are still readable. The strict alias variant is a routing dimension in its own right: it appears in `EncMeta`, in `decryptRoute`, and in the delete-time key sweep.
- Envelope versions (`ENVELOPE_VERSION_V1/V2/V3` = 1/2/3): **v1** = legacy pre-2.x (per-entry alias, bare-literal metadata); **v2** = 2.0–2.2.x and un-rotated 3.0.0 generation-1 (shared master key for `DEFAULT`, `{"v":2,...}`, no AAD); **v3** = generation ≥ 2 (after the first `rotateKeys()`) — same routing as v2 plus an *authenticated* AES-GCM envelope. There is no on-disk migration: an entry upgrades to the current envelope only when it's overwritten (or rotated).
- `envelopeVersionForWrite(keyGeneration)` — `keyGeneration >= 2 → v3`, else `v2`. Picks the envelope a fresh write uses.
- `aadFor(storeIdentity, userKey, protection, requireUnlockedDevice, keyGeneration): ByteArray` — the v3 associated data: a canonical, length-prefixed encoding binding the ciphertext to store identity + user key + protection tier + unlock policy + key generation. Tampering with any of those routing fields breaks the GCM tag, so a v3 entry can't be copied, swapped, or relocated between keys and a doctored routing field fails closed.
- `parseKeyGeneration(raw)` — reads the `g` field back (1 for legacy / missing / unparseable); `parseKeyGenerationTimestamp(raw)` reads the generation-birth timestamp the MaxAge policy measures. `parseEnvelopeVersion(raw)` recovers the envelope version.
- `parseProtection(raw)` / `parseAccessPolicy(raw)` / `parseRequireUnlockedDevice(raw)` / `extractProtectionLiteral(raw)` — read-side parsers.
- `protectionToLiteral(protection): String` — write-side.

**Why centralised:** every platform shell and `KSafeCore` used to duplicate these string constants and parsers. Pulling them into one object means the on-disk format is defined exactly once.

## `KSafeSerializerUtil.kt` — JSON + serializer-kind helpers

A handful of small functions used by the read/write paths.

**Key declarations:**

- `jsonEncode(json, serializer, value)` / `jsonDecode(json, serializer, jsonString)` — `kotlinx-serialization-json` helpers that work with type-erased `KSerializer<*>`. Used by the non-inline `*Raw` methods.
- `primitiveKindOrNull(serializer)` — returns the `PrimitiveKind` from a serializer's descriptor, unwrapping nullable markers (so `Int?`'s serializer still reports `INT`). Its only caller is `isStringSerializer` below, so it is transitively unused too.
- `builtInPrimitiveKindOrNull(serializer)` — the same, but only for the *built-in* primitive serializers. This is what `convertStoredValue` dispatches on. Custom serializers (`Duration`, `Uuid`, kotlinx-datetime) declare primitive descriptors yet are JSON-encoded by the write path, so gating on the built-in `serialName` keeps the read fast-path symmetric with what was actually stored raw.
- `isStringSerializer(serializer)` — convenience wrapper, unused since the 2.0 refactor: only the declaration exists, nothing in the library calls it. Removal is deferred to a future major release, because it is `@PublishedApi internal` and so part of the binary contract.

## `KSafeConcurrent.kt` — common concurrency primitives

Thin `expect` abstractions so `KSafeCore` can use a thread-safe map, set, counter, flag and lock without knowing how each is implemented.

**Key declarations:**

- `expect class KSafeAtomicFlag(initial: Boolean)` — atomic boolean, with `compareAndSet`.
- `expect class KSafeAtomicInt(initial: Int)` — atomic counter, with `compareAndSet`. Carries the store's `currentKeyGeneration` and its `clearEpoch`.
- `expect class KSafeConcurrentMap<V : Any>()` — thread-safe `String`-keyed map: `get` / `set` / `remove` / `containsKey` / `clear` / `snapshot()`, plus three the library depends on for correctness rather than convenience — `replaceIf(key, expected, new)` and `removeIf(key, expected)` (compare-and-set, so a background task never clobbers a newer in-flight write) and `putIfAbsent`.
- `expect class KSafeConcurrentSet<T : Any>()` — thread-safe set.
- `expect class KSafeInitLock()` — a plain mutual-exclusion lock for one-time initialisation, with `withLock`. `KSafeLazyRef<T>` beside it is ordinary common code built on it: a double-checked `getOrPut` that runs its factory exactly once.
- `expect fun <T> runBlockingOnPlatform(block: suspend () -> T): T` — `runBlocking` on Android, Apple and JVM; throws on web, where a browser cannot block its main thread. `Job.joinBlockingWithin(timeoutMs)` in the same file is the common-code helper built on it.
- `expect val decryptFlowContext: CoroutineContext` — the context a `Flow`'s per-emission decrypt runs on: `Dispatchers.Default` where that decrypt is a blocking OS-vault call, `EmptyCoroutineContext` on web, where a dispatcher hop breaks the cold-start read.

**Why `expect`:** JVM and Android use `ConcurrentHashMap` / `AtomicBoolean` / `ReentrantLock`; Apple uses copy-on-write `AtomicReference` (Kotlin/Native has no `ConcurrentHashMap`), with `KSafeAtomicFlag` backed by `AtomicInt` because a boxed `Boolean` has no stable reference identity there; web is single-threaded and uses plain `HashMap`. `KSafeCore` compiles unchanged against all three.

The module's other `expect`s are `secureRandomBytes` (`KSafeSecureRandom.kt`), `SecurityChecker`, `ksafeLogWarning` / `ksafeLogError` (`KSafeLog.kt`), and — web-only — `WebKeyStore`, `WebInterop` and `fillSecureRandomChunk`. `KSafe` itself is no longer an `expect` class: its construction lives in per-platform factory functions instead.

## `KSafeSecureRandom.kt` — cross-platform CSPRNG

Single `expect fun secureRandomBytes(size: Int): ByteArray`. Used everywhere a random IV, a new AES key, or a secret body is needed.

## `KSafeLog.kt` — severity-routed diagnostics

Two `expect fun`s, `ksafeLogWarning(message)` / `ksafeLogError(message)`. Every platform maps them to `println` **except web**, where a plain `println` becomes `console.log` and hides under DevTools' default "Errors/Warnings" filter — so js/wasmJs route warnings to `console.warn` and errors to `console.error`, keeping a failure diagnostic a developer is actively hunting visible. There are therefore only three actuals: one in `datastoreMain` (whose target set — Android + Apple + JVM — is exactly the non-web one, and whose actual is the same `println` for all three), plus `jsMain` and `wasmJsMain`.

## `SecurityChecker.kt` — runtime security probes

Platform-specific root/debugger/emulator detection, abstracted behind a common `expect object`.

**Key declaration:**

- `expect object SecurityChecker`:
  - `isDeviceRooted(): Boolean`
  - `isDebuggerAttached(): Boolean`
  - `isDebugBuild(): Boolean`
  - `isEmulator(): Boolean`

**Why an `object`:** there's only ever one checker per platform, and the consumer never instantiates it. Called once from `validateSecurityPolicy` at `KSafe` construction.

---

# Part 3 — `datastoreMain` and `jvmSharedMain`: the intermediate source sets

Android + Apple + JVM all use Jetpack DataStore Preferences. Rather than duplicate the adapter three times, KSafe defines a `datastoreMain` intermediate source set that the three depend on. It holds the adapter plus everything else those three targets would otherwise each spell for themselves.

## `datastoreMain/internal/DataStoreStorage.kt`

Implements `KSafePlatformStorage` on top of `DataStore<Preferences>`.

**Key logic:**

- The constructor takes the `DataStore<Preferences>` as `@PublishedApi internal val dataStore` — exposed at this visibility so the JVM platform-extension `KSafe.dataStore` (used by JVM whitebox tests) can read it back through `core.storage as DataStoreStorage`.
- `snapshot()` and `snapshotFlow()` both delegate to a `DataStoreCommitRelay` (below), which maps each `Preferences.Key<*>` to its matching `StoredValue` variant (Int → `IntVal`, Boolean → `BoolVal`, String → `Text`, etc.).
- `applyBatch(ops)` → a single `dataStore.edit { … }` block that processes every `StorageOp` in order, using typed `intPreferencesKey` / `longPreferencesKey` / … for writes and a name-based removal helper for deletes. The committed state is then published to the relay.
- `clear()` → `dataStore.edit { it.clear() }`, likewise published.

## `datastoreMain/internal/DataStoreCommitRelay.kt`

The read side, factored out so the JSON-fallback storage can reuse it: it projects the store through a `toStoredMap` and merges `dataStore.data` with a `replay = 1` / `DROP_OLDEST` `MutableSharedFlow` of locally committed states.

`.data` alone is not a reliable change source for a long-lived collection: a collection whose first read races an in-flight write can be stamped with the writer's already-incremented version while still reading the pre-write file, after which `.data`'s internal version filter drops that write's emission — the collector sees the change only at the *next* write, or never. Emitting the committed state directly makes every same-storage write observable regardless; `.data` stays merged in for the initial value and for changes made outside this storage.

## `datastoreMain/internal/SharedStoreBackend.kt` and `StoreLocation.kt`

`SharedStoreBackend` is the per-physical-file state sibling `KSafe` instances share: DataStore refuses two active instances on one file, and siblings must also share one engine so their in-memory key caches can't diverge from the single on-disk key slot. It carries the store's `CoroutineScope`, a per-store `commitMutex` that serializes sibling cores' batch commits, the lazily-built shared engine, the shared storage layer (so one commit relay reaches every sibling's collector), and a `SiblingRegistry` of the live cores on that file — which is what lets `clearAll()` wipe every sibling's caches, a rotation move a sibling's cached ciphertext onto the new generation, and the superseded-key sweep keep a key alive while any sibling still reads through it. Each platform subclasses it with its own storage handles, and each factory attaches its core with `core.attachSiblings(backend.siblings)`. The `SharedBackendRegistry` beside it keys live backends by store path and ref-counts them, so only the last instance to close tears one down — and it waits (bounded, under Android's ANR window) for a prior backend's scope to finish before recreating on the same path.

`StoreLocation.kt` owns the file naming — `dataStoreBaseFileName(fileName)` and the `.preferences_pb` suffix — and the store-identity pair the v3 AAD binds to (canonical plus, when they differ, the legacy spelling an earlier build wrote under). It is named rather than inlined because two string-matching consumers depend on the suffix: the Apple `clearAll` quarantine sweep and the JVM `appNamespace` copy-forward cohort.

## `datastoreMain/internal/KSafeLog.datastore.kt`

The `ksafeLogWarning` / `ksafeLogError` actual for all three targets — `println` — because `datastoreMain`'s target set is exactly the non-web one.

**Why one adapter for three platforms:** DataStore is a KMP library. Android uses `datastore-preferences`; Apple/JVM use `datastore-preferences-core`. The typed-Preferences API we rely on is identical across all three. Writing the adapter once is the whole reason for the intermediate source set.

## `jvmSharedMain` — the second intermediate source set

Android and JVM are both JVM-bytecode targets, and several of their actuals were byte-identical `java.*` code. Those live once in `jvmSharedMain`, which depends on `commonMain` and is depended on by `androidMain` and `jvmMain`. It cannot be folded into `datastoreMain`: Apple shares that set and has its own actuals for these.

- **`KSafeConcurrent.jvmShared.kt`** — `ConcurrentHashMap` / `AtomicBoolean` / `AtomicInteger` / `ReentrantLock` actuals, plus `runBlockingOnPlatform` = `runBlocking` and `decryptFlowContext` = `Dispatchers.Default`.
- **`KSafeSecureRandom.jvmShared.kt`** — `java.security.SecureRandom.nextBytes(...)`.
- **`JvmSharedCrypto.kt`** — `JvmAesGcm`: the frozen AES-GCM layout both `javax.crypto` engines build ciphers from (128-bit tag, 12-byte IV, `"AES/GCM/NoPadding"`). Every persisted ciphertext is `IV ‖ ct+tag` with exactly these sizes, so a change on one engine alone makes that platform's data undecryptable.
- **`CorruptStoreQuarantine.kt`** — the `java.io` half of the corrupt-store handling: copies an unparseable store aside as `<name>.corrupt-<timestamp>` before DataStore continues from empty, and the `File`-based sweep `clearAll()` uses to delete those copies (they still hold decryptable ciphertext).

The two `expect`-actual files use `@file:JvmName` to keep the facade class name their `jvmMain` originals had. Their top-level members are in the JVM ABI dump — `@PublishedApi internal` in `KSafeConcurrent`'s case, outright public for `secureRandomBytes` — so the facade name is part of it, and letting the source-set move rename it would break already-compiled callers for no gain.

---

# Part 4 — platform shells

Each platform shell is a single file that exposes a top-level `fun KSafe(...)` factory plus any genuinely platform-specific helpers. The factories are what consumers actually call. Internally, each calls a `private fun buildXxxKSafe(...)` that does the construction work and ends in `return KSafe(core, deviceKeyStorages, protectionInfoProvider, onClearAllCleanup)`. What the shells were spelling more than once now comes from `commonMain/internal/KSafeFactoryShared.kt` — `fileName` validation, the alias spellings and the storage-tier answer for all four; the OS-store identity constant and the deprecated-flag promotion for the two that have them — plus, for the three DataStore targets, the shared per-file backend registry in `datastoreMain`. What is left in each shell is the part that genuinely differs.

Every platform also exposes an `@PublishedApi internal fun KSafe(..., testEngine: KSafeEncryption)` overload — same params plus an injectable engine for tests. Pre-2.0 this was a secondary `internal constructor` on `actual class KSafe`; option C turned it into a same-name overload, which test call sites can use unchanged because they always pass `testEngine =` as a named argument.

**What differs between the four**, in one place, so you don't have to hold four narratives in your head:

| | Storage | Key custody | Master alias spelling | Shared per-file backend |
|---|---|---|---|---|
| Android | DataStore Preferences, app-private dir or `baseDir` | Keystore (TEE), StrongBox per write; a relaxed `DEFAULT` write rides a TEE-wrapped DEK held in memory | `eu.anifantakis.ksafe[.<fileName>].__ksafe_master__` (and `…__ksafe_master_locked__`) | yes |
| Apple | DataStore Preferences under Application Support, or `directory` | Keychain; a hardware-isolated write wraps its AES key with a Secure Enclave key (ECIES) where an Enclave is present | `eu.anifantakis.ksafe[.<fileName>].__ksafe_master__` (and `…__ksafe_master_locked__`) | yes |
| JVM | DataStore Preferences under `~/.eu_anifantakis_ksafe` or `baseDir`; a JSON file when `sun.misc.Unsafe` is absent | OS secret store (DPAPI / login Keychain / libsecret), or a key file | `[<fileName>:]__ksafe_master__` | yes |
| Web | `localStorage` under `ksafe.<ns@><fileName>:` | non-extractable WebCrypto key in IndexedDB | `[<fileName>:]__ksafe_master__` | no — every instance builds its own storage and engine |

JVM and web have no device lock, so both unlock policies collapse onto the single `__ksafe_master__` there. Android and Apple keep the two apart, because a key minted with `setUnlockedDeviceRequired` (or the matching Keychain accessibility) cannot serve a relaxed read.

## Android

### `KSafe.android.kt` — the factory

A few hundred lines, down from ~1,584 pre-2.0. Owns:

- **Top-level `KSafe(context: Context, fileName: String? = null, ..., useStrongBox: Boolean = false, baseDir: File? = null): KSafe`** — public factory.
- **Top-level `@PublishedApi internal fun KSafe(..., baseDir: File? = null, testEngine: KSafeEncryption)`** — test overload.
- **`private val backends = SharedBackendRegistry<AndroidBackend>(Dispatchers.IO)`** — top-level registry (not in a companion). Keys the shared `DataStore`, storage layer, engine and sibling registry per *canonical file path* (the absolute path only when canonicalization throws). Canonical rather than absolute so two spellings of one file share one backend instead of tripping DataStore's "multiple active instances" error; per path rather than per fileName (as it was pre-`baseDir`) so two `KSafe` instances pointing at different `baseDir`s get separate DataStores. The registry itself lives in `datastoreMain` — Apple and JVM use the same one.
- **`const val KEY_ALIAS_PREFIX = "eu.anifantakis.ksafe"`** — top-level public constant. Aliased to the shared `KSAFE_OS_STORE_IDENTITY`, the one spelling of the identity KSafe files key material under in every OS key store. Used to build the Keystore alias passed to `KSafeCore`.
- **StrongBox detection** inside `buildAndroidKSafe`. `Build.VERSION.SDK_INT >= P && context.packageManager.hasSystemFeature(FEATURE_STRONGBOX_KEYSTORE)`. Drives `deviceKeyStorages`.
- **DataStore file resolution.** If `baseDir == null` (recommended), uses `context.preferencesDataStoreFile(name)` — Context-managed app-private path under `/data/data/<package>/files/datastore/...`, where the Android sandbox enforces correct permissions. If a custom `baseDir` is supplied, KSafe creates the directory if missing and uses `File(baseDir, "$baseFileName.preferences_pb")`. Doc warns against external storage for sensitive data.
- **`modeTransformer = { promoteDefaultToIsolated(it, useStrongBox) }`** — honors the deprecated `useStrongBox` constructor flag by promoting `KSafeEncryptedProtection.DEFAULT` to `HARDWARE_ISOLATED`. `promoteDefaultToIsolated` is shared with Apple (which passes `useSecureEnclave`); the two flags meant the same thing and used to be two identical local helpers.
- **`resolveKeyTier(protection, engineAlias)`** — local helper returning one `KSafeKeyTier`, projected into both `resolveKeyStorage` and `resolveKeyLevel` via `asKeyStorage()` / `asProtectionLevel()`. Reports `HARDWARE_ISOLATED` for a `HARDWARE_ISOLATED` entry on a StrongBox-capable device *unless* the live key's own security level contradicts it: the API 31+ `KeyInfo.getSecurityLevel()` probe only ever downgrades, and only when it can prove the key actually sits in the TEE (a silent StrongBox fallback, or a tier-upgrade write that reused a pre-existing TEE key). Below API 31, or when the key can't be inspected, the device-capability inference stands. Everything else is `HARDWARE_BACKED`; a plain entry is `SOFTWARE`.
- **`SecurityChecker.applicationContext = context.applicationContext`** — wired in the factory before `validateSecurityPolicy(securityPolicy)` runs.

What's *not* here anymore: biometric integration. Pre-2.0 the Android shell owned `BiometricHelper.init(application)`, a per-scope session cache (`AtomicReference<Map<String, Long>>`), and `verifyBiometric{,Direct}` methods. All of that moved to `:ksafe-biometrics` in 2.0.

### `internal/AndroidKeystoreEncryption.kt` — the engine

Implements `KSafeEncryption` via `javax.crypto` talking to the `"AndroidKeyStore"` JCA provider. Notable specifics:

- `KeyGenerator.getInstance("AES", "AndroidKeyStore")` + a `KeyGenParameterSpec` carrying `setIsStrongBoxBacked(true)` when `hardwareIsolated` is requested, and `setUnlockedDeviceRequired(true)` (API 28+) when `requireUnlockedDevice` is set — dropped on API 28-34 while the device has no secure lock screen, where keystore2 cannot mint such a key. The relaxed mint is recorded as a reserved DataStore entry (`__ksafe____NOUNLOCKBIND____@<alias>`, deleted with the key and wiped by `clearAll()`), so `protectionInfo.notes` keeps reporting `android_lock_screen_absent` while that key is in use — including after the user sets a lock screen, since Keystore parameters are fixed at mint time. Only the next key generation re-decides, and rotation is opt-in (`keyRotationPolicy` defaults to `Never`).
- Returns a `SecretKey` that's actually a *handle* — the key bytes never leave the TEE / StrongBox.
- **Software-DEK fast path (2.1.2).** Because a Keystore-resident key runs its AES-GCM *inside* the TEE, the old per-call decrypt was a hardware round-trip (~8 ms/op on real hardware; invisible on an emulator). For relaxed `DEFAULT` writes (`!hardwareIsolated && !requireUnlockedDevice`) the engine now generates a random data-encryption key (DEK), wraps it with the Keystore master key (the KEK, still non-exportable), persists the wrapped DEK as a reserved Base64 entry (`__ksafe____DEK____`, plus a `…@<alias>` slot per further alias after a rotation) **in the safe's own DataStore** (never SharedPreferences — KSafe uses none anywhere), and unwraps it **once** into an in-process `dekCache` — after which every encrypt/decrypt is pure-CPU AES-GCM in userspace. DEK ciphertext is self-describing (`MAGIC("KSD1") + VERSION` header); `decrypt` routes by that header (with a GCM-auth fallback to the legacy TEE path), so pre-2.1.2 ciphertext stays readable and no envelope-version bump is needed. `HARDWARE_ISOLATED` and the strict `requireUnlockedDevice` master keep the per-call TEE path (key never in app memory). The engine is therefore constructed with a DataStore-backed `WrappedDekStore` (see `WrappedDekStore.kt`); an internal `useSoftwareDek` flag is a test/escape hatch.
- `deleteKey(alias)` removes the Keystore entry **and** drops the cached DEK; idempotent on missing aliases. Because the DEK's storage key is fixed per safe, the *persisted* DEK is cleared only on KEK invalidation and by `clearAll()` — never by deleting an individual key — so removing one entry can't brick the others.

### `internal/SecurityChecker.android.kt`

- `SecurityChecker` — reads `BuildConfig.DEBUG`, probes for root binaries / Magisk, checks `Debug.isDebuggerConnected()`, detects emulator via build fingerprints + the standard `goldfish` / `sdk` heuristics.

It is the only `expect` `androidMain` still answers on its own. The `KSafeConcurrent` and `KSafeSecureRandom` actuals moved to `jvmSharedMain` (they were byte-identical to the JVM ones), and `KSafeLog` to `datastoreMain`.

## Apple platforms (iOS + native macOS)

The Apple-platform implementation lives in **`appleMain/`** — a single source set shared by all five Apple targets (`iosX64`, `iosArm64`, `iosSimulatorArm64`, `macosX64`, `macosArm64`). Every Apple-side concern listed below ships once and runs identically on iOS and macOS, because Keychain Services, CryptoKit, the Secure Enclave token attribute, `NSFileManager`, and DataStore Preferences all expose byte-for-byte identical APIs across both platforms — only the *location* of the Keychain database differs (per-app on iOS, per-user on macOS). Pre-2.0.1 the same code lived in `iosMain/` under `Ios*` filenames; the move was a mechanical rename, with one behaviour fix (see `SecurityChecker.apple.kt` below).

### `KSafe.apple.kt` — the factory

A few hundred lines, down from ~1,938 pre-2.0. Owns:

- **Top-level `KSafe(fileName: String? = null, ..., useSecureEnclave: Boolean = false, directory: String? = null): KSafe`** — public factory.
- **Top-level `@PublishedApi internal fun KSafe(..., directory: String? = null, testEngine: KSafeEncryption)`** — test overload.
- **`@PublishedApi internal const val KEY_PREFIX = "eu.anifantakis.ksafe"`** — top-level constant, aliased to the shared `KSAFE_OS_STORE_IDENTITY` (the same string Android's `KEY_ALIAS_PREFIX` points at). Used to build the Keychain alias passed to `KSafeCore`.
- **Secure Enclave detection.** `hasSecureEnclave = !isSimulator() && AppleKeychainEncryption.deviceHasSecureEnclave()`. `isSimulator()` is a top-level helper that reads `SIMULATOR_UDID` out of the process environment, so it is `true` only on the iOS Simulator. The second half is a real probe — it mints an ephemeral Enclave key once and reports whether that worked — because "not the Simulator" does not imply "has an Enclave": pre-T2 Intel Macs and virtual machines have none. A device that answers `false` reports no `HARDWARE_ISOLATED` in `deviceKeyStorages` and carries `apple_secure_enclave_absent` in `protectionInfo.notes` from construction, instead of discovering the gap on its first hardware-isolated write. A transient failure on that one probe sticks as `false` for the process, deliberately: never claim stronger isolation than the engine can deliver.
- **Legacy encrypted-key format override.** Pre-1.8 iOS builds wrote encrypted entries under `"{fileName}_{key}"` rather than the common `"encrypted_{key}"`. Local helpers `iosLegacyEncryptedKey(userKey)` / `iosLegacyEncryptedPrefix()` are passed to `KSafeCore`, which uses them throughout its legacy-read paths so upgraders never lose data.
- **`useSecureEnclave` deprecated flag.** Same role as Android's `useStrongBox`, and now literally the same code: `modeTransformer = { promoteDefaultToIsolated(it, useSecureEnclave) }`, from the shared `KSafeFactoryShared.kt`.
- **`cleanupOrphanedKeychainEntriesSafe(isUserKeyDirty)`** — local suspend helper passed as `migrateAccessPolicy`. Delegates to `internal/KeychainOrphanCleanup.kt`, holding the store's shared `commitMutex` across the whole snapshot → classify → delete sequence so a batch commit's key mint can't interleave, and forwarding the dirty-key predicate so an enqueued-but-uncommitted write's key is never reaped. It returns early for a custom-`directory` store, whose Keychain namespace it would otherwise share with a same-`fileName` sibling elsewhere.
- **DataStore directory resolution.** If `directory == null` (default), uses `NSFileManager.URLForDirectory(NSApplicationSupportDirectory, NSUserDomainMask, create = true)`. On iOS this resolves to the per-app sandbox `…/Library/Application Support/`; on sandboxed macOS apps it resolves to `~/Library/Containers/<bundle-id>/Data/Library/Application Support/`; on unsandboxed macOS binaries it resolves to `~/Library/Application Support/`. If a custom path is supplied, it's used as-is. Either way the directory is `mkdir`ed via `createDirectoryAtPath(withIntermediateDirectories = true)` and the resolved file path is `"$dir/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb"`.
- **1.x → 2.0 auto-migration from `NSDocumentDirectory`.** Pre-2.0 iOS stored the DataStore in `NSDocumentDirectory` — the wrong place on iOS (user-visible via iTunes File Sharing if `UIFileSharingEnabled`, iCloud-syncable by default). 2.0 moves the default to `NSApplicationSupportDirectory`. To avoid forcing 1.x consumers to write migration code, the factory checks: when `directory == null` AND the new path is empty AND a legacy file exists at `"$NSDocumentDirectory/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb"`, it calls `NSFileManager.moveItemAtPath` to relocate the file. Idempotent (only triggers when the new location is empty) and best-effort (a failed move logs a recovery message and leaves the legacy file alone — the consumer can recover by passing `directory = "<old Documents path>"`). Apps bumping the dep from 1.x to 2.0 keep their data with zero code changes. On native macOS the migration is a benign no-op for fresh installs (1.x never shipped on macOS).
- **Corrupt-store quarantine, and the `clearAll` sweep of it.** A `ReplaceFileCorruptionHandler` copies an unparseable `.preferences_pb` aside before continuing from empty, so the bytes stay recoverable. The copy takes a *fixed* name (`<path>.corrupt`) rather than the JVM targets' timestamped one, so only the newest corruption is retained. Because such a copy still holds decryptable ciphertext, the factory also passes an `onClearAllCleanup` that deletes every quarantine copy of this store from the resolved directory — matched on the store's own file name, so a sibling safe in the same directory is never touched. Naming and sweep both come from the shared `CorruptStoreSweep.kt`.
- **No file-level `NSURLIsExcludedFromBackupKey` setting.** An earlier draft set the attribute unconditionally, but DataStore's atomic-write strategy (write-to-temp then rename) creates a new inode on every flush and clobbers the xattr — making the setting unreliable in practice. The actual security guarantee comes from key locality: encryption keys live in the Keychain with `…ThisDeviceOnly` accessibility (and Secure Enclave keys never leave the device for `HARDWARE_ISOLATED` writes), so a backed-up ciphertext is undecryptable on a restored device — effectively device-local even when the bytes themselves traverse iCloud (iOS) or Time Machine (macOS). Apps that need a hard file-level exclusion can do it themselves on the resolved path or use a per-instance subdirectory layout.
- **No public cipher-provider escape hatch.** CryptoKit initialization belongs to the internal
  engine; the former `obtainAesGcm()` helper was removed together with its third-party provider.

What's *not* here anymore: `verifyBiometric` / `verifyBiometricDirect` / `clearBiometricAuth`, the LAContext glue, and the `biometricAuthSessions` map. All moved to `:ksafe-biometrics`.

### `internal/AppleKeychainEncryption.kt` — the engine

Implements `KSafeEncryption` using KSafe's bundled Swift/C bridge to
`CryptoKit.AES.GCM`, and the raw Apple Security framework (`SecItemAdd`,
`SecItemCopyMatching`, `SecKeyCreateRandomKey`) for key persistence. The bridge exposes only
byte pointers, lengths, and status codes; Kotlin owns input validation and the frozen
`12-byte nonce || ciphertext || 16-byte tag` framing. No third-party crypto dependency or
provider object remains. The engine is still by far the biggest — raw `platform.Security.*`
cinterop has no JCA-style shortcut — but it's built on a small helper layer so the same
boilerplate doesn't repeat.

The class was named `IosKeychainEncryption` through 2.0.0; renamed to `AppleKeychainEncryption` in 2.0.1 alongside the `iosMain` → `appleMain` move. It's `@PublishedApi internal`, so the rename is invisible to direct consumer source — but stack traces and the `testEngine` constructor parameter expose it, so anything that names the class explicitly needs the rename.

**Key behaviours:**

- Plain `DEFAULT` writes store a raw AES key as a `kSecClassGenericPassword` item with service = `"eu.anifantakis.ksafe"` and account = `"eu.anifantakis.ksafe.<fileName>.<userKey>"`.
- `HARDWARE_ISOLATED` writes use ECIES: an EC private key is created in the Secure Enclave (`kSecAttrTokenIDSecureEnclave`), and the AES key is wrapped with its public key and stored as a `kSecClassGenericPassword` item under `"se.<prefix>.<userKey>"`.
- `updateKeyAccessibility(identifier, requireUnlocked)` — the only engine that actually implements this, via `SecItemUpdate`.
- Every `memScoped` body is wrapped in `kotlinx.cinterop.autoreleasepool { … }` (fix from 1.8.1) to drain Kotlin→NSString bridging allocations on worker threads that lack an ambient Objective-C autorelease pool.
- `getOrCreateKeychainKey(keyId, hardwareIsolated, requireUnlockedDevice)` — with `hardwareIsolated = true` it takes the Enclave-backed ECIES path: an existing wrapped key is unwrapped with the Enclave private key, otherwise a fresh AES key is minted, wrapped, and stored. Falling back to a plain Keychain key is deliberately **narrow**, because a fallback under a live alias would leave two divergent keys under one name. An unwrap failure, a Keychain store failure, or a generic Keychain error is rethrown with both halves of the key intact; only a proven Enclave-unusable failure — plus the Simulator's missing-entitlement case, which is checked first because `-34018` also matches "Keychain error" — falls through to plain storage. An existing Enclave envelope is replaced only when the system proves it undecodable.

**Internal helper layer** (top of the class, above the `KSafeEncryption` interface impls):

- `accessibleAttr(Boolean)` — maps the unlock-policy boolean to the right `kSecAttrAccessible*` CFString. Previously an `if/else` re-written in four places.
- `tagAsNSData(String)` — encodes an SE application-tag as UTF-8 NSData. Previously duplicated in `createSecureEnclaveKey`, `getSecureEnclaveKey`, `deleteSecureEnclaveKey`, `updateSecureEnclaveKeyAccessibility`.
- `cfErrorDescription(CFErrorRefVar)` — reads a localized description out of a `CFError` with a stable fallback message. Previously duplicated in `createSecureEnclaveKey`, `wrapAesKey`, `unwrapAesKey`.
- `usingPasswordQuery(account, configure, block)` / `usingSeKeyQuery(tagData, configure, block)` — `inline` helpers that build a `CFDictionary` with the base class/service/account (or class/keyType/applicationTag for SE) attributes pre-populated, let the caller add class-specific attrs via `configure`, run `block` with the dict, and `CFRelease` it on every exit path. Previously each `SecItemCopyMatching` / `SecItemAdd` / `SecItemUpdate` / `SecItemDelete` call-site built and released its own dict.
- `copyKeychainBytes(account)` — single unified "find this item's bytes or return null / throw" routine used by every lookup path.
- `cryptWithSeKey(key, input, wrap: Boolean)` — one shared ECIES-encrypt/decrypt implementation, with `wrap: Boolean` choosing `SecKeyCreateEncryptedData` vs `SecKeyCreateDecryptedData`.
- `runItemUpdate(query, requireUnlocked)` / `handleAccessibilityUpdateStatus(status, what)` — shared between the two `update*Accessibility` methods (SE EC private key and generic-password item), which previously duplicated the update-dictionary build and the `errSecSuccess` / `errSecItemNotFound` / `errSecInteractionNotAllowed` switch.

### `internal/KeychainOrphanCleanup.kt`

Standalone suspend function `cleanupOrphanedKeychainEntries(storage, engine, serviceName, fileName, legacyEncryptedPrefix, seKeyTagPrefix, reservedKeyIds, isInFlight)`.

- Reads `storage.snapshot()` to compute the set of user keys with live DataStore entries (through the same `protectionByKeyFromSnapshot` helper the core's own orphan sweep uses — a divergent copy would make one sweep reap what the other preserves).
- Derives the account prefix it scans under from `KSafeAliasFormat.dottedBase(fileName)` — the same producer the factory's aliases come from, rather than re-deriving it. A drift between the two spellings would reap live keys.
- Scans Keychain generic-password items (plain keys + SE-wrapped blobs) via `SecItemCopyMatching`; compares `kSecAttrAccount` against the valid-keys set, skipping `reservedKeyIds` (the shared master sentinels, which no user key references and whose deletion would render *all* `DEFAULT` ciphertext undecryptable) and anything `isInFlight` reports as an uncommitted write.
- Scans `kSecClassKey` EC private keys separately — catches SE keys that exist without a matching generic-password item (e.g. after a crash between SE-key creation and wrapped-AES-key storage).
- Deletes orphans by calling `engine.deleteKeySuspend(fullIdentifier)`, which unconditionally removes plain + SE-wrapped + SE EC artifacts for the same identifier.

**Empty-snapshot guard (added in 2.0.1):** before iterating the orphan list, the function checks `if (snapshot.isEmpty() && orphanedKeyIds.isNotEmpty()) return`. The combination "DataStore reports zero entries but the Keychain has items scoped to this service" is the signature of either (a) a 1.x → 2.0 path migration where the DataStore file failed to move, (b) a corrupted DataStore that re-initialised empty, or (c) a user-data-wipe via Settings that left the Keychain alone — and in all three cases deleting the Keychain entries destroys irrecoverable Secure Enclave EC private keys. The guard logs a message pointing at `KSafe.clearAll()` for users who genuinely intended a wipe. The complementary defence is in `KSafeCore.startBackgroundCollector`, which now subscribes to `snapshotFlow` *before* invoking this function, so the snapshot it sees has been confirmed by DataStore's first emission.

**Why separate from `AppleKeychainEncryption`:** the sweep needs both the `KSafePlatformStorage` snapshot (to know what's valid) and the `KSafeEncryption` engine (to delete). Keeping it as a standalone function lets it be unit-tested against fakes of both.

### `internal/SimulatorKeychainFallback.kt` (3.0.0)

A Simulator-only escape hatch for an entitlement-blocked Keychain. An app with no signing team / no Keychain Sharing capability gets `errSecMissingEntitlement` (-34018) from every Keychain call on the iOS Simulator. When `AppleKeychainEncryption` hits that exact status *on the Simulator*, it falls back to this sandbox-file store instead of failing every encrypted write; `protectionInfo` reports the result as SOFTWARE. Real devices never construct it (the factory gate excludes them), and it's no trust downgrade of anything real: the Simulator's Keychain is itself just a file on the host Mac (no SEP, no hardware), so a sandbox-file key here is the same tier. Keys are stored under `NSApplicationSupportDirectory` keyed by a `CC_SHA256` of the identifier.

### `internal/KSafeConcurrent.apple.kt` / `internal/KSafeSecureRandom.apple.kt` / `internal/SecurityChecker.apple.kt`

- `KSafeConcurrent` — `actual` via `kotlin.concurrent.AtomicReference` with copy-on-write semantics (Kotlin/Native lacks `ConcurrentHashMap`). `KSafeAtomicFlag` is backed by `AtomicInt` (0/1) rather than `AtomicReference<Boolean>` because boxed `Boolean` doesn't have stable reference identity on Kotlin/Native.
- `KSafeSecureRandom` — `SecRandomCopyBytes` (Security framework CSPRNG) via `kotlinx.cinterop`. Same on iOS and macOS.
- `SecurityChecker` — jailbreak detection (probes for `/Applications/Cydia.app`, `/bin/bash`, etc., plus rootless-era paths like `/var/jb` for palera1n/Dopamine), debugger check via a `sysctl(CTL_KERN, KERN_PROC, …)` `P_TRACED` probe OR-ed with env-var heuristics (`DYLD_INSERT_LIBRARIES`, an lldb parent), simulator via `NSProcessInfo.processInfo.environment` (`SIMULATOR_MODEL_IDENTIFIER` / `SIMULATOR_DEVICE_NAME`). **macOS short-circuit:** `isDeviceRooted()` early-returns `false` when `Platform.osFamily == OsFamily.MACOSX` — every Mac has `/bin/sh`, `/usr/bin/ssh`, and (after a Homebrew install) an `/etc/apt`-shaped tree, so the iOS heuristics would otherwise unconditionally report every macOS host as jailbroken and `KSafeSecurityPolicy.Strict` would refuse to run anywhere. The macOS test suite includes `MacosSecurityCheckerTest` to lock the short-circuit in (asserts that `/bin/sh` does exist on the host, then asserts that `isDeviceRooted()` returns `false` regardless).

## JVM

### `KSafe.jvm.kt` — the factory + test extensions

A few hundred lines, down from ~1,360 pre-2.0. Owns:

- **Top-level `KSafe(fileName: String? = null, ..., baseDir: File? = null): KSafe`** — public factory.
- **Top-level `@PublishedApi internal fun KSafe(..., baseDir: File? = null, testEngine: KSafeEncryption)`** — test overload.
- **DataStore directory resolution.** If `baseDir == null` (default), uses `~/.eu_anifantakis_ksafe`. If a custom `baseDir` is supplied (e.g. `$XDG_DATA_HOME/myapp`, `%APPDATA%`, a per-test temp dir), KSafe uses that. Either way the directory is `mkdir`ed if missing and the local `secureDirectory(File)` helper applies POSIX `0700` permissions — the user-supplied path is hardened the same way as the default (this was the security fix on top of [PR #25](https://github.com/ioannisa/KSafe/pull/25)). The resolved file path is `"$baseDir/eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb"`.
- **Conditional backend selection (2.1.1+).** `createJvmBackend` (called through the shared `SharedBackendRegistry`, so same-file instances get one backend) probes `isSunMiscUnsafePresent()`. With `sun.misc.Unsafe` present (the normal case) it wires the usual DataStore (`PreferenceDataStoreFactory` → `DataStoreStorage`) + `JvmSoftwareEncryption` over the OS key vault. Absent (a trimmed Compose Desktop release distributable) it instead wires `DataStoreJsonStorage` + `JvmSoftwareEncryption(vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(...)))` — the no-`Unsafe` software backend — and prints a one-time `KSafe NOTICE`. On the OS-backed path it also runs `migrateJsonFallbackToOsBacked(...)` — draining the fallback forward — whenever a `.ksafe.json` fallback file is present **and is newer than the `.migrated` archive beside it**. An existence check alone would skip a second fallback period forever, since the archive is permanent. The `keyAlias` / `masterAlias` lambdas are hoisted to locals in `buildJvmKSafe` and threaded into both, so the core and the migration compute identical aliases; both build them from the shared `KSafeAliasFormat`.
- **`internal encodeBase64(bytes)` / `decodeBase64(text)`** — thin forwarders over the shared codec, which since 3.0.0 lives once in commonMain (`KSafeBase64.kt`) instead of being re-declared per platform. They remain declared *here* only because their callers — the JVM key vaults, which persist raw key bytes as Base64 text — are jvmMain-only. `encodeBase64` was public on the JVM through 2.2.1 and is internal from 3.0.0: it exposed nothing but a wrapper over the standard library's `Base64`, and the reason previously given for keeping it public (that the test suites need it) does not hold — KMP test compilations associate with main and already consume plain-`internal` declarations. The other targets declare nothing: their own helpers (`encodeBase64`/`decodeBase64` on Apple, `encodeBase64Web`/`decodeBase64Web` on js/wasmJs) were `@PublishedApi internal` with no callers at all, so folding them into `KSafeBase64` dropped four entries from the klib dump that nothing could have linked against.
- **`onClearAllCleanup`**, built inside `createJvmBackend` and handed to `KSafe(...)` as `backend.clearAllCleanup`, in two variants. It does NOT delete the live store file after `core.clearAll()` — DataStore's `edit { clear() }` already emptied it on the write consumer, and a raw `File.delete()` on the caller thread would race a concurrent consumer batch (e.g. a key mint during rotation) and strand an in-RAM-only key. It sweeps only stale residue: on the OS-backed path the quarantine copies (matched on the `${datastoreFile.name}.corrupt` prefix, which covers the `.corrupt-<ts>` copies this target writes) plus any `<base>.ksafe*` JSON-fallback files; on the no-`Unsafe` path the same residue **minus its own two live files**, which the write consumer wipes instead. The pre-2.0 PR #25 merge had a bug where the cleanup hardcoded the home dir, so it looked in the wrong place when `baseDir` was set; that's fixed.
- **Test-surface extensions** at the bottom of the file:
  - `@PublishedApi internal val KSafe.dataStore: DataStore<Preferences>` — extension property; reaches in via `(core.storage as DataStoreStorage).dataStore`. Used by `JvmKSafeTest` for whitebox DataStore access.
  - `@PublishedApi internal val KSafe.engine: KSafeEncryption` — extension property; just `core.engine`.
  - `@PublishedApi internal fun KSafe.updateCache(prefs: Preferences)` — extension function. Lets `JvmKSafeTest` deterministically merge a DataStore snapshot into the core's cache. Wraps `core.updateCache(...)` in `runBlocking`. (Pre-2.0 this was a member of `actual class KSafe`; option C couldn't keep it there because `KSafe` is now in commonMain.)

### `internal/JvmSoftwareEncryption.kt` — the engine

Implements `KSafeEncryption` via `javax.crypto` for the payload, building its ciphers from `JvmAesGcm` in `jvmSharedMain` — the frozen `"AES/GCM/NoPadding"` / 128-bit-tag / 12-byte-IV layout it shares with the Android engine. Notable specifics:

- The AES key is **not** kept in the DataStore — it's delegated to a `JvmKeyVault` (see `internal/keyvault/` below): an OS secret store per host (Windows DPAPI, macOS Keychain, Linux libsecret). Only the legacy/fallback paths keep a Base64 key outside the OS store: `DataStoreKeyVault` (`"ksafe_key_<alias>"` in the DataStore) when no OS store is reachable, or `FileKeyVault` (a standalone `.ksafe-keys.json` at `0700`) on the no-`Unsafe` JSON-storage fallback — both with a one-time warning.
- **Migration:** on first read for an alias, a key still in the legacy DataStore location is copied into the active OS vault and the file entry removed — but only after the OS vault is read back and byte-verified, so a buggy/again-unavailable keyring can't destroy the only copy.
- In-memory key cache (`ConcurrentHashMap<String, SecretKey>`) avoids repeated vault round-trips.
- A per-alias mutex (via `ConcurrentHashMap<String, Any>` for lock objects) prevents concurrent first-time key generation/migration under the same alias from racing; the same lock guards `deleteKey` so a delete can't race a cache repopulate.

### `internal/keyvault/` — the JVM OS secret-store abstraction

`JvmKeyVault` (get/put/delete + `name`/`isOsBacked`) with `JvmKeyVaultProvider` selecting one per host and self-testing it (canary round-trip) before use:

- `WindowsDpapiKeyVault` — `CryptProtectData`/`CryptUnprotectData` via jna-platform `Crypt32Util`; the wrapped blob is persisted Base64 in DataStore under `ksafe_dpapi_`.
- `MacosKeychainKeyVault` — `SecKeychainAddGenericPassword`/`Find`/`Delete` via JNA to `Security.framework` (login keychain generic-password items).
- `LinuxSecretServiceKeyVault` — `secret_password_store/lookup/clear_sync` via JNA to libsecret (login keyring).
- `DataStoreKeyVault` — the legacy Base64-in-DataStore scheme; also the migration source and last-resort fallback.
- `FileKeyVault` — the software vault for the no-`sun.misc.Unsafe` storage fallback: alias→Base64 in a standalone `.ksafe-keys.json` at `0700`, `isOsBacked = false`. Wired via `JvmKeyVaultProvider(legacyOverride = …)` rather than host detection (there's no DataStore to host `DataStoreKeyVault` in that mode).
- `KeyVaultFailures.kt` — the one `vaultUnavailable(...)` builder every host vault throws from. The phrase it carries is `KSafeEngineMessage.VAULT_UNAVAILABLE`, the same constant the core's failure classifier matches on: it separates "the key store is temporarily unreachable" from "the key is genuinely absent", and a vault that spelled it differently would have the orphan sweep read an outage as an absent key and delete live ciphertext.

Selection is overridable with `-Dksafe.jvm.keyVault=software` (or env `KSAFE_JVM_KEY_VAULT=software`) — used by the test suite and consumers who don't want OS-store integration. JNA (`net.java.dev.jna` + `jna-platform`) is a **JVM-target-only** dependency.

### `internal/DataStoreJsonStorage.kt` — the no-`Unsafe` storage backend

`KSafePlatformStorage` for the JVM fallback. `DataStoreFactory.create(serializer, produceFile)` with a custom JSON `Serializer<Map<String,String>>` instead of the Preferences protobuf (the sole `sun.misc.Unsafe` user) — keeps DataStore's atomic-write / single-process-coordinator / corruption-handling / fsync machinery but never loads the protobuf classes. Uses datastore-core's `java.io` serializer path, **not** the okio one: okio 3.x's multi-release jar fails bytecode verification (`VerifyError: Bad return type`) on a jlink-trimmed runtime. Flattens every `StoredValue` to its string form on disk (like web `LocalStorageStorage`); `KSafeCore` re-types on read. No new dependency — datastore-core is transitive via datastore-preferences.

### `internal/JvmFallbackMigration.kt` — fallback → OS-backed forward migration

`migrateJsonFallbackToOsBacked(...)`, called once on the OS-backed path when a `.ksafe.json` is present. Re-encrypts every fallback entry into the DataStore under the same alias — decrypt with the `FileKeyVault` software key, re-encrypt with the OS-backed engine (only the key store changes) — computing the alias statelessly from each entry's metadata through `KSafeCore.aliasForRecordedMeta`, the same producer the core's own read path uses rather than a re-derived copy. `JvmFallbackMigrationAliasLockstepTest` pins the two together. **Fallback values win** (at the transition the fallback is the just-active store), so a value changed on the fallback overwrites a stale earlier-migrated one. Per-entry protection / envelope version / unlock policy are preserved; plain entries copied verbatim. Archives the source files to `*.migrated` (rename, never delete) after a clean pass — failures leave the source to retry, and re-draining is idempotent. Runs in `runBlocking` at construction, gated on file existence so the common path is free. Covered by `JvmFallbackMigrationTest`.

### `internal/SecurityChecker.jvm.kt`

The only `expect` `jvmMain` still answers on its own — `KSafeConcurrent` and `KSafeSecureRandom` moved to `jvmSharedMain` (they were byte-identical to Android's), and `KSafeLog` to `datastoreMain`.

- `SecurityChecker` — `isDeviceRooted()` and `isEmulator()` are no-ops (return `false`) because they don't map to desktop and pretending they did would be dishonest. `isDebuggerAttached()` and `isDebugBuild()` are real implementations: the former scans `ManagementFactory.getRuntimeMXBean().inputArguments` for `-agentlib:jdwp` / `-Xdebug` / `-Xrunjdwp`; the latter asks the JVM whether assertions are enabled for the class, via `desiredAssertionStatus()`, so it reads `false` in a normal production launch and honours `-ea` / `-da`. Both swallow `Throwable`: a trimmed jlink runtime may lack `java.management`, and that must read as "no debugger" rather than fail construction.

## Web (js + wasmJs)

### `KSafe.web.kt` — the shared factory

A couple of hundred lines, down from ~1,052 pre-2.0, and living in `webMain` (shared by both `jsMain` and `wasmJsMain`). Owns:

- **Top-level `KSafe(fileName: String? = null, ...): KSafe`** — public factory. Three parameters are accepted for API parity and have no effect here: `memoryPolicy` and `plaintextCacheTtl`, because the policy is forced to `PLAIN_TEXT` (below) and that policy keeps no plaintext side cache to expire; and `lazyLoad`, which is passed to the core as `false` no matter what the caller asked for. The web target has no blocking cold load, so suppressing the collector would leave the cache empty for the whole session and every non-suspend read would serve its default.
- **Top-level `@PublishedApi internal fun KSafe(..., testEngine: KSafeEncryption)`** — test overload.
- **`memoryPolicy` is forced to `PLAIN_TEXT`.** WebCrypto is async-only, so decrypting from the sync `getDirect` path is impossible — the cache has to hold pre-decrypted strings. The factory passes `memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT` to `KSafeCore` regardless of what the consumer passed.
- **Storage prefix.** Every localStorage entry is prefixed with `ksafe.<appNamespace@><fileName>:` (or `ksafe.<appNamespace@>:` for the default store). Isolates multiple `KSafe` instances — and appNamespaces — in the same origin. The older flat `ksafe_<fileName>_` / `ksafe_default_` form is a pre-appNamespace legacy layout that is migrated forward; it now survives only as the namespace for the engine's IndexedDB key records, and no live localStorage data entry is written under it.
- **`suspend fun KSafe.awaitCacheReady()`** — top-level extension function. Delegates to `core.ensureCacheReadySuspend()`. Apps that want a deterministic first `getDirect` call it once at startup before rendering. Defined as an extension because `awaitCacheReady` is web-only — JVM/Android/iOS preload synchronously and don't need it.

### `internal/LocalStorageStorage.kt` — the storage adapter

Implements `KSafePlatformStorage` on top of localStorage.

- **Strings only.** `applyBatch` flattens every `StoredValue` variant to `.toString()` and writes via `localStorage.setItem`. On read, everything comes back as `StoredValue.Text`. `KSafeCore.convertStoredValue` reconstitutes the typed primitive using the request's `KSerializer` (the `builtInPrimitiveKindOrNull` dispatch path).
- **Change notification.** localStorage's `storage` event only fires for *other* tabs, so this adapter maintains a `MutableStateFlow<Map<String, StoredValue>>` that it re-emits after every `applyBatch` or `clear`. `snapshotFlow()` returns that flow.
- **`yield()` after each batch.** Browsers are single-threaded; without yielding, downstream collectors don't see the new snapshot before the caller's suspend function returns. This was the fix for a flaky `testStateFlowUnencrypted` caught during the web port.

### `internal/WebSoftwareEncryption.kt` — the engine

Implements `KSafeEncryption` via the WebCrypto **SubtleCrypto** API called directly. Overrides only the suspend variants; the blocking `encrypt` / `decrypt` throw `UnsupportedOperationException` pointing at the suspend versions. Newly minted AES-GCM keys honor `KSafeConfig.aesKeySize` (`BITS_128` or `BITS_256`) and are **non-extractable** (`extractable = false`); the live `CryptoKey` object is persisted in **IndexedDB** (DB `ksafe-keys`) — raw key bytes never reach JS. A legacy `"<storagePrefix>ksafe_key_<alias>"` raw key in `localStorage` (KSafe ≤ 2.0) is imported as non-extractable into IndexedDB and the `localStorage` entry deleted on first access; imported and existing keys retain their inherent size, and the AES-GCM framing matches the old default so prior ciphertext still decrypts.

### `internal/WebKeyStore.kt` (+ `WebKeyStoreJsSource.kt`, `WebKeyStoreOps.kt`) — expect/actual for WebCrypto + IndexedDB

`expect` surface (`webKeyEnsure` / `webKeyEncrypt` / `webKeyDecrypt` / `webKeyCopyIfAbsent` / `webKeyDelete` / `webKeyDeleteNoWait`) driving SubtleCrypto + IndexedDB. Payloads cross the boundary as Base64 strings so the bindings stay primitive-only; Promises are bridged to `suspend` via `kotlinx.coroutines.await`.

The algorithm itself has to live as JS *text* rather than Kotlin — it is one long chain of IndexedDB request/transaction callbacks and WebCrypto promises, and the two targets can only reach them through different interop mechanisms. It used to be written out per target, twice; it now lives once in **`WebKeyStoreJsSource.kt`** as `const val` source (both bindings need a compile-time constant string), leaving each target file with nothing but its binding and its caching of the built store: on `jsMain` a `js("…")` IIFE that **returns** the dispatcher function (Kotlin invokes it — referencing Kotlin params from inside `js(...)` is unreliable under the JS IR compiler and silently broke an earlier attempt); on `wasmJsMain` an `@JsFun` arrow, which cannot keep closure state between calls and so parks the built store in a global slot instead. That is the only difference left.

**`WebKeyStoreOps.kt`** holds the seven op tokens the two bindings and the JS dispatcher all pass. The dispatcher's routing has no default-reject — its fallthrough is `del` — so a token renamed on one side alone used to fall through and *delete* the key rather than error. Spelling them once removes that failure mode.

### `internal/WebInterop.kt` — expect/actual for localStorage

Single file of `expect fun` declarations: `localStorageGet/Set/Remove/Length/Key`, `currentTimeMillisWeb`, and `webCryptoSubtleAvailable` (which decides the `web_crypto_subtle_unavailable` note on `protectionInfo`). The `LocalStorageStorage` adapter, the engine and the factory are the only callers.

Why expect/actual: `jsMain` and `wasmJsMain` both need to call localStorage but through slightly different interop (plain `external` + `kotlinx.browser` on js; `@JsFun`-annotated externals on wasmJs).

### `internal/KSafeConcurrent.web.kt` / `internal/SecurityChecker.web.kt`

- `KSafeConcurrent` — plain `HashMap` / `HashSet` / `var value: Boolean`. Browsers are single-threaded; these never need locks. `runBlockingOnPlatform` throws, and both call paths web actually reaches catch that throw: `KSafeCore.ensureCacheReadyBlocking` (in `KSafeCoreRead.kt`), so a `getDirect` racing the async preload returns `defaultValue` instead of blocking; and `KSafeCore.cancel()`, whose bounded wait for an in-flight commit goes through the common-code `Job.joinBlockingWithin`, so `close()` on web cancels immediately rather than waiting. The only other caller of `joinBlockingWithin` — the shared DataStore backend's teardown wait — lives in `datastoreMain`, a source set web is not part of.
- `SecurityChecker` — no-ops, same reasoning as JVM.

### `jsMain/internal/` and `wasmJsMain/internal/`

Four files per target, all thin — each is a binding, never an algorithm:

- **`KSafeSecureRandom.{js,wasmJs}.kt`** — `actual fun fillSecureRandomChunk(out, offset, length)` via `crypto.getRandomValues`. js uses direct DOM bindings; wasmJs uses an `@JsFun`-bridged equivalent. The public `secureRandomBytes` above it lives in `webMain`, because the part worth sharing is the chunking: `getRandomValues` rejects a view longer than 65536 bytes, so a larger request is filled one chunk at a time.
- **`WebInterop.{js,wasmJs}.kt`** — target-specific `actual` bindings for localStorage, time, and the `crypto.subtle` probe.
- **`WebKeyStore.{js,wasmJs}.kt`** — the binding that builds the shared `WebKeyStoreJsSource` dispatcher and caches it (a module-scope closure on js, a global slot on wasmJs).
- **`KSafeLog.{js,wasmJs}.kt`** — `console.warn` / `console.error` routing, the one place where web's log actual differs from every other target's `println`.

Nothing platform-specific beyond binding style; behaviour on both targets is identical.

---

# Part 5 — where key features live

Quick lookup table: if you're tracking down a specific behaviour, this is the file you want.

| Feature | File |
|---|---|
| `KSafe` class itself (members defined once) | `commonMain/KSafe.kt` |
| Per-platform factory functions | `{android,apple,jvm,web}Main/KSafe.{platform}.kt` (Apple factory shared by iOS + macOS) |
| Custom storage directory (`baseDir` / `directory`) | `{android,apple,jvm}Main/KSafe.{platform}.kt` factories |
| 1.x → 2.0 path migration (`NSDocumentDirectory` → `NSApplicationSupportDirectory`) | `appleMain/KSafe.apple.kt` (`buildAppleKSafe`) — runs on iOS + macOS |
| Apple-platform backup-exclusion stance | `appleMain/KSafe.apple.kt` (`buildAppleKSafe`) — see KDoc rationale |
| Hot cache | `commonMain/internal/KSafeCore.kt` (state) + `internal/coreparts/KSafeCoreCacheMerge.kt` / `KSafeCoreRead.kt` |
| Write coalescing | `commonMain/internal/coreparts/KSafeCoreWriteConsumer.kt` (loop) + `KSafeCoreCommit.kt` (the batch) |
| Key rotation | `commonMain/internal/KSafeCore.kt` (`rotateKeys`) + the CAS in `internal/coreparts/KSafeCoreCommit.kt` |
| Alias / AAD routing, one `decryptEntry` | `commonMain/internal/coreparts/KSafeCoreRouting.kt` (+ the `KSafeCore` companion) |
| Reserved sentinels + alias grammar | `commonMain/internal/KSafeFactoryShared.kt` (`KSafeReservedKeys`, `KSafeAliasGrammar`, `KSafeAliasFormat`) |
| Engine↔core failure phrases | `commonMain/internal/KSafeEngineMessage.kt` + `internal/coreparts/KSafeCoreFailureClassification.kt` |
| `modeTransformer` callback (honors `useStrongBox` / `useSecureEnclave`) | `commonMain/internal/KSafeCore.kt` (constructor) — `promoteDefaultToIsolated` in `KSafeFactoryShared.kt`, wired per-platform in the factories |
| Orphan-ciphertext cleanup (DataStore side) | `commonMain/internal/coreparts/KSafeCoreStartup.kt` (`cleanupOrphanedCiphertext`) |
| Orphan-key cleanup (Apple Keychain side, iOS + macOS) | `appleMain/internal/KeychainOrphanCleanup.kt` |
| Corrupt-store quarantine + its `clearAll` sweep | `commonMain/internal/CorruptStoreSweep.kt` (+ `jvmSharedMain/internal/CorruptStoreQuarantine.kt`) |
| On-disk key naming | `commonMain/internal/KeySafeMetadataManager.kt` |
| Int ↔ Long cross-type migration | `commonMain/internal/coreparts/KSafeCoreValues.kt` (`convertStoredValue`) |
| Legacy-format read path | `commonMain/internal/KeySafeMetadataManager.kt` (`classifyStorageEntry`) |
| `ENCRYPTED_WITH_TIMED_CACHE` TTL | `commonMain/internal/KSafeCore.kt` (`plaintextCache`) |
| WebCrypto suspend crypto | `webMain/internal/WebSoftwareEncryption.kt` |
| StrongBox request wiring | `androidMain/internal/AndroidKeystoreEncryption.kt` |
| Secure Enclave ECIES wrapping (iOS + macOS) | `appleMain/internal/AppleKeychainEncryption.kt` |
| macOS jailbreak-check short-circuit | `appleMain/internal/SecurityChecker.apple.kt` (`isDeviceRooted` early-out for `OsFamily.MACOSX`) |
| `var x by ksafe(0)` and the `ksafe(0, key = "x")` handle | `commonMain/KSafeReference.kt` (the handle) + `commonMain/KSafeDelegate.kt` (the factory and the flow extensions) |
| Write-mode views (`ksafe.plain` / `.encrypted` / `.hardwareIsolated`) | `commonMain/KSafeModeViews.kt` (+ `:ksafe-compose` for their `mutableStateOf` / `rememberKSafeState`) |
| Sibling instances on one store (wipe, rotation adoption, live-key check) | `commonMain/internal/SiblingRegistry.kt` + `internal/coreparts/KSafeCoreClearAll.kt` / `KSafeCoreCommit.kt`; attached by each DataStore factory via `core.attachSiblings(backend.siblings)` |
| `getOrCreateSecret` | `commonMain/KSafeSecret.kt` |
| Root/debugger/emulator checks | `*Main/internal/SecurityChecker.*.kt` |
| `secureRandomBytes` CSPRNG | `*Main/internal/KSafeSecureRandom.*.kt` |
| `encrypted: Boolean` deprecated overloads | `commonMain/KSafe.kt` (members of `class KSafe`) |
| JVM whitebox test access (`ksafe.dataStore`, `ksafe.engine`, `ksafe.updateCache`) | `jvmMain/KSafe.jvm.kt` (extension functions/properties) |
| Web `ksafe.awaitCacheReady()` | `webMain/KSafe.web.kt` (extension function) |
| Biometric verification | **`:ksafe-biometrics` module** (separate artifact) |

---

# Part 6 — test source sets

The shape you need to know when adding a test: `commonTest/KSafeTest.kt` is an abstract base holding every test that runs on every platform; each platform test source set (`jvmTest`, `iosTest`, `macosTest`, `webTest`, `androidDeviceTest`) has its own `FooKSafeTest : KSafeTest()` overriding the one abstract member, `newKSafe(fileName)` — often forwarding a `testEngine` to the internal `KSafe(..., testEngine = ...)` overload. `commonTest` also holds the value-class tests and the shared helpers (`FakeEncryption.kt`, `TestData.kt`, `ByteArraySearch.kt`); the sister modules test under `:ksafe-biometrics/…` and `:ksafe-compose/…`. Some suites can only run against real hardware or OS state (Keychain semantics, StrongBox, DataStore file layout), which is why they live in per-platform source sets rather than `commonTest`.

Three suites in `commonTest` are *invariant* tests rather than behaviour tests, guarding the single-declaration-site rules the alias plane depends on:

- `KSafeSentinelRegistryTest` — every `KSafeReservedKeys` entry is actually rejected as a user key, behind both alias delimiters.
- `KSafeAliasInjectivityTest` — no two distinct stores or user keys can derive the same engine alias.
- `KSafeAliasDerivationLockstepTest` — an entry's alias and AAD survive a round-trip through its own persisted metadata, and the Keychain classifier's backward parse undoes the producer exactly.

`JvmFallbackMigrationAliasLockstepTest` in `jvmTest` does the same for the JVM fallback migration, which lives in `jvmMain` and so is out of `commonTest`'s reach.

The full per-source-set catalogue — which suite covers which behaviour, and why each lives where it does — is maintained in **[docs/TESTING.md](TESTING.md)**.

On-device Apple coverage that a Simulator/dev-host run can't give lives in **`ios-device-test/`** (its own `README.md`): `run-xctest.sh` runs a curated Swift XCTest, `run-full-suite.sh` runs the full `kotlin.test` suite via a signed `.app`.

---

# Appendix — how to read the code when chasing a bug

After the 2.0 refactor, the call chain through the library is short:

1. **Consumer call site.** E.g., `ksafe.put("k", 42)`.
2. **Inline reified body** in `commonMain/KSafe.kt` — the body is `core.putRaw(key, value, core.defaultEncryptedMode(), serializer<T>())`. This whole expression is inlined into the consumer's compiled bytecode at the call site, so at runtime there's no `KSafe` method frame at all.
3. **`KSafeCore`** in `commonMain/internal/KSafeCore.kt` — `putRaw` shadows `mode` with `modeTransformer(mode)` (a no-op only on JVM; `promoteDefaultToIsolated` on Android and Apple, and a `requireUnlockedDevice` clear on web), then runs the actual write. From there the trail continues into the `KSafeCore*.kt` files of `commonMain/internal/coreparts/` listed in Part 2 — `KSafeCorePutSuspend.kt` stages it, `KSafeCoreWriteConsumer.kt` batches it, `KSafeCoreCommit.kt` encrypts and commits it.
4. **`KSafePlatformStorage`** (`DataStoreStorage` / `LocalStorageStorage`) — what touches disk.
5. **`KSafeEncryption`** implementation — what touches the keystore / keychain / WebCrypto.

Almost every bug hunt in KSafe ends in `KSafeCore` (or one of its `coreparts` files) or in one of the four encryption engines. The platform shells are construction-only; once a `KSafe` is built, no platform-specific code runs on the read/write hot path — except the `modeTransformer` for puts on Android, Apple and web, and the `resolveKeyStorage` / `resolveKeyLevel` callbacks that `getKeyInfo` uses.

For handle and property-delegate paths (`ksafe(0, key = "x")`, `var x by ksafe(0)`, `ksafe.mutableStateOf(...)`, the flow delegates), the chain skips step 2 — they hold a non-reified `KSerializer<T>` captured at creation time and call `ksafe.core.getDirectRaw` / `core.putDirectRaw` directly, from `commonMain/KSafeReference.kt` and `commonMain/KSafeDelegate.kt`.

For biometric verification, you're in the wrong module — see `:ksafe-biometrics`.
