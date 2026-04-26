# Architecture

This is the conceptual model. For the file-by-file walk that maps these concepts to source paths, see **[docs/TOUR.md](TOUR.md)**.

## The three modules

KSafe ships as three independent artifacts:

| Module | Purpose | Depends on |
|---|---|---|
| **`:ksafe`** | Storage core: the `KSafe` class, hot cache, write coalescer, encryption engines, DataStore / `localStorage` adapters | nothing else in the project |
| **`:ksafe-compose`** | `ksafe.mutableStateOf(...)` Compose state delegates | `:ksafe` |
| **`:ksafe-biometrics`** | `KSafeBiometrics` standalone biometric verification (Face ID / Touch ID / fingerprint) | nothing else in the project |

The biometric module is fully independent of the storage core — apps that need only biometric prompts pull `:ksafe-biometrics` without paying for DataStore + DataStore-Preferences + the encryption engines, and apps that need only storage don't pull in `androidx.biometric` / `androidx.fragment`.

## The three rings inside `:ksafe`

```
┌──────────────────────────────────────────────────────────────────┐
│  Ring 1 — public API (commonMain, single-source)                 │
│  KSafe class · KSafeDelegate · KSafeWriteMode · KSafeConfig …    │
└────────────────────────────┬─────────────────────────────────────┘
                             │ ksafe.core
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  Ring 2 — KSafeCore orchestrator (commonMain/internal)           │
│  · Hot cache (KSafeConcurrentMap)                                │
│  · 16 ms write coalescer (Channel + edit-loop)                   │
│  · Metadata classifier · cross-type migration · orphan cleanup   │
│  · modeTransformer hook for the deprecated useStrongBox flags    │
└──────────┬────────────────────────────────────┬──────────────────┘
           │ storage                            │ engineProvider
           ▼                                    ▼
┌──────────────────────┐               ┌────────────────────────┐
│ KSafePlatformStorage │               │  KSafeEncryption       │
│ — "where bytes live" │               │  — "how they're        │
│                      │               │     encrypted"         │
└──────────┬───────────┘               └──────┬─────────────────┘
           │                                  │
   ┌───────┴────────┐                  ┌──────┴───────────┐
   ▼                ▼                  ▼                  ▼
┌──────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│DataStore │  │LocalStorage  │  │AndroidKeystore│ │IosKeychain   │
│Storage   │  │Storage       │  │JvmSoftware   │  │WebSoftware   │
│(Android, │  │(js + wasmJs) │  │Encryption    │  │Encryption    │
│ iOS, JVM)│  │              │  │              │  │              │
└──────────┘  └──────────────┘  └──────────────┘  └──────────────┘

  Ring 3 — per-platform shells: factory functions that build a
  KSafeCore by wiring up the right storage adapter + encryption engine,
  plus the ~3 platform-specific decisions each platform makes
  (StrongBox detection, Secure Enclave detection, file paths, etc.).
```

**Ring 1 is single-source.** `KSafe` is no longer an `expect class` — it's a regular Kotlin class declared once in `commonMain`. All inline reified members (`getDirect`, `put`, `get`, `getFlow`, `putDirect`, plus the deprecated `encrypted: Boolean` overloads) have their bodies in commonMain too. Construction happens through per-platform top-level `fun KSafe(...)` factory functions; Kotlin treats `KSafe(context, ...)` and a constructor invocation identically at the call site, so consumer code reads the same.

**Ring 2 is the orchestrator.** A single `KSafeCore` instance per `KSafe` holds all the cross-cutting state: the hot cache, the dirty-key set, the protection metadata, the write-coalescing channel, the JSON serializer. `KSafe`'s public methods delegate to `core.getDirectRaw(...)` / `core.putDirectRaw(...)` etc. Adding a new storage primitive or fixing a cache bug happens in one place.

**Ring 3 is construction-only.** The platform shells (`KSafe.android.kt`, `KSafe.ios.kt`, `KSafe.jvm.kt`, `KSafe.web.kt`) are factories that gather platform-specific dependencies (Android `Context`, file paths, hardware probes) and pass them to `KSafeCore`'s constructor. Once a `KSafe` instance exists, **no platform-specific Kotlin code runs on the read/write hot path** — every read and write goes through `KSafeCore`.

## The hot cache + write coalescer

KSafe's defining performance trait is that synchronous reads (`getDirect`) hit an atomic in-memory map and return in microseconds, while writes (`putDirect`) optimistically update the cache and queue a background flush.

**Reads (`getDirect`):** atomic memory lookup against `KSafeCore.memoryCache`. O(1). On the very first read after cold-start the call may suspend briefly to wait for the cache preload; once warm, all reads are instant. Safe to call on the UI thread.

**Writes (`putDirect`):** updates the memory cache **immediately** so subsequent reads see the new value. The write itself is queued onto an unbounded `Channel<PendingWrite>` consumed by a single coalescer coroutine that batches operations within a 16 ms window before calling `storage.applyBatch(ops)`. This collapses bursty writes (e.g. a slider moving) into one DataStore transaction.

**Cold-start safety.** If `getDirect` is called before the background preload finishes, it falls back to a one-shot blocking read so the value is correct. After that, the cache is warm and all reads are instant.

**Suspend variants exist** (`get`, `put`) for cases where the consumer wants to await the disk flush — payments, critical writes, or coroutine-context call sites that don't need the optimistic-write semantics.

### Three memory policies

What lives in the cache changes by policy:

| Policy | Cache contents | Read cost | Trade-off |
|---|---|---|---|
| `PLAIN_TEXT` | Decrypted plaintext (forever) | O(1) lookup | Fastest, but sensitive data sits in RAM |
| `ENCRYPTED` (default) | Base64 ciphertext only | AES-GCM decrypt every read | Nothing plaintext in RAM; slower per read |
| `ENCRYPTED_WITH_TIMED_CACHE` | Ciphertext + a TTL-bounded plaintext side cache | First read decrypts, subsequent reads within the TTL are O(1) | Compose / SwiftUI re-render scenarios where the same key is read many times |

Web is forced to `PLAIN_TEXT` regardless of what the consumer requests — WebCrypto is async-only, and the synchronous `getDirect` path can't decrypt on demand. The cache must hold pre-decrypted values.

## Cold-start preload + dirty-key tracking

The hot cache only works if there's a coherent rule for "where does the cache get its values when it doesn't have them yet?" In KSafe that rule is:

1. At construction time, `KSafeCore` launches a background coroutine that subscribes to `storage.snapshotFlow()` (DataStore's reactive snapshot).
2. The first emission populates the cache with everything currently on disk.
3. Subsequent emissions reflect external changes (other `KSafe` instances writing to the same file, edits done outside KSafe, deletions, etc.) and are merged into the cache.

This is also why KSafe's reads stay coherent in the face of concurrent writers — but it creates a race: what if a `putDirect` writes to the cache *while* a snapshot from disk is being applied to the cache?

The fix is **dirty-key tracking**. Every key with an in-flight write is added to a `dirtyKeys: KSafeConcurrentSet<String>`. When the snapshot collector merges new values into the cache, it skips any key in `dirtyKeys` — that's the "I have a pending write the disk doesn't know about yet" signal. The dirty flag is *never* cleared after a flush; once dirty, always dirty for the lifetime of the instance. This is deliberate: a snapshot from before the flush is irrecoverably stale and the optimistic in-memory write is the source of truth from that point forward. The trade-off is that the dirty set grows monotonically with the working set, but in practice the set's size tracks the user's actual key cardinality and the memory footprint is negligible.

**Cold-start fallback for sync reads.** A `getDirect` call that races the preload (the cache hasn't received its first snapshot yet) blocks once on `runBlockingOnPlatform { ensureCacheReadySuspend() }`, then proceeds with the now-warm cache. After cache warm-up, all reads are O(1) memory lookups. On Web the blocking path throws; the catch falls through to returning the caller's `defaultValue`, since browsers can't block the main thread.

## The two-interface decomposition

`KSafeCore` talks to two narrow interfaces. This is the abstraction that lets the orchestrator be platform-agnostic.

### `KSafePlatformStorage` — *where bytes live*

```kotlin
interface KSafePlatformStorage {
    suspend fun snapshot(): Map<String, StoredValue>
    fun snapshotFlow(): Flow<Map<String, StoredValue>>
    suspend fun applyBatch(ops: List<StorageOp>)
    suspend fun clear()
}
```

Two implementations:

- **`DataStoreStorage`** — wraps Jetpack DataStore Preferences. Lives in the `datastoreMain` intermediate source set, shared across Android, iOS, and JVM (all three use DataStore).
- **`LocalStorageStorage`** — wraps the browser's `localStorage`. Lives in `webMain`, shared between `jsMain` and `wasmJsMain`.

### `KSafeEncryption` — *how they're encrypted*

```kotlin
interface KSafeEncryption {
    fun encrypt(identifier: String, data: ByteArray, ...): ByteArray
    fun decrypt(identifier: String, ciphertext: ByteArray): ByteArray
    fun deleteKey(identifier: String)

    suspend fun encryptSuspend(...): ByteArray   // default delegates to blocking
    suspend fun decryptSuspend(...): ByteArray   // default delegates to blocking
    suspend fun deleteKeySuspend(...)            // default delegates to blocking
}
```

Four implementations, one per platform:

- **`AndroidKeystoreEncryption`** — AES-256-GCM with hardware-backed keys (StrongBox when requested + available). Keys are handles; the bytes never leave the TEE.
- **`IosKeychainEncryption`** — AES-256-GCM via CryptoKit; keys stored as Keychain `kSecClassGenericPassword` items with `…ThisDeviceOnly` accessibility (and Secure Enclave-backed ECIES wrapping for `HARDWARE_ISOLATED` writes).
- **`JvmSoftwareEncryption`** — AES-256-GCM via `javax.crypto`; keys stored Base64-encoded inside the same DataStore as the data, with the `~/.eu_anifantakis_ksafe/` directory enforced at POSIX `0700`.
- **`WebSoftwareEncryption`** — AES-256-GCM via WebCrypto; keys in `localStorage`. WebCrypto is async-only, so this engine **only** implements the suspend variants and throws from the blocking ones — `KSafeCore` calls the suspend path from every coroutine-context site.

## Protection tiers and the honesty pattern

Encrypted writes carry a protection tier — `KSafeProtection.DEFAULT` (the regular hardware-backed path) or `KSafeProtection.HARDWARE_ISOLATED` (StrongBox on Android, Secure Enclave on iOS). The tier decides where the *encryption key* lives at rest, not where the ciphertext lives:

- **`DEFAULT`**: AES-256 key in the platform Keystore / Keychain, hardware-backed on devices with a TEE. The key bytes never leave the secure element.
- **`HARDWARE_ISOLATED`**: a stronger guarantee, expressed differently per platform — Android requests `setIsStrongBoxBacked(true)` on the `KeyGenParameterSpec`, iOS creates an EC private key in the Secure Enclave (`kSecAttrTokenIDSecureEnclave`) and uses ECIES to wrap the AES key. The key generation hardware is physically separate from the main TEE.

Not every device has StrongBox or a Secure Enclave. KSafe handles this with a **silent fallback**: a write that requested `HARDWARE_ISOLATED` on a device without the hardware lands in regular `HARDWARE_BACKED` storage. The data is still protected; it just doesn't have the stronger isolation tier.

**The honesty pattern.** A caller who wrote with `HARDWARE_ISOLATED` is owed a way to ask "did that *actually* happen?" — for UI affordances ("stored in hardware-isolated chip") or for security audits. KSafe exposes this through `getKeyInfo(userKey): KSafeKeyInfo?`:

```kotlin
data class KSafeKeyInfo(
    val protection: KSafeProtection?,    // what was requested (or null for plain)
    val storage: KSafeKeyStorage,        // where the key actually lives
)
```

The two fields can disagree. A request of `HARDWARE_ISOLATED` on a phone without StrongBox returns `KSafeKeyInfo(HARDWARE_ISOLATED, HARDWARE_BACKED)` — "you asked for the strong tier, you got the regular tier, here's what we actually delivered." The library never lies about what it did.

## The Android `modeTransformer`

The deprecated `useStrongBox: Boolean` and `useSecureEnclave: Boolean` constructor flags promote default-protection encrypted writes to `HARDWARE_ISOLATED`. In 2.0 this is implemented as a `modeTransformer: (KSafeWriteMode) -> KSafeWriteMode` callback passed to `KSafeCore`'s constructor — Android passes `::promoteMode`, iOS passes its own, JVM and web pass identity. The transform runs once at the top of `putDirectRaw` / `putRaw`. This is the only platform-specific behaviour that crosses Ring 3 → Ring 2 on the write path.

## Cross-type migration

Reads automatically widen `Int → Long` and range-check-narrow `Long → Int` so an app that originally stored a counter as `Int` and later switched to `Long` (or vice versa) keeps working. Out-of-range narrowing returns the caller's `defaultValue` rather than silently truncating. Dispatch is done off the requested `KSerializer<T>`'s `PrimitiveKind`, not off the runtime class of the default — which is what makes the same code path correct on Kotlin/JS where `Float`, `Double`, and `Int` share a runtime representation.

## The reactive layer

KSafe's storage primitives are point-in-time (read this key, write this value). Apps usually want streams: "tell me when this key changes, with the current value as the first emission." The reactive layer is built on top of `KSafeCore.getFlowRaw(...)`, which maps `storage.snapshotFlow()` emissions through the same auto-detection / decryption logic the synchronous reads use, distinct-until-changed.

Three consumer-facing shapes wrap that primitive:

- **`getFlow(key, default): Flow<T>`** — cold flow, decoded per emission, emits whenever the underlying value changes from any source (this `KSafe` writing, another instance writing, an external edit, a delete).
- **`getStateFlow(key, default, scope): StateFlow<T>`** — hot flow with a known synchronous initial value resolved via `getDirect` (so consumers don't see a brief incorrect "default" emission before the first real value lands). Materialized through `Flow.stateIn(scope, Eagerly, initial)`.
- **`asMutableStateFlow(key, default, scope): MutableStateFlow<T>`** — full `MutableStateFlow` interface; setting `.value` persists through `KSafe.putDirect`, observing collects external updates back into the wrapper.

Each of these has a property-delegate alias (`asFlow`, `asStateFlow`, `asMutableStateFlow`) so consumers can write `val state: StateFlow<User> by ksafe.asStateFlow(...)`. The delegates capture a `KSerializer<T>` once at creation rather than re-resolving it per access — without that, every call site would re-inflate the entire serialization graph.

The reactive layer doesn't change the storage contract; it's pure projection over `getFlowRaw`. The hot cache, write coalescer, and decryption rules all run unchanged.

## On-disk format

Every stored value lands in storage under canonical raw keys:

- Value bytes: `__ksafe_value_<userKey>`
- Metadata: `__ksafe_meta_<userKey>__` (a small JSON blob with protection level, access policy)

Pre-1.7 KSafe used different conventions (`encrypted_<userKey>` for ciphertext, `__ksafe_prot_<userKey>__` for metadata) and `KeySafeMetadataManager` still reads those legacy formats — when a legacy key is next written or deleted, it gets rewritten in the canonical form. iOS additionally honors a per-`fileName` legacy variant from pre-1.8 builds.

For iOS specifically there's also a 1.x → 2.0 *path* migration: pre-2.0 the DataStore lived in `NSDocumentDirectory`; 2.0 defaults to `NSApplicationSupportDirectory`, and the factory transparently moves a legacy file across on first launch when the new path is empty.

## Orphan cleanup

There are two failure modes that can leave KSafe in an inconsistent state across reinstalls and crashes, and there's a separate cleanup mechanism for each.

**DataStore-side: stale ciphertext.** A write encrypts the value, stores the ciphertext in DataStore, then stores the encryption key in the platform Keystore / Keychain. If the app is uninstalled, on Android the DataStore file goes away but the Keystore entry survives uninstalls (it's per-package but per-device); on iOS the Keychain entry survives uninstalls outright. On reinstall, KSafe might find ciphertext on disk that it no longer has the key to decrypt — or, in the reverse direction, an uninstall that didn't fully clean up could leave a key in the Keystore for which there's no corresponding ciphertext.

`KSafeCore.cleanupOrphanedCiphertext()` handles the DataStore side: at startup, it probes every encrypted entry. If decryption fails with a "key not found" error, the entry is deleted from storage. If it fails with a "device is locked" error (a transient condition), it's left alone — the entry might decrypt fine on the next launch.

**iOS Keychain-side: stale Keychain entries.** The reverse problem on iOS specifically — a Keychain entry survives an app reinstall because Keychain items aren't tied to the app's filesystem container the way DataStore files are. On reinstall, KSafe finds Keychain entries that the new install's DataStore doesn't reference. `cleanupOrphanedKeychainEntries(...)` (in `iosMain/internal/KeychainOrphanCleanup.kt`) sweeps these on first launch: it reads `storage.snapshot()` to compute the live key set, scans Keychain generic-password and `kSecClassKey` items, and deletes any whose `kSecAttrAccount` doesn't match a live DataStore key. The two scans cover both the AES-key and the wrapped-EC-key shapes, so partially-failed `HARDWARE_ISOLATED` writes (a crash between SE-key creation and the wrapped-AES storage) get cleaned up too.

Both sweeps are idempotent and "best-effort": failures during cleanup are swallowed (`runCatching`) rather than blocking startup. If a sweep can't run today (locked device, simulator quirks), it'll run cleanly on the next launch.

## Error-propagation strategy

Decryption can fail for two distinct reasons, and KSafe handles them differently:

**Transient failures.** The device is locked, the Keychain is unavailable, the Keystore is in a bad state — conditions that should clear on retry. `KSafeCore.isTransientDecryptFailure(throwable)` recognises these (string-matched against the platform error messages: "Keystore", "device is locked", iOS Keychain interaction-not-allowed). When a read encounters a transient failure, the original exception is *re-thrown*; the caller sees a real error and can decide whether to retry, prompt the user to unlock, etc. Returning a silent `defaultValue` for transient errors would mask correctness bugs as if data was missing.

**Permanent failures.** Decryption fails because the key genuinely doesn't exist (uninstall left ciphertext behind, key was deleted, etc.). These look the same to user code as "no value stored" — KSafe returns `defaultValue` and adds the entry to the orphan cleanup list. The user-facing behaviour is correct (you get the default you asked for) and the storage gets cleaned up so future reads don't pay the cost.

This split was a real bug pre-2.0: only Android's read path re-threw transient errors; iOS and JVM swallowed them. 2.0's `KSafeCore.isTransientDecryptFailure` runs on every platform, so a locked device reliably surfaces to the caller for retry handling instead of being silently masked as "no data."

## Concurrency model

KSafe is thread-safe by construction. The hot cache, the dirty-keys set, and per-instance flags all use `expect/actual` concurrency primitives (`KSafeConcurrentMap`, `KSafeConcurrentSet`, `KSafeAtomicFlag`, `runBlockingOnPlatform`):

- JVM / Android: `java.util.concurrent.ConcurrentHashMap` + `AtomicBoolean`. `runBlockingOnPlatform` uses `runBlocking`.
- iOS: `kotlin.concurrent.AtomicReference` with copy-on-write semantics (Kotlin/Native lacks `ConcurrentHashMap`). `KSafeAtomicFlag` is backed by `AtomicInt(0/1)` because boxed `Boolean` doesn't have stable reference identity on Native.
- Web: plain `HashMap` / `HashSet` / `var Boolean`. The browser is single-threaded so locking is unnecessary. `runBlockingOnPlatform` throws — the one site that calls it (`KSafeCore.ensureCacheReadyBlocking`) catches and falls through to returning the caller's default, since browsers can't block their main thread.

The write-coalescer lives in a single coroutine that drains the channel and applies batches sequentially. There's no lock contention because there's exactly one consumer.

## What 2.0 changed vs. 1.x

In one paragraph: pre-2.0, `KSafe` was an `expect class` with most of its logic duplicated four times across `KSafe.{android,ios,jvm,web}.kt` (the cache, write coalescer, metadata, orphan cleanup, `*Raw` plumbing — ~5,900 lines of platform-shell code total). 2.0 hoists everything that isn't genuinely platform-specific into `KSafeCore` in commonMain (a single ~1,500-line orchestrator), promotes `KSafe` itself to a regular common class with per-platform factory functions, factors storage and encryption behind two narrow interfaces, and extracts biometric verification into a separate optional module. Bug fixes and feature additions ship once and apply everywhere instead of being implemented and tested four times. The platform shells dropped from ~5,900 lines to ~890 lines; the tests pass identically on every target.

For the file-by-file map of where each concept lives in source, see **[docs/TOUR.md](TOUR.md)**.
