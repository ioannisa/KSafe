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
│DataStore │  │LocalStorage  │  │AndroidKeystore│ │AppleKeychain │
│Storage   │  │Storage       │  │JvmSoftware   │  │WebSoftware   │
│(Android, │  │(js + wasmJs) │  │Encryption    │  │Encryption    │
│ iOS,     │  │              │  │              │  │              │
│ macOS,   │  │              │  │              │  │              │
│ JVM)     │  │              │  │              │  │              │
└──────────┘  └──────────────┘  └──────────────┘  └──────────────┘

  Ring 3 — per-platform shells: factory functions that build a
  KSafeCore by wiring up the right storage adapter + encryption engine,
  plus the ~3 platform-specific decisions each platform makes
  (StrongBox detection, Secure Enclave detection, file paths, etc.).
```

**Ring 1 is single-source.** `KSafe` is no longer an `expect class` — it's a regular Kotlin class declared once in `commonMain`. All inline reified members (`getDirect`, `put`, `get`, `getFlow`, `putDirect`, plus the deprecated `encrypted: Boolean` overloads) have their bodies in commonMain too. Construction happens through per-platform top-level `fun KSafe(...)` factory functions; Kotlin treats `KSafe(context, ...)` and a constructor invocation identically at the call site, so consumer code reads the same.

**Ring 2 is the orchestrator.** A single `KSafeCore` instance per `KSafe` holds all the cross-cutting state: the hot cache, the dirty-key set, the protection metadata, the write-coalescing channel, the JSON serializer. `KSafe`'s public methods delegate to `core.getDirectRaw(...)` / `core.putDirectRaw(...)` etc. Adding a new storage primitive or fixing a cache bug happens in one place.

**Ring 3 is construction-only.** The platform shells (`KSafe.android.kt`, `KSafe.apple.kt` for iOS + macOS, `KSafe.jvm.kt`, `KSafe.web.kt`) are factories that gather platform-specific dependencies (Android `Context`, file paths, hardware probes) and pass them to `KSafeCore`'s constructor. Once a `KSafe` instance exists, **no platform-specific Kotlin code runs on the read/write hot path** — every read and write goes through `KSafeCore`.

## The hot cache + write coalescer

KSafe's defining performance trait is that synchronous reads (`getDirect`) hit an atomic in-memory map and return in microseconds, while writes (`putDirect`) optimistically update the cache and queue a background flush.

**Reads (`getDirect`):** atomic memory lookup against `KSafeCore.memoryCache`. O(1). On the very first read after cold-start the call may suspend briefly to wait for the cache preload; once warm, all reads are instant. Safe to call on the UI thread.

**Writes (`putDirect`):** updates the memory cache **immediately** so subsequent reads see the new value. The write itself is queued onto an unbounded `Channel<PendingWrite>` consumed by a single coalescer coroutine that batches operations before calling `storage.applyBatch(ops)`. This collapses bursty writes (e.g. a slider moving) into one DataStore transaction.

**Suspend variants share the coalescer.** `suspend put` and `suspend delete` enqueue the same `PendingWrite.*` types but attach a `CompletableDeferred<Unit>` and `await()` it. The consumer completes those deferreds after `applyBatch` returns — propagating success, exceptions, or cancellation, so awaiting callers never hang on a crashed consumer. The visible consequence: 500 concurrent `suspend put` calls from independent coroutines amortise into a small handful of `applyBatch` transactions instead of 500 of them.

**The consumer loop is two-phase.** Phase 1 is a greedy drain: after `receive()`-ing the first write, it `tryReceive()`s in a tight loop until the channel is empty (or `maxBatchSize` is reached). This is what lets a 1000-write burst land in one batch instead of being chunked. Phase 2 is the 16 ms coalescing window — but it only opens when no write in the current batch carries a `completion`. If even one caller is awaiting, the batch flushes immediately so they don't sit idle; the window is purely there to absorb sparse fire-and-forget `putDirect` calls arriving over the next frame. A single sequential `ksafe.put(...)` therefore completes in ~one round-trip, not `~window + round-trip`.

**Inside the batch, encryption is parallelised.** `processBatch` deduplicates `PendingWrite.Encrypted` entries by user-key (so multiple writes to the same key in one window only encrypt the latest value), then runs the deduplicated encrypts concurrently inside a `coroutineScope { … }` with a `Semaphore(8)` cap. Hardware-keystore IPC pipelines instead of running serially — the bound prevents flooding Binder / Keychain on large batches but allows enough overlap to mask per-call IPC latency. The downstream `StorageOp` builder still iterates the original batch in order, preserving last-applied-wins semantics and legacy-cleanup deletes for duplicate keys. The visible effect: `ENCRYPTED` memory policy adds essentially no write overhead vs `PLAIN_TEXT`.

**Cold-start safety.** If `getDirect` is called before the background preload finishes, it falls back to a one-shot blocking read so the value is correct. After that, the cache is warm and all reads are instant.

### Four memory policies

What lives in the cache changes by policy:

| Policy | Cache contents | Read cost | Trade-off |
|---|---|---|---|
| `LAZY_PLAIN_TEXT` (default) | Base64 ciphertext at rest; plaintext appears in the side cache after first read of each key and stays | First read decrypts, subsequent reads O(1) forever | Cheapest cold start *and* fastest steady-state reads; same RAM exposure as `PLAIN_TEXT` for keys you've actually read |
| `PLAIN_TEXT` (discouraged) | Decrypted plaintext (forever, eagerly populated at cold start) | O(1) lookup | Cold start pays $O(n)$ Keystore round-trips up front; can push first-read latency into ANR territory on Android with thousands of encrypted keys |
| `ENCRYPTED` | Base64 ciphertext only | AES-GCM decrypt every read | Nothing plaintext in RAM at rest; slower per read |
| `ENCRYPTED_WITH_TIMED_CACHE` | Ciphertext + a TTL-bounded plaintext side cache | First read decrypts, subsequent reads within the TTL are O(1) | Compose / SwiftUI re-render scenarios where the same encrypted value is read many times per frame and you want plaintext evicted after a window |

Web is forced to `PLAIN_TEXT` regardless of what the consumer requests — WebCrypto is async-only, and the synchronous `getDirect` path can't decrypt on demand. The cache must hold pre-decrypted values.

## Cold-start preload + dirty-key tracking

The hot cache only works if there's a coherent rule for "where does the cache get its values when it doesn't have them yet?" In KSafe that rule is:

1. At construction time, `KSafeCore` launches a background coroutine that subscribes to `storage.snapshotFlow()` (DataStore's reactive snapshot).
2. The first emission populates the cache with everything currently on disk.
3. Subsequent emissions reflect external changes (other `KSafe` instances writing to the same file, edits done outside KSafe, deletions, etc.) and are merged into the cache.

This is also why KSafe's reads stay coherent in the face of concurrent writers — but it creates a race: what if a `putDirect` writes to the cache *while* a snapshot from disk is being applied to the cache?

The fix is **dirty-key tracking**. Every key with an in-flight write is added to a `dirtyKeys: KSafeConcurrentSet<String>`. When the snapshot collector merges new values into the cache, it skips any key in `dirtyKeys` — that's the "I have a pending write the disk doesn't know about yet" signal. The dirty flag is *never* cleared after a flush; once dirty, always dirty for the lifetime of the instance. This is deliberate: a snapshot from before the flush is irrecoverably stale and the optimistic in-memory write is the source of truth from that point forward. The trade-off is that the dirty set grows monotonically with the working set, but in practice the set's size tracks the user's actual key cardinality and the memory footprint is negligible.

**Cold-start fallback for sync reads.** A `getDirect` call that races the preload (the cache hasn't received its first snapshot yet) blocks once on `runBlockingOnPlatform { ensureCacheReadySuspend() }`, then proceeds with the now-warm cache. After cache warm-up, all reads are O(1) memory lookups. On Web the blocking path throws; the catch falls through to returning the caller's `defaultValue`, since browsers can't block the main thread.

**Parallel decrypt during preload (`PLAIN_TEXT` memory mode only).** When the cache is populated from disk and the memory policy is `PLAIN_TEXT`, every encrypted entry needs to be decrypted before it lands in the cache. The classification pass over the snapshot stays sequential (it mutates `validCacheKeys` and `protectionByKey`), but the actual `engine.decryptSuspend(...)` calls are deferred into a `pendingDecrypts` list and then flushed concurrently inside a `coroutineScope { … }` with a `Semaphore(8)` cap. Under v2 (2.0+) the master key is in the engine's in-process cache after construction, so each per-entry decrypt is a pure-CPU AES-GCM op rather than a Keystore IPC round-trip — the fan-out now parallelises CPU AES across cores instead of pipelining Binder calls, and per-key amortised cost falls to single-digit microseconds even on emulators. **The default `LAZY_PLAIN_TEXT` skips this pass entirely** — it stashes ciphertext into the cache exactly like `ENCRYPTED` and defers each decrypt to the first read of that key, so its cold start is essentially free regardless of how many encrypted keys are stored (only the orphan-cleanup probe runs, and that too is parallelised). `ENCRYPTED` and `ENCRYPTED_WITH_TIMED_CACHE` likewise skip the bulk decrypt at cold start. The bulk-decrypt pass is therefore only paid by callers who explicitly opt in to the (now discouraged) `PLAIN_TEXT` policy or by the Web target where it's forced.

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

- **`DataStoreStorage`** — wraps Jetpack DataStore Preferences. Lives in the `datastoreMain` intermediate source set, shared across Android, iOS, macOS, and JVM (all four use DataStore).
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
- **`AppleKeychainEncryption`** — AES-256-GCM via CryptoKit; keys stored as Keychain `kSecClassGenericPassword` items with `…ThisDeviceOnly` accessibility (and Secure Enclave-backed ECIES wrapping for `HARDWARE_ISOLATED` writes). One implementation, lives in `appleMain`, used by both iOS and native macOS — the Keychain Services + CryptoKit APIs are byte-for-byte identical between the two platforms; only the location of the Keychain database differs (per-app on iOS, per-user on macOS). On Apple Silicon and T2-equipped Intel Macs the Secure Enclave path works exactly as on iOS devices; on older Intel Macs without a T2 chip, SE key creation throws and the engine falls back to plain Keychain storage automatically (same fallback path that already covers iPhone 5/5C without an SE).
- **`JvmSoftwareEncryption`** — AES-256-GCM via `javax.crypto` for the payload, but the AES key itself is held by an **OS secret store** through the `JvmKeyVault` abstraction (`jvmMain/internal/keyvault/`), selected per host via JNA:
  - **Windows** → DPAPI (`CryptProtectData`/`CryptUnprotectData`, current-user scope). DPAPI only *wraps*, so the opaque blob is persisted Base64 in the DataStore file under a `ksafe_dpapi_` prefix — useless without the user's Windows login.
  - **macOS** → the login Keychain via `Security.framework` (`SecKeychainAddGenericPassword`/`Find`/`Delete` generic-password items). The Keychain stores the secret; SE-gated on Apple-Silicon/T2 Macs.
  - **Linux** → the Secret Service / libsecret login keyring (`secret_password_store/lookup/clear_sync`).
  - **Fallback** — when no OS store is reachable (headless Linux with no keyring, a JNA link failure, …) it degrades to the legacy scheme: the key Base64-encoded inside the same DataStore as the data, under `~/.eu_anifantakis_ksafe/` enforced at POSIX `0700`, plus a one-time `System.err` security warning.
  - **Migration (hybrid)** — a key written by KSafe ≤ 2.0 (Base64 in the DataStore file) is moved into the OS store **lazily** on first read, then scrubbed from the file **only after the OS store is read back and byte-verified** (a buggy/again-unavailable keyring that silently no-ops can't destroy the only copy). In addition, `migrateLegacyKeysSuspend()` runs once from `KSafeCore`'s first-snapshot background pass and **eagerly** sweeps every remaining legacy key the same way, so a key that's never read again doesn't linger in the file. The sweep is a no-op under the software fallback / opt-out. Opt out of OS-store use entirely with `-Dksafe.jvm.keyVault=software` (or env `KSAFE_JVM_KEY_VAULT=software`). JNA is a JVM-target-only dependency.
- **`WebSoftwareEncryption`** — AES-256-GCM via the WebCrypto **SubtleCrypto** API called directly (no longer through `cryptography-kotlin`). The AES key is generated/imported **non-extractable** (`extractable = false`) and its live `CryptoKey` object is persisted in **IndexedDB** — the raw key bytes are never exposed to JS or written to a readable location. *Values* still live in `localStorage` (`LocalStorageStorage`); only the key moved. A legacy `localStorage` raw key (KSafe ≤ 2.0) is imported as a non-extractable key into IndexedDB on first access and the `localStorage` entry deleted (same hybrid lazy + one-time background sweep as JVM, via `migrateLegacyKeysSuspend()`); the AES-GCM framing matches the old default so previously written ciphertext still decrypts. WebCrypto is async-only, so this engine **only** implements the suspend variants and throws from the blocking ones — `KSafeCore` calls the suspend path from every coroutine-context site.

## Protection tiers and the honesty pattern

Encrypted writes carry a protection tier — `KSafeProtection.DEFAULT` (the regular hardware-backed path) or `KSafeProtection.HARDWARE_ISOLATED` (StrongBox on Android, Secure Enclave on iOS). The tier decides where the *encryption key* lives at rest, not where the ciphertext lives:

- **`DEFAULT`**: AES-256 key in the platform Keystore / Keychain, hardware-backed on devices with a TEE. The key bytes never leave the secure element.
- **`HARDWARE_ISOLATED`**: a stronger guarantee, expressed differently per platform — Android requests `setIsStrongBoxBacked(true)` on the `KeyGenParameterSpec`, iOS / macOS create an EC private key in the Secure Enclave (`kSecAttrTokenIDSecureEnclave`) and use ECIES to wrap the AES key. The key generation hardware is physically separate from the main TEE.

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

The deprecated `useStrongBox: Boolean` and `useSecureEnclave: Boolean` constructor flags promote default-protection encrypted writes to `HARDWARE_ISOLATED`. In 2.0 this is implemented as a `modeTransformer: (KSafeWriteMode) -> KSafeWriteMode` callback passed to `KSafeCore`'s constructor — Android passes `::promoteMode`, the Apple-platform factory (iOS + macOS) passes its own, JVM and web pass identity. The transform runs once at the top of `putDirectRaw` / `putRaw`. This is the only platform-specific behaviour that crosses Ring 3 → Ring 2 on the write path.

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

For Apple platforms there's also a 1.x → 2.0 *path* migration: pre-2.0 the DataStore lived in `NSDocumentDirectory`; 2.0 defaults to `NSApplicationSupportDirectory`, and the factory transparently moves a legacy file across on first launch when the new path is empty. iOS is the original target of this migration (1.x shipped on iOS); on native macOS the factory uses the same code, which means no-op for fresh installs and seamless behaviour if anyone happens to have a legacy file there.

## Orphan cleanup

There are two failure modes that can leave KSafe in an inconsistent state across reinstalls and crashes, and there's a separate cleanup mechanism for each.

**DataStore-side: stale ciphertext.** A write encrypts the value, stores the ciphertext in DataStore, then stores the encryption key in the platform Keystore / Keychain. If the app is uninstalled, on Android the DataStore file goes away but the Keystore entry survives uninstalls (it's per-package but per-device); on iOS / macOS the Keychain entry survives uninstalls outright (Keychain items are not tied to the app's filesystem container). On reinstall, KSafe might find ciphertext on disk that it no longer has the key to decrypt — or, in the reverse direction, an uninstall that didn't fully clean up could leave a key in the Keystore for which there's no corresponding ciphertext.

`KSafeCore.cleanupOrphanedCiphertext()` handles the DataStore side: at startup, it probes every encrypted entry. If decryption fails with a "key not found" error, the entry is deleted from storage. If it fails with a "device is locked" error (a transient condition), it's left alone — the entry might decrypt fine on the next launch. The probes run concurrently inside a `coroutineScope { … }` with a `Semaphore(8)` cap (same pattern as the write coalescer's parallel encrypt and the preload's parallel decrypt) — sweeping a 1500-key store completes in milliseconds rather than seconds, so it doesn't visibly delay the first read on apps with many encrypted entries.

**Apple Keychain-side: stale Keychain entries.** The reverse problem on iOS / macOS — a Keychain entry survives an app reinstall because Keychain items aren't tied to the app's filesystem container the way DataStore files are. On reinstall, KSafe finds Keychain entries that the new install's DataStore doesn't reference. `cleanupOrphanedKeychainEntries(...)` (in `appleMain/internal/KeychainOrphanCleanup.kt`) sweeps these on first launch: it reads `storage.snapshot()` to compute the live key set, scans Keychain generic-password and `kSecClassKey` items, and deletes any whose `kSecAttrAccount` doesn't match a live DataStore key. The two scans cover both the AES-key and the wrapped-EC-key shapes, so partially-failed `HARDWARE_ISOLATED` writes (a crash between SE-key creation and the wrapped-AES storage) get cleaned up too.

The Apple sweep is **destructive in a way the DataStore sweep is not** — once an SE EC private key is removed from the Secure Enclave it cannot be recreated, so any ciphertext encrypted under it becomes permanently undecryptable. Two structural invariants protect against accidental destruction:

1. **`startBackgroundCollector` runs the sweep only after the first `snapshotFlow` emission.** This guarantees DataStore has finished its initial read before the sweep computes "what's a live key" — closing a race window where the 1.x → 2.0 path migration in `KSafe.apple.kt` (which moves the file from `NSDocumentDirectory` to `NSApplicationSupportDirectory` immediately before DataStore is constructed) could deliver an empty snapshot to a sweep that would then nuke every legitimate key. (The pre-fix ordering hit exactly this on real devices upgrading directly from 1.8.x to 2.0.0-RC2; see CHANGELOG `2.0.0 → Fixed`.)
2. **The sweep refuses to delete when `snapshot.isEmpty() && orphanedKeyIds.isNotEmpty()`.** "DataStore reports zero entries but the Keychain has scoped items" is the signature of a partial view (failed migration, corrupted DataStore, OS-level data wipe that left the Keychain alone) — and in every one of those scenarios deleting the Keychain destroys irrecoverable state. The guard logs a message pointing at `KSafe.clearAll()` for users who genuinely intended a wipe, and the regression test [`KSafeCoreStartupOrderingTest`](../ksafe/src/jvmTest/kotlin/eu/anifantakis/lib/ksafe/KSafeCoreStartupOrderingTest.kt) in jvmTest pins both invariants in place.

Both sweeps are idempotent and "best-effort": failures during cleanup are swallowed (`runCatching`) rather than blocking startup. If a sweep can't run today (locked device, simulator quirks), it'll run cleanly on the next launch.

## Error-propagation strategy

Decryption can fail for two distinct reasons, and KSafe handles them differently:

**Transient failures.** The device is locked, the Keychain is unavailable, the Keystore is in a bad state — conditions that should clear on retry. `KSafeCore.isTransientDecryptFailure(throwable)` recognises these (string-matched against the platform error messages: "Keystore", "device is locked", iOS Keychain interaction-not-allowed). When a read encounters a transient failure, the original exception is *re-thrown*; the caller sees a real error and can decide whether to retry, prompt the user to unlock, etc. Returning a silent `defaultValue` for transient errors would mask correctness bugs as if data was missing.

**Permanent failures.** Decryption fails because the key genuinely doesn't exist (uninstall left ciphertext behind, key was deleted, etc.). These look the same to user code as "no value stored" — KSafe returns `defaultValue` and adds the entry to the orphan cleanup list. The user-facing behaviour is correct (you get the default you asked for) and the storage gets cleaned up so future reads don't pay the cost.

This split was a real bug pre-2.0: only Android's read path re-threw transient errors; iOS and JVM swallowed them. 2.0's `KSafeCore.isTransientDecryptFailure` runs on every platform, so a locked device reliably surfaces to the caller for retry handling instead of being silently masked as "no data."

## Concurrency model

KSafe is thread-safe by construction. The hot cache, the dirty-keys set, and per-instance flags all use `expect/actual` concurrency primitives (`KSafeConcurrentMap`, `KSafeConcurrentSet`, `KSafeAtomicFlag`, `runBlockingOnPlatform`):

- JVM / Android: `java.util.concurrent.ConcurrentHashMap` + `AtomicBoolean`. `runBlockingOnPlatform` uses `runBlocking`.
- iOS / macOS: `kotlin.concurrent.AtomicReference` with copy-on-write semantics (Kotlin/Native lacks `ConcurrentHashMap`). `KSafeAtomicFlag` is backed by `AtomicInt(0/1)` because boxed `Boolean` doesn't have stable reference identity on Native. The implementation lives in `appleMain` and is shared by all five Apple targets.
- Web: plain `HashMap` / `HashSet` / `var Boolean`. The browser is single-threaded so locking is unnecessary. `runBlockingOnPlatform` throws — the one site that calls it (`KSafeCore.ensureCacheReadyBlocking`) catches and falls through to returning the caller's default, since browsers can't block their main thread.

The write-coalescer lives in a single coroutine that drains the channel and applies batches sequentially. There's no lock contention because there's exactly one consumer.

## What 2.0 changed vs. 1.x

In one paragraph: pre-2.0, `KSafe` was an `expect class` with most of its logic duplicated four times across `KSafe.{android,ios,jvm,web}.kt` (the cache, write coalescer, metadata, orphan cleanup, `*Raw` plumbing — ~5,900 lines of platform-shell code total). 2.0 hoists everything that isn't genuinely platform-specific into `KSafeCore` in commonMain (a single ~1,500-line orchestrator), promotes `KSafe` itself to a regular common class with per-platform factory functions, factors storage and encryption behind two narrow interfaces, and extracts biometric verification into a separate optional module. Bug fixes and feature additions ship once and apply everywhere instead of being implemented and tested four times. The platform shells dropped from ~5,900 lines to ~890 lines; the tests pass identically on every target.

2.0.1 then folded `iosMain` into `appleMain` so the same Keychain + CryptoKit + Secure Enclave code now serves both iOS and native macOS — the iOS implementation never reached for UIKit, so the merge was mechanical: file moves + `Ios*` → `Apple*` renames + a single behaviour fix in `SecurityChecker` (jailbreak-style path probes short-circuit on macOS, where `/bin/sh` and friends exist on every host).

For the file-by-file map of where each concept lives in source, see **[docs/TOUR.md](TOUR.md)**.
