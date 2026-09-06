# Architecture

This is the conceptual model. For the file-by-file walk that maps these concepts to source paths, see **[docs/TOUR.md](TOUR.md)**.

## The three modules

KSafe ships as three independent artifacts:

| Module | Purpose | Depends on |
|---|---|---|
| **`:ksafe`** | Storage core: the `KSafe` class, hot cache, write coalescer, encryption engines, and the adapters over the two backing stores — Jetpack DataStore (a file-backed key-value store, used on Android, iOS, macOS and JVM Desktop) and the browser's `localStorage` | nothing else in the project |
| **`:ksafe-compose`** | `ksafe.mutableStateOf(...)` Compose state delegates | `:ksafe` |
| **`:ksafe-biometrics`** | `KSafeBiometrics` standalone process-wide biometric gate with **real OS prompts on every platform that exposes one** | nothing else in the project |

The biometric module is fully independent of the storage core — apps that need only biometric prompts pull `:ksafe-biometrics` without paying for DataStore + DataStore-Preferences + the encryption engines, and apps that need only storage don't pull in `androidx.biometric` / `androidx.fragment`.

`KSafeBiometrics` is a zero-config static `object` — no instance, no DI. `verifyBiometric(...)` shows a real system prompt on Android, iOS, macOS, JVM Desktop **and** the web: JVM-on-macOS uses `LocalAuthentication` (Touch ID / password), JVM-on-Windows uses `UserConsentVerifier` (Windows Hello), and JS/WasmJS use the browser's WebAuthn platform authenticator (shipped 2.2.1). `biometricsAvailable()` reports whether a real prompt would appear.

Where no prompt path exists, `verifyBiometric` returns `true` — an unconditional pass — so shared `commonMain` code can call it without branching per platform. That covers JVM on Linux, the iOS Simulator, a browser with no platform authenticator, and the explicit opt-outs (`-Dksafe.biometrics.jvm.prompts=off`, `KSafeBiometricsWeb.promptsEnabled = false`). Two limits on that rule: a browser without a platform authenticator passes through only while `allowDeviceCredentialFallback` is on, and a JVM Desktop bridge that fails to load passes through only for a permissive call — a strict call (`allowDeviceCredentialFallback = false`) refuses and logs why, because a failed load is a runtime fault, not a platform that has no prompts. `biometricsAvailable()` reports `false` in every one of these cases, so gate on it when you need a hard refusal. See [BIOMETRICS.md](BIOMETRICS.md).

## The three rings inside `:ksafe`

```
┌──────────────────────────────────────────────────────────────────┐
│  Ring 1 — public API (commonMain, single-source)                 │
│  KSafe class · KSafeReference · KSafeWriteMode · KSafeConfig …   │
└────────────────────────────┬─────────────────────────────────────┘
                             │ ksafe.core
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  Ring 2 — KSafeCore orchestrator (commonMain/internal)           │
│  · Hot cache (KSafeConcurrentMap)                                │
│  · 16 ms write coalescer (Channel + edit-loop)                   │
│  · Metadata classifier · cross-type migration · orphan cleanup   │
│  · modeTransformer hook — per-platform write-mode adjustment     │
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

**Ring 1 is single-source.** `KSafe` is no longer an `expect class` — it's a regular Kotlin class declared once in `commonMain`. (An `expect class` is Kotlin Multiplatform's way of declaring a type once and implementing it separately per platform, so any shared logic inside it had to be written out once per platform.) All the inline members (`getDirect`, `put`, `get`, `getFlow`, `putDirect`, plus the deprecated `encrypted: Boolean` overloads) have their bodies in commonMain too. Construction happens through per-platform top-level `fun KSafe(...)` factory functions; Kotlin treats `KSafe(context, ...)` and a constructor invocation identically at the call site, so consumer code reads the same.

**Ring 2 is the orchestrator.** A single `KSafeCore` instance per `KSafe` holds all the cross-cutting state: the hot cache, the dirty-key set, the protection metadata, the write-coalescing channel, the JSON serializer. `KSafe`'s public methods delegate to `core.getDirectRaw(...)` / `core.putDirectRaw(...)` etc. Adding a new storage primitive or fixing a cache bug happens in one place.

**Ring 3 is construction-only.** The platform shells (`KSafe.android.kt`, `KSafe.apple.kt` for iOS + macOS, `KSafe.jvm.kt`, `KSafe.web.kt`) are factory functions that gather what only that platform can supply — an Android `Context`, file paths, hardware probes — and hand it to `KSafeCore`'s constructor. Once a `KSafe` exists, no *shell* code runs on the read/write path: every read and write goes through `KSafeCore`.

What does still run there is what the shell handed over: the storage adapter on every commit, the encryption engine on every encrypted read and write, the `modeTransformer` at the top of every put, and the `resolveKeyStorage` / `resolveKeyLevel` callbacks inside `getKeyInfo`. All four reach `KSafeCore` as interfaces or function parameters, which is what keeps the orchestrator itself platform-agnostic — it can be exercised in a common test with a fake engine and an in-memory store.

## The hot cache + write coalescer

KSafe's defining performance trait is that synchronous reads (`getDirect`) hit an atomic in-memory map and — under plaintext policies — return in microseconds, while writes (`putDirect`) optimistically update the cache and queue a background flush.

**Reads (`getDirect`).** A read is an atomic lookup in `KSafeCore.memoryCache`. What it costs depends on the memory policy and on the entry:

- under a plaintext policy (`LAZY_PLAIN_TEXT`, `PLAIN_TEXT`), a warm read is an O(1) memory lookup — microseconds;
- under `ENCRYPTED`, and always for a `requireUnlockedDevice` entry whatever the policy, the cache holds ciphertext, so every read decrypts on the calling thread. That is userspace AES on Apple, JVM and Android-`DEFAULT`, where the key is already in memory — but a per-operation trip into the security hardware for a strict or hardware-isolated entry on Android;
- the very first read after cold start may block once while the cache preload finishes (see below).

So `getDirect` is a *non-suspending hot-cache read*, not a universally free one. Under the default `LAZY_PLAIN_TEXT` it is fine on the UI thread. If you put strict or hardware-isolated entries behind it, measure before reading them per frame.

**Writes (`putDirect`):** updates the memory cache **immediately** so subsequent reads see the new value. The write itself is queued onto an unbounded `Channel<PendingWrite>` consumed by a single coalescer coroutine that batches operations before calling `storage.applyBatch(ops)`. This collapses bursty writes (e.g. a slider moving) into one DataStore transaction. The unbounded queue is a deliberate trade-off: fire-and-forget writes never block or drop, but a producer that sustains a higher rate than the encrypt/commit drain (bulk imports, per-frame `putDirect` loops — plausible when every write is a hardware-keystore round-trip) holds every pending value in process memory until persisted. There is no drop/overflow policy because silently discarding an already-cache-acknowledged write would be worse; high-rate writers should use the suspending `put`, whose await naturally paces the producer.

**Suspend variants share the coalescer.** `suspend put` and `suspend delete` enqueue the same `PendingWrite.*` types but attach a `CompletableDeferred<Unit>` and `await()` it. The consumer completes those deferreds after `applyBatch` returns — propagating success, exceptions, or cancellation, so awaiting callers never hang on a crashed consumer. The visible consequence: 500 concurrent `suspend put` calls from independent coroutines amortise into a small handful of `applyBatch` transactions instead of 500 of them.

**The consumer loop is two-phase.** Phase 1 is a greedy drain: after `receive()`-ing the first write, it `tryReceive()`s in a tight loop until the channel is empty (or `maxBatchSize` is reached). This lets a burst of up to `maxBatchSize` (200) writes coalesce into one batch instead of one `applyBatch` per write; a larger burst splits into successive 200-op batches. Phase 2 is the 16 ms coalescing window — but it only opens when no write in the current batch carries a `completion`. If even one caller is awaiting, the batch flushes immediately so they don't sit idle; the window is purely there to absorb sparse fire-and-forget `putDirect` calls arriving over the next frame. A single sequential `ksafe.put(...)` therefore completes in ~one round-trip, not `~window + round-trip`.

**Inside the batch, encryption is parallelised.** `processBatch` deduplicates the batch by user-key across *all* write types (plain, encrypted, delete, rotate) — building a `finalByKey` map that keeps the last pending write per key, where a `Rotate` never displaces a same-batch user write — then derives the encrypt set from that map and runs those encrypts concurrently inside a `coroutineScope { … }` with a `Semaphore(8)` cap. Calls into the hardware key store are inter-process calls — the app asks the OS key daemon to do the work and waits for the answer — so eight in flight overlap their round-trips instead of queueing. The bound is there because unbounded fan-out floods Android's Binder transport (the channel those calls travel over) or the Apple Keychain and starves the dispatcher. The downstream `StorageOp` builder iterates that deduplicated `finalByKey` map, preserving last-applied-wins semantics and emitting legacy-cleanup deletes for each surviving key. The visible effect: `ENCRYPTED` memory policy adds essentially no write overhead vs `PLAIN_TEXT`.

**Cold-start safety.** A `getDirect` that arrives before the preload has finished blocks once and loads the cache itself, so the value it returns is correct — except on Web, which cannot block. See **Cold-start fallback for sync reads** below.

### Four memory policies

What lives in the cache changes by policy:

| Policy | Cache contents | Read cost | Trade-off |
|---|---|---|---|
| `LAZY_PLAIN_TEXT` (default) | Base64 ciphertext at rest; plaintext appears in the side cache after first read of each key and stays | First read decrypts, subsequent reads O(1) forever | Cheapest cold start *and* fastest steady-state reads; same RAM exposure as `PLAIN_TEXT` for keys you've actually read |
| `PLAIN_TEXT` (discouraged) | Decrypted plaintext (forever, eagerly populated at cold start) | O(1) lookup | Cold start pays one Keystore round-trip per encrypted key up front; with thousands of them that can push first-read latency far enough that Android declares the app unresponsive (an ANR) |
| `ENCRYPTED` | Base64 ciphertext only | AES-GCM decrypt every read | Nothing plaintext in RAM at rest; slower per read |
| `ENCRYPTED_WITH_TIMED_CACHE` | Ciphertext + a TTL-bounded plaintext side cache | First read decrypts, subsequent reads within the TTL are O(1) | Compose / SwiftUI re-render scenarios where the same encrypted value is read many times per frame and you want plaintext evicted after a window |

Web is forced to `PLAIN_TEXT` regardless of what the consumer requests — WebCrypto is async-only, and the synchronous `getDirect` path can't decrypt on demand. The cache must hold pre-decrypted values.

## Cold-start preload + dirty-key tracking

The hot cache only works if there's a coherent rule for "where does the cache get its values when it doesn't have them yet?" In KSafe that rule is:

1. At construction time — unless the factory was given `lazyLoad = true` — `KSafeCore` launches a background coroutine that subscribes to `storage.snapshotFlow()` (DataStore's reactive snapshot). Under `lazyLoad` there is no collector: the first synchronous read loads the cache itself, and triggers the one-time startup cleanup off-thread. Web ignores `lazyLoad` and always runs the preload, because it has no blocking cold-load to fall back on.
2. The first emission populates the cache with everything currently on disk.
3. Subsequent emissions reflect external changes (other `KSafe` instances writing to the same file, edits done outside KSafe, deletions, etc.) and are merged into the cache.

This is also why KSafe's reads stay coherent in the face of concurrent writers — but it creates a race: what if a `putDirect` writes to the cache *while* a snapshot from disk is being applied to the cache?

The fix is **dirty-key tracking**. Every key with an in-flight write is added to a `dirtyKeys: KSafeConcurrentSet<String>`. When the snapshot collector merges new values into the cache, it skips any key in `dirtyKeys` — that's the "I have a pending write the disk doesn't know about yet" signal. A successful flush never clears the dirty flag: once a key is dirty it stays dirty for the life of the instance. (The one exception is a write whose commit *fails* — its rollback removes the flags it set, so the key can be repopulated from disk.) This is deliberate: a snapshot from before the flush is irrecoverably stale and the optimistic in-memory write is the source of truth from that point forward. The trade-off is that the dirty set grows monotonically with the working set, but in practice the set's size tracks the user's actual key cardinality and the memory footprint is negligible. One consequence for reads: because a successful write's dirty flag never clears, `getDirect` and delegate reads of a key *this* instance has written won't reflect later *external* changes to that key — the optimistic in-memory value wins. Storage-backed Flows (`getFlowRaw`) re-read raw snapshots and *do* surface those external changes.

**Cold-start fallback for sync reads.** A `getDirect` call that races the preload (the cache hasn't received its first snapshot yet) blocks once inside `ensureCacheReadyBlocking()`, which takes a snapshot from storage and merges it, then proceeds with the now-warm cache. If another merge lands while that cold read is loading the cache, the snapshot the read took may already be stale, so it re-reads the store and merges the fresh one instead. Nothing waits on the collector, so a blocked reader can never hold the thread the collector needs. After the cache is warm, reads are memory lookups again (still decrypting per read under the ciphertext-at-rest policies). On Web the blocking path throws; the catch falls through to returning the caller's `defaultValue`, since browsers can't block the main thread.

**Parallel decrypt during preload (`PLAIN_TEXT` memory mode only).** When the cache is populated from disk and the memory policy is `PLAIN_TEXT`, every encrypted entry needs to be decrypted before it lands in the cache. The classification pass over the snapshot stays sequential (it mutates `validCacheKeys` and `protectionByKey`), but the actual `engine.decryptSuspend(...)` calls are deferred into a `pendingDecrypts` list and then flushed concurrently inside a `coroutineScope { … }` with a `Semaphore(8)` cap. The master key's raw bytes are cached in-process (Apple and JVM since 2.0; Android as of **2.1.2**, where a non-exportable master key held in the **TEE** — Android's on-chip Trusted Execution Environment, described with `AndroidKeystoreEncryption` below — wraps an in-memory data-encryption key that is unwrapped once), so each per-entry decrypt is a pure-CPU AES-GCM op rather than a keystore round-trip — the fan-out parallelises CPU AES across cores instead of pipelining Binder calls, and per-key amortised cost falls to single-digit microseconds. (Before 2.1.2 the Android path round-tripped the Keystore/TEE on every decrypt — invisible on an emulator's software keystore but ~8 ms/op on real hardware.) **The default `LAZY_PLAIN_TEXT` skips this pass entirely** — it stashes ciphertext into the cache exactly like `ENCRYPTED` and defers each decrypt to the first read of that key, so its cold start is essentially free regardless of how many encrypted keys are stored (only the orphan-cleanup probe runs, and that too is parallelised). `ENCRYPTED` and `ENCRYPTED_WITH_TIMED_CACHE` likewise skip the bulk decrypt at cold start. The bulk-decrypt pass is therefore only paid by callers who explicitly opt in to the (now discouraged) `PLAIN_TEXT` policy or by the Web target where it's forced.

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

- **`DataStoreStorage`** — wraps Jetpack DataStore Preferences. Lives in the `datastoreMain` *intermediate source set* — code compiled into more than one platform but not all of them; here, the four platforms that use DataStore: Android, iOS, macOS and JVM Desktop.
- **`LocalStorageStorage`** — wraps the browser's `localStorage`. Lives in `webMain`, shared between `jsMain` and `wasmJsMain`.

### `KSafeEncryption` — *how they're encrypted*

```kotlin
interface KSafeEncryption {
    fun encrypt(identifier: String, data: ByteArray, ..., aad: ByteArray? = null): ByteArray
    fun decrypt(identifier: String, data: ByteArray, ..., aad: ByteArray? = null): ByteArray
    fun deleteKey(identifier: String)

    // Apple re-accessibility (SecItemUpdate); no-op elsewhere
    fun updateKeyAccessibility(identifier: String, requireUnlocked: Boolean) { }
    // the backing store was wiped (clearAll) — drop in-store key caches (JVM vault; Android software-DEK cache)
    fun onStoreCleared() { }

    suspend fun encryptSuspend(..., aad: ByteArray? = null): ByteArray  // default delegates to blocking
    suspend fun decryptSuspend(..., aad: ByteArray? = null): ByteArray  // default delegates to blocking
    suspend fun deleteKeySuspend(...)                                   // default delegates to blocking

    suspend fun prewarmKey(...)                 // default: encrypt 0 bytes to mint the key
    suspend fun prewarmDekReadIfPresent(...)    // warms an existing DEK; never creates one
    suspend fun migrateLegacyKeysSuspend()      // idempotent sweep of legacy key material
}
```

Three of those members are worth a sentence each.

- **`aad`** — *associated data*: bytes that are authenticated but not encrypted. Decryption must present exactly the same bytes, or the AES-GCM tag check fails and the read errors out. This is the hook the v3 envelope rides on.
- **`updateKeyAccessibility`** — re-points an existing entry's lock policy in place. Only Apple implements it, through `SecItemUpdate`; JVM and Web have no device-lock concept, and Android Keystore key parameters are fixed when the key is minted. Because of that immutability, tightening an Android entry from relaxed to `requireUnlockedDevice` never reuses the relaxed key's alias: a strict `HARDWARE_ISOLATED` entry keys under a dedicated strict alias variant, the tighten mints a fresh strict key there (with `setUnlockedDeviceRequired`, where the platform can apply it — see `android_lock_screen_absent`), and the relaxed key is reclaimed only after the rewrite commits. Copy-on-write, so no failure between the two can strand the previous value.
- **`onStoreCleared`** — fires after `clearAll()` for the engines whose key records live *inside* the store being wiped, so a cached-but-record-less key can't silently re-encrypt with material that exists only in RAM. Two engines implement it: JVM drops its whole in-memory key cache and wipes the vault, and Android drops its cache of software-wrapped DEKs — data-encryption keys, the AES keys that encrypt your values; see the **[KEK / DEK model](#key-custody-across-platforms-the-kek--dek-model)** below — whose records live in the DataStore. It stays a no-op where key material lives outside the store — the Apple Keychain, Android's key handles inside the security hardware, and Web's IndexedDB.

Four implementations, one per platform:

- **`AndroidKeystoreEncryption`** — AES-GCM (`BITS_256` by default; `BITS_128` via `KSafeConfig.aesKeySize`) with hardware-backed keys (StrongBox when requested and available). Keys are handles, not bytes: the key material never leaves the **TEE** — the Trusted Execution Environment, an isolated mode of the main processor that runs the crypto on the app's behalf and hands back only the result.
- **`AppleKeychainEncryption`** — AES-GCM (`BITS_256` default, `BITS_128` optional) through KSafe's bundled, byte-oriented Swift/C bridge to Apple CryptoKit; there is no third-party crypto provider. Keys are stored as Keychain `kSecClassGenericPassword` items with `…ThisDeviceOnly` accessibility (and, for `HARDWARE_ISOLATED` writes, that AES key is itself wrapped by a Secure Enclave key using ECIES — elliptic-curve encryption, spelled out in the **[KEK / DEK model](#key-custody-across-platforms-the-kek--dek-model)** below). One implementation, lives in `appleMain`, used by both iOS and native macOS — the Keychain Services + CryptoKit APIs are byte-for-byte identical between the two platforms; only the location of the Keychain database differs (per-app on iOS, per-user on macOS). On Apple Silicon and T2-equipped Intel Macs the Secure Enclave path works exactly as on iOS devices; on older Intel Macs without a T2 chip, SE key creation throws and the engine falls back to plain Keychain storage automatically (same fallback path that already covers iPhone 5/5C without an SE). On the **iOS Simulator**, an app with no signing team / no Keychain Sharing capability gets `errSecMissingEntitlement` (`-34018`) from every Keychain call; the engine detects that exact status *on the Simulator only* and falls back to `FileSimulatorFallbackKeyStore` (a sandbox file store on the host Mac, reported `SOFTWARE` in `protectionInfo`) instead of failing every encrypted write. Real devices never construct this store.
- **`JvmSoftwareEncryption`** — AES-GCM (`BITS_256` default, `BITS_128` optional) via `javax.crypto` for the payload; the AES key itself is held by an **OS secret store** (Windows DPAPI, macOS login Keychain, Linux Secret Service / libsecret) reached through the `JvmKeyVault` abstraction via JNA. The vault plays the **KEK role** — it stores/wraps the key bytes at rest — and KSafe does the AES in userspace with them (the **DEK role**), so there is no per-operation hardware round-trip. When no OS store is reachable (an operating system KSafe has no vault for, a JNA link failure, or the explicit opt-out) it falls back to the pre-2.1.0 software scheme — the AES key Base64-encoded inside the store's own DataStore file — or, on the `sun.misc.Unsafe`-less JSON-file backend, to an owner-only-readable JSON key file. Both sit at the `SOFTWARE` tier, one step below the OS vault's `SANDBOX_PROTECTED`. A self-test *failure* on a host where an OS vault does exist is not a fallback at all: it is a fail-closed non-operational state (`jvm_os_vault_degraded`). `KSafeConfig.appNamespace` isolates the per-OS-user store (which is shared by every process, unlike Android/iOS per-app sandboxing), resolved as: explicit value → `-Dksafe.appNamespace` → env `KSAFE_APP_NAMESPACE` → `"shared"`. Opt out of OS-store use with `-Dksafe.jvm.keyVault=software`. The full platform-by-platform treatment — DPAPI/Keychain/Secret Service internals, the hybrid ≤ 2.0 legacy-key migration and stale-key resolution, the `jdk.unsupported` JSON-fallback backend, the namespace resolution and self-test — lives in [JVM_PROTECTION.md](JVM_PROTECTION.md). The active vault and any fallback surface through `KSafe.protectionInfo`; see [PROTECTION_INFO.md](PROTECTION_INFO.md).
- **`WebSoftwareEncryption`** — AES-GCM (`BITS_256` default, `BITS_128` optional) via the WebCrypto **SubtleCrypto** API called directly. The AES key is generated/imported **non-extractable** (`extractable = false`) and its live `CryptoKey` object is persisted in **IndexedDB** — the raw key bytes are never exposed to JS or written to a readable location. *Values* still live in `localStorage` (`LocalStorageStorage`); only the key moved. A legacy `localStorage` raw key (KSafe ≤ 2.0) is imported as a non-extractable key into IndexedDB on first access and the `localStorage` entry deleted (same hybrid lazy + one-time background sweep as JVM, via `migrateLegacyKeysSuspend()`); the AES-GCM framing matches the old default so previously written ciphertext still decrypts. The legacy localStorage key is **authoritative**: when present it is imported and **overwrites** any stale IndexedDB key *and* the page-global in-memory cache (both of which can survive a prior lifecycle within an origin) — the un-namespaced legacy `localStorage` location is never touched, so migration stays intact. The browser already isolates IndexedDB and `localStorage` per origin; `KSafeConfig.appNamespace`, when set, additionally prefixes both the `localStorage` data slots and the IndexedDB key record, so two independent KSafe setups in one origin cannot collide. WebCrypto is async-only, so this engine **only** implements the suspend variants and throws from the blocking ones — `KSafeCore` calls the suspend path from every coroutine-context site.

## Master AES keys and the v2 / v3 envelope

Starting in 2.0, KSafe stops generating a fresh AES key per encrypted entry. The pre-2.0 model — one Keystore/Keychain entry per `userKey` — meant every `put("foo", x)` paid the cost of a Keystore-backed key generation, and a write storm of 1,000 keys produced 1,000 Keystore handles. The v2 envelope replaces that with **one master AES key per datastore** for `KSafeProtection.DEFAULT` entries; `HARDWARE_ISOLATED` entries still get their own per-entry keys (the whole point of HARDWARE_ISOLATED is the StrongBox / Secure Enclave isolation, which it would lose if it shared a master).

An *envelope* here is the rule that decides how one entry was encrypted: which key alias it was written under, and what extra data was authenticated alongside the ciphertext. Every encrypted entry records its envelope version in its metadata, and the read path uses that record to reconstruct the same two answers.

KSafe writes one of two envelope versions per entry, chosen by the store's key generation (see **[Key rotation and key generations](#key-rotation-and-key-generations)** below): `KeySafeMetadataManager.envelopeVersionForWrite(generation)` returns **v2** for generation 1 (an un-rotated store — byte-identical to 2.0–2.2.x, no AAD) and **v3** once the store has been rotated at least once (generation ≥ 2). v3 keeps v2's routing but adds an **authenticated** AES-GCM envelope, described below. A generation-1 store is a pure v2 store, so upgrading to 3.0.0 changes nothing on disk until the first `rotateKeys()`.

**The two master variants.** Where the platform has a device lock — Android and Apple — a datastore carries *two* master keys per generation: a relaxed one (`requireUnlockedDevice = false`; on Apple written with `AfterFirstUnlockThisDeviceOnly`) and a strict one (`= true`; `WhenUnlockedThisDeviceOnly` on Apple, and minted with `setUnlockedDeviceRequired` on Android). The strict one cannot decrypt while the device is locked; the relaxed one keeps working as long as the user has unlocked once since boot. Each entry's own `requireUnlockedDevice` picks the master at write time. JVM and Web have no device lock, so both policies collapse onto a single master alias — a second one would never be used.

**The aliases.** Every platform shell injects two functions:

- `keyAlias(userKey)` — the per-entry alias, used for `HARDWARE_ISOLATED` entries and for pre-2.0 v1 ciphertext. Two spellings: `"<fileName>:<userKey>"` on JVM and Web (only `"<userKey>"` for the default store, which has no `fileName`), and `"eu.anifantakis.ksafe[.<fileName>].<userKey>"` on Android and Apple. Identical to the pre-2.0 scheme, so nothing has to migrate.
- `masterAlias(requireUnlockedDevice)` — the same two spellings with a reserved name where the user key would go: `__ksafe_master__`, or `__ksafe_master_locked__` for the strict variant on the platforms that have a device lock. Used by every v2 and v3 `DEFAULT` entry.

Both spellings come from one `KSafeAliasFormat` helper, and the reserved names from the `KSafeReservedKeys` registry that the write-time key-validation patterns are built from — so a user key can never be minted onto an alias KSafe already owns.

`KSafeCore.aliasForWrite(userKey, protection, requireUnlockedDevice, keyGeneration)` returns the master for `DEFAULT`, the per-entry alias for `HARDWARE_ISOLATED`, then applies the entry's generation suffix (below). `aliasForRead(userKey, protection)` does the inverse, driven by the entry's own recorded metadata to handle pre-v2 ciphertext (per-entry keys) and older generations side by side.

**Metadata-driven routing.** Every encrypted entry's on-disk metadata records its envelope version (`v=1` legacy per-entry, `v=2` master-key, `v=3` authenticated master-key), its per-entry `requireUnlockedDevice` flag, and — since 3.0.0 — its key `generation`. `KSafeCore` mirrors this into an in-memory map populated during cold-start preload, and the read path consults it to reconstruct the exact alias and (for v3) the exact AAD the entry was written with. The engine therefore serves v1, v2, and v3 ciphertext — and every past generation — side by side with no separate migration pass: an old entry decrypts under its recorded key, then the next write (or a `rotateKeys()` pass) rewrites it forward.

**The generation suffix.** `KSafeCore.aliasWithGeneration(baseAlias, generation)` returns the base alias unchanged for generation 1 (so an un-rotated store keeps the exact 2.2.x key names) and appends `.g<N>` for generation ≥ 2. This is what lets multiple generations of the master key coexist during and after a rotation; superseded generations are swept once nothing references them.

**Prewarm.** Cold start runs `engine.prewarmKey(masterAlias, …)` against each master alias from an off-thread coroutine launched in the constructor (`prewarmMasterKeys()`), independent of — and possibly ahead of — the first snapshot; on a rotated store it may race the snapshot and warm the base generation, which is harmless because the next write lazily creates the correct-generation key. It materialises the Keystore/Keychain handle eagerly so the very first user-driven `put` doesn't pay key-creation latency on the foreground path. Idempotent — a second cold start finds the handle already in place. (The Android engine overrides `prewarmKey` to create only the wrapping KEK, so a safe with no encrypted entries writes nothing.) The same pass also warms an already-persisted DEK read-only, through `prewarmDekReadIfPresent`, and never creates one. The web engine goes further and makes the whole prewarm read-only: a store with no key yet pays the key generation on its first encrypted write, and a plain-only store writes nothing to IndexedDB at all. That matters because on the web the key and the values live in separate browser stores, and minting a fresh key over key-less ciphertext would turn a recognisable "key missing" into an unclassifiable decrypt error, stranding those values for good.

**The v3 authenticated envelope.** A v3 write additionally binds an AES-GCM **associated data (AAD)** string to each ciphertext — `KeySafeMetadataManager.aadFor(storeIdentity, userKey, protection, requireUnlockedDevice, keyGeneration)` — with the two free-form fields, the store identity and the user key, written with their length in front, so two different sets of fields can never produce the same AAD string (without the lengths, a key ending in the `|` separator could imitate the next field). The remaining fields are fixed tokens with no such ambiguity. The AAD ties the ciphertext to the store's identity, the user key, the protection tier, the unlock policy, and the key generation: every security-relevant field the read path routes on. An attacker with raw file access can no longer copy a ciphertext to another entry, swap it between the relaxed and strict master, relocate it to another store, or re-tier an *encrypted* entry and have it decrypt in the wrong context — the GCM tag check fails and the read **fails closed** to the caller's default. (Rewriting an entry's metadata to plaintext — `p:"NONE"` — instead reclassifies it as plaintext, so the read returns the stored bytes verbatim: undecipherable ciphertext, never the underlying secret.) Because a generation-1 store stays pure v2 (no AAD, exact pre-3.0.0 bytes), identity authentication begins at the first `rotateKeys()`. In plain terms: once rotated, an encrypted entry can't be copied, swapped, relocated, or re-tiered between keys without the read failing closed to the default. AAD is threaded through every platform engine (see the `aad` parameter on `KSafeEncryption` above); the deeper treatment is in [KEY_ROTATION.md](KEY_ROTATION.md) and [SECURITY_MODEL.md](SECURITY_MODEL.md).

**Read concurrency.** Every `DEFAULT` entry decrypts under the same master alias, so a process pays one key resolution and every later read reuses it. Each engine holds the resolved key in memory — Android the unwrapped DEK, Apple the Keychain key bytes, JVM the `SecretKey` — and reads that cache without a lock; the per-alias lock is taken only when the key is not there yet, once per alias per process. On Apple the decrypt path takes no lock at all. A cold burst of `getDirect` calls across N distinct `DEFAULT` keys therefore serialises only behind the one key resolution they share. What the shared master bought is storage: key handles drop from O(N entries) to O(1) per datastore, versus the pre-2.0 model where every write paid a Keystore round-trip that contended on the platform's own per-key handle creation.

**Where to read the code:** `KeySafeMetadataManager.kt` — `envelopeVersionForWrite`, `aadFor`, `parseKeyGeneration`, `valueRawKey` / `metadataRawKey`. `KSafeCore.kt` — the routing entry points `aliasForWrite` / `aliasForRead` / `aadForRead`, plus the companion's `aliasWithGeneration` and `aadForEnvelope`; `aadForEnvelope` is the single v3 gate (the only caller of `KeySafeMetadataManager.aadFor`) and `encMetaMap` is the in-memory metadata mirror. `KSafeCore`'s remaining logic lives in the `internal.coreparts` sub-package as extension functions on the class: `KSafeCoreRouting.kt` holds the one `decryptEntry` that bundles the envelope-version check, alias resolution, the gated AAD and the legacy-identity retry; `KSafeCoreCacheMerge.kt` populates the metadata mirror during the first-snapshot preload; `KSafeCoreStartup.kt` holds `prewarmMasterKeys`. The platform-shell constructors that supply `masterAlias` / `keyAlias` are in `KSafe.{android,apple,jvm,web}.kt`.

## Key rotation and key generations

`KSafe.rotateKeys(): KSafeRotationResult` re-encrypts every encrypted entry under a fresh key, whole-store, on every platform:

```kotlin
val result = ksafe.rotateKeys()   // suspend; result.rotated / .skipped / .failed / .keyGeneration
```

There is no per-key rotate — the unit is the datastore. Every `DEFAULT` entry shares one master key per generation, so rotating one key means rotating that master, which means re-encrypting everything riding on it; a per-key API would be the same work behind a name that promised less. The design rests on a single store-wide **key generation** counter:

- `KSafeCore.currentKeyGeneration` starts at 1 and is bumped by a rotation. Each write records the generation it used in the entry's metadata (the `g` field); `KeySafeMetadataManager.parseKeyGeneration` reads it back. The master alias for a generation is `aliasWithGeneration(masterAlias(...), g)` — un-suffixed for generation 1, `.g<N>` above — so generations coexist.
- The store's current generation is persisted as a reserved `__ksafe_keygen__` entry, written
  through the same coalescer as every other op. Alongside the generation it records when that
  generation was born, whether the pass completed, and how many automatic retries remain — see
  **[On-disk format](#on-disk-format)** for the record's exact shape and the protocol that keeps
  it consistent across a crash.

**What a rotation pass does.** `rotateKeys()` bumps the generation, then walks every encrypted entry from a single snapshot. An entry already at (or above) the new generation is not a candidate at all and is not counted; each older entry is decrypted under its recorded generation and re-encrypted under the new one through a `Rotate` write op. That op commits under a **compare-and-swap on the entry's stored ciphertext, serialized on the write consumer**, so a concurrent user write to the same key always wins and a rotation can never clobber or resurrect a value. Once the pass finishes, a `SweepSupersededMasters` op deletes every superseded master generation that neither a persisted entry nor a live sibling instance's cache still references. The result reports `rotated` / `skipped` / `failed` / the new `keyGeneration`.

**Crash-safe with automatic same-generation resume.** Because each entry names the generation
that decrypts it, an interrupted rotation leaves a **mixed-generation store that stays fully
readable**. In 3.1.0+, the persisted `"r":1` marker — "a pass is in progress", see
**[On-disk format](#on-disk-format)** — makes the next KSafe instance resume the same target
generation in the background, even under `Never`; it becomes `"r":0` only after the entry pass
and master sweep finish. There is no per-entry journal or rollback log, and no unreadable
intermediate state. Because a 3.0.0 record has no `r` at all, its absence is never treated
as proof of interruption: the first 3.1.0 startup only stamps `r:0`, preserving the old
generation, timestamp and entries, and normal policy resumes on the following launch.

**What counts as skipped vs. failed.** A strict (`requireUnlockedDevice`) entry rotates only while the device is unlocked; on a locked device it is reported `skipped` (not failed) and marked for the next KSafe instance. A transient key-store outage is likewise `skipped`. Only a definitive decrypt/re-encrypt failure is counted `failed`, and `failed` alone does not arm automatic retry. **Values are sacred**: rotation changes key material and envelope, never data — a `getOrCreateSecret` secret (the random value KSafe mints once and must hand back byte-identically forever, such as a database passphrase; see [USAGE.md](USAGE.md)) keeps its value, only its wrapping key changes. Legacy (pre-2.x) entries are upgraded to the current envelope as a side effect.

**Automatic rotation.** `KSafeConfig.keyRotationPolicy` is `KSafeKeyRotationPolicy.Never` by
default (key material is hardware/OS-protected and does not expire, so fresh rotation is an
opt-in hygiene/compliance control). Crash recovery and same-generation skipped-work retry are
not fresh policy-triggered rotations and therefore run under every policy. When no pending
recovery/retry exists, `MaxAge(duration)`
runs a **once-per-startup** background check — never blocking startup or reads — and rotates
when the current generation is old enough. A normally completed pass's skipped entries are
retried by the next instance (or sooner by a manual call). If `MaxAge` is already due then,
the new-generation pass takes precedence.

Canonical treatment — the operational guide, the resumability proof, and the cryptographic-erasure discussion — is in **[KEY_ROTATION.md](KEY_ROTATION.md)**.

## Key custody across platforms: the KEK / DEK model

The v2 / v3 envelope settles *how many* keys a safe uses (one master per datastore, per generation). A separate question is *how that master key actually performs each encrypt/decrypt* — and the answer differs per platform, because each platform's secure store exposes the key differently. This is where the **KEK / DEK** distinction matters:

- **KEK (key-encryption key):** a key whose material stays in a secure store and is used only to *wrap* (encrypt) another key.
- **DEK (data-encryption key):** the AES key that actually encrypts your values — held *wrapped* at rest, *unwrapped into process memory* to be used.

| Platform | "At rest" custody (KEK role) | Working key (DEK role) | AES runs in | KEK wraps a DEK? |
|---|---|---|---|---|
| **Android — `DEFAULT`** (2.1.2+) | Keystore master key in the **TEE**, wraps the DEK | random AES DEK, **held in RAM** | userspace (`javax.crypto`) | **Yes** — added in 2.1.2 |
| **Android — `HARDWARE_ISOLATED`** | StrongBox / TEE per-entry key | none — key never leaves hardware | **inside the TEE / StrongBox** | No (key never in RAM) |
| **Apple — `DEFAULT`** | **Keychain** item (securityd; device-UID + passcode bound, `…ThisDeviceOnly`) | AES key bytes from the Keychain, cached in RAM (`keyBytesCache`) | userspace (**CryptoKit**) | No — the Keychain stores the key bytes directly |
| **Apple — `HARDWARE_ISOLATED`** | **Secure Enclave** EC keypair, wrapping the AES key with ECIES (elliptic-curve encryption: the Enclave's public key encrypts the AES key, and only the Enclave's private key — which never leaves the chip — can unwrap it) | AES DEK, unwrapped into RAM | userspace (CryptoKit) | **Yes** — the SE is EC-only, it can't do AES itself |
| **JVM / Desktop** | **OS vault** — DPAPI / Keychain / libsecret holds the key bytes (fallback: the key Base64-encoded in the store's own file) | AES key bytes from the vault → `SecretKeySpec` in RAM | userspace (**JCE**) | No — the vault stores the key bytes directly |
| **Web (JS / WASM)** | the browser holds a **non-extractable `CryptoKey`** in IndexedDB | none — raw bytes never exist in JS | the browser (`crypto.subtle`) | No — single key, never extractable |

**Why a DEK was needed only on Android.** It comes down to what each store hands back. The Apple Keychain and the JVM OS vaults *return the raw key bytes* on request — so KSafe loads them once, caches them, and does fast userspace AES; there was never a per-operation hardware round-trip. The **Android Keystore never returns key bytes** (non-exportable by design): it only lets you *use* the key through a `Cipher`, which executes inside the TEE — a per-operation IPC that measured ~8 ms/op on a Galaxy S24 Ultra under decrypt-every-read. 2.1.2 closes the gap by giving KSafe its *own* software DEK (which it can hold raw) and using the non-exportable Keystore key purely as a **KEK** to wrap/unwrap it once. The end state matches Apple/JVM: a raw AES key in RAM doing userspace AES, protected at rest by hardware. See [BENCHMARKS.md](BENCHMARKS.md).

**The two genuine envelopes.** Only two cases have KSafe wrapping a DEK with a hardware KEK, and for the same reason — the hardware either *cannot* or *should not* run the per-value AES itself:
1. **Android `DEFAULT` (2.1.2):** the TEE key is non-exportable, so it wraps a software DEK that does the AES in userspace.
2. **Apple `HARDWARE_ISOLATED`:** the Secure Enclave is EC-only (no symmetric AES), so its EC key ECIES-wraps an AES DEK that does the AES in CryptoKit.

In **Apple `DEFAULT`** and **JVM** there is no KSafe-managed wrap: the OS secret store itself holds the AES key bytes and protects them at rest (and that protection is often hardware-rooted — e.g. macOS Keychain is SEP-gated, DPAPI binds to the user login). **Web** is the inverse of everything else — a single non-extractable key, so no DEK and no raw bytes in memory at all; conceptually the pre-2.1.2 Android "use, not extract" model, except the browser is the secure element and is fast enough that no envelope is needed.

**On-disk locations (Android, relaxed `DEFAULT`, 2.1.2).**
- The **wrapped DEK** is a Base64 string stored as a reserved entry — key `__ksafe____DEK____`, joined by a `__ksafe____DEK____@<alias>` slot per additional alias once the store has been rotated — **inside the safe's own DataStore** (`/data/data/<package>/files/datastore/<fileName>.preferences_pb`), wrapped by the relaxed master KEK. It is **not** in SharedPreferences: KSafe deliberately uses no SharedPreferences anywhere, not even for the DEK. The `__ksafe_` prefix places it in KSafe's internal namespace (the same convention as per-key metadata), so the core never surfaces it as a user value and `clearAll()` wipes it with everything else. At rest it is ciphertext — useless without the device's Keystore.
- The **KEK** is **not a file** — it lives in the TEE / keystore daemon under the master alias (`eu.anifantakis.ksafe[.<fileName>].__ksafe_master__`) and never appears in the app sandbox.
- The encrypted **values** live as `__ksafe_value_*` entries in that **same** DataStore file — so a safe's data and its wrapped DEK travel and clear together.

**Security posture & the trade-off.** On Android-`DEFAULT`, Apple-`DEFAULT`, and JVM the *working* AES key lives in process RAM after first use — the same posture as EncryptedSharedPreferences / Tink. Durable custody stays hardware/OS-rooted (disk or backup theft yields only a wrapped / OS-protected key, useless off-device). If you need the key to *never* enter app memory, the guarantee is platform-specific. On Android, `HARDWARE_ISOLATED` (StrongBox / TEE) — or a strict `requireUnlockedDevice = true` entry — runs the per-operation AES on-chip, so the key bytes never enter RAM. On Apple, `HARDWARE_ISOLATED` only strengthens durable custody: the Secure Enclave is EC-only, so the AES DEK is still unwrapped into RAM and AES-GCM runs in CryptoKit (consistent with the table above). **2.1.2 changed only Android;** Apple, JVM, and Web are untouched.

**Where to read the code:** `AndroidKeystoreEncryption.kt` (DEK wrap/unwrap + `dekCache`) and `WrappedDekStore.kt` (the DataStore-backed `DataStoreDekStore` that persists the wrapped DEK), `AppleKeychainEncryption.kt` (`keyBytesCache`, SE ECIES wrap for `HARDWARE_ISOLATED`), `JvmSoftwareEncryption.kt` (vault → `SecretKeySpec`), and the web engine (`crypto.subtle`, non-extractable `CryptoKey`).

## Protection tiers and the honesty pattern

An encrypted write carries a protection tier, chosen through its write mode:

```kotlin
ksafe.putDirect("token", value, KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))
```

`KSafeEncryptedProtection` is the write-side vocabulary; `KSafeProtection`, with the same two names, is the read-side one that `getKeyInfo` reports. The tier decides where the *encryption key* lives at rest, not where the ciphertext lives:

- **`DEFAULT`**: an AES key (`BITS_256` by default, `BITS_128` if configured) whose durable custody is hardware- or OS-rooted — the Android Keystore TEE, the Apple Keychain, the JVM OS vault. The *working* key does userspace AES from process memory: on Apple and JVM always, on Android since 2.1.2 through a TEE-wrapped DEK (see the **KEK / DEK** section above).
- **`HARDWARE_ISOLATED`**: a stronger guarantee, expressed differently per platform. Android requests `setIsStrongBoxBacked(true)` on the `KeyGenParameterSpec`; iOS and macOS create an EC private key in the Secure Enclave (`kSecAttrTokenIDSecureEnclave`) and use it to wrap the AES key. The key-generating hardware is physically separate from the main TEE.

Not every device has StrongBox or a Secure Enclave. A write that asked for `HARDWARE_ISOLATED` on a device without the hardware lands in regular hardware-backed storage instead of failing. The fallback is silent on purpose: one body of shared code runs on every device in a fleet, and refusing the write on the phones without a security chip would cost the app its data rather than a tier. The data is still encrypted under a hardware-backed key; only the stronger isolation is missing — and the rest of this section is how you find that out.

**The honesty pattern.** A caller who wrote with `HARDWARE_ISOLATED` is owed a way to ask "did that *actually* happen?" — for a UI affordance ("stored in the security chip") or for a security audit. `getKeyInfo(userKey): KSafeKeyInfo?` answers it:

```kotlin
data class KSafeKeyInfo(
    val protection: KSafeProtection?,    // what was requested (or null for plain)
    val storage: KSafeKeyStorage,        // legacy: where the key actually lives — @Deprecated, prefer level
    val level: KSafeProtectionLevel,     // 2.1.0+: same universal scale as KSafe.protectionInfo
    val keyGeneration: Int = 1,          // 3.0.0+: generation that decrypts this entry (1 = never rotated)
)
```

The three fields can disagree, and that is the point. Asking for `HARDWARE_ISOLATED` on a phone without StrongBox gives you:

```kotlin
KSafeKeyInfo(protection = HARDWARE_ISOLATED, storage = HARDWARE_BACKED, level = HARDWARE_BACKED)
// you asked for the strong tier · you got the regular tier · here is what was delivered
```

- **`level`** uses the same scale as the instance-wide `KSafe.protectionInfo`, so comparing an instance baseline against a per-key actual is one ordinal compare.
- **`storage`** is the pre-2.1.0 three-value vocabulary, kept for source compatibility and carrying `@Deprecated(ReplaceWith("level"))`. New code should read `level`.
- **`keyGeneration`** (3.0.0+) reports which key generation decrypts this entry — 1 until it is first rotated — so a rotation can be audited per key.

How `storage` and `level` are resolved differs by platform:

| Platform | How the report is produced |
|---|---|
| Apple | Checked against the entry's own key in the live Keychain: an SE-wrapped key reports `HARDWARE_ISOLATED`, a legacy plain Keychain key still serving an SE request reports `HARDWARE_BACKED`, and a key in the Simulator's entitlement-fallback sandbox file reports `SOFTWARE`. A key that can't be classified — not minted yet, device locked — falls back to inference. |
| Android API 31+ | Checked against the Keystore key's own `KeyInfo.getSecurityLevel()`, so a per-write StrongBox fallback to the TEE, or a pre-existing TEE key reused under a later `HARDWARE_ISOLATED` request, reports `HARDWARE_BACKED` for that key. |
| Android below API 31 | `KeyInfo` can't tell StrongBox from the TEE, so the report is inferred from the requested tier plus the device's StrongBox feature flag (which is absent below API 28 anyway) — as is any key the probe cannot load. |
| JVM / Web | Inferred from the vault or engine the instance is actually running on, which the shell already knows exactly. |

## Is encryption operational? (the preflight)

Protection *strength* and encryption *operability* are two different questions, and 3.0.0 gives each its own gate on `KSafe.protectionInfo` (a `KSafeProtectionInfo`):

- **"Is protection at its intended strength?"** → compare `effectiveLevel` against `intendedLevel`. A divergence means a runtime fallback occurred, but encryption may still work fine — a JVM software-vault fallback (no OS store on the host) and an iOS-Simulator sandbox key store both report `SOFTWARE` yet encrypt/decrypt normally.
- **"Will an encrypted write actually succeed?"** → read `isEncryptionOperational: Boolean`:

  ```kotlin
  if (!ksafe.protectionInfo.isEncryptionOperational) return // refuse to store the token at all
  ```

  It is a `val` computed in common code with no platform guards: `true` wherever encryption works — *including* those weaker-but-working fallbacks — and `false` only for the two genuinely non-operational states, each carried as a `notes` code: `web_crypto_subtle_unavailable` (a page served outside a secure context, so `crypto.subtle` is absent) and `jvm_os_vault_degraded` (an OS vault exists but is unreachable at startup — a locked Keychain/keyring, a headless launch — so KSafe refuses to mint keys and every encrypted op throws). Note the asymmetry on JVM: `jvm_os_vault_unavailable` (*no* OS store reachable → software fallback) stays **operational**; only `jvm_os_vault_degraded` (a store that *should* work but doesn't) is not.

The split matters because gating on `effectiveLevel != intendedLevel` would wrongly reject the functional software fallbacks, and gating on strength would miss a store that reports a strong level but can't actually persist. An app can therefore refuse to proceed when a write would silently fail (e.g. block login until it is served over HTTPS) without penalising a merely-weaker configuration. Full per-platform truth table and the `KSafeProtectionLevel` scale: [PROTECTION_INFO.md](PROTECTION_INFO.md).

## The Android `modeTransformer`

The heading names the case this hook was introduced for, but it is not Android-only. `KSafeCore` takes a `modeTransformer: (KSafeWriteMode) -> KSafeWriteMode` from its platform shell and runs it once at the top of `putDirectRaw` / `putRaw`, before anything else looks at the write. It is the one place a platform may change what a write means, and three platforms use it for different reasons:

- **Android** and **Apple** pass the shared `promoteDefaultToIsolated`, bound to the deprecated `useStrongBox` / `useSecureEnclave` factory parameters. With the flag set, an unqualified `DEFAULT`-tier encrypted write is promoted to `HARDWARE_ISOLATED`; a write that named its own protection is left alone.
- **Web** strips `requireUnlockedDevice` from an encrypted mode. A strict entry routes every read through a blocking decrypt, and WebCrypto is async-only — so a strict entry on the web would be unreadable. Clearing the flag keeps it readable.
- **JVM** passes identity: it supplies no transformer at all, so `KSafeCore`'s constructor default `{ it }` applies.

The transform is also asked once, at construction, whether a strict per-entry alias is reachable here at all — so a platform that strips the flag also prunes the alias sweeps that would otherwise go looking for one.

This is the only place platform intent crosses Ring 3 → Ring 2 on the write path.

## Cross-type migration

Reads coerce between the numeric primitives — `Int`, `Long`, `Float`, `Double` — and from a stored `String`, so an app that first stored a counter as `Int` and later switched to `Long` (or the other way) keeps working; a `Boolean` likewise reads back from a stored boolean or string. A value out of the target's range, or fractional where an integer is asked for, or unparseable, returns the caller's `defaultValue` rather than silently truncating. Dispatch is done off the requested `KSerializer<T>`'s `PrimitiveKind`, not off the runtime class of the default — which is what makes the same code path correct on Kotlin/JS where `Float`, `Double`, and `Int` share a runtime representation.

## The reactive layer

KSafe's storage primitives are point-in-time: read this key, write this value. Apps usually want a stream instead — "tell me when this key changes, and give me the current value first". That stream is built on `KSafeCore.getFlowRaw(...)`, which reads each `storage.snapshotFlow()` emission directly (not the hot cache), applies the same protection detection and decryption the synchronous reads use, and drops an emission whose decoded value equals the previous one.

Two shapes are called directly:

- **`getFlow(key, default): Flow<T>`** — a *cold* flow: nothing runs until something collects it, and each collector gets its own decode. It emits whenever the value changes from any source — this `KSafe` writing, another instance on the same file writing, an edit made outside KSafe, a delete.

  ```kotlin
  ksafe.getFlow("token", "").collect { token -> /* … */ }
  ```
- **`getStateFlow(key, default, scope): StateFlow<T>`** — a *hot* flow: it collects once in `scope` and shares the latest value with every collector. Its first value is resolved synchronously through `getDirect`, so collectors never see a brief wrong "default" before the real value lands. Built with `Flow.stateIn(scope, Eagerly, initial)`.

  ```kotlin
  val token: StateFlow<String> = ksafe.getStateFlow("token", "", viewModelScope)
  ```

Four more are property delegates. A delegate takes the default first and the key last, because an omitted key means "use the property's own name":

| Delegate | Yields | Writes? |
|---|---|---|
| `asFlow(default, key = null)` | `Flow<T>` | no |
| `asWritableFlow(default, key = null, mode = defaultWriteMode)` | `WritableKSafeFlow<T>` — a `Flow<T>` with a `set(value)` | fire-and-forget |
| `asStateFlow(default, scope, key = null)` | `StateFlow<T>` | no |
| `asMutableStateFlow(default, scope, key = null, mode = defaultWriteMode)` | `MutableStateFlow<T>` | setting `.value` persists |

```kotlin
val token: StateFlow<String> by ksafe.asStateFlow("", viewModelScope)
val theme: MutableStateFlow<String> by ksafe.asMutableStateFlow("dark", viewModelScope)
```

`asMutableStateFlow` has no direct-call form — the delegate is the only way to get one. Setting `.value` persists through `KSafe.putDirect`; a disk emission that lags an in-flight write is suppressed, and a write whose persist fails reverts to the durable value.

Each delegate resolves its `KSerializer<T>` once, when the property is first read, and builds its flow once. Without that, every property access would re-inflate the whole serialization graph.

The reactive layer changes no storage rule; it is projection over `getFlowRaw`. The hot cache, the write coalescer and the decryption rules all run unchanged. One platform note: on Web `LocalStorageStorage` re-emits only on this instance's own writes — there is no `storage`-event listener — so a Web flow does not observe another `KSafe` instance or another browser tab.

## On-disk format

Every stored value lands in storage under canonical raw keys:

- Value bytes: `__ksafe_value_<userKey>`
- Metadata: `__ksafe_meta_<userKey>__` (a small JSON blob with envelope version, protection level, access policy, and — since 3.0.0 — the key `generation` that decrypts the entry)
- Store key generation: `__ksafe_keygen__` — a single reserved entry, shaped
  `{"g":N,"ts":…,"r":0|1,"rp":N?}`

`__ksafe_keygen__` carries the whole rotation lifecycle, so it is worth reading field by field:

- `g` — the store's current key generation.
- `ts` — when that generation was born, which is the age a `MaxAge` rotation policy measures.
- `r` — the pass lifecycle: `0` completed, `1` in progress.
- `rp` — optional; the bounded number of automatic next-instance retries still available after a
  pass ended with retryable skips.

`SetKeyGeneration` writes the generation bump and `r:1` atomically, and `CompleteKeyRotation`
changes it to `r:0` only if the persisted store is still at that generation. With skipped work
it also writes the configured retry budget (3 by default); the current instance then stops, and
the next one compare-and-swaps `r:0,rp:N` to `r:1,rp:N-1` before retrying the same generation
without changing `ts`. That decrement is durable, so a crash cannot refill the budget, and
`r:1,rp:0` means the final claimed attempt still needs crash recovery but cannot arm another
retry. If `MaxAge` is already due on that run, its fresh-generation rotation takes precedence.
A record written by 3.0.0 has no `r` or `rp`; its first 3.1.0 startup adopts it once as
completed, without doing any rotation work.

Pre-1.7 KSafe used different conventions (`encrypted_<userKey>` for ciphertext, `__ksafe_prot_<userKey>__` for metadata) and `KeySafeMetadataManager` still reads those legacy formats — when a legacy key is next written or deleted, it gets rewritten in the canonical form. iOS additionally honors a per-`fileName` legacy variant from pre-1.8 builds.

For Apple platforms there's also a 1.x → 2.0 *path* migration: pre-2.0 the DataStore lived in `NSDocumentDirectory`; 2.0 defaults to `NSApplicationSupportDirectory`, and the factory transparently moves a legacy file across on first launch when the new path is empty. iOS is the original target of this migration (1.x shipped on iOS); on native macOS the factory uses the same code, which means no-op for fresh installs and seamless behaviour if anyone happens to have a legacy file there.

## Orphan cleanup

There are two failure modes that can leave KSafe in an inconsistent state across reinstalls and crashes, and there's a separate cleanup mechanism for each.

**DataStore-side: stale ciphertext.** A write encrypts the value, stores the ciphertext in DataStore, then stores the encryption key in the platform Keystore / Keychain. If the app is uninstalled, on Android both the DataStore file and the app's Keystore keys are removed (Keystore keys are bound to the app's UID), so a clean uninstall/reinstall leaves nothing orphaned — stale ciphertext arises on Android only when Android Auto Backup restores the DataStore file on reinstall while the Keystore keys (which are never backed up) are gone. On iOS / macOS the Keychain entry survives uninstalls outright (Keychain items are not tied to the app's filesystem container). On reinstall, KSafe might find ciphertext on disk that it no longer has the key to decrypt — or, on iOS / macOS, a Keychain key for which there's no corresponding ciphertext.

`KSafeCore.cleanupOrphanedCiphertext()` handles the DataStore side. Once, at startup, it probes every canonical encrypted entry by decrypting it. Two kinds are left out: a `getOrCreateSecret` slot — reaping one would turn its refuse-to-rotate guard into a silently minted new secret — and an entry still in the pre-1.7 `encrypted_` shape, which predates the canonical layout. A failed probe reclaims the entry only when the error is a definitive key miss: one of KSafe's own `KSafe: No encryption key found` / `key not found` / `web key missing` messages, which every engine throws from the shared `KSafeEngineMessage` registry. Anything else preserves the entry — a "device is locked" failure is transient and may well decrypt on the next launch, and a raw platform error that merely contains the words "key not found" is deliberately left alone, because engine messages quote the key they failed on.

The probes run concurrently inside a `coroutineScope { … }` with a `Semaphore(8)` cap — the same pattern as the write coalescer's parallel encrypt and the preload's parallel decrypt — so sweeping a 1500-key store finishes in milliseconds instead of seconds and doesn't visibly delay the first read. The deletes then go through the store's `commitMutex`, and each candidate is re-checked against a fresh snapshot first, so a write or a rotation that landed during the probe is never erased.

**Apple Keychain-side: stale Keychain entries.** The reverse problem on iOS / macOS — a Keychain entry survives an app reinstall because Keychain items aren't tied to the app's filesystem container the way DataStore files are. On reinstall, KSafe finds Keychain entries that the new install's DataStore doesn't reference. `cleanupOrphanedKeychainEntries(...)` (in `appleMain/internal/KeychainOrphanCleanup.kt`) sweeps these on first launch: it reads `storage.snapshot()` to compute the live key set, scans Keychain generic-password and `kSecClassKey` items, and deletes any whose `kSecAttrAccount` doesn't match a live DataStore key. The two scans cover both the AES-key and the wrapped-EC-key shapes, so partially-failed `HARDWARE_ISOLATED` writes (a crash between SE-key creation and the wrapped-AES storage) get cleaned up too.

The Apple sweep is **destructive in a way the DataStore sweep is not** — once an SE EC private key is removed from the Secure Enclave it cannot be recreated, so any ciphertext encrypted under it becomes permanently undecryptable. Two structural invariants protect against accidental destruction:

1. **The startup sweep runs only after the cache has been loaded from disk** — after the first `snapshotFlow` emission on the normal path, and after the cold load under `lazyLoad`. This guarantees DataStore has finished its initial read before the sweep computes "what's a live key" — closing a race window where the 1.x → 2.0 path migration in `KSafe.apple.kt` (which moves the file from `NSDocumentDirectory` to `NSApplicationSupportDirectory` immediately before DataStore is constructed) could deliver an empty snapshot to a sweep that would then nuke every legitimate key. (The pre-fix ordering hit exactly this on real devices upgrading directly from 1.8.x to 2.0.0-RC2; see CHANGELOG `2.0.0 → Fixed`.)
2. **The sweep refuses to delete when `snapshot.isEmpty() && orphanedKeyIds.isNotEmpty()`.** "DataStore reports zero entries but the Keychain has scoped items" is the signature of a partial view (failed migration, corrupted DataStore, OS-level data wipe that left the Keychain alone) — and in every one of those scenarios deleting the Keychain destroys irrecoverable state. The guard logs a message pointing at `KSafe.clearAll()` for users who genuinely intended a wipe, and the regression test [`KSafeCoreStartupOrderingTest`](../ksafe/src/jvmTest/kotlin/eu/anifantakis/lib/ksafe/KSafeCoreStartupOrderingTest.kt) in jvmTest pins both invariants in place.

Both sweeps are idempotent and "best-effort": failures during cleanup are swallowed (`runCatching`) rather than blocking startup. If a sweep can't run today (locked device, simulator quirks), it'll run cleanly on the next launch.

Because the real Keychain / Secure Enclave behaviour these sweeps depend on can't be exercised from the Simulator, an on-device harness lives in **[`ios-device-test/`](../ios-device-test/README.md)** (`run-xctest.sh` for a curated Swift XCTest, `run-full-suite.sh` for the full `kotlin.test` suite via a signed `.app`). See [TESTING.md](TESTING.md) for the wider test map.

## Error-propagation strategy

Decryption can fail for two distinct reasons, and KSafe handles them differently:

**Transient failures.** The device is locked, the Keychain is unavailable, the Keystore is busy — conditions that clear on their own. `isTransientDecryptFailure(throwable)` (in `KSafeCoreFailureClassification.kt`) recognises them from the error message, case-insensitively: "device is locked", "Keystore", "Keychain". It first rules out the definitive results, which are never retryable — the three key-miss phrases ("No encryption key found", "key not found", "web key missing") and "vault unavailable". Those phrases are not re-typed per engine: they live in one `KSafeEngineMessage` registry that all four engines throw from and the core matches on. A key miss counts only when the message carries KSafe's own `KSafe: ` opening, because engine messages quote the key they failed on — without the anchor, a key literally named `api key not found` would turn its own vault outage into a permanent-loss verdict.

What happens next depends on which read API you called, because only one of them has somewhere to retry:

| Read | On a transient failure |
|---|---|
| `suspend get()` | re-throws, so the caller can await unlock and retry |
| `getDirect()`, the property delegates, the synchronous Compose / StateFlow seed | returns the caller's `defaultValue` — letting the exception escape would crash property access or composition on a locked device |
| `getFlow()` and everything built on it | keeps its last value and retries on a slow backoff (250 ms doubling to 30 s), so a long-lived collector neither crashes nor stays stuck at the default; the value appears once it is decryptable, with no write needed |

Returning a silent `defaultValue` from `get()` would mask a correctness bug as "no data stored", which is why it alone re-throws.

**Permanent failures.** Decryption fails because the key genuinely doesn't exist (uninstall left ciphertext behind, key was deleted, etc.). These look the same to user code as "no value stored" — KSafe returns `defaultValue`. The user-facing behaviour is correct (you get the default you asked for), and the startup **orphan cleanup** described above is what eventually reclaims the unreadable ciphertext, so it stops occupying storage.

This split was a real bug pre-2.0: only Android's read path re-threw transient errors; iOS and JVM swallowed them. 2.0's shared `isTransientDecryptFailure` runs on every platform, so a locked device reliably surfaces to the caller for retry handling instead of being silently masked as "no data."

## Concurrency model

KSafe is thread-safe by construction. The hot cache, the dirty-keys set and the per-instance flags use `expect/actual` primitives — one declaration in `commonMain`, one implementation per platform (`KSafeConcurrentMap`, `KSafeConcurrentSet`, `KSafeAtomicFlag`, `KSafeAtomicInt`, `KSafeInitLock`, `runBlockingOnPlatform`):

- **JVM / Android**: `java.util.concurrent.ConcurrentHashMap` + `AtomicBoolean`; `runBlockingOnPlatform` is `runBlocking`. The two JVM-bytecode targets share one implementation in the `jvmSharedMain` intermediate source set — the actuals are plain `java.*` and kotlinx code with no Android API in them. It can't live in `datastoreMain`, because Apple shares that set and has its own actuals for these.
- **iOS / macOS**: `kotlin.concurrent.AtomicReference` holding an immutable map that writers rebuild and compare-and-swap in, since Kotlin/Native has no `ConcurrentHashMap`. `KSafeAtomicFlag` is an `AtomicInt(0/1)`, because a boxed `Boolean` has no stable reference identity on Native and an identity compare-and-swap on one can fail. The implementation lives in `appleMain` and serves all five Apple targets.
- **Web**: plain `HashMap` / `HashSet` / `var Boolean` — the browser runs the page on one thread, so there is nothing to lock. `runBlockingOnPlatform` throws there. Two commonMain sites reach it: the cold-read cache load (`ensureCacheReadyBlocking`), which catches and returns the caller's default, and `close()`'s wait for a commit in flight, which swallows the throw and closes immediately.

**One consumer per instance, one commit lock per file.** Each `KSafe` owns a write-coalescer coroutine that drains its own channel, so its own batches never overlap. Several `KSafe` instances can point at the same store, though, and they must not commit at once: DataStore refuses two live instances on one file, and two engines over one on-disk key slot would let their key caches diverge and lose data. So Android, Apple and JVM Desktop keep one `SharedStoreBackend` per store path, ref-counted, holding the DataStore handle, the storage adapter, the encryption engine, a `commitMutex` that serialises sibling commits, and a registry of the live cores on that file. That registry is what lets `clearAll()` clear a sibling's caches and lets a rotation keep a superseded key alive while a sibling still reads through it. Web has no shared backend — each instance owns its own store handle — so one instance per store stays the rule there.

**Closing.** `close()` is needed only when re-creating a `KSafe` mid-process. It refuses new commits, waits up to 2 s for a commit already running (not on Web, which cannot block), cancels the instance's coroutines, and hands every queued write a cancellation. The last instance on a store releases the shared backend, waiting up to 1 s for the store's own writer to let go of the file; a writer still busy after that is parked, and the next instance opening that file waits for it again before building a new backend.

## What 2.0 changed vs. 1.x

Before 2.0, `KSafe` was an `expect class`: one declaration in `commonMain` and four full implementations, one per platform, each carrying its own copy of the cache, the write coalescer, the metadata handling, the orphan cleanup and the `*Raw` plumbing. A bug fix had to be written and tested four times, and three of the four regularly drifted.

2.0 hoisted everything that isn't genuinely platform-specific into `KSafeCore` in `commonMain`, promoted `KSafe` to a regular common class reached through per-platform factory functions, put storage and encryption behind the two narrow interfaces above, and moved biometric verification into its own optional module. What is left in a platform shell is construction: paths, hardware probes, the two alias spellings, and the callbacks `KSafeCore` calls back into. Fixes and features now ship once and apply everywhere, and the same test suite runs on every target. (`KSafeCore` has since grown a sub-package, `internal.coreparts`, holding much of its logic as extension functions — see [docs/TOUR.md](TOUR.md).)

2.0.1 then folded `iosMain` into `appleMain`, so one body of Keychain + CryptoKit + Secure Enclave code serves both iOS and native macOS. The iOS implementation had never reached for UIKit, so the merge was mechanical: file moves, `Ios*` → `Apple*` renames, and one behaviour fix in `SecurityChecker`, where the jailbreak-style path probes now short-circuit on macOS, on which `/bin/sh` and friends exist on every host.

For the file-by-file map of where each concept lives in source, see **[docs/TOUR.md](TOUR.md)**.
