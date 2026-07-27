# Architecture

This is the conceptual model. For the file-by-file walk that maps these concepts to source paths, see **[docs/TOUR.md](TOUR.md)**.

## The three modules

KSafe ships as three independent artifacts:

| Module | Purpose | Depends on |
|---|---|---|
| **`:ksafe`** | Storage core: the `KSafe` class, hot cache, write coalescer, encryption engines, DataStore / `localStorage` adapters | nothing else in the project |
| **`:ksafe-compose`** | `ksafe.mutableStateOf(...)` Compose state delegates | `:ksafe` |
| **`:ksafe-biometrics`** | `KSafeBiometrics` standalone process-wide biometric gate with **real OS prompts on every platform that exposes one** | nothing else in the project |

The biometric module is fully independent of the storage core — apps that need only biometric prompts pull `:ksafe-biometrics` without paying for DataStore + DataStore-Preferences + the encryption engines, and apps that need only storage don't pull in `androidx.biometric` / `androidx.fragment`.

`KSafeBiometrics` is a zero-config static `object` (no instance, no DI). `verifyBiometric(...)` shows a genuine system prompt on Android, iOS, macOS, JVM Desktop, **and** the web — JVM-on-macOS uses `LocalAuthentication` (Touch ID / password), JVM-on-Windows uses `UserConsentVerifier` (Windows Hello), and JS/WasmJS use the browser's WebAuthn platform authenticator (shipped 2.2.1). `biometricsAvailable()` reports whether a usable prompt path exists. Where no prompt API exists (JVM on Linux, a browser with no platform authenticator, or an explicit opt-out) the call returns `true` — an unconditional pass — so shared `commonMain` logic can call in without branching; gate it yourself if you need a hard refusal there. See [BIOMETRICS.md](BIOMETRICS.md).

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

KSafe's defining performance trait is that synchronous reads (`getDirect`) hit an atomic in-memory map and — under plaintext policies — return in microseconds, while writes (`putDirect`) optimistically update the cache and queue a background flush.

**Reads (`getDirect`):** atomic memory lookup against `KSafeCore.memoryCache`. Under plaintext policies a warm read is an O(1) memory lookup; under `ENCRYPTED` (and always for `requireUnlockedDevice` entries) each read runs a decrypt on the caller thread — a native keystore round-trip on hardware-backed paths — so `getDirect` is a non-suspending hot-cache API rather than a universally non-blocking one. On the very first read after cold-start the call may also suspend briefly to wait for the cache preload. Safe to call on the UI thread.

**Writes (`putDirect`):** updates the memory cache **immediately** so subsequent reads see the new value. The write itself is queued onto an unbounded `Channel<PendingWrite>` consumed by a single coalescer coroutine that batches operations before calling `storage.applyBatch(ops)`. This collapses bursty writes (e.g. a slider moving) into one DataStore transaction. The unbounded queue is a deliberate trade-off: fire-and-forget writes never block or drop, but a producer that sustains a higher rate than the encrypt/commit drain (bulk imports, per-frame `putDirect` loops — plausible when every write is a hardware-keystore round-trip) holds every pending value in process memory until persisted. There is no drop/overflow policy because silently discarding an already-cache-acknowledged write would be worse; high-rate writers should use the suspending `put`, whose await naturally paces the producer.

**Suspend variants share the coalescer.** `suspend put` and `suspend delete` enqueue the same `PendingWrite.*` types but attach a `CompletableDeferred<Unit>` and `await()` it. The consumer completes those deferreds after `applyBatch` returns — propagating success, exceptions, or cancellation, so awaiting callers never hang on a crashed consumer. The visible consequence: 500 concurrent `suspend put` calls from independent coroutines amortise into a small handful of `applyBatch` transactions instead of 500 of them.

**The consumer loop is two-phase.** Phase 1 is a greedy drain: after `receive()`-ing the first write, it `tryReceive()`s in a tight loop until the channel is empty (or `maxBatchSize` is reached). This lets a burst of up to `maxBatchSize` (200) writes coalesce into one batch instead of one `applyBatch` per write; a larger burst splits into successive 200-op batches. Phase 2 is the 16 ms coalescing window — but it only opens when no write in the current batch carries a `completion`. If even one caller is awaiting, the batch flushes immediately so they don't sit idle; the window is purely there to absorb sparse fire-and-forget `putDirect` calls arriving over the next frame. A single sequential `ksafe.put(...)` therefore completes in ~one round-trip, not `~window + round-trip`.

**Inside the batch, encryption is parallelised.** `processBatch` deduplicates the batch by user-key across *all* write types (plain, encrypted, delete, rotate) — building a `finalByKey` map that keeps the last pending write per key, where a `Rotate` never displaces a same-batch user write — then derives the encrypt set from that map and runs those encrypts concurrently inside a `coroutineScope { … }` with a `Semaphore(8)` cap. Hardware-keystore IPC pipelines instead of running serially — the bound prevents flooding Binder / Keychain on large batches but allows enough overlap to mask per-call IPC latency. The downstream `StorageOp` builder iterates that deduplicated `finalByKey` map, preserving last-applied-wins semantics and emitting legacy-cleanup deletes for each surviving key. The visible effect: `ENCRYPTED` memory policy adds essentially no write overhead vs `PLAIN_TEXT`.

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

The fix is **dirty-key tracking**. Every key with an in-flight write is added to a `dirtyKeys: KSafeConcurrentSet<String>`. When the snapshot collector merges new values into the cache, it skips any key in `dirtyKeys` — that's the "I have a pending write the disk doesn't know about yet" signal. The dirty flag is *never* cleared after a flush; once dirty, always dirty for the lifetime of the instance. This is deliberate: a snapshot from before the flush is irrecoverably stale and the optimistic in-memory write is the source of truth from that point forward. The trade-off is that the dirty set grows monotonically with the working set, but in practice the set's size tracks the user's actual key cardinality and the memory footprint is negligible. One consequence for reads: because a key's dirty flag never clears, `getDirect` and delegate reads of a key *this* instance has written won't reflect later *external* changes to that key — the optimistic in-memory value wins. Storage-backed Flows (`getFlowRaw`) re-read raw snapshots and *do* surface those external changes.

**Cold-start fallback for sync reads.** A `getDirect` call that races the preload (the cache hasn't received its first snapshot yet) blocks once on `runBlockingOnPlatform { ensureCacheReadySuspend() }`, then proceeds with the now-warm cache. After cache warm-up, all reads are O(1) memory lookups. On Web the blocking path throws; the catch falls through to returning the caller's `defaultValue`, since browsers can't block the main thread.

**Parallel decrypt during preload (`PLAIN_TEXT` memory mode only).** When the cache is populated from disk and the memory policy is `PLAIN_TEXT`, every encrypted entry needs to be decrypted before it lands in the cache. The classification pass over the snapshot stays sequential (it mutates `validCacheKeys` and `protectionByKey`), but the actual `engine.decryptSuspend(...)` calls are deferred into a `pendingDecrypts` list and then flushed concurrently inside a `coroutineScope { … }` with a `Semaphore(8)` cap. The master key's raw bytes are cached in-process (Apple and JVM since 2.0; Android as of **2.1.2**, where the non-exportable TEE master key wraps an in-memory data-encryption key that is unwrapped once), so each per-entry decrypt is a pure-CPU AES-GCM op rather than a keystore round-trip — the fan-out parallelises CPU AES across cores instead of pipelining Binder calls, and per-key amortised cost falls to single-digit microseconds. (Before 2.1.2 the Android path round-tripped the Keystore/TEE on every decrypt — invisible on an emulator's software keystore but ~8 ms/op on real hardware.) **The default `LAZY_PLAIN_TEXT` skips this pass entirely** — it stashes ciphertext into the cache exactly like `ENCRYPTED` and defers each decrypt to the first read of that key, so its cold start is essentially free regardless of how many encrypted keys are stored (only the orphan-cleanup probe runs, and that too is parallelised). `ENCRYPTED` and `ENCRYPTED_WITH_TIMED_CACHE` likewise skip the bulk decrypt at cold start. The bulk-decrypt pass is therefore only paid by callers who explicitly opt in to the (now discouraged) `PLAIN_TEXT` policy or by the Web target where it's forced.

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
    fun encrypt(identifier: String, data: ByteArray, ..., aad: ByteArray? = null): ByteArray
    fun decrypt(identifier: String, data: ByteArray, ..., aad: ByteArray? = null): ByteArray
    fun deleteKey(identifier: String)

    // iOS re-accessibility (SecItemUpdate); no-op elsewhere
    fun updateKeyAccessibility(identifier: String, requireUnlocked: Boolean) { }
    // the backing store was wiped (clearAll) — drop in-store key caches (JVM vault; Android software-DEK cache)
    fun onStoreCleared() { }

    suspend fun encryptSuspend(..., aad: ByteArray? = null): ByteArray  // default delegates to blocking
    suspend fun decryptSuspend(..., aad: ByteArray? = null): ByteArray  // default delegates to blocking
    suspend fun deleteKeySuspend(...)                                   // default delegates to blocking
}
```

`aad` is the authenticated-associated-data hook the v3 envelope rides on: when non-null it is authenticated (not encrypted) alongside the ciphertext, so decryption must present byte-identical AAD or the GCM tag fails. `updateKeyAccessibility` lets an engine re-point an entry's lock policy in place (only Apple acts on it, via `SecItemUpdate`; JVM has no lock concept). Android Keystore key parameters are immutable once minted, so a policy *tightening* (relaxed → `requireUnlockedDevice`) never reuses the relaxed key's alias: strict `HARDWARE_ISOLATED` entries key under a dedicated strict alias variant, the tighten mints its strict key (with `setUnlockedDeviceRequired`) under that fresh alias, and the relaxed key is reclaimed only after the rewrite commits — copy-on-write, so no failure between the two can strand the previous value. `onStoreCleared` fires for the engines whose key records live *inside* the store it's wiping: the JVM DataStore-backed vault drops its whole in-memory key cache and wipes the OS/file vault, and on Android the Keystore engine drops its software-wrapped DEK cache (those DEK records live in the DataStore) — in both cases so a cached-but-record-less key can't silently re-encrypt with RAM-only material. It stays a no-op where key material lives outside the store: the Apple Keychain, Android's TEE key handles (untouched by the DEK-cache drop), and Web IndexedDB.

Four implementations, one per platform:

- **`AndroidKeystoreEncryption`** — AES-GCM (256-bit by default; `KSafeConfig.keySize` is configurable to 128-bit on Android/Apple/JVM, while Web is fixed at 256) with hardware-backed keys (StrongBox when requested + available). Keys are handles; the bytes never leave the TEE.
- **`AppleKeychainEncryption`** — AES-GCM (256-bit default, 128-bit if `keySize` is configured) via CryptoKit; keys stored as Keychain `kSecClassGenericPassword` items with `…ThisDeviceOnly` accessibility (and Secure Enclave-backed ECIES wrapping for `HARDWARE_ISOLATED` writes). One implementation, lives in `appleMain`, used by both iOS and native macOS — the Keychain Services + CryptoKit APIs are byte-for-byte identical between the two platforms; only the location of the Keychain database differs (per-app on iOS, per-user on macOS). On Apple Silicon and T2-equipped Intel Macs the Secure Enclave path works exactly as on iOS devices; on older Intel Macs without a T2 chip, SE key creation throws and the engine falls back to plain Keychain storage automatically (same fallback path that already covers iPhone 5/5C without an SE). On the **iOS Simulator**, an app with no signing team / no Keychain Sharing capability gets `errSecMissingEntitlement` (`-34018`) from every Keychain call; the engine detects that exact status *on the Simulator only* and falls back to `FileSimulatorFallbackKeyStore` (a sandbox file store on the host Mac, reported `SOFTWARE` in `protectionInfo`) instead of failing every encrypted write. Real devices never construct this store.
- **`JvmSoftwareEncryption`** — AES-GCM (256-bit default, 128-bit if `keySize` is configured) via `javax.crypto` for the payload; the AES key itself is held by an **OS secret store** (Windows DPAPI, macOS login Keychain, Linux Secret Service / libsecret) reached through the `JvmKeyVault` abstraction via JNA. The vault plays the **KEK role** — it stores/wraps the key bytes at rest — and KSafe does the AES in userspace with them (the **DEK role**), so there is no per-operation hardware round-trip. When no OS store is reachable (headless Linux, a JNA link failure, a `sun.misc.Unsafe`-less trimmed distributable) it degrades to a software `0700`-file vault at the same `SOFTWARE` tier; a self-test *failure* on a host where an OS vault exists is instead a fail-closed non-operational state (`jvm_os_vault_degraded`), not a silent software fallback. `KSafeConfig.appNamespace` isolates the per-OS-user store (which is shared by every process, unlike Android/iOS per-app sandboxing), resolved as: explicit value → `-Dksafe.appNamespace` → env `KSAFE_APP_NAMESPACE` → `"shared"`. Opt out of OS-store use with `-Dksafe.jvm.keyVault=software`. The full platform-by-platform treatment — DPAPI/Keychain/Secret Service internals, the hybrid ≤ 2.0 legacy-key migration and stale-key resolution, the `jdk.unsupported` JSON-fallback backend, the namespace resolution and self-test — lives in [JVM_PROTECTION.md](JVM_PROTECTION.md). The active vault and any fallback surface through `KSafe.protectionInfo`; see [PROTECTION_INFO.md](PROTECTION_INFO.md).
- **`WebSoftwareEncryption`** — AES-256-GCM via the WebCrypto **SubtleCrypto** API called directly (no longer through `cryptography-kotlin`). The AES key is generated/imported **non-extractable** (`extractable = false`) and its live `CryptoKey` object is persisted in **IndexedDB** — the raw key bytes are never exposed to JS or written to a readable location. *Values* still live in `localStorage` (`LocalStorageStorage`); only the key moved. A legacy `localStorage` raw key (KSafe ≤ 2.0) is imported as a non-extractable key into IndexedDB on first access and the `localStorage` entry deleted (same hybrid lazy + one-time background sweep as JVM, via `migrateLegacyKeysSuspend()`); the AES-GCM framing matches the old default so previously written ciphertext still decrypts. The legacy localStorage key is **authoritative**: when present it is imported and **overwrites** any stale IndexedDB key *and* the page-global in-memory cache (both of which can survive a prior lifecycle within an origin) — the un-namespaced legacy `localStorage` location is never touched, so migration stays intact. The browser already isolates IndexedDB/localStorage per origin; `KSafeConfig.appNamespace`, when set, additionally prefixes the IndexedDB record as defense-in-depth for multiple independent KSafe setups in one origin. WebCrypto is async-only, so this engine **only** implements the suspend variants and throws from the blocking ones — `KSafeCore` calls the suspend path from every coroutine-context site.

## Master AES keys and the v2 / v3 envelope

Starting in 2.0, KSafe stops generating a fresh AES key per encrypted entry. The pre-2.0 model — one Keystore/Keychain entry per `userKey` — meant every `put("foo", x)` paid the cost of a Keystore-backed key generation, and a write storm of 1,000 keys produced 1,000 Keystore handles. The v2 envelope replaces that with **one master AES key per datastore** for `KSafeProtection.DEFAULT` entries; `HARDWARE_ISOLATED` entries still get their own per-entry keys (the whole point of HARDWARE_ISOLATED is the StrongBox / Secure Enclave isolation, which it would lose if it shared a master).

KSafe writes one of two envelope versions per entry, chosen by the store's key generation (see **[Key rotation and key generations](#key-rotation-and-key-generations)** below): `KeySafeMetadataManager.envelopeVersionForWrite(generation)` returns **v2** for generation 1 (an un-rotated store — byte-identical to 2.0–2.2.x, no AAD) and **v3** once the store has been rotated at least once (generation ≥ 2). v3 keeps v2's routing but adds an **authenticated** AES-GCM envelope, described below. A generation-1 store is a pure v2 store, so upgrading to 3.0.0 changes nothing on disk until the first `rotateKeys()`.

**The two master variants.** Apple targets carry *two* master keys per datastore — one with relaxed accessibility (`requireUnlockedDevice = false`, written via `AfterFirstUnlockThisDeviceOnly`) and one strict (`= true`, `WhenUnlockedThisDeviceOnly`). The strict one fails to decrypt while the device is locked; the relaxed one keeps working as long as the user has unlocked once since boot. Per-entry `requireUnlockedDevice` picks the right master at write time. JVM collapses both variants into a single alias (there is no "device locked" concept on JVM, so a second master would never be used).

**The aliases.** Platform shells inject two functions:
- `keyAlias(userKey) → "$fileName?:$userKey"` on JVM and web, `"eu.anifantakis.ksafe[.$fileName].$userKey"` on Android and Apple — used for `HARDWARE_ISOLATED` entries, identical to the pre-2.0 scheme.
- `masterAlias(requireUnlockedDevice)` — the same two shapes with a reserved sentinel (`__ksafe_master__`, or `__ksafe_master_locked__` for the strict variant on the platforms that have a device lock) where the user key would go. Used for every v2 `DEFAULT` entry.

Both spellings come from a single `KSafeAliasFormat` helper, and the sentinels from the `KSafeReservedKeys` registry that the write-time reservation regexes are built from — so a user key can never be minted onto an alias KSafe already owns.

`KSafeCore.aliasForWrite(userKey, protection, requireUnlockedDevice, keyGeneration)` returns the master for `DEFAULT`, the per-entry alias for `HARDWARE_ISOLATED`, then applies the entry's generation suffix (below). `aliasForRead(userKey, protection)` does the inverse, driven by the entry's own recorded metadata to handle pre-v2 ciphertext (per-entry keys) and older generations side by side.

**Metadata-driven routing.** Every encrypted entry's on-disk metadata records its envelope version (`v=1` legacy per-entry, `v=2` master-key, `v=3` authenticated master-key), its per-entry `requireUnlockedDevice` flag, and — since 3.0.0 — its key `generation`. `KSafeCore` mirrors this into an in-memory map populated during cold-start preload, and the read path consults it to reconstruct the exact alias and (for v3) the exact AAD the entry was written with. The engine therefore serves v1, v2, and v3 ciphertext — and every past generation — side by side with no separate migration pass: an old entry decrypts under its recorded key, then the next write (or a `rotateKeys()` pass) rewrites it forward.

**The generation suffix.** `KSafeCore.aliasWithGeneration(baseAlias, generation)` returns the base alias unchanged for generation 1 (so an un-rotated store keeps the exact 2.2.x key names) and appends `.g<N>` for generation ≥ 2. This is what lets multiple generations of the master key coexist during and after a rotation; superseded generations are swept once nothing references them.

**Prewarm.** Cold start runs `engine.prewarmKey(masterAlias, …)` against each master alias from an off-thread coroutine launched in the constructor (`prewarmMasterKeys()`), independent of — and possibly ahead of — the first snapshot; on a rotated store it may race the snapshot and warm the base generation, which is harmless because the next write lazily creates the correct-generation key. It materialises the Keystore/Keychain handle eagerly so the very first user-driven `put` doesn't pay key-creation latency on the foreground path. Idempotent — a second cold start finds the handle already in place. (The Android engine overrides `prewarmKey` to create only the wrapping KEK, so a safe with no encrypted entries writes nothing.)

**The v3 authenticated envelope.** A v3 write additionally binds an AES-GCM **associated data (AAD)** string to each ciphertext — `KeySafeMetadataManager.aadFor(storeIdentity, userKey, protection, requireUnlockedDevice, keyGeneration)` — length-prefixed so the encoding is injective. The AAD ties the ciphertext to the store's identity, the user key, the protection tier, the unlock policy, and the key generation: every security-relevant field the read path routes on. An attacker with raw file access can no longer copy a ciphertext to another entry, swap it between the relaxed and strict master, relocate it to another store, or re-tier an *encrypted* entry and have it decrypt in the wrong context — the GCM tag check fails and the read **fails closed** to the caller's default. (Rewriting an entry's metadata to plaintext — `p:"NONE"` — instead reclassifies it as plaintext, so the read returns the stored bytes verbatim: undecipherable ciphertext, never the underlying secret.) Because a generation-1 store stays pure v2 (no AAD, exact pre-3.0.0 bytes), identity authentication begins at the first `rotateKeys()`. In plain terms: once rotated, an encrypted entry can't be copied, swapped, relocated, or re-tiered between keys without the read failing closed to the default. AAD is threaded through every platform engine (see the `aad` parameter on `KSafeEncryption` above); the deeper treatment is in [KEY_ROTATION.md](KEY_ROTATION.md) and [SECURITY_MODEL.md](SECURITY_MODEL.md).

**Read concurrency.** Because every `DEFAULT` read now decrypts under the *same* alias, the per-alias lock inside each engine (the lock that serialised concurrent encrypts pre-2.0) now serialises every `DEFAULT` decrypt on the master alias. The hot cache absorbs hot keys, but a cold burst of `getDirect` calls across N distinct `DEFAULT` keys still funnels through one lock. The trade-off is intentional: storage / handle counts drop from O(N entries) to O(1) per datastore, and the lock is in-process (cheap) — versus the previous model where every write paid a Keystore round-trip that contended on the platform's own per-key handle creation.

**Where to read the code:** `KeySafeMetadataManager.kt` — `envelopeVersionForWrite`, `aadFor`, `parseKeyGeneration`, `valueRawKey` / `metadataRawKey`. `KSafeCore.kt` — the routing entry points `aliasForWrite` / `aliasForRead` / `aadForRead`, plus the companion's `aliasWithGeneration` and `aadForEnvelope`; `aadForEnvelope` is the single v3 gate (the only caller of `KeySafeMetadataManager.aadFor`) and `encMetaMap` is the in-memory metadata mirror. `KSafeCore`'s remaining logic lives in the `internal.coreparts` sub-package as extension functions on the class: `KSafeCoreRouting.kt` holds the one `decryptEntry` that bundles the envelope-version check, alias resolution, the gated AAD and the legacy-identity retry; `KSafeCoreCacheMerge.kt` populates the metadata mirror during the first-snapshot preload; `KSafeCoreStartup.kt` holds `prewarmMasterKeys`. The platform-shell constructors that supply `masterAlias` / `keyAlias` are in `KSafe.{android,apple,jvm,web}.kt`.

## Key rotation and key generations

`KSafe.rotateKeys(): KSafeRotationResult` re-encrypts every encrypted entry under a fresh key, whole-store, on every platform. There is no per-key rotate — the unit is the datastore. The design rests on a single store-wide **key generation** counter:

- `KSafeCore.currentKeyGeneration` starts at 1 and is bumped by a rotation. Each write records the generation it used in the entry's metadata (the `g` field); `KeySafeMetadataManager.parseKeyGeneration` reads it back. The master alias for a generation is `aliasWithGeneration(masterAlias(...), g)` — un-suffixed for generation 1, `.g<N>` above — so generations coexist.
- The store's current generation is persisted as a reserved entry (`__ksafe_keygen__`, a small `{"g":N,"ts":…}` JSON), written through the same coalescer as every other op via a `SetKeyGeneration` write. The `ts` is the generation's birth time — the age the `MaxAge` policy measures.

**What a rotation pass does.** `rotateKeys()` bumps the generation, then walks every encrypted entry from a single snapshot: any entry already at (or above) the new generation is skipped; each older entry is decrypted under its recorded generation and re-encrypted under the new one through a `Rotate` write op. That op commits under a **compare-and-swap on the entry's stored ciphertext, serialized on the write consumer**, so a concurrent user write to the same key always wins and a rotation can never clobber or resurrect a value. Once the pass finishes, a `SweepSupersededMasters` op deletes every superseded master generation that nothing on disk still references. The result reports `rotated` / `skipped` / `failed` / the new `keyGeneration`.

**Crash-safe without a journal.** Because each entry names the generation that decrypts it, an interrupted rotation simply leaves a **mixed-generation store that stays fully readable** — old keys are retained until the last entry referencing them is gone, and the next `rotateKeys()` picks up whatever is still behind. There is no rollback log and no unreadable intermediate state.

**What counts as skipped vs. failed.** A strict (`requireUnlockedDevice`) entry rotates only while the device is unlocked; on a locked device it is reported `skipped` (not failed) and retried on a later pass. A transient key-store outage is likewise `skipped`. Only a definitive decrypt/re-encrypt failure is counted `failed`. **Values are sacred**: rotation changes key material and envelope, never data — a `getOrCreateSecret` secret keeps its value, only its wrapping key changes, so a database passphrase survives rotation untouched. Legacy (pre-2.x) entries are upgraded to the current envelope as a side effect.

**Automatic rotation.** `KSafeConfig.keyRotationPolicy` is `KSafeKeyRotationPolicy.Never` by default (key material is hardware/OS-protected and does not expire, so rotation is an opt-in hygiene/compliance control). `MaxAge(duration)` runs a **once-per-startup** background check — never blocking startup or reads — that rotates when the current generation is older than allowed; the age clock starts at the first launch under the policy and restarts on each rotation. Whatever it can't rotate this launch (strict entries on a locked device) is retried later — a manual `rotateKeys()` picks them up immediately, but the automatic `MaxAge` scheduler re-attempts only on the first launch after another full `maxAge`, because each rotation restamps the generation birth time and restarts the age clock. Left-behind entries stay readable under their retained old key until then.

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
| **Apple — `HARDWARE_ISOLATED`** | **Secure Enclave** EC keypair, ECIES-wraps the AES key | AES DEK, unwrapped into RAM | userspace (CryptoKit) | **Yes** — the SE is EC-only, it can't do AES itself |
| **JVM / Desktop** | **OS vault** — DPAPI / Keychain / libsecret holds the key bytes (fallback: a `0700` file) | AES key bytes from the vault → `SecretKeySpec` in RAM | userspace (**JCE**) | No — the vault stores the key bytes directly |
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

Encrypted writes carry a protection tier — `KSafeProtection.DEFAULT` (the regular hardware-backed path) or `KSafeProtection.HARDWARE_ISOLATED` (StrongBox on Android, Secure Enclave on iOS). The tier decides where the *encryption key* lives at rest, not where the ciphertext lives:

- **`DEFAULT`**: AES-256 key whose durable custody is hardware/OS-rooted (Android Keystore TEE, Apple Keychain, JVM OS vault). The *working* key does userspace AES from process memory — on Apple/JVM always, on Android since 2.1.2 via a TEE-wrapped DEK (see the **KEK / DEK** section above). `HARDWARE_ISOLATED`, by contrast, keeps the key out of app memory.
- **`HARDWARE_ISOLATED`**: a stronger guarantee, expressed differently per platform — Android requests `setIsStrongBoxBacked(true)` on the `KeyGenParameterSpec`, iOS / macOS create an EC private key in the Secure Enclave (`kSecAttrTokenIDSecureEnclave`) and use ECIES to wrap the AES key. The key generation hardware is physically separate from the main TEE.

Not every device has StrongBox or a Secure Enclave. KSafe handles this with a **silent fallback**: a write that requested `HARDWARE_ISOLATED` on a device without the hardware lands in regular `HARDWARE_BACKED` storage. The data is still protected; it just doesn't have the stronger isolation tier.

**The honesty pattern.** A caller who wrote with `HARDWARE_ISOLATED` is owed a way to ask "did that *actually* happen?" — for UI affordances ("stored in hardware-isolated chip") or for security audits. KSafe exposes this through `getKeyInfo(userKey): KSafeKeyInfo?`:

```kotlin
data class KSafeKeyInfo(
    val protection: KSafeProtection?,    // what was requested (or null for plain)
    val storage: KSafeKeyStorage,        // legacy: where the key actually lives — @Deprecated, prefer level
    val level: KSafeProtectionLevel,     // 2.1.0+: same universal scale as KSafe.protectionInfo
    val keyGeneration: Int = 1,          // 3.0.0+: generation that decrypts this entry (1 = never rotated)
)
```

The protection/storage/level fields can disagree. A request of `HARDWARE_ISOLATED` on a phone without StrongBox returns `KSafeKeyInfo(HARDWARE_ISOLATED, HARDWARE_BACKED, HARDWARE_BACKED)` — "you asked for the strong tier, you got the regular tier, here's what we actually delivered." `level` carries the same scale as the instance-level `KSafe.protectionInfo`, so cross-comparisons (instance baseline vs. per-key actual) are one ordinal compare. `storage` is the pre-2.1.0 three-value vocabulary, kept for source compatibility with a `@Deprecated(ReplaceWith("level"))` annotation; new code should prefer `level`. `keyGeneration` (3.0.0+) reports which key generation decrypts the entry — 1 until it is first rotated — so a rotation can be audited per key. How `storage`/`level` are resolved differs by platform: on Apple they are verified against the live Keychain custody of the entry's own key — an SE-wrapped key reports `HARDWARE_ISOLATED`, a legacy pre-SE plain Keychain key kept serving an SE request reports `HARDWARE_BACKED`, and a key living in the Simulator's entitlement-fallback sandbox file reports `SOFTWARE`; where the key cannot be classified (not yet minted, device locked) the report falls back to inference. On Android API 31+ they are verified against the Keystore key's actual security level (`KeyInfo.getSecurityLevel()`), so a per-write StrongBox fallback to TEE, or a pre-existing TEE key reused under a later `HARDWARE_ISOLATED` request, reports `HARDWARE_BACKED` per key; API 28-30 cannot distinguish StrongBox from TEE via `KeyInfo`, so those fall back to inference from the requested tier plus device capability (the StrongBox feature flag), as does any key the probe cannot load.

## Is encryption operational? (the preflight)

Protection *strength* and encryption *operability* are two different questions, and 3.0.0 gives each its own gate on `KSafe.protectionInfo` (a `KSafeProtectionInfo`):

- **"Is protection at its intended strength?"** → compare `effectiveLevel` against `intendedLevel`. A divergence means a runtime fallback occurred, but encryption may still work fine — a JVM software-vault fallback (no OS store on the host) and an iOS-Simulator sandbox key store both report `SOFTWARE` yet encrypt/decrypt normally.
- **"Will an encrypted write actually succeed?"** → read `isEncryptionOperational: Boolean`. It is a `val` computed in common code with no platform guards: `true` wherever encryption works — *including* those weaker-but-working fallbacks — and `false` only for the two genuinely non-operational states, each carried as a `notes` code: `web_crypto_subtle_unavailable` (a page served outside a secure context, so `crypto.subtle` is absent) and `jvm_os_vault_degraded` (an OS vault exists but is unreachable at startup — a locked Keychain/keyring, a headless launch — so KSafe refuses to mint keys and every encrypted op throws). Note the asymmetry on JVM: `jvm_os_vault_unavailable` (*no* OS store reachable → software fallback) stays **operational**; only `jvm_os_vault_degraded` (a store that *should* work but doesn't) is not.

The split matters because gating on `effectiveLevel != intendedLevel` would wrongly reject the functional software fallbacks, and gating on strength would miss a store that reports a strong level but can't actually persist. An app can therefore refuse to proceed when a write would silently fail (e.g. block login until it is served over HTTPS) without penalising a merely-weaker configuration. Full per-platform truth table and the `KSafeProtectionLevel` scale: [PROTECTION_INFO.md](PROTECTION_INFO.md).

## The Android `modeTransformer`

The deprecated `useStrongBox: Boolean` and `useSecureEnclave: Boolean` constructor flags promote default-protection encrypted writes to `HARDWARE_ISOLATED`. In 2.0 this is implemented as a `modeTransformer: (KSafeWriteMode) -> KSafeWriteMode` callback passed to `KSafeCore`'s constructor — Android and the Apple-platform factory (iOS + macOS) both pass the shared `promoteDefaultToIsolated`, bound to their respective flag; JVM and web pass identity. The transform runs once at the top of `putDirectRaw` / `putRaw`. This is the only platform-specific behaviour that crosses Ring 3 → Ring 2 on the write path.

## Cross-type migration

Reads automatically widen `Int → Long` and range-check-narrow `Long → Int` so an app that originally stored a counter as `Int` and later switched to `Long` (or vice versa) keeps working. Out-of-range narrowing returns the caller's `defaultValue` rather than silently truncating. Dispatch is done off the requested `KSerializer<T>`'s `PrimitiveKind`, not off the runtime class of the default — which is what makes the same code path correct on Kotlin/JS where `Float`, `Double`, and `Int` share a runtime representation.

## The reactive layer

KSafe's storage primitives are point-in-time (read this key, write this value). Apps usually want streams: "tell me when this key changes, with the current value as the first emission." The reactive layer is built on top of `KSafeCore.getFlowRaw(...)`, which maps `storage.snapshotFlow()` emissions through the same auto-detection / decryption logic the synchronous reads use, distinct-until-changed.

Three consumer-facing shapes wrap that primitive:

- **`getFlow(key, default): Flow<T>`** — cold flow, decoded per emission, emits whenever the underlying value changes from any source (this `KSafe` writing, another instance writing, an external edit, a delete). The multi-source wording is native-only: on Web each `LocalStorageStorage` re-emits solely on this instance's own writes (there is no `storage`-event listener), so Flows do **not** observe writes from another KSafe instance or another browser tab.
- **`getStateFlow(key, default, scope): StateFlow<T>`** — hot flow with a known synchronous initial value resolved via `getDirect` (so consumers don't see a brief incorrect "default" emission before the first real value lands). Materialized through `Flow.stateIn(scope, Eagerly, initial)`.
- **`asMutableStateFlow(key, default, scope): MutableStateFlow<T>`** — full `MutableStateFlow` interface; setting `.value` persists through `KSafe.putDirect`, observing collects external updates back into the wrapper.

Each of these has a property-delegate alias (`asFlow`, `asStateFlow`, `asMutableStateFlow`) so consumers can write `val state: StateFlow<User> by ksafe.asStateFlow(...)`. The delegates capture a `KSerializer<T>` once at creation rather than re-resolving it per access — without that, every call site would re-inflate the entire serialization graph.

The reactive layer doesn't change the storage contract; it's pure projection over `getFlowRaw`. The hot cache, write coalescer, and decryption rules all run unchanged.

## On-disk format

Every stored value lands in storage under canonical raw keys:

- Value bytes: `__ksafe_value_<userKey>`
- Metadata: `__ksafe_meta_<userKey>__` (a small JSON blob with envelope version, protection level, access policy, and — since 3.0.0 — the key `generation` that decrypts the entry)
- Store key generation: `__ksafe_keygen__` (a single reserved `{"g":N,"ts":…}` entry recording the store's current generation and its birth time; written on the first rotation, or on the first launch under a `MaxAge` policy to stamp the age clock — absent otherwise)

Pre-1.7 KSafe used different conventions (`encrypted_<userKey>` for ciphertext, `__ksafe_prot_<userKey>__` for metadata) and `KeySafeMetadataManager` still reads those legacy formats — when a legacy key is next written or deleted, it gets rewritten in the canonical form. iOS additionally honors a per-`fileName` legacy variant from pre-1.8 builds.

For Apple platforms there's also a 1.x → 2.0 *path* migration: pre-2.0 the DataStore lived in `NSDocumentDirectory`; 2.0 defaults to `NSApplicationSupportDirectory`, and the factory transparently moves a legacy file across on first launch when the new path is empty. iOS is the original target of this migration (1.x shipped on iOS); on native macOS the factory uses the same code, which means no-op for fresh installs and seamless behaviour if anyone happens to have a legacy file there.

## Orphan cleanup

There are two failure modes that can leave KSafe in an inconsistent state across reinstalls and crashes, and there's a separate cleanup mechanism for each.

**DataStore-side: stale ciphertext.** A write encrypts the value, stores the ciphertext in DataStore, then stores the encryption key in the platform Keystore / Keychain. If the app is uninstalled, on Android both the DataStore file and the app's Keystore keys are removed (Keystore keys are bound to the app's UID), so a clean uninstall/reinstall leaves nothing orphaned — stale ciphertext arises on Android only when Android Auto Backup restores the DataStore file on reinstall while the Keystore keys (which are never backed up) are gone. On iOS / macOS the Keychain entry survives uninstalls outright (Keychain items are not tied to the app's filesystem container). On reinstall, KSafe might find ciphertext on disk that it no longer has the key to decrypt — or, on iOS / macOS, a Keychain key for which there's no corresponding ciphertext.

`KSafeCore.cleanupOrphanedCiphertext()` handles the DataStore side: at startup, it probes every encrypted entry. If decryption fails with a "key not found" *or* "No encryption key found" error (case-insensitive — matches both Apple Keychain and Android Keystore phrasings), the entry is deleted from storage. If it fails with a "device is locked" error (a transient condition), it's left alone — the entry might decrypt fine on the next launch. The probes run concurrently inside a `coroutineScope { … }` with a `Semaphore(8)` cap (same pattern as the write coalescer's parallel encrypt and the preload's parallel decrypt) — sweeping a 1500-key store completes in milliseconds rather than seconds, so it doesn't visibly delay the first read on apps with many encrypted entries.

**Apple Keychain-side: stale Keychain entries.** The reverse problem on iOS / macOS — a Keychain entry survives an app reinstall because Keychain items aren't tied to the app's filesystem container the way DataStore files are. On reinstall, KSafe finds Keychain entries that the new install's DataStore doesn't reference. `cleanupOrphanedKeychainEntries(...)` (in `appleMain/internal/KeychainOrphanCleanup.kt`) sweeps these on first launch: it reads `storage.snapshot()` to compute the live key set, scans Keychain generic-password and `kSecClassKey` items, and deletes any whose `kSecAttrAccount` doesn't match a live DataStore key. The two scans cover both the AES-key and the wrapped-EC-key shapes, so partially-failed `HARDWARE_ISOLATED` writes (a crash between SE-key creation and the wrapped-AES storage) get cleaned up too.

The Apple sweep is **destructive in a way the DataStore sweep is not** — once an SE EC private key is removed from the Secure Enclave it cannot be recreated, so any ciphertext encrypted under it becomes permanently undecryptable. Two structural invariants protect against accidental destruction:

1. **`startBackgroundCollector` runs the sweep only after the first `snapshotFlow` emission.** This guarantees DataStore has finished its initial read before the sweep computes "what's a live key" — closing a race window where the 1.x → 2.0 path migration in `KSafe.apple.kt` (which moves the file from `NSDocumentDirectory` to `NSApplicationSupportDirectory` immediately before DataStore is constructed) could deliver an empty snapshot to a sweep that would then nuke every legitimate key. (The pre-fix ordering hit exactly this on real devices upgrading directly from 1.8.x to 2.0.0-RC2; see CHANGELOG `2.0.0 → Fixed`.)
2. **The sweep refuses to delete when `snapshot.isEmpty() && orphanedKeyIds.isNotEmpty()`.** "DataStore reports zero entries but the Keychain has scoped items" is the signature of a partial view (failed migration, corrupted DataStore, OS-level data wipe that left the Keychain alone) — and in every one of those scenarios deleting the Keychain destroys irrecoverable state. The guard logs a message pointing at `KSafe.clearAll()` for users who genuinely intended a wipe, and the regression test [`KSafeCoreStartupOrderingTest`](../ksafe/src/jvmTest/kotlin/eu/anifantakis/lib/ksafe/KSafeCoreStartupOrderingTest.kt) in jvmTest pins both invariants in place.

Both sweeps are idempotent and "best-effort": failures during cleanup are swallowed (`runCatching`) rather than blocking startup. If a sweep can't run today (locked device, simulator quirks), it'll run cleanly on the next launch.

Because the real Keychain / Secure Enclave behaviour these sweeps depend on can't be exercised from the Simulator, an on-device harness lives in **[`ios-device-test/`](../ios-device-test/README.md)** (`run-xctest.sh` for a curated Swift XCTest, `run-full-suite.sh` for the full `kotlin.test` suite via a signed `.app`). See [TESTING.md](TESTING.md) for the wider test map.

## Error-propagation strategy

Decryption can fail for two distinct reasons, and KSafe handles them differently:

**Transient failures.** The device is locked, the Keychain is unavailable, the Keystore is in a bad state — conditions that should clear on retry. `isTransientDecryptFailure(throwable)` (in `KSafeCoreFailureClassification.kt`) recognises these, case-insensitively matching the platform error messages for "device is locked", "Keystore" and "Keychain" — after first excluding KSafe's own definitive results ("No encryption key found", "key not found", "vault unavailable"), which are never retryable. Those phrases are not re-typed per engine: they live in one `KSafeEngineMessage` registry that all four engines throw from and the core matches on. On a transient failure the behaviour depends on the read API: the suspend `get()` re-throws the original exception so the caller can await unlock and retry; `getDirect()`, the property delegates, and the synchronous Compose / StateFlow seed have no retry seam and return the caller's `defaultValue` (letting the exception escape would crash property access or composition on a locked device); a `getFlow()` observer skips that emission and keeps its last value, so a locked device doesn't crash long-lived collectors — the next decryptable snapshot updates it. Returning a silent `defaultValue` from the suspend `get()` for transient errors would mask correctness bugs as if data was missing.

**Permanent failures.** Decryption fails because the key genuinely doesn't exist (uninstall left ciphertext behind, key was deleted, etc.). These look the same to user code as "no value stored" — KSafe returns `defaultValue` and adds the entry to the orphan cleanup list. The user-facing behaviour is correct (you get the default you asked for) and the storage gets cleaned up so future reads don't pay the cost.

This split was a real bug pre-2.0: only Android's read path re-threw transient errors; iOS and JVM swallowed them. 2.0's shared `isTransientDecryptFailure` runs on every platform, so a locked device reliably surfaces to the caller for retry handling instead of being silently masked as "no data."

## Concurrency model

KSafe is thread-safe by construction. The hot cache, the dirty-keys set, and per-instance flags all use `expect/actual` concurrency primitives (`KSafeConcurrentMap`, `KSafeConcurrentSet`, `KSafeAtomicFlag`, `runBlockingOnPlatform`):

- JVM / Android: `java.util.concurrent.ConcurrentHashMap` + `AtomicBoolean`. `runBlockingOnPlatform` uses `runBlocking`. The two JVM-bytecode targets share one implementation in the `jvmSharedMain` intermediate source set (the actuals are `java.*` and kotlinx code with no Android API in them); it can't be `datastoreMain`, because Apple shares that set and has its own actuals for these.
- iOS / macOS: `kotlin.concurrent.AtomicReference` with copy-on-write semantics (Kotlin/Native lacks `ConcurrentHashMap`). `KSafeAtomicFlag` is backed by `AtomicInt(0/1)` because boxed `Boolean` doesn't have stable reference identity on Native. The implementation lives in `appleMain` and is shared by all five Apple targets.
- Web: plain `HashMap` / `HashSet` / `var Boolean`. The browser is single-threaded so locking is unnecessary. `runBlockingOnPlatform` throws — the only site that reaches it on web (`KSafeCore.ensureCacheReadyBlocking`) catches and falls through to returning the caller's default, since browsers can't block their main thread. (The other caller, the shared DataStore backend's teardown wait, is in `datastoreMain` and never compiles for web.)

The write-coalescer lives in a single coroutine that drains the channel and applies batches sequentially. There's no lock contention because there's exactly one consumer.

## What 2.0 changed vs. 1.x

In one paragraph: pre-2.0, `KSafe` was an `expect class` with most of its logic duplicated four times across `KSafe.{android,ios,jvm,web}.kt` (the cache, write coalescer, metadata, orphan cleanup, `*Raw` plumbing — ~5,900 lines of platform-shell code total). 2.0 hoists everything that isn't genuinely platform-specific into `KSafeCore` in commonMain (a single ~1,500-line orchestrator), promotes `KSafe` itself to a regular common class with per-platform factory functions, factors storage and encryption behind two narrow interfaces, and extracts biometric verification into a separate optional module. Bug fixes and feature additions ship once and apply everywhere instead of being implemented and tested four times. The platform shells dropped from ~5,900 lines to ~890 lines; the tests pass identically on every target.

2.0.1 then folded `iosMain` into `appleMain` so the same Keychain + CryptoKit + Secure Enclave code now serves both iOS and native macOS — the iOS implementation never reached for UIKit, so the merge was mechanical: file moves + `Ios*` → `Apple*` renames + a single behaviour fix in `SecurityChecker` (jailbreak-style path probes short-circuit on macOS, where `/bin/sh` and friends exist on every host).

For the file-by-file map of where each concept lives in source, see **[docs/TOUR.md](TOUR.md)**.
