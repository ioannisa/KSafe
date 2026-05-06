# Performance Benchmarks

Here are benchmark results comparing KSafe against popular Android persistence libraries.

> **2.0 release headline:** these numbers reflect the **v2 envelope** introduced in 2.0 — a single per-datastore master AES key (held in-process after first unwrap) replaces per-entry Keystore keys for `KSafeProtection.DEFAULT` writes. Every encrypted op that used to round-trip the Android Keystore now runs as in-process AES-GCM against cached key bytes. The biggest gains land on the IPC-bound paths: `ENCRYPTED`-memory reads dropped 45×, suspend `put` of encrypted values dropped 5–10×. `HARDWARE_ISOLATED` writes still use per-entry keys (StrongBox isolation requires it) and are unchanged.
>
> The default memory policy is **`LAZY_PLAIN_TEXT`** in 2.0. Its read profile matches `PLAIN_TEXT` after first access (plaintext cached permanently in the side cache) and matches `ENCRYPTED` cold-start (no bulk decrypt at startup). The first read of each key under `LAZY_PLAIN_TEXT` pays one decrypt — comparable to a single `ENCRYPTED`-memory read.

### Benchmark Environment

- **Device:** AOSP Emulator, API 37, running on a MacBook Pro with the **18-core M5 Pro** chip.
- **Test:** 500 read/write operations per library, exercised in their natural usage pattern.
- **Reported numbers:** values from a representative steady-state run after the workload reaches stable JIT behavior.
- **Libraries tested:** KSafe, SharedPreferences, EncryptedSharedPreferences, MMKV, DataStore, Multiplatform Settings, KVault.

> **Emulator caveat:** an emulator on Apple Silicon is not a physical Android device. Host-CPU encryption performance, IPC routing through `binder` emulation, and storage I/O all behave somewhat differently from a real Pixel or Galaxy. Treat absolute numbers as indicative; the **relative comparisons between libraries on the same emulator** are the meaningful signal. Run-to-run variance at µs scale can reach ±20–30%; the numbers below are typical, not best-case.

### Results Summary

#### Unencrypted Operations

| Library | Read | Write |
|---------|------|-------|
| MMKV | 0.0006 ms | 0.0132 ms |
| SharedPreferences | 0.0007 ms | 0.0131 ms |
| Multiplatform Settings | 0.0009 ms | 0.0132 ms |
| **KSafe (Delegated)** | **0.0021 ms** | **0.0043 ms** |
| **KSafe (Direct)** | 0.0094 ms | 0.0067 ms |
| KSafe (Coroutine) | 0.0208 ms | 0.6204 ms |
| DataStore | 0.3386 ms | 2.87 ms |

> **Note:** KSafe unencrypted reads are ~3× slower than MMKV in absolute terms (2.1 µs vs 0.6 µs) — the cost of cross-platform generics and `kotlinx-serialization`-driven type widening. Both numbers are well below human perception thresholds. Writes are excellent: KSafe Delegated is **~3× faster than MMKV** (4.3 µs vs 13.2 µs) and **~3× faster than SharedPreferences**.

#### Encrypted Read Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory, Delegated)** | **0.0044 ms** | — |
| KSafe (PLAIN_TEXT memory, Direct) | 0.0090 ms | — |
| KSafe (PLAIN_TEXT memory, Coroutine) | 0.0262 ms | — |
| KVault | 0.0916 ms | KSafe is **~21× faster** |
| EncryptedSharedPreferences | 0.1077 ms | KSafe is **~24× faster** |
| KSafe (ENCRYPTED memory, Delegated) | 0.1421 ms | *(real AES-GCM decryption on every read, master-key-cached)* |
| KSafe (ENCRYPTED memory, Coroutine) | 0.2299 ms | |
| KSafe (ENCRYPTED memory, Direct) | 0.2372 ms | |

> **Note on ENCRYPTED memory policy:** This policy keeps ciphertext in RAM and performs real AES-GCM decryption on every read. Under v2, the master AES key lives in the engine's in-process cache after construction, so each decrypt is a pure-CPU op — no Keystore IPC. Result: ENCRYPTED-memory reads are now ~45× faster than they were under v1's per-entry-key scheme (10.6 ms → 0.24 ms on this benchmark). For most use cases the default `LAZY_PLAIN_TEXT` is still preferable (first read decrypts, subsequent reads are O(1) memory lookups), but ENCRYPTED is no longer a "you'll regret it under bursty reads" choice.

#### Encrypted Write Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory, Delegated)** | **0.0095 ms** | — |
| KSafe (ENCRYPTED memory, Direct) | 0.0111 ms | — |
| KSafe (ENCRYPTED memory, Delegated) | 0.0114 ms | — |
| KSafe (PLAIN_TEXT memory, Direct) | 0.0176 ms | — |
| EncryptedSharedPreferences | 0.1361 ms | KSafe is **~14× faster** |
| KSafe (ENCRYPTED memory, Coroutine) | 0.7791 ms | *(awaits disk commit)* |
| KSafe (PLAIN_TEXT memory, Coroutine) | 1.19 ms | *(awaits disk commit)* |
| KVault | 1.21 ms | KSafe is **~127× faster** |

> **v2 impact on suspend writes.** Coroutine-API encrypted writes that wait for the disk commit dropped from 3.84 ms (v1) → 0.78 ms (v2) for ENCRYPTED memory and from 4.26 ms → 1.19 ms for PLAIN_TEXT — a 4–5× speedup. The dominant cost in v1 was per-entry Keystore IPC inside the encrypt batch; v2 collapses that to a single in-process AES op against the cached master key. Direct-API writes (which return immediately and let the coalescer flush in the background) were already fast and are now marginally faster.

### Key Performance Highlights

**vs DataStore (KSafe's backend):**
- :zap: **~673× faster writes** (2.87 ms → 0.0043 ms)
- :zap: **~163× faster reads** (0.339 ms → 0.0021 ms)

**vs KVault (encrypted KMP storage):**
- :zap: **~21× faster encrypted reads** (0.092 ms → 0.0044 ms with PLAIN_TEXT memory)
- :zap: **~127× faster encrypted writes** (1.21 ms → 0.0095 ms)

**vs EncryptedSharedPreferences:**
- :zap: **~24× faster encrypted reads** (0.108 ms → 0.0044 ms with PLAIN_TEXT memory)
- :zap: **~14× faster encrypted writes** (0.136 ms → 0.0095 ms)

**vs SharedPreferences (unencrypted baseline):**
- KSafe unencrypted writes are **~3× faster** than SharedPreferences (0.0043 ms vs 0.0131 ms)
- Reads are ~3× slower (0.0021 ms vs 0.0007 ms) — the cost of type-safe generics and cross-platform API

**vs multiplatform-settings (Russell Wolf):**
- KSafe writes ~3× faster (0.0043 ms vs 0.0132 ms)
- KSafe reads ~2× slower (0.0021 ms vs 0.0009 ms)
- KSafe adds: encryption, biometrics, type-safe serialization, hardware isolation

**Direct vs Suspend API (within KSafe):**
- `getDirect()` is **~10× faster** than suspend `get()` for reads (hot cache vs DataStore round-trip)
- `putDirect()` is **~146× faster** than suspend `put()` for writes (queue + return vs await disk commit)

### Cold Start Performance

How quickly each library is ready to serve reads after the in-process cache is cleared and forced to repopulate. The KSafe instance is reused (DataStore is a singleton) — the harness clears `memoryCache` and times the next `getDirect()` that triggers the reload.

| Library | Keys | Time |
|---------|------|------|
| SharedPreferences | 501 | 0.024 ms |
| **KSafe (PLAIN_TEXT memory)** | 3006 (1500 encrypted + 1506 plain) | **0.031 ms** |
| Multiplatform Settings | 501 | 0.032 ms |
| MMKV | 501 | 0.050 ms |
| DataStore | 501 | 0.495 ms |
| EncryptedSharedPrefs | 501 | 8.24 ms |
| KVault | 650 | 9.91 ms |
| **KSafe (ENCRYPTED memory)** | 1503 (1500 encrypted + 3 plain) | **12.70 ms** |

> **Reading these numbers honestly.** The harness measures cache-repopulation throughput, not first-launch process boot. Both KSafe modes benefit from the v2 master key being in the engine cache (it's pre-warmed once at construction); per-key Keystore IPC during repopulation is gone. The per-key asymmetry between the two modes reflects what they actually do during the reload:
>
> - **`ENCRYPTED` memory mode** stashes ciphertext into the cache and does an orphan-cleanup probe (one decrypt round-trip per encrypted key, parallelised eight-at-a-time via `Semaphore(8)`). With 1500 encrypted entries, that probe dominates the 12.7 ms total at ~8.5 µs/key.
> - **`PLAIN_TEXT` memory mode** decrypts every encrypted entry into the cache eagerly. Despite reloading more keys (3006 vs 1503), it lands at 0.031 ms because the harness is timing one `getDirect()` after the reload completes — the rebuild work happens inside the collector coroutine and the timed call is a hashmap hit.
>
> Real cold-start (process restart) under `ENCRYPTED` and `LAZY_PLAIN_TEXT` is ~free regardless of key count: the cache holds ciphertext, no eager decryption happens. `PLAIN_TEXT` pays the bulk-decrypt up-front; under v2 with the master key cached, that's microseconds-per-key amortised. Both modes still destroy `EncryptedSharedPreferences` (8.24 ms for 501 keys = ~16 µs/key, serial Keystore IPC) and `KVault` (9.91 ms for 650 keys = ~15 µs/key, serial) on a per-key basis — both libraries serialise their hardware-backed crypto and pay one IPC per entry on every cold start.

### How KSafe Achieves This Performance

KSafe uses a **hot cache architecture** similar to SharedPreferences, but built on top of DataStore:

```
Vanilla DataStore:
  Read:  suspend → Flow.first() → disk I/O → ~0.34 ms
  Write: suspend → edit{} → serialize → disk I/O → ~2.9 ms

KSafe with Hot Cache:
  Read:  getDirect() → ConcurrentHashMap lookup → ~0.002 ms (no disk!)
  Write: putDirect() → update HashMap + queue → ~0.004 ms (returns immediately)
         Background: batched, parallelised DataStore.edit() (user doesn't wait)
```

**Key optimizations:**

1. **ConcurrentHashMap cache** — O(1) per-key reads and writes
2. **v2 master-key envelope (new in 2.0)** — `KSafeProtection.DEFAULT` writes encrypt against a single per-datastore AES key cached in-process after first unwrap, instead of a per-entry Keystore key. Eliminates the Keystore IPC round-trip from every encrypt and decrypt of non-isolated values. `HARDWARE_ISOLATED` writes still get per-entry keys.
3. **Write coalescing** — batches writes within a 16 ms window into a single DataStore edit; concurrent suspend `put()` calls from independent coroutines coalesce automatically
4. **Parallel encryption inside the batch** — encrypts up to 8 entries concurrently per batch via `coroutineScope` + `Semaphore(8)`; under v2 this still helps `HARDWARE_ISOLATED` IPC pipelining and parallelises the (now CPU-only) AES work for `DEFAULT` entries
5. **Parallel decryption at cold start** — `PLAIN_TEXT` memory mode populates the cache by decrypting all stored entries through the same `coroutineScope` + `Semaphore(8)` pattern; under v2 these decrypts are pure-CPU AES, not IPC
6. **Deferred encryption** — encryption work moved to background; the UI thread returns instantly from `putDirect`
7. **SecretKey caching (per-engine, in-process)** — Android, Apple, and JVM engines all hold the unwrapped key bytes in a process-static map keyed by alias. Combined with v2's master alias, the entire datastore's encryption flow needs zero IPC after the first unwrap
8. **Auto-protection-detection** — readers don't have to remember whether a key is encrypted; the library figures it out from per-key metadata. Stores with no encrypted entries short-circuit the lookup via an atomic flag, so plain-only consumers pay zero overhead. Mixed stores pay a single sub-microsecond `ConcurrentHashMap` lookup per read. Eliminates a class of "wrote encrypted, read plain" bugs

This means KSafe gives you DataStore's safety guarantees (atomic transactions, type-safe) with SharedPreferences-class read latency and **faster writes than any other compared library**.

### Methodology Notes

- **Read benchmarks** for the suspend API issue all 500 reads as concurrent `GlobalScope.launch` jobs and wait via `joinAll()`. This represents real-app usage where multiple coroutines read from KSafe in parallel (Compose recompositions, Flow collectors, repository fan-out). The reported per-op time is the amortised wall-clock cost when the workload genuinely overlaps.
- **Write benchmarks** for the suspend API use the same concurrent pattern. KSafe's write coalescer sees the burst of N writes in its channel, batches them into a small number of `applyBatch` transactions, and amortises the disk-flush cost across all callers. This is **the architectural feature suspend `put` was designed to enable** — the previous "1 sequential await per call" pattern was effectively single-threading a multi-threaded primitive.
- **Direct (`getDirect`/`putDirect`) and Delegated (`var x by ksafe(0)`)** variants of KSafe perform similarly on the hot path. On encrypted reads under `ENCRYPTED` memory, Delegated tends to land slightly faster than Direct in the table — that's because the Delegated path's first call seeds the plaintext side cache, so subsequent reads hit RAM instead of running another decrypt; whereas the Direct cell here is repeatedly forcing the decrypt path. Both paths use the master-key cache.
- **Coroutine encrypted ops show the largest v2 wins** — they wait for the actual encrypt or decrypt to complete, so removing the Keystore IPC dropped them 4–80× depending on the cell. Coroutine encrypted READ under PLAIN_TEXT (2.13 ms → 0.026 ms) is the biggest absolute reduction in the suite.
- **Total benchmark runtime is now ~11 seconds** for 500 iterations across all cells (down from ~23 seconds pre-v2). Most of that is still encrypted writes (where the disk-commit await dominates per-batch time on the Coroutine API) and the cold-start orphan-cleanup probe under ENCRYPTED memory.

***
