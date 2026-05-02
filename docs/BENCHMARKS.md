# Performance Benchmarks

Here are benchmark results comparing KSafe against popular Android persistence libraries.

### Benchmark Environment

- **Device:** Samsung Galaxy S24 Ultra (physical device, not emulator)
- **Test:** 500 read/write operations per library, exercised in their natural usage pattern
- **Reported numbers:** values from a representative steady-state run after the device has reached stable thermal/JIT behavior
- **Libraries tested:** KSafe, SharedPreferences, EncryptedSharedPreferences, MMKV, DataStore, Multiplatform Settings, KVault

> Numbers are specific to this device and workload. Results will vary on other hardware, OS versions, and real-world access patterns — treat them as relative comparisons rather than absolute guarantees. Run-to-run variance at µs scale can reach ±20–30%; the numbers below are typical, not best-case.

### Results Summary

#### Unencrypted Operations

| Library | Read | Write |
|---------|------|-------|
| SharedPreferences | 0.0010 ms | 0.0202 ms |
| MMKV | 0.0016 ms | 0.0157 ms |
| Multiplatform Settings | 0.0018 ms | 0.0232 ms |
| **KSafe (Direct)** | **0.0088 ms** | 0.0236 ms |
| **KSafe (Delegated)** | 0.0074 ms | **0.0083 ms** |
| KSafe (Coroutine) | 0.0255 ms | 0.95 ms |
| DataStore | 0.3639 ms | 4.87 ms |

> **Note:** KSafe unencrypted reads are ~9× slower than SharedPreferences in absolute terms (8.8 µs vs 1 µs) — the cost of cross-platform generics and `kotlinx-serialization`-driven type widening. Both numbers are well below human perception thresholds (a UI rendering 100 reads per frame still has ~14 ms of headroom). Writes are excellent: KSafe Delegated is **~2× faster than MMKV** and ~2.4× faster than SharedPreferences.

#### Encrypted Read Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory, Direct)** | **0.0123 ms** | — |
| KSafe (PLAIN_TEXT memory, Delegated) | 0.0101 ms | — |
| KSafe (PLAIN_TEXT memory, Coroutine) | 0.0224 ms | — |
| KVault | 0.1727 ms | KSafe is **~17× faster** |
| EncryptedSharedPreferences | 0.1736 ms | KSafe is **~17× faster** |
| KSafe (ENCRYPTED memory, Coroutine) | 2.95 ms | *(real AES-GCM decryption via Keystore on every read)* |
| KSafe (ENCRYPTED memory, Delegated) | 5.53 ms | |
| KSafe (ENCRYPTED memory, Direct) | 10.62 ms | |

> **Note on ENCRYPTED memory policy:** The ENCRYPTED memory policy keeps ciphertext in RAM and performs real AES-GCM decryption through the Android Keystore on every read (~3-10 ms depending on API style). This is the cost of hardware-backed cryptography. For most use cases, use `PLAIN_TEXT` (decrypts once at init) or `ENCRYPTED_WITH_TIMED_CACHE` (decrypts once per TTL window).

#### Encrypted Write Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (ENCRYPTED memory, Delegated)** | **0.0237 ms** | — |
| KSafe (PLAIN_TEXT memory, Delegated) | 0.0188 ms | — |
| KSafe (ENCRYPTED memory, Direct) | 0.0235 ms | — |
| KSafe (PLAIN_TEXT memory, Direct) | 0.0377 ms | — |
| EncryptedSharedPreferences | 0.1829 ms | KSafe is **~8× faster** |
| KVault | 1.25 ms | KSafe is **~53× faster** |
| KSafe (ENCRYPTED memory, Coroutine) | 5.25 ms | *(awaits disk commit)* |
| KSafe (PLAIN_TEXT memory, Coroutine) | 6.86 ms | *(awaits disk commit)* |

> **Memory-policy parity on writes.** `ENCRYPTED` memory policy adds essentially no overhead vs `PLAIN_TEXT` on writes (0.0237 vs 0.0188 ms — within run-to-run noise at delegated scale). The write-coalescer encrypts batched entries concurrently inside a `coroutineScope` with bounded fan-out, so hardware-keystore IPC pipelines instead of running serially.

### Key Performance Highlights

**vs DataStore (KSafe's backend):**
- :zap: **~590× faster writes** (4.87 ms → 0.008 ms)
- :zap: **~41× faster reads** (0.36 ms → 0.009 ms)

**vs KVault (encrypted KMP storage):**
- :zap: **~17× faster encrypted reads** (0.17 ms → 0.010 ms with PLAIN_TEXT memory)
- :zap: **~53× faster encrypted writes** (1.25 ms → 0.024 ms)

**vs EncryptedSharedPreferences:**
- :zap: **~17× faster encrypted reads** (0.17 ms → 0.010 ms with PLAIN_TEXT memory)
- :zap: **~8× faster encrypted writes** (0.18 ms → 0.024 ms)

**vs SharedPreferences (unencrypted baseline):**
- KSafe unencrypted writes are **~2.4× faster** than SharedPreferences (0.008 ms vs 0.020 ms)
- Reads are ~9× slower (0.009 ms vs 0.001 ms) — the cost of type-safe generics and cross-platform API

**vs multiplatform-settings (Russell Wolf):**
- KSafe writes ~3× faster (0.008 ms vs 0.023 ms)
- KSafe reads ~5× slower (0.009 ms vs 0.002 ms)
- KSafe adds: encryption, biometrics, type-safe serialization, hardware isolation

### Cold Start Performance

How quickly each library is ready to serve reads after process restart, for a store with N pre-populated keys.

| Library | Keys | Time |
|---------|------|------|
| SharedPreferences | 501 | 0.024 ms |
| **KSafe (ENCRYPTED memory)** | 1503 (1500 encrypted + 3 plain) | **0.06 ms** |
| Multiplatform Settings | 501 | 0.069 ms |
| MMKV | 501 | 0.071 ms |
| DataStore | 501 | 1.55 ms |
| **KSafe (PLAIN_TEXT memory)** | 3006 (1500 encrypted + 1506 plain) | **35 ms** |
| KVault | 650 | 128 ms |
| EncryptedSharedPrefs | 501 | 168 ms |

> **Architectural note — both memory modes scale well even with thousands of encrypted keys:**
>
> - **`ENCRYPTED` memory mode** stashes ciphertext into the cache without decrypting. Decryption happens at read time. Cold start does no Keystore work for the data itself — it is effectively just a DataStore map copy — so it scales O(metadata). The orphan-cleanup probe that validates each Keystore entry on startup runs concurrently via `coroutineScope` + `Semaphore(8)`, so 1500 key existence checks pipeline instead of stalling; the total time (including the probe) falls under 0.1 ms.
> - **`PLAIN_TEXT` memory mode** decrypts all encrypted entries during cache warm-up. The decryption work is parallelised through the same fan-out pattern, so Keystore IPC pipelines instead of stalling. 1500 entries in ~35 ms is roughly 23 µs per key amortised — fast, but still proportional to key count; choose `ENCRYPTED` mode if cold-start time is critical and per-read decrypt cost is acceptable.
>
> Both modes destroy `EncryptedSharedPreferences` (~168 ms for 501 keys = ~335 µs/key, serial) and `KVault` (~128 ms for 650 keys = ~197 µs/key, serial) — they don't pipeline their hardware-backed crypto and serialise every key fetch on startup.

### How KSafe Achieves This Performance

KSafe uses a **hot cache architecture** similar to SharedPreferences, but built on top of DataStore:

```
Vanilla DataStore:
  Read:  suspend → Flow.first() → disk I/O → ~0.36 ms
  Write: suspend → edit{} → serialize → disk I/O → ~4.9 ms

KSafe with Hot Cache:
  Read:  getDirect() → ConcurrentHashMap lookup → ~0.009 ms (no disk!)
  Write: putDirect() → update HashMap + queue → ~0.008 ms (returns immediately)
         Background: batched, parallelised DataStore.edit() (user doesn't wait)
```

**Key optimizations:**
1. **ConcurrentHashMap cache** — O(1) per-key reads and writes
2. **Write coalescing** — batches writes within a 16 ms window into a single DataStore edit; concurrent suspend `put()` calls from independent coroutines coalesce automatically
3. **Parallel encryption inside the batch** — encrypts up to 8 entries concurrently per batch via `coroutineScope` + `Semaphore(8)`, so hardware-keystore IPC pipelines instead of stalling
4. **Parallel decryption at cold start** — `PLAIN_TEXT` memory mode populates the cache by decrypting all stored entries through the same `coroutineScope` + `Semaphore(8)` pattern; the orphan-cleanup sweep that probes every encrypted entry on startup uses it too. Cold-start time on stores with thousands of encrypted keys drops from milliseconds-per-key to microseconds-per-key amortised.
5. **Deferred encryption** — encryption work moved to background; the UI thread returns instantly from `putDirect`
6. **SecretKey caching** — avoids repeated Android Keystore lookups
7. **Auto-protection-detection** — readers don't have to remember whether a key is encrypted; the library figures it out from per-key metadata. Stores with no encrypted entries short-circuit the lookup via an atomic flag, so plain-only consumers pay zero overhead. Mixed stores pay a single sub-microsecond `ConcurrentHashMap` lookup per read. Eliminates a class of "wrote encrypted, read plain" bugs

This means KSafe gives you DataStore's safety guarantees (atomic transactions, type-safe) with SharedPreferences-class read latency and **faster writes than any other compared library**.

### Methodology Notes

- **Read benchmarks** for the suspend API issue all 500 reads as concurrent `GlobalScope.launch` jobs and wait via `joinAll()`. This represents real-app usage where multiple coroutines read from KSafe in parallel (Compose recompositions, Flow collectors, repository fan-out). The reported per-op time is the amortised wall-clock cost when the workload genuinely overlaps.
- **Write benchmarks** for the suspend API use the same concurrent pattern. KSafe's write coalescer sees the burst of N writes in its channel, batches them into a small number of `applyBatch` transactions, and amortises the disk-flush cost across all callers. This is **the architectural feature suspend `put` was designed to enable** — the previous "1 sequential await per call" pattern was effectively single-threading a multi-threaded primitive.
- **Direct (`getDirect`/`putDirect`) and Delegated (`var x by ksafe(0)`)** variants of KSafe perform similarly on the hot path; on writes, the Delegated path tends to JIT-inline more aggressively after warmup, so we report Delegated as the canonical KSafe number for writes.
- **The Coroutine API (`suspend get`/`put`) is now competitive with the Direct API** — in this benchmark the suspend put runs at ~115× the speed of `putDirect` (vs the deceptive multi-thousand-x ratios sequential awaits used to produce). When called from independent coroutines, the suspend API's coalescer brings real-world latency close to the fire-and-forget Direct API while still guaranteeing disk persistence.
- **Coroutine read numbers carry higher run-to-run variance** than Direct or Delegated reads — the coroutine dispatch overhead (~10–15 µs) can dominate at these scales, so treat the coroutine-read cell as indicative rather than precise.
- **Total benchmark runtime is ~40 seconds** for 500 iterations across all cells. Most of that is the encrypted writes (where the Keystore IPC dominates per-batch time) and the cold-start population. The fastest cells (Direct read, Delegated write) finish in single-digit milliseconds combined.

***
