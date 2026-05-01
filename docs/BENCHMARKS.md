# Performance Benchmarks

Here are benchmark results comparing KSafe against popular Android persistence libraries.

### Benchmark Environment

- **Device:** Samsung Galaxy S24 Ultra (physical device, not emulator)
- **Test:** 500 sequential read/write operations per library, averaged
- **Reported numbers:** median across 4 full benchmark runs to filter out single-run variance
- **Libraries tested:** KSafe, SharedPreferences, EncryptedSharedPreferences, MMKV, DataStore, Multiplatform Settings, KVault

> Numbers are specific to this device and workload. Results will vary on other hardware, OS versions, and real-world access patterns — treat them as relative comparisons rather than absolute guarantees. At the µs scale these benchmarks operate, run-to-run variance can reach ±30% even on identical builds; the medians below are stable across 4 runs but individual cells can swing.

### Results Summary

#### Unencrypted Operations

| Library | Read | Write |
|---------|------|-------|
| SharedPreferences | 0.0018 ms | 0.0296 ms |
| MMKV | 0.0028 ms | 0.0198 ms |
| Multiplatform Settings | 0.0030 ms | 0.0237 ms |
| **KSafe (Delegated)** | **0.0124 ms** | **0.0163 ms** |
| DataStore | 0.4551 ms | 5.95 ms |

> **Note:** KSafe unencrypted reads are ~7× slower than SharedPreferences in absolute terms (12 µs vs 1.8 µs) — the cost of cross-platform generics, `kotlinx-serialization`-driven type widening, and 2.0's auto-protection-detection. Both numbers are well below human perception thresholds (a UI rendering 100 reads per frame still has ~14 ms of headroom). Writes are competitive: KSafe Delegated edges out SharedPreferences and Multiplatform Settings, and is roughly on par with MMKV.

#### Encrypted Read Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory, Delegated)** | **0.0160 ms** | — |
| KVault | 0.2522 ms | KSafe is **~16× faster** |
| EncryptedSharedPreferences | 0.3074 ms | KSafe is **~19× faster** |
| KSafe (ENCRYPTED memory, Delegated) | 6.27 ms | *(real AES-GCM decryption via Keystore on every read)* |

> **Note on ENCRYPTED memory policy:** The ENCRYPTED memory policy keeps ciphertext in RAM and performs real AES-GCM decryption through the Android Keystore on every read (~6 ms). This is the cost of hardware-backed cryptography. For most use cases, use `PLAIN_TEXT` (decrypts once at init) or `ENCRYPTED_WITH_TIMED_CACHE` (decrypts once per TTL window).

#### Encrypted Write Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory, Delegated)** | **0.0270 ms** | — |
| KSafe (ENCRYPTED memory, Delegated) | 0.0261 ms | — |
| EncryptedSharedPreferences | 0.2369 ms | KSafe is **~9× faster** |
| KVault | 1.08 ms | KSafe is **~40× faster** |

> **Memory-policy parity on writes.** As of the latest release, `ENCRYPTED` memory policy adds essentially no overhead vs `PLAIN_TEXT` on writes (median 0.0261 vs 0.0270 ms — within run-to-run noise). The 2.0.0 release docs noted a 37% gap; that gap closed when the write-coalescer was rewritten to encrypt batched entries concurrently inside a `coroutineScope` with bounded fan-out. Hardware-keystore IPC now pipelines instead of running serially.

### Key Performance Highlights

**vs DataStore (KSafe's backend):**
- :zap: **~370× faster writes** (5.95 ms → 0.016 ms)
- :zap: **~37× faster reads** (0.46 ms → 0.012 ms)

**vs KVault (encrypted KMP storage):**
- :zap: **~16× faster encrypted reads** (0.25 ms → 0.016 ms with PLAIN_TEXT memory)
- :zap: **~40× faster encrypted writes** (1.08 ms → 0.027 ms)

**vs EncryptedSharedPreferences:**
- :zap: **~19× faster encrypted reads** (0.31 ms → 0.016 ms with PLAIN_TEXT memory)
- :zap: **~9× faster encrypted writes** (0.24 ms → 0.027 ms)

**vs SharedPreferences (unencrypted baseline):**
- KSafe unencrypted writes are competitive with SharedPreferences (0.016 ms vs 0.030 ms)
- Reads are ~7× slower (0.012 ms vs 0.0018 ms) — the cost of type-safe generics, cross-platform API, and auto-protection-detection on reads

**vs multiplatform-settings (Russell Wolf):**
- KSafe writes faster (0.016 ms vs 0.024 ms)
- KSafe reads ~4× slower (0.012 ms vs 0.003 ms)
- KSafe adds: encryption, biometrics, type-safe serialization, hardware isolation

### Cold Start Performance

How quickly each library is ready to serve reads after process restart, for a store with N pre-populated keys.

| Library | Keys | Time |
|---------|------|------|
| **KSafe (ENCRYPTED memory)** | 1503 (1500 encrypted + 3 plain) | **0.047 ms** |
| SharedPreferences | 501 | 0.089 ms |
| Multiplatform Settings | 501 | 0.154 ms |
| MMKV | 501 | 0.168 ms |
| **KSafe (PLAIN_TEXT memory)** | 3006 (1500 encrypted + 1506 plain) | **0.431 ms** |
| DataStore | 501 | 0.552 ms |
| KVault | 650 | 96 ms |
| EncryptedSharedPrefs | 501 | 126 ms |

> **Architectural note — the two memory modes have opposite cold-start strategies, both fast:**
>
> - **`ENCRYPTED` memory mode** stashes ciphertext into the cache without decrypting. Decryption happens at read time. Cold start does no Keystore work, so it completes in tens of microseconds regardless of how many encrypted keys are stored. This is the right choice for stores where most values are read sparingly.
> - **`PLAIN_TEXT` memory mode** decrypts every encrypted entry up front so subsequent reads are pure in-memory lookups. The decryption work is parallelised through `coroutineScope` + `Semaphore(8)`, so 1500 hardware-backed AES-GCM decrypts complete in ~430 µs (~290 ns/key amortised — the Keystore IPC pipelines instead of stalling). This is the right choice for hot caches read on every frame.
>
> Both modes destroy `EncryptedSharedPreferences` (~110 µs/key, serial) and `KVault` (~195 µs/key, serial) — they don't pipeline their hardware-backed crypto.

### How KSafe Achieves This Performance

KSafe uses a **hot cache architecture** similar to SharedPreferences, but built on top of DataStore:

```
Vanilla DataStore:
  Read:  suspend → Flow.first() → disk I/O → ~0.46 ms
  Write: suspend → edit{} → serialize → disk I/O → ~5.9 ms

KSafe with Hot Cache:
  Read:  getDirect() → ConcurrentHashMap lookup → ~0.012 ms (no disk!)
  Write: putDirect() → update HashMap + queue → ~0.016 ms (returns immediately)
         Background: batched, parallelised DataStore.edit() (user doesn't wait)
```

**Key optimizations:**
1. **ConcurrentHashMap cache** — O(1) per-key reads and writes
2. **Write coalescing** — batches writes within a 16 ms window into a single DataStore edit
3. **Parallel encryption inside the batch** — encrypts up to 8 entries concurrently per batch via `coroutineScope` + `Semaphore(8)`, so hardware-keystore IPC pipelines instead of stalling
4. **Parallel decryption at cold start** — `PLAIN_TEXT` memory mode populates the cache by decrypting all stored entries through the same `coroutineScope` + `Semaphore(8)` pattern; the orphan-cleanup sweep that probes every encrypted entry on startup uses it too. Cold-start time on stores with thousands of encrypted keys drops from milliseconds-per-key to microseconds-per-key amortised.
5. **Deferred encryption** — encryption work moved to background; the UI thread returns instantly from `putDirect`
6. **SecretKey caching** — avoids repeated Android Keystore lookups
7. **Auto-protection-detection** — readers don't have to remember whether a key is encrypted; the library figures it out from per-key metadata. Costs ~3 µs per read but eliminates a class of "wrote encrypted, read plain" bugs

This means KSafe gives you DataStore's safety guarantees (atomic transactions, type-safe) with SharedPreferences-class read latency and faster writes than any other compared library.

### Methodology Notes

- Numbers above are **medians across 4 full benchmark runs** on the same physical device under similar thermal conditions. Single-run numbers can swing ±30% on µs-scale operations; the 4-run median is what we publish.
- Direct (`getDirect`/`putDirect`) and Delegated (`var x by ksafe(0)`) variants of KSafe perform similarly on reads (the delegate is a thin wrapper over the same hot-cache lookup); on writes, the Delegated path tends to JIT-inline more aggressively after warmup, so we report Delegated as the canonical KSafe number.
- The Coroutine API (`suspend get`/`put`) intentionally awaits the disk flush, so it's roughly 60–70× slower than `getDirect` on reads (waits for DataStore Flow) and ~1500× slower on writes (waits for the disk transaction). Use it for "must guarantee persistence" code paths — payments, auth-token refresh, and similar — and stick to the Direct/Delegated API for everything else.

***
