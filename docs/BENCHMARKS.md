# Performance Benchmarks

Here are benchmark results comparing KSafe against popular Android persistence libraries.

### Benchmark Environment

- **Device:** Samsung Galaxy S24 Ultra (physical device, not emulator)
- **Test:** 1000 sequential read/write operations per library
- **Reported numbers:** values from a representative 1000-iteration run after the device has reached steady-state thermal/JIT behavior
- **Libraries tested:** KSafe, SharedPreferences, EncryptedSharedPreferences, MMKV, DataStore, Multiplatform Settings, KVault

> Numbers are specific to this device and workload. Results will vary on other hardware, OS versions, and real-world access patterns — treat them as relative comparisons rather than absolute guarantees. **Higher-iteration runs (1000+) give more honest steady-state numbers than shorter runs:** the device has time to reach a stable thermal regime and the JIT settles, so individual cells stop swinging. Lower iteration counts can cherry-pick thermal-favorable wins that don't reflect production behavior.

### Results Summary

#### Unencrypted Operations

| Library | Read | Write |
|---------|------|-------|
| SharedPreferences | 0.0022 ms | 0.0401 ms |
| MMKV | 0.0027 ms | 0.0100 ms |
| Multiplatform Settings | 0.0029 ms | 0.0366 ms |
| **KSafe (Delegated)** | **0.0109 ms** | **0.0101 ms** |
| DataStore | 0.4409 ms | 8.17 ms |

> **Note:** KSafe unencrypted reads are ~5× slower than SharedPreferences in absolute terms (11 µs vs 2 µs) — the cost of cross-platform generics and `kotlinx-serialization`-driven type widening. Both numbers are well below human perception thresholds (a UI rendering 100 reads per frame still has ~14 ms of headroom). Writes are competitive: KSafe Delegated is roughly on par with MMKV and ~3-4× faster than SharedPreferences and Multiplatform Settings.

#### Encrypted Read Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory, Delegated)** | **0.0136 ms** | — |
| KVault | 0.2476 ms | KSafe is **~18× faster** |
| EncryptedSharedPreferences | 0.2461 ms | KSafe is **~18× faster** |
| KSafe (ENCRYPTED memory, Delegated) | 6.42 ms | *(real AES-GCM decryption via Keystore on every read)* |

> **Note on ENCRYPTED memory policy:** The ENCRYPTED memory policy keeps ciphertext in RAM and performs real AES-GCM decryption through the Android Keystore on every read (~6 ms). This is the cost of hardware-backed cryptography. For most use cases, use `PLAIN_TEXT` (decrypts once at init) or `ENCRYPTED_WITH_TIMED_CACHE` (decrypts once per TTL window).

#### Encrypted Write Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (ENCRYPTED memory, Delegated)** | **0.0209 ms** | — |
| KSafe (PLAIN_TEXT memory, Delegated) | 0.0210 ms | — |
| EncryptedSharedPreferences | 0.1978 ms | KSafe is **~9× faster** |
| KVault | 1.18 ms | KSafe is **~56× faster** |

> **Memory-policy parity on writes.** `ENCRYPTED` memory policy adds essentially no overhead vs `PLAIN_TEXT` on writes (0.0209 vs 0.0210 ms — within run-to-run noise). Hardware-keystore IPC pipelines instead of running serially because the write-coalescer encrypts batched entries concurrently inside a `coroutineScope` with bounded fan-out.

### Key Performance Highlights

**vs DataStore (KSafe's backend):**
- :zap: **~810× faster writes** (8.17 ms → 0.010 ms)
- :zap: **~40× faster reads** (0.44 ms → 0.011 ms)

**vs KVault (encrypted KMP storage):**
- :zap: **~18× faster encrypted reads** (0.25 ms → 0.014 ms with PLAIN_TEXT memory)
- :zap: **~56× faster encrypted writes** (1.18 ms → 0.021 ms)

**vs EncryptedSharedPreferences:**
- :zap: **~18× faster encrypted reads** (0.25 ms → 0.014 ms with PLAIN_TEXT memory)
- :zap: **~9× faster encrypted writes** (0.20 ms → 0.021 ms)

**vs SharedPreferences (unencrypted baseline):**
- KSafe unencrypted writes are **~4× faster** than SharedPreferences (0.010 ms vs 0.040 ms)
- Reads are ~5× slower (0.011 ms vs 0.0022 ms) — the cost of type-safe generics and cross-platform API

**vs multiplatform-settings (Russell Wolf):**
- KSafe writes ~3.6× faster (0.010 ms vs 0.037 ms)
- KSafe reads ~4× slower (0.011 ms vs 0.003 ms)
- KSafe adds: encryption, biometrics, type-safe serialization, hardware isolation

### Cold Start Performance

How quickly each library is ready to serve reads after process restart, for a store with N pre-populated keys.

| Library | Keys | Time |
|---------|------|------|
| SharedPreferences | 1001 | 0.082 ms |
| **KSafe (PLAIN_TEXT memory)** | 6006 (2000 encrypted + 4006 plain) | **0.116 ms** |
| **KSafe (ENCRYPTED memory)** | 3003 (2000 encrypted + 1003 plain) | **0.234 ms** |
| Multiplatform Settings | 1001 | 0.247 ms |
| MMKV | 1001 | 0.385 ms |
| DataStore | 1001 | 2.10 ms |
| KVault | 1200 | 45 ms |
| EncryptedSharedPrefs | 1001 | 46 ms |

> **Architectural note — both memory modes are sub-millisecond cold-start, even with thousands of encrypted keys:**
>
> - **`ENCRYPTED` memory mode** stashes ciphertext into the cache without decrypting. Decryption happens at read time. Cold start does no Keystore work, so it completes in fractions of a millisecond regardless of how many encrypted keys are stored. This is the right choice for stores where most values are read sparingly.
> - **`PLAIN_TEXT` memory mode** decrypts encrypted entries during cache warm-up. The decryption work is parallelised through `coroutineScope` + `Semaphore(8)`, so the Keystore IPC pipelines instead of stalling. This is the right choice for hot caches read on every frame.
>
> Both modes destroy `EncryptedSharedPreferences` (~46 ms for 1001 keys) and `KVault` (~45 ms for 1200 keys) — they don't pipeline their hardware-backed crypto and serialise every key fetch.
>
> **Methodology caveat:** these cold-start numbers measure cache-population time inside the same process (DataStore singleton already loaded). Some runs report higher numbers (10s of ms) when the synchronous read wins a race against KSafe's own background snapshot collector and ends up doing the population work itself; other runs report sub-millisecond numbers when the background collector finishes first and the timed `getDirect` call only measures a hot-cache hit. The numbers above are typical, but the cold-start cell is the most run-to-run-variable in the suite.

### How KSafe Achieves This Performance

KSafe uses a **hot cache architecture** similar to SharedPreferences, but built on top of DataStore:

```
Vanilla DataStore:
  Read:  suspend → Flow.first() → disk I/O → ~0.44 ms
  Write: suspend → edit{} → serialize → disk I/O → ~8.2 ms

KSafe with Hot Cache:
  Read:  getDirect() → ConcurrentHashMap lookup → ~0.011 ms (no disk!)
  Write: putDirect() → update HashMap + queue → ~0.010 ms (returns immediately)
         Background: batched, parallelised DataStore.edit() (user doesn't wait)
```

**Key optimizations:**
1. **ConcurrentHashMap cache** — O(1) per-key reads and writes
2. **Write coalescing** — batches writes within a 16 ms window into a single DataStore edit
3. **Parallel encryption inside the batch** — encrypts up to 8 entries concurrently per batch via `coroutineScope` + `Semaphore(8)`, so hardware-keystore IPC pipelines instead of stalling
4. **Parallel decryption at cold start** — `PLAIN_TEXT` memory mode populates the cache by decrypting all stored entries through the same `coroutineScope` + `Semaphore(8)` pattern; the orphan-cleanup sweep that probes every encrypted entry on startup uses it too. Cold-start time on stores with thousands of encrypted keys drops from milliseconds-per-key to microseconds-per-key amortised.
5. **Deferred encryption** — encryption work moved to background; the UI thread returns instantly from `putDirect`
6. **SecretKey caching** — avoids repeated Android Keystore lookups
7. **Auto-protection-detection** — readers don't have to remember whether a key is encrypted; the library figures it out from per-key metadata. Stores with no encrypted entries short-circuit the lookup via an atomic flag, so plain-only consumers pay zero overhead. Mixed stores pay a single sub-microsecond `ConcurrentHashMap` lookup per read. Eliminates a class of "wrote encrypted, read plain" bugs

This means KSafe gives you DataStore's safety guarantees (atomic transactions, type-safe) with SharedPreferences-class read latency and faster writes than any other compared library.

### Methodology Notes

- Numbers above come from a **1000-iteration run** on the physical device after the device has reached steady-state thermal/JIT behavior. Lower iteration counts (200–500) can occasionally produce thermal-favorable cells that don't generalise — the 1000-iter run is what we publish because it represents production behavior, not best-case.
- Direct (`getDirect`/`putDirect`) and Delegated (`var x by ksafe(0)`) variants of KSafe perform similarly on reads (the delegate is a thin wrapper over the same hot-cache lookup); on writes, the Delegated path tends to JIT-inline more aggressively after warmup, so we report Delegated as the canonical KSafe number.
- **The Coroutine API (`suspend get`/`put`) intentionally awaits the disk flush.** It's roughly ~25× slower than `getDirect` on reads (waits for DataStore Flow) and ~5000× slower on writes (waits for the actual disk transaction). Use it for "must guarantee persistence" code paths — payments, auth-token refresh, and similar — and stick to the Direct/Delegated API for everything else.
- **Why does running this benchmark take 5+ minutes?** Almost all of the wall time is the suspend-API write cells. 1000 sequential `suspend put()` calls each waiting for an actual disk transaction = ~50–110 ms × 1000 = ~50–110 seconds *per cell*. KSafe has 3 such cells (unencrypted, encrypted-PLAIN_TEXT-memory, encrypted-ENCRYPTED-memory), so just those three cells account for ~3–4 minutes. The Direct/Delegated cells finish in single-digit seconds combined. The "slow" wall time is the cost of exercising the deliberately-slow suspend path 3000 times — not a slow library.

***
