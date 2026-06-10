# Performance Benchmarks

Here are benchmark results comparing KSafe against popular Android persistence libraries.

> **2.1.2 release headline — Android software-DEK fast path.** Before 2.1.2, `ENCRYPTED`-memory "decrypt on every read" ran its AES-GCM *inside* the Android Keystore (TEE) on every call, so each read was a hardware round-trip — ~8 ms/op on a real Galaxy S24 Ultra (an emulator's software keystore hid this; it looked like ~0.2 ms). 2.1.2 keeps the per-datastore master key (the **KEK**) non-exportable in the TEE but uses it to wrap a **data-encryption key (DEK)** that is unwrapped **once** into process memory; per-value AES-GCM then runs in **userspace**. Result: `ENCRYPTED`-memory decrypt-every-read dropped from **~8 ms → ~0.014 ms** on the S24 Ultra — KSafe now *beats* EncryptedSharedPreferences and KVault even on the decrypt-every-read path. This brings Android in line with the Apple (CryptoKit) and JVM (JCE) engines, which already held raw key bytes in memory and did userspace AES. `HARDWARE_ISOLATED` writes and the strict `requireUnlockedDevice` master keep keys inside the TEE on every op (unchanged).
>
> The default memory policy is **`LAZY_PLAIN_TEXT`**. Its read profile matches `PLAIN_TEXT` after first access (plaintext cached in the side cache) and matches `ENCRYPTED` cold-start (no bulk decrypt at startup). The first read of each key under `LAZY_PLAIN_TEXT` pays one decrypt — comparable to a single `ENCRYPTED`-memory read.

### Benchmark Environment

- **Device:** Samsung Galaxy S24 Ultra (`SM-S928B`), Android 16, release build.
- **Library:** KSafe 2.1.2.
- **Test:** 500 read/write operations per library, exercised in their natural usage pattern, after a full warmup of every code path.
- **Reported numbers:** values from a representative steady-state run.

> **Real-device note.** The S24 Ultra is a high-end flagship; mid-range and older devices will be slower in absolute terms, and the per-read AES cost scales with value size. The **relative comparisons between libraries on the same device** are the meaningful signal. Run-to-run variance at µs scale can reach ±20–30%; the numbers below are typical, not best-case. Numbers are reported in a single unit (ms) throughout.

### Results Summary

KSafe exposes three API shapes. **Direct** (`getDirect`/`putDirect`) is the canonical hot-cache API and the one quoted below; the **Delegated** (`by ksafe(...)`) path routes through the same code and performs equivalently; the **Coroutine** (suspend `get`/`put`) path awaits the DataStore disk commit (durable) and is fired concurrently, so its figures are throughput, not per-op latency.

#### Unencrypted Operations

| Library | Read | Write |
|---------|------|-------|
| SharedPreferences | 0.00017 ms | 0.0123 ms |
| Multiplatform Settings | 0.00030 ms | 0.0138 ms |
| MMKV | 0.00051 ms | 0.0131 ms |
| **KSafe (Direct)** | **0.0015 ms** | **0.0010 ms** |
| KSafe (Coroutine, durable) | 0.0024 ms | 0.86 ms |
| DataStore | 0.3254 ms | 1.68 ms |

> **Note:** KSafe unencrypted reads are ~9× slower than SharedPreferences in absolute terms (1.5 µs vs 0.17 µs) — the cost of cross-platform generics and `kotlinx-serialization`-driven type widening. Both are far below human perception. Writes are excellent: KSafe `putDirect()` is **~12× faster than SharedPreferences** and ~13× faster than MMKV (1.0 µs vs 12–13 µs), because the write returns immediately and the durable commit is coalesced in the background.

#### Encrypted Read Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory, Direct)** | **0.0013 ms** | — *(cached plaintext, decrypt once)* |
| KSafe (PLAIN_TEXT memory, Coroutine) | 0.0141 ms | |
| **KSafe (ENCRYPTED memory, Direct)** | **0.0144 ms** | *(real AES-GCM decryption on **every** read — userspace DEK)* |
| KSafe (ENCRYPTED memory, Coroutine) | 0.0213 ms | |
| KVault | 0.0378 ms | KSafe ENCRYPTED is **~2.6× faster**; PLAIN_TEXT **~28× faster** |
| EncryptedSharedPreferences | 0.0496 ms | KSafe ENCRYPTED is **~3.4× faster**; PLAIN_TEXT **~37× faster** |

> **Note on the `ENCRYPTED` memory policy.** This policy keeps ciphertext in RAM and performs real AES-GCM decryption on **every** read. Under 2.1.2 the decrypt is a pure-CPU operation against the in-memory DEK — no per-read Keystore/TEE round-trip — so even the decrypt-every-read path (the fair, apples-to-apples comparison against ESP/KVault, which also decrypt every read) is now **faster than both**. Before 2.1.2 this same path cost ~8 ms/op on this device. For most use cases the default `LAZY_PLAIN_TEXT` is still preferable (first read decrypts, subsequent reads are O(1) memory lookups), but `ENCRYPTED` is no longer expensive under bursty reads.

#### Encrypted Write Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory, Direct `putDirect`)** | **0.0020 ms** | — *(queue + return)* |
| KSafe (ENCRYPTED memory, Direct `putDirect`) | 0.0041 ms | — |
| EncryptedSharedPreferences | 0.0604 ms | KSafe is **~31× faster** |
| KSafe (ENCRYPTED memory, Coroutine, durable) | 0.57 ms | *(awaits disk commit)* |
| KVault | 0.7525 ms | KSafe is **~383× faster** |
| KSafe (PLAIN_TEXT memory, Coroutine, durable) | 1.22 ms | *(awaits disk commit)* |

> Direct-API encrypted writes return immediately and let the coalescer flush in the background; ESP/KVault `apply()`-style writes are the fair fire-and-forget counterpart. The Coroutine rows wait for the actual disk commit and are fired concurrently (durable throughput), which is the workload KSafe's write-coalescer is designed for.

### Key Performance Highlights

**vs DataStore (KSafe's backend):**
- :zap: **~211× faster reads** (`getDirect()` hot-cache 0.0015 ms vs DataStore flow read 0.3254 ms)
- :zap: **~2× faster durable writes** (coalesced `put()` 0.86 ms vs `DataStore.edit()` 1.68 ms — both durable; KSafe batches concurrent puts in a ~16 ms window, DataStore is measured one-at-a-time, so this is not strictly like-for-like). For fire-and-forget, `putDirect()` (0.0010 ms) returns ~1600× sooner than a durable `DataStore.edit()`.

**vs EncryptedSharedPreferences:**
- :zap: **~3.4× faster encrypted reads** even decrypt-every-read (`ENCRYPTED` memory, 0.0144 ms vs 0.0496 ms); **~37× faster** with `PLAIN_TEXT` memory (cached)
- :zap: **~31× faster encrypted writes** (0.0020 ms vs 0.0604 ms)

**vs KVault (encrypted KMP storage):**
- :zap: **~2.6× faster encrypted reads** decrypt-every-read; **~28× faster** cached
- :zap: **~383× faster encrypted writes** (0.0020 ms vs 0.7525 ms)

**vs SharedPreferences / multiplatform-settings (unencrypted baselines):**
- KSafe unencrypted `putDirect()` is **~12× faster than SharedPreferences** and ~14× faster than multiplatform-settings
- Reads are ~9× slower in absolute µs (cost of type-safe generics + cross-platform API) — still ~1.5 µs

**Direct vs Suspend API (within KSafe):**
- `getDirect()` is **~10× faster** than suspend `get()` for encrypted reads (hot cache vs DataStore round-trip), ~1.5× for unencrypted.
- `putDirect()` is **~800× faster** than suspend `put()` for writes (queue + return vs await disk commit). Reach for suspend `get`/`put` only when you must guarantee the value has hit disk.

### Cold Start Performance

How quickly each library is ready to serve reads after the in-process cache is cleared and forced to repopulate. The KSafe instance is reused (DataStore is a singleton) — the harness clears the cache and times re-population, taking the **median of several cycles** (a single sample is dominated by GC and collector-thread timing).

| Library | Keys | Time | Per key |
|---------|------|------|---------|
| SharedPreferences | 501 | 0.032 ms | 0.06 µs |
| MMKV | 501 | 0.047 ms | 0.09 µs |
| Multiplatform Settings | 501 | 0.049 ms | 0.10 µs |
| DataStore | 501 | 0.43 ms | 0.85 µs |
| **KSafe (ENCRYPTED memory)** | 1503 | **8.54 ms** | **5.7 µs** |
| **KSafe (PLAIN_TEXT memory)** | 3006 | **17.19 ms** | **5.7 µs** |
| KVault | 650 | 29.14 ms | 45 µs |
| EncryptedSharedPrefs | 501 | 34.24 ms | 68 µs |

> **Reading these numbers honestly.** The two KSafe modes repopulate at the same **~5.7 µs/key** — the difference in their totals is purely key count (the PLAIN_TEXT instance also holds all the unencrypted keys in this suite). Both decrypt their stored entries with the in-memory DEK at cold start (`PLAIN_TEXT` eagerly into the plaintext cache; `ENCRYPTED` via an integrity probe), now pure-CPU rather than per-key Keystore IPC. On a **per-key** basis KSafe is **~8–12× faster than KVault and EncryptedSharedPreferences**, both of which serialise hardware-backed crypto and pay one round-trip per entry on every cold start. Real first-launch cost under `LAZY_PLAIN_TEXT` (the default) is near-free regardless of key count: the cache holds ciphertext and nothing is eagerly decrypted.

### How KSafe Achieves This Performance

KSafe uses a **hot cache architecture** similar to SharedPreferences, but built on top of DataStore:

```
Vanilla DataStore:
  Read:  suspend → Flow.first() → disk I/O → ~0.33 ms
  Write: suspend → edit{} → serialize → disk I/O → ~1.7 ms

KSafe with Hot Cache:
  Read:  getDirect() → ConcurrentHashMap lookup → ~0.0015 ms (no disk!)
  Write: putDirect() → update HashMap + queue → ~0.001 ms (returns immediately)
         Background: batched, parallelised DataStore.edit() (user doesn't wait)
```

**Key optimizations:**

1. **ConcurrentHashMap cache** — O(1) per-key reads and writes.
2. **Per-datastore master-key envelope** — `KSafeProtection.DEFAULT` writes encrypt against a single per-datastore key cached in-process, instead of a per-entry Keystore key, eliminating per-entry key lookups.
3. **Userspace AES via a wrapped DEK (Android, 2.1.2)** — the master key (KEK) stays non-exportable in the TEE and wraps a random data-encryption key (DEK); the DEK is unwrapped **once** into memory, after which every encrypt/decrypt of a `DEFAULT` value is pure-CPU AES-GCM with no Keystore/TEE round-trip. This matches what the Apple (CryptoKit) and JVM (JCE) engines already do. The wrapped DEK is stored at rest; the unwrapped DEK lives in process memory after first use — the same posture as EncryptedSharedPreferences/Tink. `HARDWARE_ISOLATED` and the strict `requireUnlockedDevice` master keep keys inside the TEE and decrypt there on every op.
4. **Write coalescing** — batches writes within a 16 ms window into a single DataStore edit; concurrent suspend `put()` calls coalesce automatically.
5. **Deferred encryption** — encryption work moves to the background; the UI thread returns instantly from `putDirect`.
6. **Auto-protection-detection** — readers don't have to remember whether a key is encrypted; the library figures it out from per-key metadata. Plain-only stores short-circuit the lookup via an atomic flag.

This means KSafe gives you DataStore's safety guarantees (atomic transactions, type-safe) with SharedPreferences-class read latency and **faster writes than any other compared library**.

### Methodology Notes

- **Warmup.** Every KSafe code path (both memory-policy instances, plain + encrypted, Direct + Delegated + suspend) is exercised before any timed benchmark, so benchmark order does not bias per-op numbers. Direct and Delegated therefore land close together (they share the same `core` path); the canonical figures quoted above use the **Direct** API.
- **Read/write benchmarks** for the suspend API issue all 500 operations as concurrent `GlobalScope.launch` jobs awaited with `joinAll()`. This represents real-app usage where many coroutines hit KSafe in parallel and exercises the write-coalescer. The reported per-op time is amortised concurrent throughput, **not** sequential per-op latency — so it is not directly comparable to the Direct API's sequential numbers.
- **`ENCRYPTED`-memory reads** decrypt on every read. Under 2.1.2 (Android) this is in-process AES-GCM against the cached DEK, so the decrypt-every-read figure is a fair apples-to-apples comparison against ESP/KVault (which also decrypt every read) — and KSafe now wins it.
- **Cold start** is reported as the median of several clear→reload cycles to remove single-sample GC/collector-thread noise.
- **Total benchmark runtime is now ~4.6 s wall-clock** for 500 iterations across all cells (down from ~17–25 s before the 2.1.2 DEK fast path, which is where most of the old time went — the per-read TEE round-trips).

***
