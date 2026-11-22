# Performance Benchmarks

Benchmark results comparing KSafe against the persistence libraries an Android developer would otherwise reach for. The comparison tables were measured on Android (Galaxy S24 Ultra). Measurements of KSafe on its own on other platforms are in [Apple: iPhone 15 Pro Max](#apple-iphone-15-pro-max) and [Desktop (JVM) and Web](#desktop-jvm-and-web).

**Terms used on this page**

- **Hot cache** — KSafe keeps a copy of every stored value in memory. Reads are served from that copy; the file on disk is read once at startup and then watched for changes written by other instances of the same store.
- **Direct API** — `getDirect(key, defaultValue)` and `putDirect(key, value)`: ordinary, non-`suspend` functions. `putDirect` updates the cache and returns; the disk write happens afterwards, in the background.
- **Suspend API** — `get(key, defaultValue)` and `put(key, value)`: `suspend` functions. `put` returns only once the value is on disk.
- **Durable** — the write has reached disk. A `putDirect` becomes durable shortly after it returns, when the background commit lands; a `put` is durable when it returns.
- **Memory policy** — what an instance keeps in its cache for an encrypted key: the plaintext, the ciphertext, or the ciphertext plus a *side cache* (a second map that holds plaintext beside it). Set per instance with the factory's `memoryPolicy` parameter. The default is `LAZY_PLAIN_TEXT`: a key is decrypted on its first read, and that plaintext then lives in the side cache. All four policies are listed under [Results Summary](#results-summary); full detail in [MEMORY.md](MEMORY.md).
- **Keystore / TEE** — the Android Keystore is the system service that holds encryption keys. On a real phone the key lives in the Trusted Execution Environment (TEE), a separate part of the processor, so any encryption done *with* that key is a round-trip into it.
- **KEK / DEK** — a key-encryption key (KEK) wraps — that is, encrypts — a data-encryption key (DEK). KSafe keeps the KEK in the TEE and uses it once to unwrap the DEK into memory; the DEK then does every per-value encryption on the CPU. See [ARCHITECTURE.md](ARCHITECTURE.md#key-custody-across-platforms-the-kek--dek-model).
- **Write coalescing** — several writes queued close together are committed to disk as one transaction.

### Benchmark Environment

- **Device:** Samsung Galaxy S24 Ultra (`SM-S928B`), Android 16, release build of the benchmark app (not debuggable).
- **Library:** KSafe 3.3.0 from Maven Central, measured on 2026-10-06.
- **Test:** 500 read/write operations per library, each library called the way its own documentation recommends, after every code path had been run once so that no class loading or first-use setup lands inside a timed loop.
- **Reported numbers:** the median of three runs, taken after one discarded warm-up run of the whole suite.
- **Harness:** the benchmark app is not part of this repository. Treat the figures as a reference measurement, not as a test you can re-run from the source tree.

> **Compared with the previous measurement (KSafe 2.1.2).** Direct reads are as fast or faster (an encrypted warm read went from 1.3 to 1.1 µs, decrypt-every-read from 14.4 to 10.5 µs); only a suspend `get()` of an unencrypted key got slower (2.4 → 4.6 µs). Cold start went from 5.7 to 3.9–4.9 µs per key. A fire-and-forget `putDirect` now costs 4–7 µs, against 1–4 µs in 2.1.2; it still returns before any encryption or disk work. The phone's system software and the other libraries have also changed since then (a raw DataStore read went from 0.33 to 0.27 ms on the same phone), so compare rows within one table, not across the two measurements.

> **Real-device note.** The S24 Ultra is a high-end flagship; mid-range and older devices will be slower in absolute terms, and the per-read AES cost grows with value size. The **relative comparisons between libraries on the same device** are the meaningful signal. Run-to-run variance at microsecond scale can reach ±20–30%, and more on single cells; that is why the tables report the median of three runs. Tables use milliseconds (ms); per-key figures and some notes use microseconds (µs; 1 ms = 1000 µs). Ratios are computed from the unrounded timings, so they can differ by a few percent from what the rounded cells give.

### Results Summary

KSafe has three ways to read and write — Direct, Delegated and Suspend — and they do not cost the same:

```kotlin
// Direct: plain functions served from the hot cache. These are the rows the tables quote.
val token = ksafe.getDirect("token", "")
ksafe.putDirect("token", "abc")           // returns at once; the disk write follows

// Delegated: the same Direct code behind a property, or behind a handle.
var counter by ksafe(0)                   // reads and writes go through getDirect/putDirect
val score = ksafe(0, key = "score")       // same thing without `by`
score.value++

// Suspend: called from inside a coroutine. `put` waits for the disk commit;
// `get` only hops to a background dispatcher.
ksafe.put("token", "abc")                 // returns when the value is on disk
val t = ksafe.get("token", "")
```

- **Direct** is the hot-cache API and the one the tables quote.
- **Delegated** (`by ksafe(...)`, and the `ksafe(default, key).value` handle) calls the same code as Direct and performs the same.
- **Suspend `put`** waits for the disk commit. In this suite the 500 `put` calls were fired at the same time, so its write figures are throughput (total time divided by 500), not the time one call takes on its own.
- **Suspend `get`** reads the same cache as `getDirect` and never touches the disk. Its extra cost is the switch to a background coroutine dispatcher, nothing else.

Writes are encrypted unless you say otherwise: `putDirect(key, value)` and `put(key, value)` use the instance's default write mode, which is encrypted. The unencrypted rows below are the same calls with `mode = KSafeWriteMode.Plain`. Reads need no such flag — KSafe records per key whether the value is encrypted and detects it on read.

In the tables the suspend rows are labelled *Coroutine*.

The encrypted rows below are labelled by **memory policy**, the factory's `memoryPolicy` setting that decides what the cache holds for an encrypted key:

| Policy | Cache holds | Cost of a warm read |
|---|---|---|
| `PLAIN_TEXT` | plaintext, decrypted at startup | lookup only |
| `LAZY_PLAIN_TEXT` (default) | ciphertext, plus plaintext after the key's first read | first read decrypts, then lookup only |
| `ENCRYPTED_WITH_TIMED_CACHE` | ciphertext, plus plaintext for `plaintextCacheTtl` (5 s) after a read | as `LAZY_PLAIN_TEXT` while fresh, else as `ENCRYPTED` |
| `ENCRYPTED` | ciphertext only | one AES-GCM decrypt per read |

`LAZY_PLAIN_TEXT` and `ENCRYPTED_WITH_TIMED_CACHE` are not separate rows: a warm read under them costs what the `PLAIN_TEXT` row shows, a cold one what the `ENCRYPTED` row shows. Full description in [MEMORY.md](MEMORY.md).

#### Unencrypted Operations

| Library | Read | Write |
|---------|------|-------|
| SharedPreferences | 0.00013 ms | 0.0073 ms |
| Multiplatform Settings | 0.00018 ms | 0.0068 ms |
| MMKV | 0.00048 ms | 0.0124 ms |
| **KSafe (Direct)** | **0.0005 ms** | **0.0042 ms** |
| KSafe (Coroutine, durable) | 0.0046 ms | 0.66 ms |
| DataStore | 0.2674 ms | 1.49 ms |

> **Note:** KSafe unencrypted reads are ~4× slower than SharedPreferences in absolute terms (0.50 µs vs 0.13 µs). The extra fraction of a microsecond is the price of a type-safe generic API: every read checks the cached value against the type you asked for and converts it when the stored type differs (a value saved as `Int` and read back as `Long`, say), and non-primitive values are decoded from JSON — see [SERIALIZATION.md](SERIALIZATION.md). Both are far below human perception. On writes, KSafe `putDirect()` (4.2 µs) returns **~1.7× sooner than SharedPreferences' `apply()`** (7.3 µs) and ~1.6× sooner than Multiplatform Settings (6.8 µs), because the durable commit is coalesced in the background. MMKV's write (2.7–19 µs) and KSafe's unencrypted Direct read (0.46–2.8 µs) varied most across the three runs; the figures above are medians.

#### Encrypted Read Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory, Direct)** | **0.0011 ms** | — *(cached plaintext, decrypt once)* |
| KSafe (PLAIN_TEXT memory, Coroutine) | 0.0046 ms | |
| **KSafe (ENCRYPTED memory, Direct)** | **0.0105 ms** | *(real AES-GCM decryption on **every** read — userspace DEK)* |
| KSafe (ENCRYPTED memory, Coroutine) | 0.0130 ms | |
| KVault | 0.0403 ms | KSafe ENCRYPTED is **~3.8× faster**; PLAIN_TEXT **~36× faster** |
| EncryptedSharedPreferences | 0.0405 ms | KSafe ENCRYPTED is **~3.9× faster**; PLAIN_TEXT **~36× faster** |

> **Note on the `ENCRYPTED` memory policy.** This policy keeps ciphertext in RAM and runs a real AES-GCM decrypt on **every** read. Since 2.1.2 that decrypt is CPU work against the in-memory DEK, with no Keystore/TEE round-trip. EncryptedSharedPreferences and KVault also decrypt on every read, so this row is the fair comparison against them — and KSafe wins it. Before 2.1.2 this same path cost ~8 ms per read on this device. For most apps the default `LAZY_PLAIN_TEXT` is still the better choice (first read decrypts, later reads are a lookup), but `ENCRYPTED` is no longer expensive under bursty reads.

#### Encrypted Write Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory, Direct `putDirect`)** | **0.0046 ms** | — *(queue + return)* |
| KSafe (ENCRYPTED memory, Direct `putDirect`) | 0.0067 ms | — |
| EncryptedSharedPreferences | 0.0442 ms | KSafe is **~9.7× faster** |
| KSafe (ENCRYPTED memory, Coroutine, durable) | 0.46 ms | *(awaits disk commit)* |
| KVault | 0.7367 ms | KSafe is **~161× faster** |
| KSafe (PLAIN_TEXT memory, Coroutine, durable) | 0.90 ms | *(awaits disk commit)* |

> Direct-API encrypted writes return as soon as the value is queued; the background writer commits the queue to disk shortly after. The fair comparison is the other libraries' fire-and-forget write (SharedPreferences' `apply()`, which also returns before the disk write). The Coroutine rows wait for the disk commit and were fired together, so they measure durable throughput — the workload the write queue is built for.

### Key Performance Highlights

**vs DataStore (KSafe's backend):**
- :zap: **~535× faster reads** (median `getDirect()` hot-cache 0.0005 ms vs DataStore flow read 0.2674 ms)
- :zap: **~2.3× faster durable writes** (coalesced `put()` 0.66 ms vs `DataStore.edit()` 1.49 ms, both durable). The 500 `put` calls were fired together, so most of them were already queued when KSafe's background writer drained its queue, and it committed them in a few transactions of up to 200 writes each; DataStore was measured one `edit()` at a time. This is not strictly like-for-like. For fire-and-forget, `putDirect()` (0.0042 ms) returns ~355× sooner than a durable `DataStore.edit()`.

**vs EncryptedSharedPreferences:**
- :zap: **~3.9× faster encrypted reads** even decrypt-every-read (`ENCRYPTED` memory, 0.0105 ms vs 0.0405 ms); **~36× faster** with `PLAIN_TEXT` memory (cached)
- :zap: **~9.7× faster encrypted writes** (0.0046 ms vs 0.0442 ms)

**vs KVault (encrypted KMP storage):**
- :zap: **~3.8× faster encrypted reads** decrypt-every-read; **~36× faster** cached
- :zap: **~161× faster encrypted writes** (0.0046 ms vs 0.7367 ms)

**vs SharedPreferences / multiplatform-settings (unencrypted baselines):**
- KSafe unencrypted `putDirect()` returns **~1.7× sooner than SharedPreferences' `apply()`** and ~1.6× sooner than multiplatform-settings
- Reads are ~4× slower in absolute µs (cost of type-safe generics + cross-platform API) — still half a microsecond

**Direct vs Suspend API (within KSafe):**
- `getDirect()` and suspend `get()` read the same cache and run the same decrypt; the difference is the suspend path's hop to `Dispatchers.Default`, a background thread pool. That hop costs a few microseconds, so how much it shows depends on how cheap the read itself is: ~9× for unencrypted reads (0.0005 vs 0.0046 ms) and ~4× for `PLAIN_TEXT`-memory reads (0.0011 vs 0.0046 ms), where the read is a bare lookup and the hop is most of the cost; ~1.2× for `ENCRYPTED`-memory reads (0.0105 vs 0.0130 ms), where the decrypt dominates.
- `putDirect()` returns after queueing (4–7 µs); suspend `put()` returns after the disk commit (0.46–0.90 ms in this suite), a gap of roughly 70× to 200× depending on the row. Reach for suspend `put` only when the caller must know the value is on disk.

### Cold Start Performance

How long each library takes to be ready to serve reads again after its in-memory cache is thrown away and rebuilt from disk. The KSafe instance is reused (KSafe keeps one DataStore per file, shared by every instance on that file), so the harness clears the cache and times re-population, taking the **median of several cycles**: a single sample is dominated by garbage collection and by when the background loader thread happens to run.

| Library | Keys | Time | Per key |
|---------|------|------|---------|
| Multiplatform Settings | 501 | 0.058 ms | 0.12 µs |
| SharedPreferences | 501 | 0.089 ms | 0.18 µs |
| MMKV | 501 | 0.160 ms | 0.32 µs |
| DataStore | 501 | 0.47 ms | 0.93 µs |
| **KSafe (ENCRYPTED memory)** | 1503 | **7.32 ms** | **4.9 µs** |
| **KSafe (PLAIN_TEXT memory)** | 3006 | **11.78 ms** | **3.9 µs** |
| KVault | 650 | 26.57 ms | 41 µs |
| EncryptedSharedPrefs | 501 | 28.82 ms | 58 µs |

> **Reading these numbers.** The KSafe rows repopulate at **~4–5 µs per key**. The `PLAIN_TEXT` instance in this suite also holds every unencrypted key, which is why its total is larger. The two per-key figures are not directly comparable: the instances hold different key mixes, and only `PLAIN_TEXT` decrypts at load. `PLAIN_TEXT` decrypts eagerly: every encrypted entry goes into the cache as plaintext before the first read, and each of those decrypts is CPU work against the in-memory DEK rather than a Keystore round-trip — which is why the per-key cost stays in microseconds. `ENCRYPTED` keeps ciphertext in the cache and decrypts on each read instead. Separately, a startup orphan sweep — a one-time pass that test-decrypts each encrypted entry to find ciphertext whose key no longer exists — runs once per instance under *every* memory policy, on a background thread. Per key, KSafe is **~8–15× faster than KVault and EncryptedSharedPreferences**, which run one hardware-backed crypto call per entry on every cold start.
>
> The default `LAZY_PLAIN_TEXT` is not in the table. It keeps ciphertext in the cache and decrypts a key the first time that key is read, so the blocking part of its cold start is the disk load alone, whatever the key count. The same startup orphan sweep still runs once in the background, so the CPU cost of one decrypt per encrypted entry is paid off the caller's thread rather than avoided.

### Apple: iPhone 15 Pro Max

Measured on 2026-10-06 on an iPhone 15 Pro Max (`iPhone16,2`), iOS 27.0.1, unlocked, over USB, with KSafe 3.3.0. This is the cross-platform KSafe benchmark harness, a Kotlin test suite built as an optimized (release) Kotlin/Native binary — not the Android comparison app, so there are no other libraries in this table. 200 operations per cell, 18-byte string values, Direct API unless stated; each figure is the mean of two runs.

| Operation | Time |
|---|---|
| Plain read | 0.24 µs |
| Encrypted read, default `LAZY_PLAIN_TEXT`, warm | 0.65 µs |
| Encrypted read, `ENCRYPTED` memory (AES-GCM on every read) | 3.9 µs |
| First read of an encrypted key on a fresh instance (one decrypt) | ~20 µs |
| `putDirect`, plain / encrypted | 1.3 µs / 1.6 µs |
| Suspend `put`, encrypted (waits for the disk commit) | 0.36 ms |
| First encrypted `put` on a fresh store (store key created in the Keychain) | 0.44 ms |
| `requireUnlockedDevice = true` entry, every read (Keychain fetch) | 0.32 ms |
| `HARDWARE_ISOLATED` entry, warm read | 0.51 µs |
| `HARDWARE_ISOLATED` + `requireUnlockedDevice = true`, every read (Secure Enclave unwrap) | 6.25 ms |
| First `HARDWARE_ISOLATED` `put` (Secure Enclave key created) | 10.4 ms |
| Cold open: new instance over a 50-entry store + first read (default policy; about the same for every tier) | 1.3 ms |
| Background startup sweep of 50 `HARDWARE_ISOLATED` entries | 0.25 s |

- **The CPU-bound cells are a release-build measurement.** A debug build of the same harness ran the Direct and delegate cells 3–13× slower on the same phone; suspend calls, whose time is mostly the dispatcher hop or the disk commit, only 1–3× slower.
- **The hardware-bound cells are the device, not KSafe's code.** Entries written with `requireUnlockedDevice = true` never enter the plaintext cache, so every read is a Keychain fetch or, for `HARDWARE_ISOLATED`, a Secure Enclave unwrap. Those cells do not change with the build type.

### Desktop (JVM) and Web

Measured on 2026-10-06 on a MacBook Pro with an Apple M5 Pro chip (18 cores) and 48 GB of RAM, macOS 27.0.1: the JVM build on JDK 25.0.3, and the Kotlin/Wasm build, production-optimized, in headless Google Chrome. Same KSafe-only harness and settings as the iPhone section (KSafe 3.3.0, 200 operations per cell, 18-byte string values, Direct API unless stated). Untimed warm-up passes run before each measured configuration (three on the JVM, two on the web); each figure is the mean of two runs unless stated.

| Operation | Desktop JVM | Web (Kotlin/Wasm) |
|---|---|---|
| Plain read | 0.05 µs | 0.26 µs |
| Encrypted read, default `LAZY_PLAIN_TEXT`, warm | 0.12 µs | 0.32 µs |
| Encrypted read, `ENCRYPTED` memory (AES-GCM on every read) | ~1 µs | — (see below) |
| `putDirect`, plain / encrypted | 0.21 µs / 0.26 µs | 0.70 µs / 0.81 µs |
| Suspend `put`, encrypted (waits for the write to land) | 0.24 ms | 0.10 ms |
| First encrypted `put` on a fresh store | ~0.6 ms (median of 16 equivalent cells, 0.27–0.73 ms; the store key is already created in the background when the store opens) | ~0.4 ms, store key created (median of 32 equivalent cells, 0.32–0.54 ms) |
| Cold open: new instance over 50 encrypted entries, ready to read (default policy) | 0.54 ms | 13.0 ms |
| First read of an encrypted key on that fresh instance | 0.20 ms | ~0 (already decrypted at open) |
| `HARDWARE_ISOLATED` | falls back to the default tier (see below) | falls back to the default tier |

- **JVM.** The test run uses KSafe's software key vault, which keeps the suite off the developer's login Keychain. With an OS vault (Keychain, DPAPI, Secret Service), opening a store adds one round trip to the vault, and creating or first fetching each key (one per store, or one per entry for `HARDWARE_ISOLATED`) goes through it; per-value AES-GCM stays in user space either way. `requireUnlockedDevice` has no lock-state source on the desktop: such an entry is stored like any other, but it skips the plaintext cache, so each read is one user-space decrypt (about 1–3 µs). KSafe's JVM build has no route to the Mac's Secure Enclave or a PC's TPM, so `HARDWARE_ISOLATED` falls back to the default tier's custody. Each such entry still gets its own key, though: the first `put` of a new one takes 1.4 ms instead of ~0.6 ms, and a `PLAIN_TEXT`-policy cold open of 50 such entries 3.8 ms instead of 0.86 ms. Warm reads are unchanged.
- **Web.** The browser engine has a single memory policy: WebCrypto is asynchronous, so KSafe decrypts every encrypted entry when the store opens and then serves reads from plaintext. That is why the `ENCRYPTED`-memory row does not apply, and why opening a store of 50 encrypted entries takes 13.0 ms while 50 plain entries open in 0.25 ms: about 0.26 ms per encrypted entry, amortized (KSafe runs up to 8 WebCrypto calls at once). Values live in `localStorage`, so "waits for the write to land" means the browser has accepted the write, not that it reached the disk. The suite ran as the production-optimized Kotlin/Wasm build (binaryen), wired into the browser test task, in Chrome with its 5 µs timer resolution (cross-origin isolated); the averages are over 200 calls. The development build ran the CPU-bound cells about 1.5–2× slower; WebCrypto and storage times were about the same.

### How KSafe Achieves This Performance

> **Why Android needed a DEK.** Under the `ENCRYPTED` memory policy KSafe decrypts on every read. If that AES-GCM ran inside the Keystore, every read would be a trip into the TEE: 3.6 ms per decrypt on the Galaxy S24 Ultra in this suite's attribution check (earlier measurements on the same phone saw up to ~8 ms; an emulator's software keystore hides this — there it looks like ~0.2 ms). The same AES-GCM decrypt against a key held in process memory takes about 6 µs, roughly 580× less. KSafe therefore keeps the store's master key (the KEK) in the TEE, non-exportable, and uses it once to unwrap a data-encryption key (DEK) into process memory. Every per-value AES-GCM call then runs on the CPU. On the S24 Ultra that turns the decrypt-every-read figure from milliseconds into ~0.010 ms, which is why KSafe beats EncryptedSharedPreferences and KVault even on that path. The Apple (CryptoKit) and JVM Desktop (JCE) engines already worked this way, holding the raw key bytes in memory. Two kinds of entry stay inside the TEE on every operation, read and write alike, by design: those written as `HARDWARE_ISOLATED`, and those written with `requireUnlockedDevice = true`.

KSafe uses a **hot cache architecture** similar to SharedPreferences, but built on top of DataStore, the Android storage library that owns the file on disk. Reading DataStore directly means collecting a `Flow` and waiting for its first value; writing means an `edit {}` transaction that returns after the disk write:

```
Vanilla DataStore:
  Read:  suspend → Flow.first() → disk I/O → ~0.27 ms
  Write: suspend → edit{} → serialize → disk I/O → ~1.5 ms

KSafe with Hot Cache:
  Read:  getDirect() → in-memory map lookup → ~0.0005 ms (no disk!)
  Write: putDirect() → update map + queue → ~0.004 ms (returns immediately)
         Background: one DataStore.edit() per batch; the encrypts inside a batch
                     run up to 8 at a time (user doesn't wait)
```

**Key optimizations:**

1. **Concurrent in-memory cache** — one map lookup per read or write (`ConcurrentHashMap` on Android and JVM Desktop, an atomic copy-on-write map on iOS/macOS, a plain map on the single-threaded web runtime).
2. **One master key per store** — a `DEFAULT` write encrypts under the store's single master key, resolved once and reused, instead of minting and looking up a separate Keystore key for every entry. Per-entry hardware keys are what `HARDWARE_ISOLATED` entries use, and why they are far slower.
3. **Userspace AES via a wrapped DEK (Android, since 2.1.2)** — the mechanism in the note above: the DEK is unwrapped out of the TEE once, and every encrypt or decrypt of a `DEFAULT` value after that is CPU-only AES-GCM with no Keystore round-trip. What sits on disk is the wrapped DEK; the unwrapped copy lives in process memory from first use onwards — the same posture as EncryptedSharedPreferences and the Tink crypto library it is built on.
4. **Write coalescing** — every write goes into a queue drained by one background consumer. The consumer takes everything already queued (up to 200 writes per batch) and commits it as one DataStore transaction. If none of those writes is being awaited, it keeps the batch open for up to 16 ms (about one frame) to absorb further fire-and-forget writes; an awaited `put` closes the batch at once, so its caller gets one round-trip. Concurrent `put` calls therefore still share a transaction whenever they are queued together, but they never wait for the window.
5. **Deferred encryption** — `putDirect` serializes the value on the caller's thread (so an unserializable value fails right there), then hands the encryption and the disk write to the background consumer. The caller returns before any AES runs.
6. **Auto-protection-detection** — readers don't have to remember whether a key is encrypted; the library reads that from per-key metadata. A store that has never held an encrypted entry skips the metadata lookup entirely, via a flag that is set the first time one is seen.

This means KSafe gives you DataStore's safety guarantees (atomic transactions, type-safe) with SharedPreferences-class read latency, the fastest fire-and-forget write in the comparison (by median), and durable writes about twice as fast as DataStore's own.

### Methodology Notes

- **Warmup.** Every KSafe code path (both memory-policy instances, plain + encrypted, Direct + Delegated + suspend) is exercised before any timed benchmark, so benchmark order does not bias per-op numbers. Direct and Delegated therefore land close together (they share the same `core` path); the canonical figures quoted above use the **Direct** API.
- **Read/write benchmarks for the suspend API** launch all 500 operations at once as independent coroutines and wait for all of them to finish. This mirrors an app where many coroutines hit KSafe at the same time, and it is what the write queue is built for: puts that are queued together are committed in one transaction. The reported per-op time is total time divided by 500 — concurrent throughput rather than the time of one sequential call — so it is not directly comparable to the Direct API's sequential numbers.
- **`ENCRYPTED`-memory reads** decrypt on every read. Since 2.1.2 (Android) this is in-process AES-GCM against the cached DEK, so the decrypt-every-read figure is a fair comparison against EncryptedSharedPreferences and KVault (which also decrypt every read) — and KSafe wins it.
- **Scope of these Android figures.** The tables above are measured on Android (the S24 Ultra) against the Android competitors. The Apple (CryptoKit) and JVM (JCE) engines already held raw key bytes in memory and did userspace AES before the wrapped-DEK work, so they carry no equivalent per-read penalty. Measurements of KSafe on its own on an iPhone, the desktop JVM and the web are in [Apple: iPhone 15 Pro Max](#apple-iphone-15-pro-max) and [Desktop (JVM) and Web](#desktop-jvm-and-web).
- **Cold start** is reported as the median of five clear→reload cycles (after one discarded cycle) to remove single-sample GC/loader-thread noise. Each cycle clears the cache immediately before the timed read. An earlier version of the harness paused between the clear and the read; a background collector could re-merge the snapshot during that pause, and the cycle then timed an already warm cache.
- **Total benchmark runtime is ~10 s wall-clock** for 500 iterations across all cells, including the cold-start cycles and the TEE attribution check, down from ~17–25 s before the 2.1.2 DEK fast path; the per-read TEE round-trips were where most of that old time went.

### Key rotation cost

Key rotation (`rotateKeys()`, added in 3.0.0) re-encrypts every *encrypted* entry under a new key; entries stored in plain text have no key and are left alone. It does not appear in the tables above because it never runs inside a read or a write.

- **One pass, only when asked.** `rotateKeys()` decrypts and re-encrypts each encrypted entry once: a one-time cost proportional to how many of them exist at the moment you call it. Reads and writes before and after the call cost exactly what the tables show.
- **Never on the startup path.** `KSafeKeyRotationPolicy.MaxAge(...)` checks the key's age once per startup, in the background, and rotates behind the scenes while normal reads keep serving. The default policy is `Never`, which starts no rotation. Under either policy, a pass that was interrupted (a crash mid-rotation, or an entry that could not be reached while the device was locked) is finished by a later instance, also in the background, and that retry is bounded: `KSafeConfig.keyRotationRetryAttempts` (3 by default; 0 disables it) caps how many later instances retry the entries a completed pass had to skip. How this is tracked on disk is described in [KEY_ROTATION.md](KEY_ROTATION.md#semantics-and-guarantees).
- **No steady-state cost from the v3 envelope.** After the first rotation, entries carry an authenticated AES-GCM envelope (the "v3" format): a few extra bytes of associated data, checked in the same GCM pass that already runs, that tie the ciphertext to its key name and settings so it cannot be moved to another entry. It adds nothing measurable per operation, so the hot-path numbers hold for rotated and un-rotated stores alike. Details in [KEY_ROTATION.md](KEY_ROTATION.md#authenticated-envelope-v3).

What a rotation costs in wall-clock time per entry (about 2 ms for `DEFAULT`, about 400 ms for `HARDWARE_ISOLATED` on the same device) and the full crash-safety model (resumable, mixed-generation stores stay readable, values are preserved) are in [KEY_ROTATION.md](KEY_ROTATION.md#what-it-costs).

***
