# Performance Benchmarks

Benchmark results comparing KSafe against the persistence libraries an Android developer would otherwise reach for. Every number on this page was measured on Android; [Methodology Notes](#methodology-notes) explains why the other platforms are not listed separately.

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

- **Device:** Samsung Galaxy S24 Ultra (`SM-S928B`), Android 16, release build.
- **Library:** measured on KSafe 2.1.2. The suite has not been re-run since; the note below explains why the figures still describe 3.2.0.
- **Test:** 500 read/write operations per library, each library called the way its own documentation recommends, after every code path had been run once so that no class loading or first-use setup lands inside a timed loop.
- **Reported numbers:** values from one representative steady-state run.
- **Harness:** the benchmark app is not part of this repository. Treat the figures as a reference measurement, not as a test you can re-run from the source tree.

> **Why the 2.1.2 figures still describe 3.2.0.** A timed operation here ends in one of three places: a lookup in the in-memory cache, one AES-GCM call against a key that is already in memory, or one disk transaction. None of the three has changed since 2.1.2 — a store that has never been rotated still writes the same bytes to disk and decrypts them through the same code, and the background writer still drains up to 200 queued writes into a single transaction, with the same 16 ms window. Later versions added key rotation (opt-in, and never inside a read or a write; see [Key rotation cost](#key-rotation-cost)), fixed correctness bugs around concurrent writes, and changed how the background write loop waits for the next write while a batch is still open. None of that adds work to a single `getDirect`, `putDirect`, `get` or `put` call, so the relative comparisons hold. The absolute microsecond values remain a 2.1.2 measurement.

> **Real-device note.** The S24 Ultra is a high-end flagship; mid-range and older devices will be slower in absolute terms, and the per-read AES cost grows with value size. The **relative comparisons between libraries on the same device** are the meaningful signal. Run-to-run variance at microsecond scale can reach ±20–30%; the numbers below are typical, not best-case. Tables use milliseconds (ms); per-key figures and some notes use microseconds (µs; 1 ms = 1000 µs). Ratios are computed from the unrounded timings, so they can differ by a few percent from what the rounded cells give.

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
| SharedPreferences | 0.00017 ms | 0.0123 ms |
| Multiplatform Settings | 0.00030 ms | 0.0138 ms |
| MMKV | 0.00051 ms | 0.0131 ms |
| **KSafe (Direct)** | **0.0015 ms** | **0.0010 ms** |
| KSafe (Coroutine, durable) | 0.0024 ms | 0.86 ms |
| DataStore | 0.3254 ms | 1.68 ms |

> **Note:** KSafe unencrypted reads are ~9× slower than SharedPreferences in absolute terms (1.5 µs vs 0.17 µs). The extra microsecond is the price of a type-safe generic API: every read checks the cached value against the type you asked for and converts it when the stored type differs (a value saved as `Int` and read back as `Long`, say), and non-primitive values are decoded from JSON — see [SERIALIZATION.md](SERIALIZATION.md). Both are far below human perception. Writes are excellent: KSafe `putDirect()` is **~12× faster than SharedPreferences** and ~13× faster than MMKV (1.0 µs vs 12–13 µs), because the write returns immediately and the durable commit is coalesced in the background.

#### Encrypted Read Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory, Direct)** | **0.0013 ms** | — *(cached plaintext, decrypt once)* |
| KSafe (PLAIN_TEXT memory, Coroutine) | 0.0141 ms | |
| **KSafe (ENCRYPTED memory, Direct)** | **0.0144 ms** | *(real AES-GCM decryption on **every** read — userspace DEK)* |
| KSafe (ENCRYPTED memory, Coroutine) | 0.0213 ms | |
| KVault | 0.0378 ms | KSafe ENCRYPTED is **~2.6× faster**; PLAIN_TEXT **~28× faster** |
| EncryptedSharedPreferences | 0.0496 ms | KSafe ENCRYPTED is **~3.4× faster**; PLAIN_TEXT **~37× faster** |

> **Note on the `ENCRYPTED` memory policy.** This policy keeps ciphertext in RAM and runs a real AES-GCM decrypt on **every** read. Since 2.1.2 that decrypt is CPU work against the in-memory DEK, with no Keystore/TEE round-trip. EncryptedSharedPreferences and KVault also decrypt on every read, so this row is the fair comparison against them — and KSafe wins it. Before 2.1.2 this same path cost ~8 ms per read on this device. For most apps the default `LAZY_PLAIN_TEXT` is still the better choice (first read decrypts, later reads are a lookup), but `ENCRYPTED` is no longer expensive under bursty reads.

#### Encrypted Write Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory, Direct `putDirect`)** | **0.0020 ms** | — *(queue + return)* |
| KSafe (ENCRYPTED memory, Direct `putDirect`) | 0.0041 ms | — |
| EncryptedSharedPreferences | 0.0604 ms | KSafe is **~31× faster** |
| KSafe (ENCRYPTED memory, Coroutine, durable) | 0.57 ms | *(awaits disk commit)* |
| KVault | 0.7525 ms | KSafe is **~383× faster** |
| KSafe (PLAIN_TEXT memory, Coroutine, durable) | 1.22 ms | *(awaits disk commit)* |

> Direct-API encrypted writes return as soon as the value is queued; the background writer commits the queue to disk shortly after. The fair comparison is the other libraries' fire-and-forget write (SharedPreferences' `apply()`, which also returns before the disk write). The Coroutine rows wait for the disk commit and were fired together, so they measure durable throughput — the workload the write queue is built for.

### Key Performance Highlights

**vs DataStore (KSafe's backend):**
- :zap: **~211× faster reads** (`getDirect()` hot-cache 0.0015 ms vs DataStore flow read 0.3254 ms)
- :zap: **~2× faster durable writes** (coalesced `put()` 0.86 ms vs `DataStore.edit()` 1.68 ms, both durable). The 500 `put` calls were fired together, so most of them were already queued when KSafe's background writer drained its queue, and it committed them in a few transactions of up to 200 writes each; DataStore was measured one `edit()` at a time. This is not strictly like-for-like. For fire-and-forget, `putDirect()` (0.0010 ms) returns ~1600× sooner than a durable `DataStore.edit()`.

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
- `getDirect()` and suspend `get()` read the same cache and run the same decrypt; the difference is the suspend path's hop to `Dispatchers.Default`, a background thread pool. How much that hop shows depends on how cheap the read itself is: ~1.5× for unencrypted reads (0.0015 vs 0.0024 ms) and for `ENCRYPTED`-memory reads (0.0144 vs 0.0213 ms), where the decrypt dominates; ~10× for `PLAIN_TEXT`-memory reads (0.0013 vs 0.0141 ms), where the read is a bare lookup and the hop is most of the cost.
- `putDirect()` returns after queueing (1–4 µs); suspend `put()` returns after the disk commit (0.57–1.22 ms in this suite), a gap of roughly 140× to 860× depending on the row. Reach for suspend `put` only when the caller must know the value is on disk.

### Cold Start Performance

How long each library takes to be ready to serve reads again after its in-memory cache is thrown away and rebuilt from disk. The KSafe instance is reused (KSafe keeps one DataStore per file, shared by every instance on that file), so the harness clears the cache and times re-population, taking the **median of several cycles**: a single sample is dominated by garbage collection and by when the background loader thread happens to run.

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

> **Reading these numbers.** Both KSafe rows repopulate at the same **~5.7 µs per key**; the totals differ only because the `PLAIN_TEXT` instance in this suite also holds every unencrypted key. Both rows decrypt encrypted entries at cold start, and every one of those decrypts is CPU work against the in-memory DEK rather than a Keystore round-trip — which is why the per-key cost stays in microseconds. `PLAIN_TEXT` decrypts eagerly: every entry goes into the cache as plaintext before the first read. `ENCRYPTED` keeps ciphertext in the cache, and its cold-start decrypts come from the startup orphan sweep — a one-time pass that test-decrypts each encrypted entry to find ciphertext whose key no longer exists. That sweep runs once per instance under *every* memory policy, on a background thread, so `PLAIN_TEXT` pays it as well. Per key, KSafe is **~8–12× faster than KVault and EncryptedSharedPreferences**, which run one hardware-backed crypto call per entry on every cold start.
>
> The default `LAZY_PLAIN_TEXT` is not in the table. It keeps ciphertext in the cache and decrypts a key the first time that key is read, so the blocking part of its cold start is the disk load alone, whatever the key count. The same startup orphan sweep still runs once in the background, so the CPU cost of one decrypt per encrypted entry is paid off the caller's thread rather than avoided.

### How KSafe Achieves This Performance

> **Why Android needed a DEK.** Under the `ENCRYPTED` memory policy KSafe decrypts on every read. If that AES-GCM ran inside the Keystore, every read would be a trip into the TEE: about 8 ms per operation on a Galaxy S24 Ultra (an emulator's software keystore hides this — there it looks like ~0.2 ms). KSafe instead keeps the store's master key (the KEK) in the TEE, non-exportable, and uses it once to unwrap a data-encryption key (DEK) into process memory. Every per-value AES-GCM call then runs on the CPU. On the S24 Ultra that turns the decrypt-every-read figure from ~8 ms into ~0.014 ms, which is why KSafe beats EncryptedSharedPreferences and KVault even on that path. The Apple (CryptoKit) and JVM Desktop (JCE) engines already worked this way, holding the raw key bytes in memory. Two kinds of entry stay inside the TEE on every operation, read and write alike, by design: those written as `HARDWARE_ISOLATED`, and those written with `requireUnlockedDevice = true`.

KSafe uses a **hot cache architecture** similar to SharedPreferences, but built on top of DataStore, the Android storage library that owns the file on disk. Reading DataStore directly means collecting a `Flow` and waiting for its first value; writing means an `edit {}` transaction that returns after the disk write:

```
Vanilla DataStore:
  Read:  suspend → Flow.first() → disk I/O → ~0.33 ms
  Write: suspend → edit{} → serialize → disk I/O → ~1.7 ms

KSafe with Hot Cache:
  Read:  getDirect() → in-memory map lookup → ~0.0015 ms (no disk!)
  Write: putDirect() → update map + queue → ~0.001 ms (returns immediately)
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

This means KSafe gives you DataStore's safety guarantees (atomic transactions, type-safe) with SharedPreferences-class read latency, the fastest fire-and-forget write in the comparison, and durable writes about twice as fast as DataStore's own.

### Methodology Notes

- **Warmup.** Every KSafe code path (both memory-policy instances, plain + encrypted, Direct + Delegated + suspend) is exercised before any timed benchmark, so benchmark order does not bias per-op numbers. Direct and Delegated therefore land close together (they share the same `core` path); the canonical figures quoted above use the **Direct** API.
- **Read/write benchmarks for the suspend API** launch all 500 operations at once as independent coroutines and wait for all of them to finish. This mirrors an app where many coroutines hit KSafe at the same time, and it is what the write queue is built for: puts that are queued together are committed in one transaction. The reported per-op time is total time divided by 500 — concurrent throughput rather than the time of one sequential call — so it is not directly comparable to the Direct API's sequential numbers.
- **`ENCRYPTED`-memory reads** decrypt on every read. Since 2.1.2 (Android) this is in-process AES-GCM against the cached DEK, so the decrypt-every-read figure is a fair comparison against EncryptedSharedPreferences and KVault (which also decrypt every read) — and KSafe wins it.
- **Scope of these Android figures.** Everything above is measured on Android (the S24 Ultra) against the Android competitors. The Apple (CryptoKit) and JVM (JCE) engines already held raw key bytes in memory and did userspace AES before the wrapped-DEK work, so they carry no equivalent per-read penalty and are not separately benchmarked here.
- **Cold start** is reported as the median of several clear→reload cycles to remove single-sample GC/loader-thread noise.
- **Total benchmark runtime is ~4.6 s wall-clock** for 500 iterations across all cells, down from ~17–25 s before the 2.1.2 DEK fast path; the per-read TEE round-trips were where most of that old time went.

### Key rotation cost

Key rotation (`rotateKeys()`, added in 3.0.0) re-encrypts every *encrypted* entry under a new key; entries stored in plain text have no key and are left alone. It does not appear in the tables above because it never runs inside a read or a write.

- **One pass, only when asked.** `rotateKeys()` decrypts and re-encrypts each encrypted entry once: a one-time cost proportional to how many of them exist at the moment you call it. Reads and writes before and after the call cost exactly what the tables show.
- **Never on the startup path.** `KSafeKeyRotationPolicy.MaxAge(...)` checks the key's age once per startup, in the background, and rotates behind the scenes while normal reads keep serving. The default policy is `Never`, which starts no rotation. Under either policy, a pass that was interrupted (a crash mid-rotation, or an entry that could not be reached while the device was locked) is finished by a later instance, also in the background, and that retry is bounded: `KSafeConfig.keyRotationRetryAttempts` (3 by default; 0 disables it) caps how many later instances retry the entries a completed pass had to skip. How this is tracked on disk is described in [KEY_ROTATION.md](KEY_ROTATION.md#semantics-and-guarantees).
- **No steady-state cost from the v3 envelope.** After the first rotation, entries carry an authenticated AES-GCM envelope (the "v3" format): a few extra bytes of associated data, checked in the same GCM pass that already runs, that tie the ciphertext to its key name and settings so it cannot be moved to another entry. It adds nothing measurable per operation, so the hot-path numbers hold for rotated and un-rotated stores alike. Details in [KEY_ROTATION.md](KEY_ROTATION.md#authenticated-envelope-v3).

What a rotation costs in wall-clock time per entry (about 2 ms for `DEFAULT`, about 400 ms for `HARDWARE_ISOLATED` on the same device) and the full crash-safety model (resumable, mixed-generation stores stay readable, values are preserved) are in [KEY_ROTATION.md](KEY_ROTATION.md#what-it-costs).

***
