# Performance Benchmarks

Here are benchmark results comparing KSafe against popular Android persistence libraries.

### Benchmark Environment
- **Device:** Physical Android device
- **Test:** 500 sequential read/write operations per library, averaged
- **Libraries tested:** KSafe, SharedPreferences, EncryptedSharedPreferences, MMKV, DataStore, Multiplatform Settings, KVault

### Results Summary

#### Unencrypted Operations

| Library | Read | Write |
|---------|------|-------|
| SharedPreferences | 0.0017 ms | 0.0224 ms |
| MMKV | 0.0024 ms | 0.0232 ms |
| Multiplatform Settings | 0.0054 ms | 0.0228 ms |
| **KSafe (Delegated)** | **0.0073 ms** | **0.0218 ms** |
| DataStore | 0.5549 ms | 5.17 ms |

> **Note:** KSafe unencrypted writes are **on par with SharedPreferences** (0.0218 ms vs 0.0224 ms) while providing KMP support, type-safe serialization, and optional encryption.

#### Encrypted Read Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory)** | **0.0174 ms** | — |
| KVault | 0.2418 ms | KSafe is **14x faster** |
| EncryptedSharedPreferences | 0.2603 ms | KSafe is **15x faster** |
| KSafe (ENCRYPTED memory) | 4.93 ms | *(real AES-GCM decryption via Keystore on every read)* |

> **Note on ENCRYPTED memory policy:** The ENCRYPTED memory policy keeps ciphertext in RAM and performs real AES-GCM decryption through the Android Keystore on every read (~5 ms). This is the cost of hardware-backed cryptography. For most use cases, use `PLAIN_TEXT` (decrypts once at init) or `ENCRYPTED_WITH_TIMED_CACHE` (decrypts once per TTL window).

#### Encrypted Write Operations

| Library | Time | vs KSafe |
|---------|------|----------|
| **KSafe (PLAIN_TEXT memory)** | **0.0254 ms** | — |
| KSafe (ENCRYPTED memory) | 0.0347 ms | — |
| EncryptedSharedPreferences | 0.2234 ms | KSafe is **9x faster** |
| KVault | 0.8516 ms | KSafe is **34x faster** |

### Key Performance Highlights

**vs DataStore (KSafe's backend):**
- :zap: **237x faster writes** (5.17 ms → 0.0218 ms)
- :zap: **76x faster reads** (0.55 ms → 0.0073 ms)

**vs KVault (encrypted KMP storage):**
- :zap: **14x faster encrypted reads** (0.24 ms → 0.0174 ms with PLAIN_TEXT memory)
- :zap: **34x faster encrypted writes** (0.85 ms → 0.0254 ms)

**vs EncryptedSharedPreferences:**
- :zap: **15x faster encrypted reads** (0.26 ms → 0.0174 ms with PLAIN_TEXT memory)
- :zap: **9x faster encrypted writes** (0.22 ms → 0.0254 ms)

**vs SharedPreferences (unencrypted baseline):**
- :zap: KSafe unencrypted writes match SharedPreferences (0.0218 ms vs 0.0224 ms)
- Reads are ~4x slower (0.0073 ms vs 0.0017 ms) — the cost of type-safe generics and cross-platform API

**vs multiplatform-settings (Russell Wolf):**
- Similar write performance (0.0218 ms vs 0.0228 ms)
- Similar read performance (0.0073 ms vs 0.0054 ms)
- KSafe adds: encryption, biometrics, type-safe serialization

### Cold Start Performance

How fast can each library load existing data on app startup?

| Library | Keys | Time |
|---------|------|------|
| SharedPreferences | 501 | 0.032 ms |
| Multiplatform Settings | 501 | 0.109 ms |
| MMKV | 501 | 0.119 ms |
| DataStore | 501 | 0.559 ms |
| **KSafe (ENCRYPTED)** | 1503 | **18.2 ms** |
| KSafe (PLAIN_TEXT) | 3006 | 45.7 ms |
| EncryptedSharedPrefs | 501 | 56.2 ms |
| KVault | 650 | 58.3 ms |

> **Note:** KSafe ENCRYPTED mode is **2.5x faster** to cold-start than PLAIN_TEXT mode. This is because ENCRYPTED defers decryption until values are accessed, while PLAIN_TEXT decrypts all values upfront during initialization. Both KSafe modes cold-start faster than EncryptedSharedPreferences and KVault.

### How KSafe Achieves This Performance

KSafe uses a **hot cache architecture** similar to SharedPreferences, but built on top of DataStore:

```
Vanilla DataStore:
  Read:  suspend → Flow.first() → disk I/O → ~0.55 ms
  Write: suspend → edit{} → serialize → disk I/O → ~5.2 ms

KSafe with Hot Cache:
  Read:  getDirect() → ConcurrentHashMap lookup → ~0.007 ms (no disk!)
  Write: putDirect() → update HashMap + queue → ~0.022 ms (returns immediately)
         Background: batched DataStore.edit() (user doesn't wait)
```

**Key optimizations:**
1. **ConcurrentHashMap cache** - O(1) per-key reads and writes
2. **Write coalescing** - Batches writes within 16ms window into single DataStore edit
3. **Deferred encryption** - Encryption moved to background thread, UI thread returns instantly
4. **SecretKey caching** - Avoids repeated Android Keystore lookups

This means KSafe gives you DataStore's safety guarantees (atomic transactions, type-safe) with SharedPreferences-level performance.

***
