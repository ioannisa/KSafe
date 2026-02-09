# Changelog

All notable changes to KSafe will be documented in this file.

## [1.5.0] - 2025-02-09

### Added

#### Configurable Device Lock-State Policy: `requireUnlockedDevice`

New `KSafeConfig.requireUnlockedDevice: Boolean = false` property that controls whether encrypted data should only be accessible when the device is unlocked.

| Platform | `false` (default) | `true` |
|----------|-------------------|--------|
| **Android** | Keys accessible at any time | Keys created with `setUnlockedDeviceRequired(true)` (API 28+) |
| **iOS** | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |
| **JVM** | No effect (software-backed keys) | No effect (software-backed keys) |

**Automatic migration:** Changing this value in either direction triggers a one-time migration on the next KSafe initialization:
- **Android:** Existing encrypted values are decrypted with the old key, the old Keystore key is deleted, and values are re-encrypted with a new key that has the updated policy. This applies in both directions (`false→true` and `true→false`). Migration is atomic — the policy marker is only written on success, so a crash safely retries.
- **iOS:** Existing Keychain items have their `kSecAttrAccessible` attribute updated in-place via `SecItemUpdate` (no re-encryption needed). The migration marker is only written if all key updates succeed — if any fail (e.g., device is locked), migration retries on next launch.
- **JVM:** Only the policy marker is written (no lock concept on JVM).

```kotlin
// Require device to be unlocked for all encrypted data access
val ksafe = KSafe(
    context = context,
    config = KSafeConfig(requireUnlockedDevice = true)
)
```

**Breaking change (iOS default behavior):** Previously, iOS always used `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, meaning Keychain items were only accessible when the device was unlocked. With `requireUnlockedDevice = false` (the new default), iOS now uses `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, making items accessible after the first unlock — matching Android's existing behavior and enabling background access patterns.

- New `KSafeEncryption.updateKeyAccessibility()` interface method (default no-op, overridden on iOS)
- Migration marker `__ksafe_access_policy__` stored in DataStore (skipped by `updateCache()` on all platforms)

**Error behavior when locked:** When `requireUnlockedDevice = true` and the device is locked, encrypted reads (`getDirect`, `get`, `getFlow`) and suspend writes (`put`) throw `IllegalStateException` instead of silently returning default values. `putDirect` does not throw — the background write consumer logs the error and drops the batch while staying alive for future writes. On Android, `InvalidKeyException` from `Cipher.init()` is wrapped as `IllegalStateException("device is locked")` and propagated through `resolveFromCache` and `getEncryptedFlow`. Apps can catch this exception to detect and handle locked-device scenarios.

#### New Memory Policy: `ENCRYPTED_WITH_TIMED_CACHE`

A third memory policy that balances security and performance. The primary `memoryCache` still holds ciphertext (like `ENCRYPTED`), but a secondary plaintext cache stores recently-decrypted values for a configurable TTL.

**Why this matters:** Under `ENCRYPTED` policy, every read triggers AES-GCM decryption. In UI frameworks like Jetpack Compose or SwiftUI, the same encrypted property may be read multiple times during a single recomposition/re-render cycle. This causes redundant crypto operations that waste CPU and can drop frames on lower-end devices.

`ENCRYPTED_WITH_TIMED_CACHE` eliminates this: only the first read decrypts; subsequent reads within the TTL window are pure memory lookups. After the TTL expires, the plaintext is evicted and the next read decrypts again.

```kotlin
// Android
val ksafe = KSafe(
    context = context,
    memoryPolicy = KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE,
    plaintextCacheTtl = 5.seconds  // default
)

// JVM
val ksafe = KSafe(
    memoryPolicy = KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE,
    plaintextCacheTtl = 10.seconds
)

// iOS
val ksafe = KSafe(
    memoryPolicy = KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE,
    plaintextCacheTtl = 3.seconds
)
```

**How the three policies compare:**

| Policy | RAM contents | Read cost | Security |
|--------|-------------|-----------|----------|
| `PLAIN_TEXT` | Plaintext (forever) | O(1) lookup | Low — all data exposed in memory |
| `ENCRYPTED` | Ciphertext | AES-GCM decrypt every read | High — nothing plaintext in RAM |
| `ENCRYPTED_WITH_TIMED_CACHE` | Ciphertext + short-lived plaintext | First read decrypts, then O(1) for TTL | Medium — plaintext only for recently-accessed keys, only for seconds |

**Race condition safety:** Reads capture a local reference to the cached entry atomically. There is no background sweeper — expired entries are simply ignored on the next access. Even under concurrent reads and writes, the worst case is a single extra decryption, never a crash or data corruption.

- New `plaintextCacheTtl: Duration` constructor parameter (default: 5 seconds) on all platforms
- Uses `kotlin.time.TimeSource.Monotonic` for cross-platform monotonic timestamps
- Thread-safe: `ConcurrentHashMap` on Android/JVM, `AtomicReference<Map>` on iOS

#### Orphaned Ciphertext Cleanup on Startup

After uninstalling an app and reinstalling, Android Auto Backup restores the DataStore file (containing ciphertext) but **not** the Android Keystore keys (hardware-bound). This leaves orphaned ciphertext that wastes space and creates confusion — encrypted values silently return defaults because the key is gone. On iOS, a similar scenario occurs if Keychain entries are cleared during a device reset.

KSafe now proactively detects and removes orphaned ciphertext on startup. A new `cleanupOrphanedCiphertext()` method runs once in `startBackgroundCollector()` after migration and before the DataStore `collect`:

```kotlin
private fun startBackgroundCollector() {
    CoroutineScope(Dispatchers.Default + SupervisorJob()).launch {
        migrateAccessPolicyIfNeeded()
        cleanupOrphanedCiphertext()   // ← NEW
        dataStore.data.collect { updateCache(it) }
    }
}
```

**How it works:**
1. Reads all DataStore entries with the `encrypted_` prefix
2. Attempts to decrypt each entry using the platform's encryption engine
3. If decryption permanently fails (key gone, invalidated, or wrong key) → marks for removal
4. If decryption temporarily fails (device is locked) → skips, retries next launch
5. Atomically removes all orphaned entries from DataStore and memory cache

**Error classification by platform:**
- **Android:** "device is locked" → skip (temporary). `KeyPermanentlyInvalidatedException`, `AEADBadTagException`, "No encryption key found" → orphaned.
- **iOS:** "device is locked" or "Keychain" errors → skip (temporary). All others → orphaned.
- **JVM:** All decrypt failures → orphaned (no device lock concept).

> **Note on unencrypted values:** This cleanup targets only encrypted entries (those with the `encrypted_` prefix in DataStore). Unencrypted values (`encrypted = false`) are not affected. On Android, if `android:allowBackup="true"` is set in the manifest, Auto Backup may restore unencrypted DataStore entries after reinstall with stale values from the last backup snapshot.

### Fixed

#### iOS Keychain operations now check return values

- `storeInKeychain()` now checks the `SecItemAdd` return value — previously it was silently ignored, meaning key storage could fail without any error
- `updateKeyAccessibility()` now checks the `SecItemUpdate` return value and throws on failure

#### Suspend API no longer blocks the calling dispatcher during encryption/decryption

The suspend functions `put(encrypted = true)` and `get(encrypted = true)` previously called `engine.encrypt()`/`engine.decrypt()` directly on the caller's coroutine dispatcher. If called from `Dispatchers.Main` (e.g., inside `viewModelScope.launch`), the blocking AES-GCM operation would run on the main thread. On Android, first-time Keystore key generation can take 50–200ms — enough to drop frames.

**Before (broken):**
```kotlin
// In ViewModel — encryption runs on Main thread!
viewModelScope.launch {
    ksafe.put("token", myToken, encrypted = true)
}
```

**After (fixed):**
- `putEncrypted` now wraps `engine.encrypt()` in `withContext(Dispatchers.Default)`
- `getEncrypted` now wraps `resolveFromCache()` in `withContext(Dispatchers.Default)`
- Applied consistently across all three platforms (Android, JVM, iOS)
- `Dispatchers.Default` is correct because encryption is CPU-bound, not I/O-bound

**Note:** `putDirect` was already safe — it defers encryption to `processBatch()` on a background scope. This fix brings the suspend API (`put`/`get`) to the same level of thread safety.

#### ENCRYPTED mode plaintext leak via Direct API

`putDirect()` stored plaintext JSON in `memoryCache` for instant read-back, but `processBatch()` never replaced it with ciphertext after encryption completed. Because dirty keys are permanent (by design), `updateCache()` couldn't fix this either. Result: `ENCRYPTED` mode advertised "ciphertext in RAM" but Direct API writes left plaintext in RAM permanently.

**Fixed:** After `processBatch()` encrypts and persists data to DataStore, it now atomically replaces plaintext with ciphertext in the memory cache using compare-and-swap (CAS):
- **Android/JVM**: `ConcurrentHashMap.replace(key, oldValue, newValue)` — atomic, no-op if a newer `putDirect()` wrote a different value
- **iOS**: `AtomicReference.compareAndSet` loop with same "skip if newer write" semantics

A brief plaintext window (~16ms write coalescing) remains inherent to deferred encryption — it keeps `putDirect()` at ~13μs instead of 4-6ms. The suspend API (`put()`) does not have this window; it encrypts immediately via `withContext(Dispatchers.Default)`.

#### Long values silently stored as Int in unencrypted suspend writes (Android + iOS)

`putUnencrypted` coerced small Long values (those fitting in Int range) to Int before storing. On Android, this created a type mismatch — `getUnencryptedKey` correctly selected `longPreferencesKey` but the stored value was an Int. On iOS, both key selection and value were coerced to Int, silently changing the stored type. The in-memory cache masked the issue during runtime (because `resolveFromCache` handles Int-to-Long conversion), but DataStore's typed key system could not round-trip the value correctly from disk after a restart.

**Fixed:** All primitives are now stored as their declared type — a Long stays a Long, an Int stays an Int. No `Number` coercion. JVM was already correct. Existing data is safe: `resolveFromCache` already handles Int-to-Long conversion on read, so old values stored as Int will still be read correctly as Long through the cache layer.

#### Redundant serialization and cache write in `putDirect`

The encrypted branch of `putDirect()` previously called `json.encodeToString()` twice and `updateMemoryCache()` twice with the same value. The shared `toCache` computation was wasted for encrypted writes because the encrypted branch recomputed it independently. Restructured so encrypted and unencrypted branches are fully independent — each computes its own cache value and calls `updateMemoryCache()` once. Applied across all three platforms.

#### Stale comment in `updateCache` (Android + JVM)

A comment in `updateCache()` incorrectly stated "Dirty flags are cleared in processBatch after successful persistence." In reality, dirty flags are intentionally kept permanently to prevent race conditions. Updated the comment to reflect the actual behavior.

#### Background write consumer dies on encryption failure

If `processBatch()` threw an exception (e.g., device locked with `requireUnlockedDevice = true`), the Channel consumer coroutine would crash and never restart — all future `putDirect` writes would silently queue up and never persist. Now `processBatch()` is wrapped in a try-catch: the failed batch is dropped with a log message, and the consumer stays alive for future writes after the device is unlocked.

#### Nullable primitive retrieval returns default instead of stored value (all platforms)

When retrieving an unencrypted primitive with a nullable type and `null` default (e.g., `get<String?>(key, defaultValue = null, encrypted = false)`), KSafe always returned `null` even when a value was stored. The `when(defaultValue)` dispatch in `convertStoredValue` matched `null` against `is String` — which fails because `null` is not a `String` instance — falling through to the `else` branch that attempted JSON deserialization on a plain string like `"hello"`. Since `"hello"` is not valid JSON, deserialization silently failed and the catch returned `null`.

**Fixed:** The `else` branch now tries a direct cast (`storedValue as T`) before JSON deserialization. For primitives (String, Int, Boolean, etc.), the cast succeeds and the value is returned immediately. JSON deserialization is only attempted as a fallback for complex types (data classes). Applied on Android, iOS, and JVM.

#### Cache cleanup evicts newly-written keys (all platforms)

`updateCache()` removed any key from `memoryCache` that wasn't present in the DataStore snapshot. But between `putDirect()` and `processBatch()` flushing to DataStore, newly-written keys exist only in the cache — the DataStore snapshot doesn't contain them yet. A concurrent `updateCache()` would evict these keys, causing the next `getDirect()` to return the default value instead of the just-written value.

**Fixed:** The key-removal filter in `updateCache()` now also checks `dirtyKeys`, preserving any key that has a pending write. Applied on Android, iOS, and JVM.

### Added (Testing)

- `testNewKeysSurviveCacheCleanup` — stress test: 10 writers × 200 iterations verifying that `putDirect` + immediate `getDirect` never returns default (targets the cache cleanup race condition)
- `testOrphanedCiphertextIsCleanedUpOnStartup` — uses a togglable fake engine to simulate lost encryption keys after backup restore; verifies orphaned ciphertext is detected and that unencrypted data is left untouched
- `testValidCiphertextIsNotCleanedUp` — verifies that valid encrypted entries survive the startup cleanup
- `testEncryptedPutGetNeverReturnsDefault` — 5 concurrent readers + writers verifying encrypted values never transiently return defaults

### Dependencies

- `play-services-base` 18.9.0 → 18.10.0
- `vanniktech-mavenPublish` 0.35.0 → 0.36.0

---

## [1.4.2] - 2025-01-26

### Fixed

- **Critical iOS data loss on upgrade from v1.2.0** - Removed erroneous `clearAllKeychainEntriesSync()` function that was wiping all Keychain entries on first launch
  - **Root cause**: The function was based on a flawed premise that v1.2.0 stored "biometric-protected" Keychain entries that needed cleanup
  - **Reality**: v1.2.0 used `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` which is NOT biometric protection—it simply means "accessible when device is unlocked"
  - **Impact**: Users upgrading from v1.2.0 to v1.3.0+ lost all their encrypted data unnecessarily
  - **Fix**: Removed the one-time cleanup that ran on startup. The legitimate `cleanupOrphanedKeychainEntries()` function (which removes Keychain keys without matching DataStore entries after app reinstall) remains intact
  - **Who was affected**: Only users who upgraded FROM v1.2.0 TO any version between v1.3.0–v1.4.1. Users who started fresh on v1.3.0+ or upgraded between v1.3.x/v1.4.x versions were NOT affected
  - **Why in-between upgrades were safe**: The cleanup used NSUserDefaults to track execution via `BIOMETRIC_CLEANUP_KEY`. Once it ran (on first launch after upgrading from v1.2.0), the flag was set and subsequent version upgrades (e.g., v1.3.0→v1.4.0→v1.4.1) skipped the cleanup entirely. The damage only occurred on that single first upgrade from v1.2.0

### Removed

- `clearAllKeychainEntriesSync()` - iOS function that unnecessarily deleted all Keychain entries
- `BIOMETRIC_CLEANUP_KEY` constant - No longer needed without the erroneous cleanup

---

## [1.4.1] - 2025-01-21

### Performance Improvements

KSafe 1.4.1 delivers **massive performance improvements**, making it faster than EncryptedSharedPreferences and KVault for encrypted operations while maintaining hardware-backed security.

#### Benchmark Results (1.4.0 → 1.4.1)

| Metric | 1.4.0 | 1.4.1 | Improvement |
|--------|-------|-------|-------------|
| Unencrypted Write | 0.23 ms | 0.0115 ms | **20x faster** |
| Encrypted Write (ENCRYPTED mem) | 0.44 ms | 0.053 ms | **8x faster** |
| Encrypted Write (PLAIN_TEXT mem) | 0.70 ms | 0.012 ms | **58x faster** |
| Encrypted Write vs ESP | 2.4x slower | **17x faster** | Now beats ESP! |
| DataStore Write Acceleration | 20x | 327x | **16x more** |

#### Comparison with Other Libraries (Unencrypted)

| Library | Read | Write | Notes |
|---------|------|-------|-------|
| SharedPreferences | 0.0006 ms | 0.0152 ms | Android only, no encryption |
| MMKV | 0.0007 ms | 0.0577 ms | Fast, but no KMP, no hardware encryption |
| Multiplatform Settings | 0.0009 ms | 0.0192 ms | KMP, but no encryption |
| **KSafe 1.4.1** | **0.0016 ms** | **0.0115 ms** | KMP + encryption + biometrics |
| DataStore | 1.10 ms | 3.76 ms | Safe but slow |

> **Note:** KSafe unencrypted writes are now **faster than SharedPreferences**!

#### Comparison with Other Libraries (Encrypted)

| Library | Read | Write | vs KSafe |
|---------|------|-------|----------|
| **KSafe (PLAIN_TEXT memory)** | **0.0058 ms** | **0.0123 ms** | — |
| KSafe (ENCRYPTED memory) | 0.0276 ms | 0.0531 ms | *(decrypts on-demand)* |
| KVault | 0.6003 ms | 1.05 ms | KSafe is **103x/85x faster** |
| EncryptedSharedPrefs | 0.6817 ms | 0.2064 ms | KSafe is **117x/17x faster** |

**vs KVault (encrypted KMP storage):**
- **103x faster encrypted reads** (0.60 ms → 0.0058 ms with PLAIN_TEXT memory)
- **85x faster encrypted writes** (1.05 ms → 0.0123 ms)

**vs multiplatform-settings (Russell Wolf):**
- **1.7x faster writes** (0.0192 ms → 0.0115 ms)
- Similar read performance (0.0016 ms vs 0.0009 ms)
- KSafe adds: hardware-backed encryption, biometric auth, auto-serialization

#### Cold Start / Reinitialization Performance

| Library | Keys | Time |
|---------|------|------|
| SharedPreferences | 201 | 0.0315 ms |
| Multiplatform Settings | 201 | 0.0400 ms |
| MMKV | 201 | 0.0402 ms |
| DataStore | 201 | 0.4901 ms |
| **KSafe (ENCRYPTED)** | 603 | **1.26 ms** |
| KVault | 320 | 4.77 ms |
| EncryptedSharedPrefs | 201 | 6.41 ms |
| KSafe (PLAIN_TEXT) | 1206 | 6.49 ms |

> **Note:** KSafe ENCRYPTED mode is **5x faster** to cold-start than PLAIN_TEXT mode (defers decryption until access).

#### Optimizations Implemented

1. **ConcurrentHashMap for Hot Cache**
   - Replaced `AtomicReference<Map>` with `ConcurrentHashMap`
   - O(1) per-key updates instead of copy-on-write
   - Eliminates full map copy on every write

2. **ConcurrentHashMap for Dirty Keys**
   - Replaced `AtomicReference` with CAS loops with `ConcurrentHashMap.newKeySet()`
   - O(1) add/remove operations for tracking pending writes
   - Prevents stale data overwrites during async persistence

3. **Write Coalescing**
   - New `Channel<WriteOperation>` for queuing writes
   - Single consumer coroutine batches operations within 16ms window
   - Multiple writes coalesced into single `DataStore.edit{}` call
   - Reduces disk I/O overhead significantly

4. **Deferred Encryption**
   - Encryption moved from UI thread to background batch processor
   - `putDirect()` queues plaintext, returns immediately
   - `processBatch()` encrypts all pending operations before DataStore write
   - UI thread no longer blocked by Android Keystore operations

5. **SecretKey Caching (Android)**
   - Added `ConcurrentHashMap<String, SecretKey>` cache in `AndroidKeystoreEncryption`
   - Avoids repeated Android Keystore lookups
   - Double-checked locking with `synchronized(keyAlias.intern())`
   - Cache cleared when keys are deleted

6. **Shared Write Scope**
   - Reuses single `CoroutineScope(Dispatchers.IO + SupervisorJob())` for all write operations
   - Avoids object allocation overhead of creating new scope per `putDirect()` call

7. **Simplified Cache Updates**
   - `updateMemoryCache()` now uses O(1) direct `ConcurrentHashMap` operations
   - Eliminated CAS loops and map copying previously required with `AtomicReference<Map>`

### Technical Details

**Write Flow Before (1.4.0):**
```
putDirect() → encrypt (BLOCKING) → launch coroutine → DataStore.edit()
             ↑ 4-6ms on UI thread!
```

**Write Flow After (1.4.1):**
```
putDirect() → update cache → queue WriteOperation → return (~13µs)
                                     ↓
Background: collect 16ms window → encrypt all → single DataStore.edit()
```

### Fixed

- **Critical Data Integrity Fix (Hot Cache)** - Fixed a bug where plaintext values like `"true"`, `"false"`, or numbers (which are valid Base64) were incorrectly attempted to be decrypted during optimistic reads.
  - Previously, "decrypting" these values produced garbage which failed JSON parsing outside the recovery block.
  - Now validates JSON structure post-decryption; invalid results trigger the correct plaintext fallback.
  - Fixes potential read failures for specific primitive values immediately after writing.

- **ConcurrentHashMap iteration race condition (JVM)** - Fixed `NoSuchElementException` crash during rapid concurrent writes

- **HashMap concurrency crash (iOS)** - Fixed `IllegalStateException` ("Have object hashCodes changed?") crash during concurrent cache access
  - Kotlin/Native's HashMap is not thread-safe unlike JVM's ConcurrentHashMap
  - Implemented proper copy-on-write semantics with AtomicReference for all cache mutations
  - Added synchronized access to dirty keys set
  - Background collector can no longer corrupt cache while UI reads values

- **Dirty keys race condition** - Fixed cache corruption where keys could be removed prematurely
  - Dirty flags are now intentionally NOT cleared after persistence
  - Prevents stale DataStore snapshots from overwriting optimistic cache values
  - Trade-off: Small memory overhead (~10KB for 1000 keys) for guaranteed correctness

- **Self-Healing Key Recovery (Android)** - Fixed rare crash when Android Keystore keys become invalidated
  - **This is rare**: KSafe keys are configured WITHOUT these flags:
    - `setUserAuthenticationRequired(true)` - NOT set (keys usable without unlocking device)
    - `setInvalidatedByBiometricEnrollment(true)` - NOT set (keys survive biometric changes)
  - This means KSafe keys are stable and always accessible
  - Invalidation only occurs in edge cases: factory reset, OEM Keystore bugs, or system corruption
  - Now catches `KeyPermanentlyInvalidatedException` during encrypt/decrypt operations
  - **Self-healing behavior**: Automatically deletes invalidated key and regenerates a fresh one
  - Encryption: Seamlessly retries with new key (data preserved)
  - Decryption: Returns default value (old encrypted data cannot be recovered with destroyed key)

- **iOS Keychain error handling** - Improved error handling to prevent silent data loss
  - `errSecItemNotFound` → Creates new key (correct - key doesn't exist)
  - `errSecInteractionNotAllowed` → Throws error (device locked - key exists but inaccessible)
  - Other errors → Throws error with status code (prevents silent key regeneration)
  - Previously, ANY error would silently create a new key, potentially causing data loss

### Added (Testing)

- **Concurrency stress tests** in `JvmKSafeTest`:
  - `testConcurrentPutDirectStress` - 10 writers × 500 iterations
  - `testConcurrentEncryptedPutDirectStress` - 5 writers × 100 encrypted iterations
  - `testConcurrentReadWriteStress` - Simultaneous read/write on shared keys
  - `testDirtyKeysStress` - 20 writers × 1000 iterations targeting dirty key mechanism
- **iOS Keychain error handling tests** in `IosKeychainEncryptionTest`:
  - `testThrowsOnKeychainErrorInTestEnvironment` - Verifies errors throw (not silently create keys)
  - `testDecryptThrowsOnKeychainError` - Verifies decrypt fails safely
  - `testDeleteKeyDoesNotThrow` - Verifies delete is safe (no data loss risk)
  - `testCustomConfigIsAccepted` - Verifies 128-bit and 256-bit config
  - Documentation tests for error codes and device-locked scenario

### Changed

- `WriteOperation.Encrypted` now carries plaintext + keyAlias instead of pre-computed ciphertext
- Encryption happens in `processBatch()` instead of `putDirect()`
- All three platforms (Android, iOS, JVM) use consistent write coalescing architecture

### Documentation

- **Added Direct API recommendation** for bulk/concurrent operations (~950x faster than Coroutine API)
- Added Cold Start / Reinitialization benchmark results
- Added comprehensive comparison table (KSafe vs SharedPreferences vs DataStore vs KVault)
- Added performance benchmarks section with detailed results including KVault
- Added explanation of hot cache architecture
- Updated "Alternatives & Comparison" section with KVault

---

## [1.4.0] - 2025-01-11

### Added

#### Runtime Security Policy
- **New `KSafeSecurityPolicy`** for detecting runtime security threats
- **Configurable actions** - `IGNORE`, `WARN`, or `BLOCK` for each security check:
  - `IGNORE` - No detection performed, no callback invoked
  - `WARN` - Detection runs, callback invoked, app continues normally
  - `BLOCK` - Detection runs, callback invoked, throws `SecurityViolationException`
- **Preset policies** - `Default`, `Strict`, `WarnOnly` for common configurations
  ```kotlin
  val ksafe = KSafe(
      context = context,
      securityPolicy = KSafeSecurityPolicy.Strict
  )
  ```

#### Root & Jailbreak Detection
- **Enhanced Android root detection**:
  - su binary paths (`/system/bin/su`, `/system/xbin/su`, etc.)
  - Magisk paths (`/sbin/.magisk`, `/data/adb/magisk`, etc.)
  - BusyBox installation paths
  - Xposed Framework (files + stack trace detection)
  - Root management apps (Magisk Manager, SuperSU, LSPosed, KingRoot, etc.)
  - Build tags (`test-keys`) and dangerous system properties
- **iOS jailbreak detection**:
  - Cydia, Sileo, and other jailbreak app paths
  - System write access test (fails on non-jailbroken devices)
  - Common jailbreak tool paths (`/bin/bash`, `/usr/sbin/sshd`, etc.)
- ⚠️ **Limitation**: Sophisticated root-hiding tools (Magisk DenyList, Shamiko, Zygisk) may bypass detection

#### Debugger & Emulator Detection
- **Debugger detection** - Detect attached debuggers on all platforms
- **Emulator detection** - Detect emulators/simulators (Android & iOS)
- **Debug build detection** - Detect debug builds

#### Platform Integrity Verification
- **New `IntegrityChecker`** class for server-side device verification
- **Google Play Integrity** (Android) - Generates tokens for server verification
  - Requires Google Cloud project number
  - Graceful fallback on non-GMS devices (Huawei, Amazon Fire)
- **Apple DeviceCheck** (iOS) - Generates tokens for server verification
  - No additional configuration needed
- **JVM** - Returns `IntegrityResult.NotSupported`
  ```kotlin
  // Android
  val checker = IntegrityChecker(context, cloudProjectNumber = 123456789L)

  // iOS
  val checker = IntegrityChecker()

  when (val result = checker.requestIntegrityToken(nonce)) {
      is IntegrityResult.Success -> sendToServer(result.token)
      is IntegrityResult.Error -> handleError(result.message)
      is IntegrityResult.NotSupported -> fallback()
  }
  ```
- ⚠️ **Important**: Tokens MUST be verified server-side. Client-side verification is insecure.

#### Compose Support
- **New `UiSecurityViolation`** - Immutable wrapper for `SecurityViolation` ensuring Compose stability
  ```kotlin
  @Immutable
  data class UiSecurityViolation(val violation: SecurityViolation)
  ```
  - Allows `ImmutableList<UiSecurityViolation>` to skip unnecessary recompositions
  - Located in `ksafe-compose` module

### Added (Testing)
- **Comprehensive test suite** for new security features:
  - `KSafeSecurityPolicyTest` - SecurityAction, SecurityViolation, presets
  - `IntegrityCheckerTest` - IntegrityResult sealed class behavior
  - `BiometricAuthorizationDurationTest` - Duration and scope patterns
  - `KSafeMemoryPolicyTest` - Memory policy enum
  - `JvmSecurityCheckerTest` - JVM-specific security behavior
- **ksafe-compose module tests**:
  - `KSafeComposeStateTest` - Compose state integration tests
  - `KSafeMutableStateOfTest` - MutableState behavior tests
  - `AndroidKSafeMutableStateOfTest` - Android instrumented tests
  - `JvmKSafeMutableStateOfTest` - JVM-specific tests

### Changed
- **iOS Simulator uses real Keychain** - Removed `MockKeychain` in favor of actual iOS Keychain APIs
  - Simulator: Software-backed Keychain
  - Real device: Hardware-encrypted Keychain (protected by device passcode)
  - Added threat model and security boundaries
  - Added compatibility matrix
  - Added GCM (Galois/Counter Mode) explanation
  - Added detailed Actions behavior documentation with examples
  - Added non-GMS device compatibility notes
  - Added root detection methods documentation

### Removed
- **`MockKeychain.kt`** - iOS Simulator now uses real Keychain APIs instead of UserDefaults-based mock
- **Irrelevant images** - Removed unnecessary publishing screenshots from repository

---

## [1.3.0] - 2025-12-31

### Added

#### Standalone Biometric Authentication
- **New `verifyBiometric()` suspend function** - Coroutine-based biometric verification
- **New `verifyBiometricDirect()` callback function** - Non-blocking biometric verification for any context
- **Biometric authentication is now decoupled from storage** - Use it to protect any action (API calls, navigation, data display), not just KSafe operations

#### Authorization Duration Caching
- **New `BiometricAuthorizationDuration` data class** for configuring cached authentication:
  ```kotlin
  data class BiometricAuthorizationDuration(
      val duration: Long,       // Duration in milliseconds
      val scope: String? = null // Optional scope identifier
  )
  ```
- **Duration caching** - Avoid repeated biometric prompts by caching successful auth for a specified duration
- **Scoped authorization** - Different scopes maintain separate auth timestamps for fine-grained control
- **Recommended pattern**: Use `viewModelScope.hashCode().toString()` for ViewModel-scoped auth that auto-invalidates when the ViewModel is recreated

#### Authorization Management
- **New `clearBiometricAuth()` function** - Force re-authentication by clearing cached auth
  - `clearBiometricAuth()` - Clear all cached authorizations
  - `clearBiometricAuth(scope)` - Clear only a specific scope

#### Configurable Encryption
- **New `KSafeConfig` data class** for encryption customization
- Configurable AES key size: 128-bit or 256-bit (default)
  ```kotlin
  // Default (AES-256)
  val ksafe = KSafe(context)

  // Custom key size (AES-128)
  val ksafe128 = KSafe(context, config = KSafeConfig(keySize = 128))
  ```

### Changed
- **iOS thread safety improvements** - Biometric callbacks now always execute on Main thread
- **License consistency** - Fixed Maven POM metadata to use Apache-2.0 (matching repository)

---

## [1.2.0] - 2025-01-15

### Added
- **Hybrid "Hot Cache" Architecture** - Zero-latency UI reads with async preloading
- **Memory Security Policy** - Choose between `ENCRYPTED` (max security) or `PLAIN_TEXT` (max performance)
- **Nullable value support** - Correctly store and retrieve `null` values
- **Multiple KSafe instances** - Create separate instances with different file names
- **JVM/Desktop support** - Full support alongside Android and iOS
- **KSafeConfig** - Configurable encryption parameters (key size)
- **Lazy loading option** - Defer data loading until first access

### Changed
- `getDirect()` now performs atomic memory lookup (O(1)) instead of blocking disk read
- `putDirect()` uses optimistic updates - immediate cache update with background persistence
- Eager preloading on initialization by default (use `lazyLoad = true` to defer)

---

## [1.1.0] - 2024-12-01

### Added
- Initial release with encrypted persistence
- Property delegation (`by ksafe(defaultValue)`)
- Compose state support (`by ksafe.mutableStateOf(defaultValue)`)
- Android Keystore and iOS Keychain integration
- Suspend and Direct APIs
