# Changelog

All notable changes to KSafe will be documented in this file.

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
  - Real device: Hardware-backed Keychain (Secure Enclave)
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
