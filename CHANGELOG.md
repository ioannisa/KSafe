# Changelog

All notable changes to KSafe will be documented in this file.

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
