# Changelog

All notable changes to KSafe will be documented in this file.

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

### Changed
- **Removed `useBiometrics` parameter** from all storage APIs (`get`, `put`, `getDirect`, `putDirect`)
- Biometric verification is now a separate step you control explicitly
- **iOS thread safety improvements** - Biometric callbacks now always execute on Main thread

### Migration from 1.2.x

#### Before (1.2.x)
```kotlin
// Biometrics tied to storage
ksafe.put("key", value, useBiometrics = true)
val data = ksafe.get("key", default, useBiometrics = true)
```

#### After (1.3.0)
```kotlin
// Biometrics as a separate verification step
ksafe.verifyBiometricDirect("Authenticate to save") { success ->
    if (success) {
        ksafe.putDirect("key", value)
    }
}

// Or with suspend function
if (ksafe.verifyBiometric("Authenticate to read")) {
    val data = ksafe.get("key", default)
}

// With duration caching (60 seconds, scoped to ViewModel)
ksafe.verifyBiometricDirect(
    reason = "Authenticate",
    authorizationDuration = BiometricAuthorizationDuration(
        duration = 60_000L,
        scope = viewModelScope.hashCode().toString()
    )
) { success ->
    if (success) { /* ... */ }
}
```

### Benefits of New Architecture
- **Full control** over when biometric prompts appear
- **Reusable** - Same biometric helper protects any action
- **Flexible caching** - Avoid prompt fatigue with duration caching
- **Scoped invalidation** - Auth tied to ViewModel lifecycle or custom scopes
- **Cleaner separation** - Storage and authentication are independent concerns

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
