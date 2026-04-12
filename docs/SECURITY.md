# Security

## Runtime Security Policy

KSafe can detect and respond to runtime security threats:

```kotlin
val ksafe = KSafe(
    context = context,
    securityPolicy = KSafeSecurityPolicy(
        rootedDevice = SecurityAction.WARN,      // IGNORE, WARN, or BLOCK
        debuggerAttached = SecurityAction.BLOCK,
        debugBuild = SecurityAction.WARN,
        emulator = SecurityAction.IGNORE,
        onViolation = { violation ->
            analytics.log("Security: ${violation.name}")
        }
    )
)
```

| Check | Android | iOS | JVM | WASM | Description |
|-------|---------|-----|-----|------|-------------|
| `rootedDevice` | ✅ | ✅ | ❌ | ❌ | Detects rooted/jailbroken devices |
| `debuggerAttached` | ✅ | ✅ | ✅ | ❌ | Detects attached debuggers |
| `debugBuild` | ✅ | ✅ | ✅ | ❌ | Detects debug builds |
| `emulator` | ✅ | ✅ | ❌ | ❌ | Detects emulators/simulators |

### Actions Explained

| Action | Behavior | Use Case |
|--------|----------|----------|
| `IGNORE` | No detection performed | Development, non-sensitive apps |
| `WARN` | Callback invoked, app continues | Logging/analytics, user warnings |
| `BLOCK` | Callback invoked, throws `SecurityViolationException` | Banking, enterprise apps |

**Example behavior with `WARN`:**
```kotlin
val ksafe = KSafe(
    context = context,
    securityPolicy = KSafeSecurityPolicy(
        rootedDevice = SecurityAction.WARN,
        onViolation = { violation ->
            // This is called, but app continues working
            showWarningDialog("Security risk: ${violation.name}")
            analytics.log("security_warning", violation.name)
        }
    )
)
// KSafe initializes successfully, user sees warning
```

**Example behavior with `BLOCK`:**
```kotlin
val ksafe = KSafe(
    context = context,
    securityPolicy = KSafeSecurityPolicy(
        rootedDevice = SecurityAction.BLOCK,
        onViolation = { violation ->
            // This is called BEFORE the exception is thrown
            analytics.log("security_block", violation.name)
        }
    )
)
// If device is rooted: SecurityViolationException is thrown
// App must catch this or it will crash
```

### Preset Policies

```kotlin
KSafeSecurityPolicy.Default   // All checks ignored (backwards compatible)
KSafeSecurityPolicy.Strict    // Blocks on root/debugger, warns on debug/emulator
KSafeSecurityPolicy.WarnOnly  // Warns on everything, never blocks
```

### Handling BLOCK Exceptions

```kotlin
try {
    val ksafe = KSafe(context, securityPolicy = KSafeSecurityPolicy.Strict)
} catch (e: SecurityViolationException) {
    showSecurityErrorScreen(e.violation.name)
}
```

### Providing User-Friendly Descriptions

Since `SecurityViolation` is an enum without hardcoded messages, provide your own descriptions:

```kotlin
fun getViolationDescription(violation: SecurityViolation): String {
    return when (violation) {
        SecurityViolation.RootedDevice ->
            "The device is rooted (Android) or jailbroken (iOS). " +
            "This allows apps to bypass sandboxing and potentially access encrypted data."
        SecurityViolation.DebuggerAttached ->
            "A debugger is attached to the process. " +
            "This allows inspection of memory and runtime values including decrypted secrets."
        SecurityViolation.DebugBuild ->
            "The app is running in debug mode. " +
            "Debug builds may have weaker security settings and expose more information."
        SecurityViolation.Emulator ->
            "The app is running on an emulator/simulator. " +
            "Emulators don't have hardware-backed security like real devices."
    }
}
```

### Collecting Violations for UI Display

Since KSafe initializes before ViewModels, use a holder to bridge violations to your UI:

```kotlin
// 1. Create a holder to collect violations during initialization
object SecurityViolationsHolder {
    private val _violations = mutableListOf<SecurityViolation>()
    val violations: List<SecurityViolation> get() = _violations.toList()

    fun addViolation(violation: SecurityViolation) {
        if (violation !in _violations) {
            _violations.add(violation)
        }
    }
}

// 2. Configure KSafe to populate the holder
val ksafe = KSafe(
    context = context,
    securityPolicy = KSafeSecurityPolicy.Strict.copy(
        onViolation = { violation ->
            SecurityViolationsHolder.addViolation(violation)
        }
    )
)

// 3. Read from the holder in your ViewModel
class SecurityViewModel : ViewModel() {
    val violations = mutableStateListOf<UiSecurityViolation>()

    init {
        SecurityViolationsHolder.violations.forEach { violation ->
            violations.add(UiSecurityViolation(violation))
        }
    }
}
```

### Compose Stability for SecurityViolation

When using `SecurityViolation` in Jetpack Compose, the Compose compiler treats it as "unstable" because it resides in the core `ksafe` module. The `ksafe-compose` module provides `UiSecurityViolation`—a wrapper marked with `@Immutable`:

```kotlin
@Immutable
data class UiSecurityViolation(
    val violation: SecurityViolation
)
```

| Type | Compose Stability |
|------|------------------|
| `ImmutableList<SecurityViolation>` | Unstable (causes recomposition) |
| `ImmutableList<UiSecurityViolation>` | Stable (enables skipping) |

The [KSafeDemo app](https://github.com/ioannisa/KSafeDemo) makes use of `UiSecurityViolation`—visit the demo application's source to see it in action.

### Root Detection Methods (Android)

- `su` binary paths (`/system/bin/su`, `/system/xbin/su`, etc.)
- Magisk paths (`/sbin/.magisk`, `/data/adb/magisk`, etc.)
- BusyBox installation paths
- Xposed Framework files and stack trace detection
- Root management apps (Magisk Manager, SuperSU, KingRoot, etc.)
- Build tags (`test-keys`) and dangerous system properties

### Jailbreak Detection Methods (iOS)

- Cydia, Sileo, and other jailbreak app paths
- System write access test (fails on non-jailbroken devices)
- Common jailbreak tool paths (`/bin/bash`, `/usr/sbin/sshd`, etc.)

> **Limitation:** Sophisticated root-hiding tools (Magisk DenyList, Shamiko, Zygisk) can bypass most client-side detection methods.

***

## How Encryption Works

KSafe provides enterprise-grade encrypted persistence using DataStore Preferences with platform-specific secure key storage.

### Platform Details

| Platform | Cipher | Key Storage | Security |
|----------|--------|-------------|----------|
| **Android** | AES-256-GCM | Android Keystore — TEE by default, StrongBox opt-in | Keys non-exportable, app-bound, auto-deleted on uninstall |
| **iOS** | AES-256-GCM via CryptoKit | iOS Keychain Services — Secure Enclave opt-in | Protected by device passcode/biometrics, not in backups |
| **JVM/Desktop** | AES-256-GCM via javax.crypto | Software-backed in `~/.eu_anifantakis_ksafe/` | Relies on OS file permissions (0700 on POSIX) |
| **WASM/Browser** | AES-256-GCM via WebCrypto | `localStorage` (Base64-encoded) | Scoped per origin, ~5-10 MB limit |

### Encryption Flow

1. **Serialize value → plaintext bytes** using kotlinx.serialization
2. **Load (or generate) a random 256-bit AES key** from Keystore/Keychain (unique per preference key)
3. **Encrypt with AES-GCM** (nonce + auth-tag included)
4. **Persist value** in DataStore/localStorage under `__ksafe_value_<key>`
   (encrypted writes store Base64 ciphertext, plaintext writes keep native type where supported)
5. **Persist metadata** under `__ksafe_meta_<key>__` as compact JSON
   (for example: `{"v":1,"p":"DEFAULT"}` or `{"v":1,"p":"DEFAULT","u":"unlocked"}`)
6. **Keys managed by platform** - never stored in DataStore

**What is GCM?** GCM (Galois/Counter Mode) is an authenticated encryption mode that provides both confidentiality and integrity. The authentication tag detects any tampering—if someone modifies even a single bit of the ciphertext, decryption will fail.

### Security Boundaries & Threat Model

**What KSafe protects against:**
- ✅ Casual file inspection (data at rest is encrypted)
- ✅ Data extraction from unrooted device backups
- ✅ App data access by other apps (sandboxing + encryption)
- ✅ Reinstall data leakage (automatic cleanup)
- ✅ Tampering detection (GCM authentication tag)
- ✅ Rooted/jailbroken devices (detection with configurable WARN/BLOCK)
- ✅ Debugger attachment (detection with configurable WARN/BLOCK)
- ✅ Emulator/simulator usage (detection with configurable WARN/BLOCK)

**What KSafe does NOT protect against:**
- ❌ Sophisticated root-hiding tools (e.g., Magisk Hide) — detection can be bypassed
- ❌ Memory dump attacks while app is running (mitigated by `ENCRYPTED` or `ENCRYPTED_WITH_TIMED_CACHE` memory policy)
- ❌ Device owner with physical access and device unlock credentials
- ❌ Compromised OS or hardware

**Recommendations:**
- Use `KSafeSecurityPolicy.Strict` for high-security apps (Banking, Medical, Enterprise)
- Use `KSafeMemoryPolicy.ENCRYPTED` for highly sensitive data (tokens, passwords)
- Use `KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE` for encrypted data accessed frequently during UI rendering (Compose recomposition, SwiftUI re-render)
- Combine with biometric verification for critical operations
- Never store master secrets client-side; prefer server-derived tokens
- Consider certificate pinning for API communications

**A note on hardware security models:** By default, Android stores AES keys in the TEE (Trusted Execution Environment) — a hardware-isolated zone on the main processor where encryption happens entirely on-chip and the key never enters app memory. With `mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)`, KSafe targets a physically separate security chip (StrongBox on Android, Secure Enclave on iOS) with automatic fallback to default hardware. On iOS, `HARDWARE_ISOLATED` uses **envelope encryption**: an EC P-256 key pair in the Secure Enclave wraps/unwraps the AES symmetric key via ECIES, so the AES key material is hardware-protected even though AES-GCM itself runs in CryptoKit. Without hardware isolation, AES keys are stored as Keychain items — still encrypted by the OS and protected by the device passcode.

**Hardware isolation (per-property):**
```kotlin
// StrongBox on Android, Secure Enclave on iOS
var secret by ksafe(
    "",
    mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)
)

// Or with suspend/direct API
ksafe.put("secret", value, mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))
ksafe.putDirect("secret", value, mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))
```
Hardware isolation provides the highest security level — keys live on a dedicated chip that is physically separate from the main processor. If the device lacks the hardware, KSafe automatically falls back to the platform default with no code changes required. Note that hardware-isolated key generation is slower and per-operation latency is higher, so only enable it for high-security use cases. KSafe's memory policies mitigate read-side latency since most reads come from the hot cache.

**Migrating existing keys to hardware isolation:** Using `HARDWARE_ISOLATED` only affects *new* key generation. Existing keys continue working from wherever they were originally generated. To migrate existing data to hardware-isolated keys, delete the KSafe data (or the specific keys) and reinitialize.

**Per-key metadata (single entry):** Each key stores one metadata entry (`__ksafe_meta_{key}__`) that includes:
- `p` → protection tier (`NONE`, `DEFAULT`, `HARDWARE_ISOLATED`)
- optional `u` → unlock policy (`"unlocked"` when `requireUnlockedDevice=true`)

This metadata is used for read auto-detection and `getKeyInfo()`.
Legacy metadata (`__ksafe_prot_{key}__`) is still read for backward compatibility and cleaned on next write/delete.

### Querying Device Security Capabilities

KSafe exposes properties and methods to query what security hardware is available on the device, and to inspect both the **protection tier** (what the caller requested) and **storage location** (where the key material actually lives) of individual keys:

```kotlin
val ksafe = KSafe(context)

// Device-level: what hardware is available?
ksafe.deviceKeyStorages  // e.g. {HARDWARE_BACKED, HARDWARE_ISOLATED}
ksafe.deviceKeyStorages.max()  // HARDWARE_ISOLATED (highest available)

// Per-key: what protection was used and where is the key stored?
val info = ksafe.getKeyInfo("auth_token")
// info?.protection  → KSafeProtection.DEFAULT        (encrypted tier, null if plaintext)
// info?.storage     → KSafeKeyStorage.HARDWARE_BACKED (where the key lives)
```

`getKeyInfo` returns a `KSafeKeyInfo` data class:

```kotlin
data class KSafeKeyInfo(
    val protection: KSafeProtection?,  // null, DEFAULT, or HARDWARE_ISOLATED
    val storage: KSafeKeyStorage       // SOFTWARE, HARDWARE_BACKED, or HARDWARE_ISOLATED
)
```

The `KSafeKeyStorage` enum has three levels with natural ordinal ordering:

| Level | Meaning | Platforms |
|-------|---------|-----------|
| `SOFTWARE` | Software-only (file system / localStorage) | JVM, WASM |
| `HARDWARE_BACKED` | On-chip hardware (TEE / Keychain) | Android, iOS |
| `HARDWARE_ISOLATED` | Dedicated security chip (StrongBox / Secure Enclave) | Android (if available), iOS (real devices) |

#### `deviceKeyStorages` — Device Capabilities

Query what hardware security levels the device supports:

| Platform | `deviceKeyStorages` |
|----------|---------------------|
| **Android** | Always `{HARDWARE_BACKED}`. Adds `HARDWARE_ISOLATED` if `PackageManager.FEATURE_STRONGBOX_KEYSTORE` is present (API 28+). |
| **iOS** | Always `{HARDWARE_BACKED}`. Adds `HARDWARE_ISOLATED` on real devices (not simulator). |
| **JVM** | `{SOFTWARE}` |
| **WASM** | `{SOFTWARE}` |

#### `getKeyInfo(key)` — Per-Key Protection and Storage

Query the protection tier and storage location of a specific key:

```kotlin
ksafe.getKeyInfo("auth_token")    // KSafeKeyInfo(DEFAULT, HARDWARE_BACKED) on Android/iOS
ksafe.getKeyInfo("theme")         // KSafeKeyInfo(null, SOFTWARE) if unencrypted
ksafe.getKeyInfo("nonexistent")   // null (key doesn't exist)
```

| Scenario | Return value |
|----------|-------------|
| Key not found | `null` |
| Unencrypted key | `KSafeKeyInfo(null, SOFTWARE)` |
| Encrypted key (Android/iOS) | `KSafeKeyInfo(DEFAULT, HARDWARE_BACKED)` |
| Encrypted key (JVM/WASM) | `KSafeKeyInfo(DEFAULT, SOFTWARE)` |
| `HARDWARE_ISOLATED` key (device supports it) | `KSafeKeyInfo(HARDWARE_ISOLATED, HARDWARE_ISOLATED)` |
| `HARDWARE_ISOLATED` key (device lacks it, fell back) | `KSafeKeyInfo(HARDWARE_ISOLATED, HARDWARE_BACKED)` |

**Use cases:**
- Display a security badge in your UI based on device capabilities
- Verify that a specific key is stored at the expected hardware level
- Choose the appropriate `KSafeEncryptedProtection` level based on what the device supports
- Log/report the security posture of the device for compliance

```kotlin
// Adaptive protection based on device capabilities
val protection = if (KSafeKeyStorage.HARDWARE_ISOLATED in ksafe.deviceKeyStorages)
    KSafeEncryptedProtection.HARDWARE_ISOLATED
else
    KSafeEncryptedProtection.DEFAULT

var secret by ksafe("", mode = KSafeWriteMode.Encrypted(protection))

// Verify a key's actual storage level after writing
ksafe.putDirect("secret", "value", mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))
val info = ksafe.getKeyInfo("secret")
// info?.protection == HARDWARE_ISOLATED (always matches what was requested)
// info?.storage == HARDWARE_ISOLATED on devices with StrongBox/SE, HARDWARE_BACKED otherwise
```

### Legacy Key Migration (v1.6.x → v1.7.0 canonical keys)

KSafe now uses canonical, namespaced storage keys:
- value: `__ksafe_value_{key}`
- metadata: `__ksafe_meta_{key}__`

Legacy keys are still supported on reads:
- `encrypted_{key}`
- bare `{key}`
- `__ksafe_prot_{key}__`

Migration is lazy and safe:
- Reads can consume both canonical and legacy key shapes.
- Writes (`put`/`putDirect`) always persist canonical keys and remove legacy entries for that key.
- Delete paths remove canonical and legacy entries.

***

## Security Features

### Platform-Specific Protection

#### Android
* Keys stored in Android Keystore (TEE by default)
* Optional StrongBox support via `KSafeEncryptedProtection.HARDWARE_ISOLATED` (through `KSafeWriteMode.Encrypted`) — uses a physically separate security chip with automatic TEE fallback on devices without StrongBox
* Hardware-backed encryption when available
* Keys bound to your application
* Automatic cleanup on app uninstall

#### iOS
* Keys stored in iOS Keychain Services
* Optional Secure Enclave support via `KSafeEncryptedProtection.HARDWARE_ISOLATED` (through `KSafeWriteMode.Encrypted`) — uses envelope encryption (SE-backed EC P-256 wraps/unwraps the AES key) with automatic Keychain fallback on devices without SE
* Protected by device authentication
* Not included in iCloud/iTunes backups
* Automatic cleanup of orphaned keys on first app use after reinstall

#### JVM/Desktop
* AES-256-GCM encryption via standard javax.crypto
* Keys stored in user home directory with restricted permissions
* Suitable for desktop applications and server-side use

#### WASM/Browser
* AES-256-GCM encryption via WebCrypto API
* Keys and data stored in browser `localStorage` (Base64-encoded)
* Scoped per origin (~5-10 MB storage limit)
* Memory policy always `PLAIN_TEXT` internally (WebCrypto is async-only)

### Hardware Verified

KSafe's hardware-backed encryption has been tested and verified on real devices:

| Platform | Device | Hardware Security |
|----------|--------|-------------------|
| iOS | iPhone 15 Pro Max (A17 Pro) | Secure Enclave |
| Android | Samsung Galaxy S24 Ultra (Snapdragon 8 Gen 3) | StrongBox (Knox Vault) |

### Error Handling

If decryption fails (e.g., corrupted data or missing key), KSafe gracefully returns the default value, ensuring your app continues to function.

**Exception:** When `requireUnlockedDevice = true` and the device is locked, KSafe throws `IllegalStateException` instead of returning the default value. This allows your app to detect and handle the locked state explicitly (e.g., showing a "device is locked" message).

### Reinstall Behavior

KSafe ensures clean reinstalls on all platforms:
* **Android:** Keystore entries automatically deleted on uninstall. If Auto Backup restores the DataStore file without Keystore keys, orphaned ciphertext is detected and removed on next startup.
* **iOS:** Orphaned Keychain entries (keys without data) detected and cleaned on first use. Orphaned ciphertext (data without keys) detected and cleaned on startup.
* **JVM:** Orphaned ciphertext detected and cleaned on startup if encryption key files are lost.

> **Note on unencrypted values:** The orphaned ciphertext cleanup targets only encrypted entries (those with the `encrypted_` prefix in DataStore). Unencrypted values (`encrypted = false`) are not affected by this cleanup. On Android, if `android:allowBackup="true"` is set in the manifest, Auto Backup may restore unencrypted DataStore entries after reinstall with stale values from the last backup snapshot.

### iOS Keychain Cleanup Mechanism

* **Installation ID:** Each app install gets a unique ID stored in DataStore
* **First Access:** On first get/put operation after install, cleanup runs
* **Orphan Detection:** Compares Keychain entries with DataStore entries
* **Automatic Removal:** Deletes any Keychain keys without matching DataStore data

### Orphaned Ciphertext Cleanup (All Platforms)

On startup, KSafe probes each encrypted DataStore entry by attempting decryption:
* **Permanent failure** (key gone, invalidated, wrong key): entry removed from DataStore
* **Temporary failure** (device locked): skipped, retried on next launch
* Runs once per startup, after migration and before the DataStore collector begins

### Known Limitations

* **iOS:** Keychain access may require device to be unlocked depending on `requireUnlockedDevice` setting (default: accessible after first unlock)
* **Android:** Some devices may not have hardware-backed keystore; `setUnlockedDeviceRequired` requires API 28+
* **JVM:** No hardware security module; relies on file system permissions
* **WASM:** No hardware security; relies on browser `localStorage` which can be cleared by the user. Security checks (root, debugger, emulator) are no-ops
* **All Platforms:** Encrypted data is lost if encryption keys are deleted (by design for security)

***
