# Migration Guide

### From v1.x to v2.0

The 2.0 release is largely a non-breaking architectural refactor (single `KSafeCore` orchestrator, thin platform shells, on-disk format preserved). The **one consumer-visible breaking change** is that biometric authentication has moved into a separate, optional module.

#### Biometrics extracted into `:ksafe-biometrics` ([#14](https://github.com/ioannisa/KSafe/issues/14))

Pre-2.0, biometric verification was a member of `KSafe`. In 2.0 it lives in its own artifact with no dependency on the storage library:

```kotlin
// Before — biometrics on KSafe
import eu.anifantakis.lib.ksafe.BiometricAuthorizationDuration

ksafe.verifyBiometricDirect(reason, BiometricAuthorizationDuration(60_000L)) { ok -> }
ksafe.verifyBiometric(reason)
ksafe.clearBiometricAuth()
```

```kotlin
// After — biometrics is a static API in :ksafe-biometrics
// build.gradle.kts:
//   implementation("eu.anifantakis:ksafe-biometrics:2.0.0-RC1")

import eu.anifantakis.lib.ksafe.biometrics.KSafeBiometrics
import eu.anifantakis.lib.ksafe.biometrics.BiometricAuthorizationDuration

KSafeBiometrics.verifyBiometricDirect(reason, BiometricAuthorizationDuration(60_000L)) { ok -> }
KSafeBiometrics.verifyBiometric(reason)
KSafeBiometrics.clearBiometricAuth()
```

Method names (`verifyBiometric`, `verifyBiometricDirect`, `clearBiometricAuth`) and signatures are preserved — only the receiver and import paths change. `BiometricHelper.confirmationRequired` and `BiometricHelper.promptTitle` continue to work the same way, just imported from `eu.anifantakis.lib.ksafe.biometrics`.

**No DI wiring needed.** `KSafeBiometrics` is a Kotlin `object` — call it directly from anywhere. There's no instance to construct, no `Context` parameter, no Koin / Hilt / manual injection. On Android the library bootstraps itself via a `ContentProvider` declared in its merged manifest (the same pattern WorkManager / Firebase / AppCompat use), so your `Application.onCreate()` doesn't need any biometric init either. iOS / JVM / web have no init at all.

If you don't use biometrics, no migration is needed — don't add the new artifact and the old `androidx.biometric` / `androidx.fragment` transitive deps stop being pulled in.

Storage API (`getDirect`, `putDirect`, `get`, `put`, `getFlow`, property delegates, Compose state) is unchanged. `import eu.anifantakis.lib.ksafe.KSafe` still resolves; `ksafe.put(...)` / `ksafe.get(...)` / `by ksafe(0)` keep working without code changes.

Full migration walkthrough and rationale: [docs/BIOMETRICS.md](BIOMETRICS.md#migration-from-ksafe-1x).

#### iOS default storage path moved from `NSDocumentDirectory` to `NSApplicationSupportDirectory`

Pre-2.0 iOS stored its DataStore file under `NSDocumentDirectory` — visible to iTunes File Sharing (if `UIFileSharingEnabled` was set) and iCloud-syncable by default. 2.0 moves the default to `NSApplicationSupportDirectory`, the Apple-recommended location for invisible app data.

**The migration is automatic.** When you don't pass an explicit `directory` and the new location is empty, KSafe checks the legacy `NSDocumentDirectory` path on first launch and moves the file. Idempotent (only runs while the new path is empty), best-effort (a failed move logs a warning and leaves the legacy file in place). Apps bumping the dep from 1.x to 2.0 need **no code changes** to keep their data — just bump the version, ship, done.

```kotlin
// 1.x and 2.0 — same call, KSafe handles the move internally.
val safe = KSafe(fileName = "vault")
```

If for some reason you want to keep reading from the old Documents location indefinitely (instead of letting KSafe migrate), you can pass `directory` explicitly — that disables the automatic migration:

```kotlin
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSUserDomainMask
import kotlinx.cinterop.ExperimentalForeignApi

@OptIn(ExperimentalForeignApi::class)
val docsPath = NSFileManager.defaultManager.URLForDirectory(
    directory = NSDocumentDirectory,
    inDomain = NSUserDomainMask,
    appropriateForURL = null,
    create = false,
    error = null,
)?.path

val safe = KSafe(fileName = "vault", directory = docsPath)
```

#### KSafe data on iOS is always excluded from iCloud Backup

KSafe data is unconditionally marked with `NSURLIsExcludedFromBackupKey` on iOS. There's no parameter and no opt-out — the DataStore file never travels through iCloud Backup.

This is not a security feature so much as a correctness one: KSafe's encryption keys live in the Keychain with `…ThisDeviceOnly` accessibility (and Secure Enclave keys never leave the device for `HARDWARE_ISOLATED` writes), so a restored device would have the ciphertext but not the keys — KSafe would fail to decrypt and return defaults. Backing up the ciphertext would manifest as silent data loss on a restored device, disguised as "your data is here" when in fact it's unrecoverable. Forcing exclusion prevents that broken state.

If you need device-portable preferences (theme, settings, onboarding flags that should follow the user to a new iPhone), use `UserDefaults`. That's the right tool for that semantics. KSafe is for device-local encrypted (or explicitly local plain) storage.

***

### From v1.6.x to v1.7.0

#### `encrypted: Boolean` → `KSafeWriteMode` (WARNING)

The `encrypted: Boolean` parameter on all API methods is deprecated at `DeprecationLevel.WARNING` — code using it still compiles but shows strikethrough warnings in the IDE with one-click `ReplaceWith` auto-fix. Migrate to `KSafeWriteMode`:

```kotlin
// Old (WARNING — still compiles but deprecated)
ksafe.put("key", value, encrypted = true)
ksafe.get("key", "", encrypted = false)

// New — writes specify mode, reads auto-detect
ksafe.put("key", value)                                  // encrypted default
ksafe.put("key", value, mode = KSafeWriteMode.Plain)     // unencrypted
val v = ksafe.get("key", "")                                 // auto-detects
```

The mapping is: `encrypted = true` → `KSafeWriteMode.Encrypted()`, `encrypted = false` → `KSafeWriteMode.Plain`.

#### Canonical storage keys and metadata

KSafe now writes:
- values under `__ksafe_value_{key}`
- metadata under `__ksafe_meta_{key}__`

Legacy keys (`encrypted_{key}`, bare `{key}`, `__ksafe_prot_{key}__`) are still readable and are cleaned when that key is next written/deleted.

#### Read APIs Auto-Detect Protection

Read methods (`get`, `getDirect`, `getFlow`, `getStateFlow`) no longer accept a `protection` parameter. They automatically detect whether stored data is encrypted from persisted metadata. You specify write behavior via **mode**:

```kotlin
// Writes — specify mode
ksafe.put("secret", token)                                              // encrypted (default)
ksafe.putDirect("theme", "dark", mode = KSafeWriteMode.Plain)          // unencrypted
var pin by ksafe(
    "",
    mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)
)    // StrongBox / SE

// Reads — auto-detect, no protection needed
val secret = ksafe.get("secret", "")
val theme = ksafe.getDirect("theme", "light")
val flow = ksafe.getFlow("secret", "")
```

This eliminates the common mistake of mismatching protection levels between put and get calls.

### From v1.1.x to v1.2.0+

#### Binary Compatibility
The public API surface (`get`, `put`, `getDirect`, `putDirect`) remains backward compatible.

#### Behavior Changes
- **Initialization is now eager by default.** If you relied on KSafe doing absolutely nothing until the first call, pass `lazyLoad = true`.
- **Nullable values now work correctly.** No code changes needed, but you can now safely store `null` values.

#### Compose Module Import Fix
If upgrading from early 1.2.0 alphas, update your imports:
```kotlin
// Old (broken in alpha versions)
import eu.eu.anifantakis.lib.ksafe.compose.mutableStateOf

// New (correct)
import eu.anifantakis.lib.ksafe.compose.mutableStateOf
```

***
