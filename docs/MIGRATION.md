# Migration Guide

### From v3.0 to v3.1

**Upgrading needs no code change. Stored data remains compatible.**

- `KSafeConfig(keySize = 128)` still compiles and still links — it is deprecated, not removed,
  and goes away in 4.0.0 with the rest of the deprecation sweep. Move to
  `KSafeConfig(aesKeySize = KSafeAesKeySize.BITS_128)` at your convenience; `BITS_256` remains
  the default. The `keySize` property and `copy(keySize = …)` are kept too.
  - One residue: `KSafeConfig`'s generated `component1()` now returns `KSafeAesKeySize` rather
    than `Int`, because a data class derives it from the primary constructor. Only destructuring
    a config is affected.
- **The one genuine break:** the Apple-only `obtainAesGcm()` is gone. It returned a
  `dev.whyoleg.cryptography` type, and that dependency was removed — so the function cannot be
  kept even as a deprecation, since its return type no longer exists. If you called it you
  already depend on that library yourself to use the result, so replace the call with
  `CryptographyProvider.CryptoKit.get(AES.GCM)` in your own code.

The AES-GCM algorithm and ciphertext framing are unchanged. Upgrading does not regenerate
existing keys or re-encrypt entries, so previously stored values remain readable. The selected
`aesKeySize` applies only when a key is first created or replaced by rotation; an existing key
keeps its original size until then. Web now honors this setting too; a Web key created by an
older release remains AES-256 until it is rotated.

`KSafeConfig.keyRotationRetryAttempts` is also new and defaults to 3; set it to 0 to disable automatic
next-instance retries for normally skipped work. KSafe 3.1 also adds automatic recovery of a
rotation interrupted by process death. New 3.1 rotations persist `"r":1` with the generation
bump and change it to `"r":0` only after the entry pass and old-key sweep complete; the next
instance can therefore resume the same generation under every policy, including `Never`.

A normally completed 3.1 pass with retryable `skipped` entries uses a separate optional
`"rp":N` budget. It remains `r:0` because the pass did return, and the current KSafe instance
does not try again. Each next instance consumes at most one attempt by durably changing
`r:0,rp:N` to `r:1,rp:N-1` before work. If its configured `MaxAge` is already due by then, the
normal fresh-generation rotation takes precedence instead. `failed` alone does not schedule
the retry.

The released 3.0 format has no `r` field, so an absent field cannot prove whether an old pass
completed or crashed. The first 3.1 startup handles this conservatively: it stamps the existing
generation record as `"r":0`, preserves its generation and timestamp, and performs no resume,
generation bump, entry rewrite, key sweep, or same-launch `MaxAge` pass. From the next launch,
the configured policy behaves normally. If 3.0 really left a mixed-generation store, every
entry remains readable under the generation in its own metadata; a later explicit
`rotateKeys()` or due `MaxAge` pass moves it normally. Unknown future `r` values are preserved
and rejected fail-closed rather than reinterpreted.

### From v2.2 to v3.0

**No code changes are needed for rotation.** 3.0 adds **key rotation** on every platform. An un-rotated store's existing entries stay byte-identical to 2.2.x — bump the dependency, ship, done — and existing data keeps working without migration. (A new or rewritten strict `HARDWARE_ISOLATED` entry keys under 3.0.0's strict alias variant, with the same downgrade consequence as rotated entries — see the caveat below.)

The on-disk model gains a store-wide **key generation** counter. A freshly upgraded store is *generation 1* and uses the exact key names and envelope (v2) that 2.2.x wrote, so upgrading (and even downgrading again, before any rotation or strict write) is free. (One exception: an `appNamespace` whose token doesn't survive sanitization intact — characters outside `[A-Za-z0-9._-]`, or more than 120 of them — is relocated under a collision-safe digested identity on the first 3.0.0 launch; a downgraded 2.2.x binary then sees the retained pre-upgrade copy, and interim writes are not carried back on re-upgrade. Use a clean, short token to keep downgrade free.)

Rotation is **opt-in**. Nothing rotates until you ask:

```kotlin
// Manual — re-encrypt every entry under a fresh key generation, sweep the old keys.
val result = ksafe.rotateKeys()   // KSafeRotationResult(rotated, skipped, failed, keyGeneration)

// Or declarative — a once-per-startup background check, never blocking startup or reads.
val ksafe = KSafe(
    config = KSafeConfig(keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(90.days))
)
```

The default policy is `KSafeKeyRotationPolicy.Never` — key material is hardware/OS-protected and doesn't expire, so starting new generations automatically is an opt-in hygiene/compliance control. Rotation is crash-safe: an interrupted pass leaves a readable mixed-generation store and a later `rotateKeys()` rotates the remainder (3.1.0 adds automatic same-generation recovery for passes it starts). In 3.1.0, a normally completed pass with `skipped` work also writes `rp:N`, a bounded automatic retry budget configured by `KSafeConfig.keyRotationRetryAttempts` (3 by default, 0 disables it). Each next KSafe instance consumes at most one attempt even under `Never`; an already-due `MaxAge` pass may move the work straight into a fresh generation instead. Concurrent writes always win, and values are sacred — `getOrCreateSecret` secrets keep their value; only the wrapping key changes. Strict (`requireUnlockedDevice`) entries rotate only while the device is unlocked, and a transient key-store outage counts as `skipped`, never `failed`. There is no per-key rotate — `rotateKeys()` is whole-store.

**One migration caveat, and it only applies after you rotate.** The first `rotateKeys()` upgrades the store to *generation ≥ 2*, which switches encrypted entries to an authenticated **v3 envelope** (AES-GCM whose associated data binds each ciphertext to store identity, user key, protection tier, unlock policy, and key generation). Once rotated, **downgrading to a pre-3.0.0 binary must be treated as destructive for the rotated entries** (the same applies to strict `HARDWARE_ISOLATED` entries written by 3.0.0): the older binary can't resolve their keys, and its startup orphan sweep permanently deletes the rows and metadata it can't decrypt — typically on the first launch. Upgrading back restores access only if that sweep never ran. So finish rolling out 3.0 before you call `rotateKeys()` in production, and back up before any planned downgrade.

Full walkthrough, per-platform behavior, and the cryptographic-erasure notes: [docs/KEY_ROTATION.md](KEY_ROTATION.md).

### From v2.0 to v2.1

**No breaking changes, no code changes.** 2.1 changes *where the AES key lives* on two targets; the on-disk value format, the public API, and the AES-256-GCM scheme are unchanged, so previously written data still decrypts.

- **JVM/Desktop:** the key moves from Base64-in-the-DataStore-file to the host **OS secret store** — Windows DPAPI, macOS Keychain, or Linux Secret Service (libsecret). On the first read of each key after upgrading, KSafe copies the legacy key into the OS store and removes it from the file — **only after reading it back and byte-verifying** the OS store persisted it. If no OS store is reachable (e.g. headless Linux with no keyring) it transparently keeps using the legacy file scheme and logs a one-time warning. Opt out entirely with `-Dksafe.jvm.keyVault=software` (or env `KSAFE_JVM_KEY_VAULT=software`).
- **Web (Kotlin/JS + Kotlin/WASM):** the key moves from a raw Base64 value in `localStorage` to a **non-extractable `CryptoKey` in IndexedDB**. A legacy `localStorage` key is imported as non-extractable and the `localStorage` entry deleted on first access.

On both targets the migration is **hybrid**: it happens lazily the first time each key is read/written, **and** a one-time best-effort background sweep (off the construction/UI path, a no-op under the JVM software fallback) relocates any remaining legacy keys so a key that is never read again doesn't keep its plaintext sitting in the weak location.

The migration is **automatic and idempotent** — bump the dependency, ship, done. One inherent caveat to be aware of: once a JVM key is migrated into an OS secret store it is bound to that OS user/login; if that store is later lost (different OS account, keychain/keyring reset, machine move without it) the data becomes unrecoverable — this is the trade-off of OS-bound key storage and only matters for portability scenarios. JVM consumers also gain a new transitive dependency on JNA (`net.java.dev.jna` + `jna-platform`), JVM-target-only.

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
//   implementation("eu.anifantakis:ksafe-biometrics:3.0.0")

import eu.anifantakis.lib.ksafe.biometrics.KSafeBiometrics
import eu.anifantakis.lib.ksafe.biometrics.BiometricAuthorizationDuration

KSafeBiometrics.verifyBiometricDirect(reason, BiometricAuthorizationDuration(60_000L)) { ok -> }
KSafeBiometrics.verifyBiometric(reason)
KSafeBiometrics.clearBiometricAuth()
```

Method names (`verifyBiometric`, `verifyBiometricDirect`, `clearBiometricAuth`) and signatures are preserved — only the receiver and import paths change. `BiometricHelper.confirmationRequired` continues to work the same way, just imported from `eu.anifantakis.lib.ksafe.biometrics`. (`BiometricHelper.promptTitle`/`promptSubtitle` were removed in 3.0.0 — use `KSafeBiometrics.defaultTitle`, which also names the web passkey, and `KSafeBiometrics.defaultReason`.)

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

#### KSafe data on iOS is effectively device-local

KSafe's encryption keys live in the Keychain with `…ThisDeviceOnly` accessibility (and Secure Enclave keys never leave the device for `HARDWARE_ISOLATED` writes). Even if the DataStore file is included in an iCloud Backup, its encrypted bytes are undecryptable on a restored device — the keys are not there. So backed-up ciphertext is benign in practice: it's just dead bytes, not exfiltrable secrets.

The library does **not** set `NSURLIsExcludedFromBackupKey` on the DataStore file. We tried, and it doesn't work reliably: DataStore's atomic-write strategy (write-to-temp then rename) creates a new inode on every flush and clobbers the extended attribute. Reliable file-level exclusion would require architectural gymnastics (a per-instance subdirectory whose directory-level xattr the inner file inherits), and the security guarantee already comes from key locality.

If you need device-portable preferences (theme, settings, onboarding flags that should follow the user to a new iPhone), use `UserDefaults`. That's the right tool for that semantics. KSafe is for encrypted (or explicitly local plain) storage where the keys do not roam.

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

**Performance cost of auto-detection.** Auto-detect is a single `ConcurrentHashMap` lookup on the read path — sub-microsecond on the hot path, well within run-to-run benchmark variance. Stores that contain only plaintext values short-circuit even that lookup via an internal flag, so plain-only consumers pay zero overhead. In exchange, you can no longer accidentally read an encrypted value as plaintext (or vice versa) — a real bug source in 1.x.

This eliminates the common mistake of mismatching protection levels between put and get calls.

### From v1.1.x to v1.2.0+

#### Binary Compatibility
The public API surface (`get`, `put`, `getDirect`, `putDirect`) remains backward compatible.

#### Behavior Changes
- **Initialization is now eager by default.** Pass `lazyLoad = true` to defer the background snapshot preload (and its startup orphan sweep) until the first call. Note the write consumer and master-key prewarm still start eagerly, so `lazyLoad` defers the on-disk preload, not literally all startup work.
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
