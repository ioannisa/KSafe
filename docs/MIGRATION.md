# Migration Guide

Sections run newest first: find the version you are on, then read upward. Each one says whether
stored data survives the upgrade, and lists the code changes — if any — that the upgrade forces.

Two words appear throughout, both introduced in 3.0.0:

- **Key rotation** — re-encrypting every stored entry under a freshly created key, then deleting
  the old one. It is opt-in; see [docs/KEY_ROTATION.md](KEY_ROTATION.md).
- **Key generation** — a counter on the store, raised by one on each rotation. A store that has
  never rotated is generation 1.

## From v3.1 to v3.2

**Upgrading needs no code change. Stored data remains compatible.** Nothing was removed or
renamed from the public API, so a project that compiles against 3.1 compiles against 3.2.

Four things are worth knowing.

**`ksafe(default, key)` now returns a handle you can keep.** The call that backs the `by` delegate
returns `KSafeReference` instead of a bare `ReadWriteProperty`. `KSafeReference` is still a
`ReadWriteProperty`, so every existing `by ksafe(…)` keeps compiling — but you can now also hold
it in a plain `val` and read or write through `.value`:

```kotlin
// Still works exactly as before — the property name becomes the storage key.
var counter by ksafe(0)
counter++

// New — a handle in a val. `.value` reads the cache; a write returns immediately
// and is persisted in the background.
val visits = ksafe(0, key = "visits")
visits.value++
```

Direct `.value` access needs the explicit `key`. A plain assignment carries no property name for
Kotlin to hand over, so a handle created without a `key` stays delegate-only and `.value` on it
throws `IllegalStateException`. Reading `.value` inside a composable does not trigger
recomposition — use `rememberKSafeState` from `:ksafe-compose`, or
`getStateFlow(key, default, scope).collectAsState()`, for state the UI observes.

**`kotlinx-coroutines-core` and `compose-runtime` now come along with the modules that expose
them.** Gradle passes a library's own dependency on to your module only when the library declares
it `api`; declared `implementation`, it stays private to the library. Both were `implementation`,
yet `Flow`, `StateFlow` and `CoroutineScope` appear in `:ksafe`'s public signatures, and
`:ksafe-compose`'s `KSafeComposeState` publicly implements Compose's `MutableState` — so a module
calling `getFlow` or `asStateFlow`, or naming that state type, could not compile against the
documented API without declaring those libraries itself. `:ksafe` now exposes
`kotlinx-coroutines-core` as `api`, and `:ksafe-compose` exposes `compose-runtime` the same way.
Projects that already declare them are unaffected.

**Android 28-34: a `requireUnlockedDevice` write on a device with no lock screen now succeeds.**
`requireUnlockedDevice` asks the platform to keep an entry's key usable only while the device is
unlocked. The Android Keystore — the OS service that holds the key and does the crypto — cannot
tie a key to an unlock that does not exist, so on a device with no PIN, pattern or password such a
write used to fail inside key generation. KSafe now creates the key without that binding and
reports the downgrade as `android_lock_screen_absent` in `protectionInfo.notes` (the per-instance
report of what protection you actually got). Keystore parameters are fixed when a key is created,
so the note keeps being reported even after the user sets a lock screen; call `rotateKeys()` once
— or configure a rotation policy — to create a new key generation with the binding in place.
API 35+ is unaffected.

**On the web, `lazyLoad` is now accepted and ignored.** Reading the browser's storage is
synchronous, so there is nothing to defer — and suppressing the preload used to make every
non-suspending read return its default for the whole session. If you passed `lazyLoad = true` on
a web target, you can drop it; the flag stays in the signature for parity with the other targets.

## From v3.0 to v3.1

**Upgrading needs no code change for storage. Stored data remains compatible.** One Apple-only
function was removed; everything else is a deprecation you can migrate at your own pace.

**The one break: the Apple-only `obtainAesGcm()` is gone.** It returned a type from the
`dev.whyoleg.cryptography` library, and that dependency was removed — so the function could not be
kept even as a deprecation, because its return type no longer exists. If you called it, you
already depend on that library yourself in order to use the result, so replace the call with
`CryptographyProvider.CryptoKit.get(AES.GCM)` in your own code.

**`KSafeConfig(keySize = 128)` still compiles.** It is deprecated, not removed, and goes away in
4.0.0 with the rest of the deprecation sweep. Move to
`KSafeConfig(aesKeySize = KSafeAesKeySize.BITS_128)` when convenient; `BITS_256` remains the
default. The `keySize` property and `copy(keySize = …)` are kept too.

One side effect: `KSafeConfig` is a data class, so Kotlin derives its `component1()` from the
primary constructor — which now starts with `aesKeySize`. Only destructuring is affected:

```kotlin
val (size, requireUnlocked) = config   // `size` is now KSafeAesKeySize, not Int
val bits = size.bits                   // 128 or 256, as before
```

The AES-GCM algorithm and the layout of stored bytes are unchanged. Upgrading does not recreate
existing keys or re-encrypt entries, so previously stored values stay readable. `aesKeySize`
applies only when a key is first created, or replaced by rotation; an existing key keeps its
original size until then. The web target now honours the setting too — a web key created by an
older release stays AES-256 until it is rotated.

**Rotation gets two automatic recoveries.** Neither needs a code change:

- A rotation that was interrupted by process death is finished by the next `KSafe` instance, at
  the same key generation, under every policy — including the default `Never`.
- A rotation that finished but could not reach some entries (typically a `requireUnlockedDevice`
  entry while the device was locked) is retried by later instances, one attempt each. The new
  `KSafeConfig.keyRotationRetryAttempts` sets the budget: 3 by default, `0` to switch the retries
  off. Entries reported as `failed` rather than `skipped` are never retried automatically. If the
  app has configured `KSafeKeyRotationPolicy.MaxAge` — the age-based automatic rotation added in
  3.0, covered in the next section — and the current generation is already due when that instance
  starts, a normal fresh-generation rotation runs instead and absorbs the pending work.

A store written by 3.0 is adopted conservatively: the first 3.1 launch records that its rotation
state is complete and does nothing else — no resume, no new generation, no re-encryption, no key
deletion. Normal policy resumes from the next launch. If 3.0 really did leave a half-rotated store
behind, every entry is still readable under the key recorded in its own metadata, and a later
`rotateKeys()` or due `MaxAge` pass moves the rest. The on-disk fields behind all of this are
described in [docs/KEY_ROTATION.md](KEY_ROTATION.md#semantics-and-guarantees).

## From v2.2 to v3.0

**No code changes are needed for rotation.** 3.0 adds **key rotation** on every platform. An
un-rotated store's existing entries stay byte-identical to 2.2.x — bump the dependency, ship, done
— and existing data keeps working without migration. The only forced source edits are three small
removals, listed at the end of this section.

One thing does change even without rotating. An entry written with `requireUnlockedDevice = true`
is a **strict** entry: its key is usable only while the device is unlocked. When such a write also
asks for `HARDWARE_ISOLATED` — that is,
`KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED, requireUnlockedDevice = true)`
— 3.0.0 stores it under a key name only 3.0.0 and later know, because a key's unlock binding is
fixed when the key is minted and so a tightened entry needs a fresh key rather than a reused one.
That carries the same downgrade consequence as a rotated entry; see the caveat below.

The on-disk model gains a store-wide **key generation** counter. A freshly upgraded store is
*generation 1* and uses the exact key names and stored bytes that 2.2.x wrote, so upgrading (and
even downgrading again, before any rotation or strict `HARDWARE_ISOLATED` write) is free.

One exception to that free upgrade, and only if you set `KSafeConfig.appNamespace`. That is an id
that keeps two apps sharing one machine or one browser origin from reading each other's data, so
it has an effect on JVM Desktop and the web only — Android and iOS already give each app its own
sandbox. KSafe reduces the id to the characters `A-Z a-z 0-9 . _ -`, and 120 of them at most. If
your value survives that untouched, nothing happens. If it does not, the store is moved on the
first 3.0.0 launch to a location derived from a hash of the original, so two ids that reduce to
the same text stay apart. A downgraded 2.2.x binary then sees the copy left behind at the old
location, and writes made in between are not carried back if you upgrade again. Keep the id short
and inside that character set and downgrade stays free.

Rotation is **opt-in**. Nothing rotates until you ask:

```kotlin
import kotlin.time.Duration.Companion.days

// Manual — re-encrypt every entry under a fresh key generation, sweep the old keys.
val result = ksafe.rotateKeys()   // KSafeRotationResult(rotated, skipped, failed, keyGeneration)

// Or declarative — a once-per-startup background check, never blocking startup or reads.
val ksafe = KSafe(
    // Android takes the context first: KSafe(context, config = KSafeConfig(...))
    config = KSafeConfig(keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(90.days))
)
```

The default policy is `KSafeKeyRotationPolicy.Never`: key material is protected by the hardware or
the OS and does not expire, so starting new generations automatically is a hygiene or compliance
choice, not a security fix. What a rotation guarantees:

- **Values are never touched.** Rotation changes key material and how each value is wrapped, never
  your data. A `getOrCreateSecret` secret keeps its value; only the key wrapping it changes.
- **Concurrent writes win.** An entry is re-encrypted only if the bytes on disk are still the ones
  the pass read. If your write lands first, that entry is left for a later pass instead of being
  overwritten; if the rotation lands first, your write goes on top of it as usual. A rotation can
  never bring an older value back.
- **An interruption is safe.** A pass cut short leaves a store where some entries sit on the old
  key and some on the new — and every one of them still reads. A later `rotateKeys()` finishes the
  rest; from 3.1.0 the next instance finishes it on its own.
- **Locked entries wait.** A strict (`requireUnlockedDevice`) entry rotates only while the device
  is unlocked. A locked entry, or a temporary key-store outage, counts as `skipped` — never
  `failed` — and is picked up by a later pass. From 3.1.0 that retry is automatic and bounded by
  `KSafeConfig.keyRotationRetryAttempts` (3 by default, `0` disables it); it runs even under
  `Never`, and an already-due `MaxAge` pass takes precedence over it.

There is no per-key rotate: `rotateKeys()` covers the whole store.

**One migration caveat, and it only applies after you rotate.** The first `rotateKeys()` upgrades
the store to *generation ≥ 2*, which switches encrypted entries to an authenticated **v3
envelope** — the packaging KSafe writes around a value. It is AES-GCM with *associated data*:
extra bytes the cipher checks but does not encrypt, here the store's identity, your key's name,
the protection tier, the unlock policy and the key generation. Change any of them and the decrypt
fails instead of returning wrong plaintext, so a ciphertext copied onto another entry no longer
opens. Once rotated, **downgrading to a pre-3.0.0 binary must be treated as destructive
for the rotated entries** — and the same applies to the strict `HARDWARE_ISOLATED` entries
described above. The older binary can't resolve their keys, and its startup orphan sweep
permanently deletes the rows and metadata it can't decrypt — typically on the first launch.
Upgrading back restores access only if that sweep never ran. So finish rolling out 3.0 before you
call `rotateKeys()` in production, and back up before any planned downgrade.

**Three small removals.** Each is a one-line fix, and each only bites if you used the symbol:

| Removed in 3.0.0 | Replacement |
| --- | --- |
| `BiometricHelper.promptTitle` / `promptSubtitle` (Android-only globals) | `KSafeBiometrics.defaultTitle` / `KSafeBiometrics.defaultReason` — common code, and they also name the web passkey |
| `KSafeConfig.androidAuthValiditySeconds` | Delete the argument; it never had any effect on any platform |
| `encodeBase64(ByteArray)` on JVM Desktop, no longer public | `Base64.encode` from `kotlin.io.encoding` in the standard library |

On Android, `secureRandomBytes` also moved to the `KSafeSecureRandom_jvmKt` facade class. The
import and the call are unchanged, so a rebuild is all it takes — but a pre-built Android binary
that called it will not resolve the old class.

Full walkthrough, per-platform behavior, and the cryptographic-erasure notes:
[docs/KEY_ROTATION.md](KEY_ROTATION.md).

## From v2.0 to v2.1

**No breaking changes, no code changes.** 2.1 changes *where the AES key lives* on two targets; the on-disk value format, the public API, and the AES-256-GCM scheme are unchanged, so previously written data still decrypts.

- **JVM/Desktop:** the key moves from Base64-in-the-DataStore-file to the host **OS secret store** — Windows DPAPI, macOS Keychain, or Linux Secret Service (libsecret). On the first read of each key after upgrading, KSafe copies the legacy key into the OS store and removes it from the file — **only after reading it back and byte-verifying** the OS store persisted it. If no OS store is reachable (e.g. headless Linux with no keyring) it transparently keeps using the legacy file scheme and logs a one-time warning. Opt out entirely with `-Dksafe.jvm.keyVault=software` (or env `KSAFE_JVM_KEY_VAULT=software`).
- **Web (Kotlin/JS + Kotlin/WASM):** the key moves from a raw Base64 value in `localStorage` to a **non-extractable key in IndexedDB** — one the browser will use for encryption and decryption but will not hand back to JavaScript, so page code can never read the key itself. A legacy `localStorage` key is imported in that form and the `localStorage` entry deleted on first access.

On both targets the migration is **hybrid**: it happens lazily the first time each key is read/written, **and** a one-time best-effort background sweep (off the construction/UI path, a no-op under the JVM software fallback) relocates any remaining legacy keys so a key that is never read again doesn't keep its plaintext sitting in the weak location.

The migration is **automatic and idempotent** — bump the dependency, ship, done. One inherent caveat to be aware of: once a JVM key is migrated into an OS secret store it is bound to that OS user/login; if that store is later lost (different OS account, keychain/keyring reset, machine move without it) the data becomes unrecoverable — this is the trade-off of OS-bound key storage and only matters for portability scenarios. JVM consumers also gain a new transitive dependency on JNA (`net.java.dev.jna` + `jna-platform`), JVM-target-only.

## From v1.x to v2.0

The 2.0 release is largely an internal refactor: the storage format on disk is unchanged, and so
is nearly all of the public API. The **one consumer-visible breaking change** is that biometric
authentication moved into a separate, optional module.

### Biometrics extracted into `:ksafe-biometrics` ([#14](https://github.com/ioannisa/KSafe/issues/14))

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
//   implementation("eu.anifantakis:ksafe-biometrics:3.1.0")

import eu.anifantakis.lib.ksafe.biometrics.KSafeBiometrics
import eu.anifantakis.lib.ksafe.biometrics.BiometricAuthorizationDuration

KSafeBiometrics.verifyBiometricDirect(reason, BiometricAuthorizationDuration(60_000L)) { ok -> }
KSafeBiometrics.verifyBiometric(reason)
KSafeBiometrics.clearBiometricAuth()
```

Method names (`verifyBiometric`, `verifyBiometricDirect`, `clearBiometricAuth`) and signatures are
preserved — only the receiver and import paths change. `BiometricHelper` is Android-only and stays
that way; `BiometricHelper.confirmationRequired` works as before, now imported from
`eu.anifantakis.lib.ksafe.biometrics`. (`BiometricHelper.promptTitle`/`promptSubtitle` were removed
in 3.0.0 — use `KSafeBiometrics.defaultTitle`, which also names the web passkey, and
`KSafeBiometrics.defaultReason`.)

**No DI wiring needed.** `KSafeBiometrics` is a Kotlin `object` — call it directly from anywhere. There's no instance to construct, no `Context` parameter, no Koin / Hilt / manual injection. On Android the library bootstraps itself via a `ContentProvider` declared in its merged manifest (the same pattern WorkManager / Firebase / AppCompat use), so your `Application.onCreate()` doesn't need any biometric init either. iOS / JVM / web have no init at all.

If you don't use biometrics, no migration is needed — don't add the new artifact and the old `androidx.biometric` / `androidx.fragment` transitive deps stop being pulled in.

Storage API (`getDirect`, `putDirect`, `get`, `put`, `getFlow`, property delegates, Compose state) is unchanged. `import eu.anifantakis.lib.ksafe.KSafe` still resolves; `ksafe.put(...)` / `ksafe.get(...)` / `by ksafe(0)` keep working without code changes.

Full migration walkthrough and rationale: [docs/BIOMETRICS.md](BIOMETRICS.md#migration-from-ksafe-1x).

### iOS default storage path moved from `NSDocumentDirectory` to `NSApplicationSupportDirectory`

Pre-2.0 iOS stored its DataStore file under `NSDocumentDirectory` — visible to iTunes File Sharing (if `UIFileSharingEnabled` was set) and iCloud-syncable by default. 2.0 moves the default to `NSApplicationSupportDirectory`, the Apple-recommended location for invisible app data.

**The migration is automatic.** When you don't pass an explicit `directory` and no store file
exists yet at the new location, KSafe looks for one at the legacy `NSDocumentDirectory` path on
first launch and moves it. Idempotent (it only runs while the new path holds no store file),
best-effort (a failed move logs a warning and leaves the legacy file in place). Apps bumping the
dep from 1.x to 2.0 need **no code changes** to keep their data — just bump the version, ship,
done.

```kotlin
// 1.x and 2.0 — same call, KSafe handles the move internally.
val safe = KSafe(fileName = "vault")
```

If for some reason you want to keep reading from the old Documents location indefinitely (instead
of letting KSafe migrate), pass `directory` explicitly. That turns off the automatic move — and
also the Keychain orphan sweep, which only runs for the default location:

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

### KSafe data on iOS is effectively device-local

KSafe's encryption keys live in the Keychain with `…ThisDeviceOnly` accessibility (and Secure Enclave keys never leave the device for `HARDWARE_ISOLATED` writes). Even if the DataStore file is included in an iCloud Backup, its encrypted bytes are undecryptable on a restored device — the keys are not there. So backed-up ciphertext is benign in practice: it's just dead bytes, not exfiltrable secrets.

The library does **not** set `NSURLIsExcludedFromBackupKey` on the DataStore file. We tried, and it doesn't work reliably: DataStore's atomic-write strategy (write-to-temp then rename) creates a new inode on every flush and clobbers the extended attribute. Reliable file-level exclusion would require architectural gymnastics (a per-instance subdirectory whose directory-level xattr the inner file inherits), and the security guarantee already comes from key locality.

If you need device-portable preferences (theme, settings, onboarding flags that should follow the user to a new iPhone), use `UserDefaults`. That's the right tool for that semantics. KSafe is for encrypted (or explicitly local plain) storage where the keys do not roam.

***

## From v1.6.x to v1.7.0

### `encrypted: Boolean` → `KSafeWriteMode` (WARNING)

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

The mapping is: `encrypted = true` → `KSafeWriteMode.Encrypted()`, `encrypted = false` →
`KSafeWriteMode.Plain`. These overloads keep working through all of 3.x and are removed in 4.0.0.

### Canonical storage keys and metadata

KSafe now writes:
- values under `__ksafe_value_{key}`
- metadata under `__ksafe_meta_{key}__`

Legacy keys (`encrypted_{key}`, bare `{key}`, `__ksafe_prot_{key}__`) are still readable and are cleaned when that key is next written/deleted.

### Read APIs Auto-Detect Protection

Read methods (`get`, `getDirect`, `getFlow`, `getStateFlow`) work out on their own whether a
stored value is encrypted, from metadata KSafe writes next to it. You no longer say how to read;
you say how to **write**, with a mode:

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

The old `protection` parameter on `getStateFlow` still compiles, deprecated at
`DeprecationLevel.WARNING`, and its value is ignored — drop it. `get`, `getDirect` and `getFlow`
never had one; their deprecated third argument is the `encrypted: Boolean` flag covered above.

**Performance cost of auto-detection.** Detection is one lookup in an in-memory map on the read
path, small enough to disappear into run-to-run benchmark noise. A store that has never held an
encrypted value skips even that lookup, through an internal flag, so plain-only consumers pay
nothing. In exchange, you can no longer read an encrypted value as plaintext, or the reverse — a
real source of bugs in 1.x.

This eliminates the common mistake of mismatching protection levels between put and get calls.

## From v1.1.x to v1.2.0+

### Binary Compatibility
The public API surface (`get`, `put`, `getDirect`, `putDirect`) remains backward compatible.

### Behavior Changes
- **Initialization is now eager by default.** Pass `lazyLoad = true` to defer the background
  snapshot preload (and its startup orphan sweep) until the first call. The background worker that
  commits writes, and the one-time warm-up of the encryption key, still start eagerly — so
  `lazyLoad` defers the read of the stored file, not literally all startup work. On the web the
  flag is accepted and ignored: reading the browser's storage is synchronous, so there is nothing
  to defer.
- **Nullable values now work correctly.** No code changes needed, but you can now safely store `null` values.

### Compose Module Import Fix
If upgrading from early 1.2.0 alphas, update your imports:
```kotlin
// Old (broken in alpha versions)
import eu.eu.anifantakis.lib.ksafe.compose.mutableStateOf

// New (correct)
import eu.anifantakis.lib.ksafe.compose.mutableStateOf
```

***
