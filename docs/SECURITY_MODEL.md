# Security Model

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

| Check | Android | iOS | JVM | Web (wasmJs+js) | Description |
|-------|---------|-----|-----|-----------------|-------------|
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

> **Surfacing violations in your UI.** Because KSafe initializes before your
> ViewModels, bridge violations through a holder and (in Compose) wrap them in
> the `@Immutable` `UiSecurityViolation` from `ksafe-compose` so lists stay
> skippable. The full holder + `UiSecurityViolation` recipe lives in
> [USAGE.md](USAGE.md).

### Root Detection Methods (Android)

- `su` binary paths (`/system/bin/su`, `/system/xbin/su`, etc.)
- Magisk paths (`/sbin/.magisk`, `/data/adb/magisk`, etc.)
- BusyBox installation paths
- Xposed Framework files and stack trace detection
- Root management apps (Magisk Manager, SuperSU, KingRoot, etc.)
- Build tags (`test-keys`) and dangerous system properties

### Jailbreak Detection Methods (iOS)

- Cydia, Sileo, and other jailbreak app paths
- Rootless-era jailbreak paths (`/var/jb` — palera1n, Dopamine / Procursus)
- System write access test (fails on non-jailbroken devices)
- Common jailbreak tool paths (`/bin/bash`, `/usr/sbin/sshd`, etc.)

> **Limitation:** All root, jailbreak, and debugger checks are best-effort, fail-open heuristics — sophisticated hiding tools (Magisk DenyList, Shamiko, Zygisk) can bypass most client-side detection methods. On Android 11+ the root-management-app probe depends on package visibility; the library ships the required `<queries>` declarations in its manifest (merged into the consuming app), and other signals (build type, system properties, filesystem paths) do not need them. For high-assurance integrity decisions, pair these heuristics with server-verified attestation: Play Integrity on Android, App Attest / DeviceCheck on Apple platforms.

***

## How Encryption Works

KSafe provides enterprise-grade encrypted persistence using DataStore Preferences with platform-specific secure key storage.

> **Want to see it with your own eyes?** [docs/ENCRYPTION_PROOF.md](ENCRYPTION_PROOF.md) walks through the per-platform automated proof tests (`*EncryptionProofTest`) and gives manual commands to dump the raw `.preferences_pb` / `localStorage` bytes so you can verify the ciphertext-not-plaintext property yourself.

### Platform Details

| Platform | Cipher | Key Storage | Security |
|----------|--------|-------------|----------|
| **Android** | AES-256-GCM | Android Keystore — TEE by default, StrongBox opt-in | Keys non-exportable, app-bound, auto-deleted on uninstall |
| **iOS** | AES-256-GCM via CryptoKit | iOS Keychain Services — Secure Enclave opt-in | Protected by device passcode/biometrics, not in backups |
| **JVM/Desktop** | AES-256-GCM via javax.crypto | OS secret store — Windows DPAPI / macOS Keychain / Linux Secret Service (libsecret); software fallback in `~/.eu_anifantakis_ksafe/` | Key bound to the OS user login. The store is **per-OS-user, shared across all of that user's apps** (not per-app like Android/iOS) — set `KSafeConfig.appNamespace` to isolate one app's keys from another's. Legacy ≤2.0 keys migrate on first read and remain authoritative (a stale store entry can't shadow them). Fallback (no keyring) relies on OS file permissions (0700 POSIX) + a one-time warning |
| **Kotlin/WASM (Browser)** | AES-256-GCM via WebCrypto | Non-extractable `CryptoKey` in **IndexedDB**; values in `localStorage` | Raw key bytes never exposed to JS. Scoped per origin, ~5-10 MB limit. Requires WasmGC (Chrome 119+ / Firefox 120+ / Safari 18+) |
| **Kotlin/JS (Browser)** | AES-256-GCM via WebCrypto | Non-extractable `CryptoKey` in **IndexedDB**; values in `localStorage` | Raw key bytes never exposed to JS. Scoped per origin. Same origin/IndexedDB as wasmJs — data readable by either target; legacy ≤2.0 localStorage keys migrate on first access |

> **Cipher note:** the AES key size defaults to 256-bit and is configurable to 128-bit via `KSafeConfig.keySize` on Android/Apple/JVM; the Web target is fixed at AES-256-GCM.

### Encryption Flow

1. **Serialize value → plaintext bytes** using kotlinx.serialization
2. **Load (or generate) a random AES key** (256-bit by default, 128-bit if configured via `KSafeConfig.keySize` on Android/Apple/JVM; Web is always 256-bit) from the platform key store — Android Keystore / Apple Keychain / JVM OS secret store (DPAPI·Keychain·libsecret) / non-extractable WebCrypto `CryptoKey` in IndexedDB (a shared per-store master key since 2.0; the WebCrypto `CryptoKey` stays non-extractable)
3. **Encrypt with AES-GCM** (nonce + auth-tag included)
4. **Persist value** in DataStore/localStorage under `__ksafe_value_<key>`
   (encrypted writes store Base64 ciphertext, plaintext writes keep native type where supported)
5. **Persist metadata** under `__ksafe_meta_<key>__` as compact JSON
   (for example: `{"v":2,"p":"DEFAULT"}` or `{"v":2,"p":"DEFAULT","u":"unlocked"}` — `v:2` since 2.0 and for an un-rotated 3.0.0 store; entries from pre-2.0 builds still read `v:1`. After the first [`rotateKeys()`](KEY_ROTATION.md) the entry re-encrypts to `v:3` and gains a generation marker `"g":<n>`)
6. **Key material managed by the platform key store** — no raw key is ever written to DataStore; on Android's relaxed `DEFAULT` tier a KEK-wrapped DEK (useless without the non-exportable Keystore KEK) is persisted alongside the values

**What is GCM?** GCM (Galois/Counter Mode) is an authenticated encryption mode that provides both confidentiality and integrity. The authentication tag detects any tampering—if someone modifies even a single bit of the ciphertext, decryption will fail.

**Envelope versions (v1/v2/v3).** `v1` is the pre-2.x legacy shape (per-entry alias, bare-literal metadata). `v2` is the 2.0–2.2.x format and the shape an un-rotated 3.0.0 generation-1 store still writes byte-for-byte, so upgrading to 3.0.0 is a drop-in. The first [`rotateKeys()`](KEY_ROTATION.md) bumps the store to generation ≥ 2, and from then on entries are written as the **authenticated `v3` envelope**: the same routing as v2 plus AES-GCM *associated data* (AAD) that binds each ciphertext to the store identity, user key, protection tier, unlock policy, and key generation. Once rotated, an encrypted entry can no longer be copied, swapped, or relocated between keys — such tampering breaks the GCM tag, so the read fails closed to the caller's default rather than decrypting in the wrong context. (Rewriting an entry's metadata to plaintext, `p:"NONE"`, instead reclassifies it as plaintext: the read then returns the stored bytes verbatim — undecipherable ciphertext, never the underlying secret.) See [KEY_ROTATION.md](KEY_ROTATION.md) and [ARCHITECTURE.md](ARCHITECTURE.md) for the envelope/AAD detail.

### Security Boundaries & Threat Model

**What KSafe protects against:**
- ✅ Casual file inspection (data at rest is encrypted)
- ✅ Data extraction from unrooted device backups
- ✅ App data access by other apps (Android/iOS: OS sandboxing + encryption). **JVM/Desktop caveat:** the OS secret store is per-OS-user and shared across that user's processes — set a unique `KSafeConfig.appNamespace` so a different desktop app run by the same user can't collide with or overwrite this app's keys (Web is isolated per origin by the browser).
- ✅ Reinstall data leakage (automatic cleanup)
- ✅ Tampering detection (GCM authentication tag). **Once a store has been rotated (`v3` envelope):** the tag also authenticates the routing metadata, so an entry can't be relocated, swapped, or re-tiered between keys — such tampering breaks the GCM tag and fails closed to the default rather than decrypting (rewriting the metadata to plaintext instead reclassifies the entry, returning the stored bytes verbatim as undecipherable ciphertext, never the underlying secret)
- ✅ Key ageing / compromise window (opt-in [key rotation](KEY_ROTATION.md) re-encrypts every entry under a fresh key generation)
- ✅ Rooted/jailbroken devices (detection with configurable WARN/BLOCK)
- ✅ Debugger attachment (detection with configurable WARN/BLOCK)
- ✅ Emulator/simulator usage (detection with configurable WARN/BLOCK)

**What KSafe does NOT protect against:**
- ❌ Sophisticated root-hiding tools (e.g., Magisk Hide) — detection can be bypassed
- ❌ Memory dump attacks while app is running (mitigated by `ENCRYPTED` or `ENCRYPTED_WITH_TIMED_CACHE` memory policy — the default `LAZY_PLAIN_TEXT` and the eager `PLAIN_TEXT` both leave plaintext in RAM after first read)
- ❌ Device owner with physical access and device unlock credentials
- ❌ Compromised OS or hardware

**Recommendations:**
- Use `KSafeSecurityPolicy.Strict` for high-security apps (Banking, Medical, Enterprise)
- Use `KSafeMemoryPolicy.ENCRYPTED` for highly sensitive data (tokens, passwords) — the default `LAZY_PLAIN_TEXT` keeps plaintext in RAM permanently for any key that's been read at least once
- Use `KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE` for encrypted data accessed frequently during UI rendering (Compose recomposition, SwiftUI re-render) where you want plaintext evicted after a window
- Gate critical operations behind a biometric prompt. `ksafe-biometrics` is a standalone, process-wide gate with **real OS prompts on every target** — Android (BiometricPrompt), iOS/macOS (LocalAuthentication), JVM Desktop (macOS Touch ID / Windows Hello), and web (WebAuthn platform authenticators). See [BIOMETRICS.md](BIOMETRICS.md)
- For long-lived secrets, enable [key rotation](KEY_ROTATION.md) so a key that ages or is suspected compromised is retired without data loss
- Never store master secrets client-side; prefer server-derived tokens
- Consider certificate pinning for API communications

### Key Rotation & Key Lifetime

By default KSafe never rotates keys (`KSafeKeyRotationPolicy.Never`) — the safest default, since rotation only pays off against a *specific* threat (a key that has aged out of a compliance window, or that you suspect is compromised) and every store stays byte-compatible with pre-3.0.0 until you opt in. When you want it:

```kotlin
// Manual, whole-store rotation
val result: KSafeRotationResult = ksafe.rotateKeys()
//   result.rotated / .skipped / .failed / .keyGeneration

// Or automatic: check age once per startup, in the background, never blocking startup or reads
val ksafe = KSafe(
    context = context,
    config = KSafeConfig(
        keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(90.days)
    )
)
```

`rotateKeys()` is **whole-store** — there is no per-key rotation. It bumps a store-wide key *generation* counter, then re-encrypts each entry under a fresh generation via a per-entry compare-and-set serialized on the write consumer. Old-generation keys are retained until nothing references them, then swept. The process is crash-safe and resumable **without a journal**: a mixed-generation store stays fully readable, concurrent writes always win, and stored **values are sacred** — a `getOrCreateSecret` secret keeps its exact value; only the wrapping key changes. Strict (`requireUnlockedDevice`) entries rotate only while the device is unlocked (otherwise counted `skipped`), and a transient key-store outage counts an entry `skipped`, not `failed`. Full model, guarantees, and the "what *deleted* means" cryptographic-erasure discussion: **[KEY_ROTATION.md](KEY_ROTATION.md)**.

**A note on hardware security models:** By default (`DEFAULT` protection), Android generates the per-datastore master key in the TEE (Trusted Execution Environment) as a **non-exportable** key — it never leaves the chip. That master key (the KEK) wraps a data-encryption key (DEK) that KSafe unwraps **once** into app memory and uses for userspace AES-GCM, so the *durable* key custody stays hardware-backed (disk theft and backups yield only ciphertext and a TEE-wrapped DEK) while the working DEK lives in process memory after first use — the same envelope model as EncryptedSharedPreferences/Tink and KSafe's own Apple and JVM engines. If you need the working key to never enter app memory, use `HARDWARE_ISOLATED` (below) or `requireUnlockedDevice = true`. This holds fully only on Android (StrongBox/TEE), where the per-operation AES runs on-chip and the key bytes never enter RAM; on iOS/macOS the Secure Enclave is EC-only, so `HARDWARE_ISOLATED` keeps the EC *wrapping* key on-chip while the AES DEK is still unwrapped into RAM for CryptoKit. With `mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)`, KSafe targets a physically separate security chip (StrongBox on Android, Secure Enclave on iOS) with automatic fallback to default hardware. On iOS, `HARDWARE_ISOLATED` uses **envelope encryption**: an EC P-256 key pair in the Secure Enclave wraps/unwraps the AES symmetric key via ECIES, so the AES key material is hardware-protected even though AES-GCM itself runs in CryptoKit. Without hardware isolation, AES keys are stored as Keychain items — still encrypted by the OS and protected by the device passcode. The full per-platform KEK/DEK envelope breakdown lives in **[ARCHITECTURE.md](ARCHITECTURE.md)**; latency figures (the TEE round-trip cost of the pre-DEK design, etc.) are in **[BENCHMARKS.md](BENCHMARKS.md)**.

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
- `v` → envelope version of **that entry**, not of the store: `2` for an entry written at generation 1, `3` for one written at generation ≥ 2. A rotated store is expected to hold a **mix** — an entry skipped or failed by a rotation keeps decrypting under its recorded generation until a later pass rewrites it. See [ENCRYPTION_PROOF.md](ENCRYPTION_PROOF.md#what-lands-on-disk).
- `p` → protection-tier *literal string* (`"NONE"`, `"DEFAULT"`, `"HARDWARE_ISOLATED"`). The `KSafeProtection` enum itself only has `DEFAULT` and `HARDWARE_ISOLATED`; the literal `"NONE"` is what's persisted for plaintext entries (it surfaces as `KSafeProtection? = null` through `getKeyInfo().protection`).
- optional `u` → unlock policy (`"unlocked"` when `requireUnlockedDevice=true`)
- optional `g` → key generation, written only once the entry has been rotated to generation ≥ 2 (absent means generation 1)

This metadata is used for read auto-detection and `getKeyInfo()`.
Legacy metadata (`__ksafe_prot_{key}__`) is still read for backward compatibility and cleaned on next write/delete.

### Querying Device Security Capabilities

KSafe exposes properties and methods to query what security hardware is available on the device, and to inspect both the **protection tier** (what the caller requested) and **storage location** (where the key material actually lives) of individual keys:

```kotlin
val ksafe = KSafe(context)

// Device-level: what hardware is available?
ksafe.deviceKeyStorages  // e.g. {HARDWARE_BACKED, HARDWARE_ISOLATED}
ksafe.deviceKeyStorages.max()  // HARDWARE_ISOLATED (highest available)

// Per-key: what protection was used, where the key lives, and which generation decrypts it
val info = ksafe.getKeyInfo("auth_token")
// info?.protection    → KSafeProtection.DEFAULT          (encrypted tier, null if plaintext)
// info?.level         → KSafeProtectionLevel.HARDWARE_BACKED (where the key lives)
// info?.keyGeneration → 1 until the entry has been rotated

// Instance-level: will an encrypted write actually succeed right now?
ksafe.protectionInfo.isEncryptionOperational
```

`getKeyInfo` returns a `KSafeKeyInfo` data class:

```kotlin
data class KSafeKeyInfo(
    val protection: KSafeProtection?,    // null, DEFAULT, or HARDWARE_ISOLATED — what the write asked for
    val storage: KSafeKeyStorage,        // legacy 3-value scale (DEPRECATED, use level)
    val level: KSafeProtectionLevel,     // 4-value universal scale: SOFTWARE < SANDBOX_PROTECTED < HARDWARE_BACKED < HARDWARE_ISOLATED
    val keyGeneration: Int = 1,          // 1 for a never-rotated entry, higher after rotateKeys(); always 1 for plaintext
)
```

> **Prefer `level` over `storage`.** `level` distinguishes JVM OS-vault keys and
> Web browser-origin keys (`SANDBOX_PROTECTED`) from a raw software fallback
> (`SOFTWARE`); `storage` collapses both to `SOFTWARE` and is kept only for
> KSafe ≤ 2.0 compatibility.

Three surfaces answer three different questions, all detailed in **[PROTECTION_INFO.md](PROTECTION_INFO.md)**:

- **`ksafe.deviceKeyStorages`** — what the *device* can do (e.g. `{HARDWARE_BACKED, HARDWARE_ISOLATED}` on a StrongBox/SE device; `{SOFTWARE}` on JVM and web).
- **`ksafe.getKeyInfo(key)`** — the tier, storage `level`, and `keyGeneration` of a *specific* key (returns `null` if the key doesn't exist).
- **`ksafe.protectionInfo`** — what *this instance* is running at right now, including `intendedLevel` vs `effectiveLevel` (protection *strength*) and `isEncryptionOperational` (see below).

#### `isEncryptionOperational` — startup preflight

`protectionInfo.isEncryptionOperational` is the cross-platform "will an encrypted write actually persist?" gate, distinct from protection *strength*. It is `true` wherever encryption works — **including the weaker-but-working JVM software-vault fallback and the iOS-Simulator sandbox fallback**. It is `false` only in the two non-operational states, where every encrypted read/write throws:

- **`web_crypto_subtle_unavailable`** — the page is served outside a secure context, so `crypto.subtle` is absent (serve over HTTPS or a `localhost` origin to restore it).
- **`jvm_os_vault_degraded`** — an OS vault *exists* but is unreachable at startup (locked Keychain/keyring, headless launch), so KSafe refuses to mint keys rather than overwrite the real OS key on a later healthy launch.

A JVM host with *no* OS vault at all (`jvm_os_vault_unavailable`) is operational — it simply runs on the software fallback. Gate app startup on `isEncryptionOperational` when your data must be encrypted; the full note-code model lives in [PROTECTION_INFO.md](PROTECTION_INFO.md).

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
* Keys stored in iOS Keychain Services with `…ThisDeviceOnly` accessibility (and Secure Enclave-backed wrapping for `HARDWARE_ISOLATED` writes)
* Optional Secure Enclave support via `KSafeEncryptedProtection.HARDWARE_ISOLATED` (through `KSafeWriteMode.Encrypted`) — uses envelope encryption (SE-backed EC P-256 wraps/unwraps the AES key) with automatic Keychain fallback on devices without SE
* Protected by device authentication
* **Effectively device-local** — encryption keys never leave the device, so even if the DataStore file is included in an iCloud Backup, the ciphertext is undecryptable on a restored device. KSafe does not set `NSURLIsExcludedFromBackupKey` because DataStore's atomic-write strategy (write-to-temp + rename) clobbers the xattr on every flush; the security guarantee already comes from key locality. Apps that need device-portable preferences should use `UserDefaults`.
* DataStore stored under `NSApplicationSupportDirectory` (the Apple-recommended location for invisible app data) since 2.0; pre-2.0 used `NSDocumentDirectory` and is auto-migrated on first 2.0 launch.
* Automatic cleanup of orphaned keys on first app use after reinstall
* **iOS Simulator fallback:** an entitlement-less Simulator can have the Keychain reject the process (`errSecMissingEntitlement` / error `-34018`); KSafe then falls back to a sandbox file store and reports `SOFTWARE` (note `apple_keychain_entitlement_missing`) with `isEncryptionOperational == true`. **Real devices are unaffected** — this never fires on device.

#### JVM/Desktop
* AES-256-GCM encryption via standard javax.crypto
* The AES key is held by the host **OS secret store** — Windows DPAPI, macOS Keychain, or Linux Secret Service (libsecret) — via the `JvmKeyVault` abstraction (JNA). The key is bound to the OS user login
* When no secret store is reachable (e.g. headless Linux with no keyring), it falls back to a key Base64-encoded in the DataStore file under `~/.eu_anifantakis_ksafe/` (POSIX `0700`) and logs a one-time security warning
* **No-`sun.misc.Unsafe` fallback (2.1.1+):** on a trimmed Compose Desktop release distributable that omits `jdk.unsupported`, KSafe persists through the same DataStore engine under the same AES-256-GCM but with the key in a `0700` file (`…ksafe-keys.json`) — the same `SOFTWARE` tier as the no-keyring case above. The key is recoverable by anyone who can read that file, so the off-host caveat below applies; adding the module migrates the data forward and restores OS-backed custody. Full risk + mechanism: [JVM_PROTECTION.md](JVM_PROTECTION.md#compose-desktop-release-distributables-jdkunsupported)
* Keys written by KSafe ≤ 2.0 are migrated into the OS store on first read (scrubbed only after read-back verification). Opt out with `-Dksafe.jvm.keyVault=software`
* Suitable for desktop applications and server-side use
* Full per-platform deep dive — what each store actually is, threat model, fallback behaviour, self-test, namespace resolution: **[docs/JVM_PROTECTION.md](JVM_PROTECTION.md)**
* Instance-level diagnostic that captures which vault was actually selected (and surfaces any fallback to plaintext): **`KSafe.protectionInfo`** — see **[docs/PROTECTION_INFO.md](PROTECTION_INFO.md)**

#### Web (Kotlin/WASM + Kotlin/JS)
* AES-256-GCM encryption via WebCrypto **SubtleCrypto** on both browser targets
* The AES key is a **non-extractable `CryptoKey`** (`extractable = false`) whose live key object is persisted in **IndexedDB** — the raw key bytes are never exposed to JS. Values are stored in `localStorage`. Both targets share the same origin/IndexedDB, so data written from one reads back from the other; a legacy ≤2.0 `localStorage` key is imported as non-extractable and the `localStorage` entry deleted on first access
* Scoped per origin (~5-10 MB storage limit)
* Memory policy always `PLAIN_TEXT` internally (WebCrypto is async-only)
* **Requires a secure context.** `crypto.subtle` is only exposed over HTTPS or a `localhost` origin. Served from a plain-HTTP non-localhost origin, WebCrypto is absent: `protectionInfo.effectiveLevel` degrades to `SOFTWARE`, the note `web_crypto_subtle_unavailable` is set, `isEncryptionOperational` is `false`, and every encrypted read/write fails. A healthy secure-context web key otherwise reports `SANDBOX_PROTECTED` (browser origin isolation), not raw `SOFTWARE`.
* Kotlin/WASM requires WasmGC (Chrome 119+, Firefox 120+, Safari 18+); Kotlin/JS runs on any modern browser

### Hardware Verified

KSafe's hardware-backed encryption has been tested and verified on real devices:

| Platform | Device | Hardware Security |
|----------|--------|-------------------|
| iOS | iPhone 15 Pro Max (A17 Pro) | Secure Enclave |
| Android | Samsung Galaxy S24 Ultra (Snapdragon 8 Gen 3) | StrongBox (Knox Vault) |

### Error Handling

If decryption fails **permanently** (e.g., corrupted data or a missing key), KSafe gracefully returns the default value on every read path, ensuring your app continues to function. On a **transient** failure (such as a locked device), behaviour depends on the read API: only the suspend `get()` surfaces the failure as an exception so you can await unlock and retry, while `getDirect()` / property delegates return the default and `getFlow()` skips that emission (keeping its last value until the next decryptable snapshot).

**Exception:** When `requireUnlockedDevice = true` and the device is locked, KSafe throws `IllegalStateException` instead of returning the default value. This allows your app to detect and handle the locked state explicitly (e.g., showing a "device is locked" message).

### Reinstall Behavior

KSafe ensures clean reinstalls on all platforms:
* **Android:** Keystore entries automatically deleted on uninstall. If Auto Backup restores the DataStore file without Keystore keys, orphaned ciphertext is detected and removed on next startup.
* **iOS:** Orphaned Keychain entries (keys without data) detected and cleaned on first use. Orphaned ciphertext (data without keys) detected and cleaned on startup.
* **JVM:** Orphaned ciphertext detected and cleaned on startup if encryption key files are lost.

> **Note on unencrypted values:** The orphaned ciphertext cleanup targets only encrypted entries (those with the `encrypted_` legacy prefix or `__ksafe_meta_` canonical metadata indicating encryption in DataStore). Unencrypted values (written with `mode = KSafeWriteMode.Plain`) are not affected by this cleanup. On Android, if `android:allowBackup="true"` is set in the manifest, Auto Backup may restore unencrypted DataStore entries after reinstall with stale values from the last backup snapshot.

### iOS Keychain Cleanup Mechanism

* **Snapshot-based:** on first data load KSafe reads the current DataStore snapshot and derives the live key-ID set from the value/metadata entries
* **Orphan Detection:** scans app-scoped Keychain generic-password items and Secure Enclave EC keys against that set (master-key sentinels preserved; in-flight writes excluded)
* **Automatic Removal:** deletes library-written Keychain/SE entries whose DataStore counterpart is gone
* **Scope & fail-safe:** skipped on macOS (shared per-user login Keychain) and when the snapshot is empty but scoped Keychain entries exist

### Orphaned Ciphertext Cleanup (All Platforms)

On startup, KSafe probes each encrypted DataStore entry by attempting decryption:
* **Missing-key failure** (encryption key gone/absent): entry removed from DataStore. Other decryption failures (a wrong or invalidated key surfacing as a GCM bad-tag error) are treated as a graceful default-return and are **not** deleted
* **Temporary failure** (device locked): skipped, retried on next launch
* Runs once per startup, after the access-policy migration and only once the collector's first snapshot has populated the cache — sweeping an empty pre-load snapshot would reap every live key. Under `lazyLoad`, where no collector runs, the first access triggers it off-thread instead

### Known Limitations

* **iOS:** Keychain access may require device to be unlocked depending on `requireUnlockedDevice` setting (default: accessible after first unlock). The **Simulator** may fall back to a sandbox file store (`SOFTWARE`) when it has no entitlement; real devices are unaffected
* **Android:** Some devices may not have hardware-backed keystore; `setUnlockedDeviceRequired` requires API 28+. Before Android 15 (API 35) the platform's `setUnlockedDeviceRequired(true)` additionally had documented bugs on API 28-34: removing the lock screen can silently delete such keys (the affected values then self-heal to their defaults via the missing-key sweep), and key generation/use can fail while no secure lock screen is configured. KSafe applies the flag only when `requireUnlockedDevice = true` is explicitly requested (default is `false`) and does not gate it by API level — an explicitly requested policy is honored as asked; weigh the caveat before enabling it broadly on pre-35 fleets
* **JVM:** No TEE/HSM. The key is held by the OS secret store (DPAPI / macOS Keychain / libsecret), bound to the OS user login; the no-keyring fallback relies on OS file permissions (0700). A key migrated into the OS store becomes unrecoverable if that store is later lost (different OS account, keyring/keychain reset) — inherent to OS-bound storage. If an OS vault exists but is unreachable at startup, KSafe fails closed (`jvm_os_vault_degraded`, `isEncryptionOperational == false`) rather than silently downgrading
* **Web (wasmJs + js):** No hardware security. The AES key is a non-extractable WebCrypto `CryptoKey` in IndexedDB (not exportable by JS); values are in `localStorage`. Both IndexedDB and `localStorage` can be cleared by the user. Outside a secure context there is no `crypto.subtle`, so encrypted ops fail (`web_crypto_subtle_unavailable`). Security checks (root, debugger, emulator) are no-ops on both targets
* **All Platforms:** Encrypted data is lost if encryption keys are deleted (by design for security — see [KEY_ROTATION.md](KEY_ROTATION.md) on what "deleted" means as cryptographic erasure)

***

## Cryptographic Utilities

KSafe exposes two crypto primitives that back its own internals:

- **`secureRandomBytes(size)`** — a cross-platform CSPRNG delegating to each platform's strongest source (`SecureRandom` on JVM/Android, `SecRandomCopyBytes` on Apple, `crypto.getRandomValues()` on web). This is the same primitive KSafe uses internally for IVs and key generation.
- **`getOrCreateSecret(key, …)`** — generates a cryptographically secure random secret on first call and returns the same one thereafter, stored under KSafe's encryption. Defaults: `size = 32` bytes (256-bit), `protection = HARDWARE_ISOLATED`, `requireUnlockedDevice = false`. It **refuses to overwrite** a secret it can't read back (locked vault, invalidated key) rather than silently minting a new one and orphaning data (e.g. a SQLCipher database). Under [key rotation](KEY_ROTATION.md) the secret's **value is preserved** — only the wrapping key changes.

Custom sizes and the Room + SQLCipher / SQLDelight passphrase recipes are in **[USAGE.md](USAGE.md)**.

***
