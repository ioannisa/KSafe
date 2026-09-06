# Security Model

KSafe stores key–value pairs. **Every write is encrypted unless the call passes `KSafeWriteMode.Plain`** — the default is `KSafeWriteMode.Encrypted` at the platform's normal key tier, with the instance's unlock policy. Reads never take a mode: KSafe records how each entry was written and detects it on the way back.

This document has three parts:

1. **Runtime Security Policy** — optional checks that run once, when you create a `KSafe`, and can warn or refuse on a rooted device, an attached debugger, a debug build or an emulator. Every check is off by default.
2. **How Encryption Works** — the cipher, where each platform keeps the key, what lands on disk, and what the threat model does and does not cover.
3. **Security Features** — the per-platform detail, error behaviour, reinstall cleanup, and known limitations.

Code samples below use the Android factory (`KSafe(context, …)`). On iOS, macOS, JVM Desktop and web the factory takes the same named arguments without `context` — for example `KSafe(securityPolicy = …)`.

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

| Check | Android | iOS | macOS | JVM | Web (wasmJs+js) | Description |
|-------|---------|-----|-------|-----|-----------------|-------------|
| `rootedDevice` | ✅ | ✅ | ❌ | ❌ | ❌ | Detects rooted/jailbroken devices. Always reports clean on macOS: the jailbreak paths it probes for exist on every Mac, so probing there would block the library on healthy machines |
| `debuggerAttached` | ✅ | ✅ | ✅ | ✅ | ❌ | Detects attached debuggers (JVM: the JDWP launch flags `-agentlib:jdwp`, `-Xdebug`, `-Xrunjdwp`) |
| `debugBuild` | ✅ | ✅ | ✅ | ✅ | ❌ | Detects debug builds (Android: the debuggable flag; Apple: Xcode / simulator / malloc-debug environment variables; JVM: assertions enabled, i.e. `-ea`) |
| `emulator` | ✅ | ✅ | ❌ | ❌ | ❌ | Detects emulators and simulators. On macOS there is nothing to detect — the Apple probe looks for Simulator environment variables |

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
- Build signals: build type `userdebug` or `eng`, or build tags containing `test-keys`. `dev-keys` is deliberately ignored, because Google emulator images sign `user` builds with it
- Dangerous system properties (`ro.debuggable=1`, `ro.secure=0`), read through the property area directly because `getprop` is SELinux-denied to an untrusted app

### Jailbreak Detection Methods (iOS)

- Cydia, Sileo, and other jailbreak app paths
- Rootless-era jailbreak paths (`/var/jb` — palera1n, Dopamine / Procursus)
- System write access test (fails on non-jailbroken devices)
- Common jailbreak tool paths (`/bin/bash`, `/usr/sbin/sshd`, etc.)

> **Limitation:** All root, jailbreak, and debugger checks are best-effort heuristics that *fail open* — if a probe cannot answer, it reports clean rather than blocking a healthy device. Sophisticated hiding tools (Magisk DenyList, Shamiko, Zygisk) can bypass most client-side detection methods. On Android 11+ the root-management-app probe depends on package visibility; the library ships the required `<queries>` declarations in its manifest (merged into the consuming app), and other signals (build type, system properties, filesystem paths) do not need them. For high-assurance integrity decisions, pair these heuristics with server-verified attestation: Play Integrity on Android, App Attest / DeviceCheck on Apple platforms.

***

## How Encryption Works

Every value KSafe stores is encrypted with AES-GCM under a key the platform holds, unless the write explicitly asks for `KSafeWriteMode.Plain`. Where the bytes land differs per platform — DataStore Preferences on Android, Apple and JVM Desktop, a JSON file on a JVM runtime without `sun.misc.Unsafe`, and `localStorage` in the browser — but the cipher and the key custody rules below are the same everywhere.

> **Want to see it with your own eyes?** [docs/ENCRYPTION_PROOF.md](ENCRYPTION_PROOF.md) walks through the per-platform automated proof tests (`*EncryptionProofTest`) and gives manual commands to dump the raw `.preferences_pb` / `localStorage` bytes so you can verify the ciphertext-not-plaintext property yourself.

### Platform Details

A few names recur in the table below and in the sections after it:

- **TEE (Trusted Execution Environment)** — a secure area of the main chip that holds keys and runs crypto where the operating system cannot read the key bytes.
- **StrongBox** (Android) / **Secure Enclave** (Apple) — a physically separate security chip, one step stronger than the TEE.
- **KEK / DEK** — a *key-encryption key* that never leaves secure hardware, wrapping a *data-encryption key* that does the actual per-value AES.
- **DataStore** — Jetpack's file-backed key–value store; KSafe uses it as the place bytes land, not as the thing that encrypts them.
- **DPAPI** (Windows) / **login Keychain** (macOS) / **Secret Service, via libsecret** (Linux) — the operating system's own secret store, unlocked with the user's login.
- **WebCrypto `CryptoKey` in IndexedDB** — a browser key object that JavaScript can *use* but never read the bytes of. **WasmGC** is the browser feature the Kotlin/WASM build needs.

| Platform | Cipher | Key Storage | Security |
|----------|--------|-------------|----------|
| **Android** | AES-GCM (256-bit default; 128-bit optional) | Android Keystore — TEE by default, StrongBox opt-in | Keys non-exportable, app-bound, auto-deleted on uninstall |
| **iOS / macOS** | AES-GCM through KSafe's bundled CryptoKit bridge (256-bit default; 128-bit optional) | Apple Keychain Services — Secure Enclave opt-in | Protected by device passcode/biometrics, not in backups |
| **JVM/Desktop** | AES-GCM via javax.crypto (256-bit default; 128-bit optional) | OS secret store — Windows DPAPI / macOS Keychain / Linux Secret Service (libsecret); software fallback in `~/.eu_anifantakis_ksafe/` | Key bound to the OS user login. The store is **per-OS-user, shared across all of that user's apps** (not per-app like Android/iOS) — set `KSafeConfig.appNamespace` to isolate one app's keys from another's. Legacy ≤2.0 keys migrate on first read and remain authoritative (a stale store entry can't shadow them). Fallback (no keyring) relies on OS file permissions (0700 POSIX on the data directory) + a one-time warning |
| **Kotlin/WASM (Browser)** | AES-GCM via WebCrypto (256-bit default; 128-bit optional) | Non-extractable `CryptoKey` in **IndexedDB**; values in `localStorage` | Raw key bytes never exposed to JS. Scoped per origin, ~5-10 MB limit. Requires WasmGC (Chrome 119+ / Firefox 120+ / Safari 18+) |
| **Kotlin/JS (Browser)** | AES-GCM via WebCrypto (256-bit default; 128-bit optional) | Non-extractable `CryptoKey` in **IndexedDB**; values in `localStorage` | Raw key bytes never exposed to JS. Scoped per origin. Same origin/IndexedDB as wasmJs — data readable by either target; legacy ≤2.0 localStorage keys migrate on first access |

> **Cipher note:** use `KSafeConfig.aesKeySize` with `KSafeAesKeySize.BITS_128` or
> `BITS_256` (default). The choice applies to newly generated keys on every platform; an
> existing key keeps its size until rotation.

### Encryption Flow

1. **Serialize value → plaintext bytes** using kotlinx.serialization
2. **Load (or generate) a random AES key** (`BITS_256` by default, or `BITS_128` via `KSafeConfig.aesKeySize` on every platform) from the platform key store — Android Keystore / Apple Keychain / JVM OS secret store (DPAPI·Keychain·libsecret) / non-extractable WebCrypto `CryptoKey` in IndexedDB (a shared per-store master key since 2.0; the WebCrypto `CryptoKey` stays non-extractable)
3. **Encrypt with AES-GCM.** Each ciphertext carries a fresh random *nonce* — a one-time value that makes two encryptions of the same text differ, also called an IV — and an *authentication tag*
4. **Persist value** in DataStore/localStorage under `__ksafe_value_<key>`
   (encrypted writes store Base64 ciphertext, plaintext writes keep native type where supported)
5. **Persist metadata** under `__ksafe_meta_<key>__` as compact JSON
   (for example: `{"v":2,"p":"DEFAULT"}` or `{"v":2,"p":"DEFAULT","u":"unlocked"}` — `v:2` since 2.0 and for an un-rotated 3.0.0 store; entries from pre-2.0 builds still read `v:1`. After the first [`rotateKeys()`](KEY_ROTATION.md) — which re-encrypts the whole store under a fresh *key generation*, a numbered set of keys that replaces the previous one — the entry re-encrypts to `v:3` and gains a generation marker `"g":<n>`)
6. **Key material managed by the platform key store** — no raw key is ever written to DataStore; on Android's relaxed `DEFAULT` tier a KEK-wrapped DEK (useless without the non-exportable Keystore KEK) is persisted alongside the values

**What is GCM?** GCM (Galois/Counter Mode) is an authenticated encryption mode that provides both confidentiality and integrity. The authentication tag detects any tampering—if someone modifies even a single bit of the ciphertext, decryption will fail.

**Envelope versions (v1/v2/v3).** `v1` is the pre-2.x legacy shape (per-entry alias, bare-literal metadata). `v2` is the 2.0–2.2.x format and the shape an un-rotated 3.0.0 generation-1 store still writes byte-for-byte, so upgrading to 3.0.0 is a drop-in. The first [`rotateKeys()`](KEY_ROTATION.md) bumps the store to generation ≥ 2, and from then on entries are written as the **authenticated `v3` envelope**: the same routing as v2 plus AES-GCM *associated data* (AAD) that binds each ciphertext to the store identity, user key, protection tier, unlock policy, and key generation. Once rotated, an encrypted entry can no longer be copied, swapped, or relocated between keys — such tampering breaks the GCM tag, so the read **fails closed**: it hands back the caller's default instead of decrypting the entry in the wrong context. (Rewriting an entry's metadata to plaintext, `p:"NONE"`, instead reclassifies it as plaintext: the read then returns the stored bytes verbatim — undecipherable ciphertext, never the underlying secret.) See [KEY_ROTATION.md](KEY_ROTATION.md) and [ARCHITECTURE.md](ARCHITECTURE.md) for the envelope/AAD detail.

### Security Boundaries & Threat Model

**What KSafe protects against:**
- ✅ Casual file inspection (data at rest is encrypted)
- ✅ Data extraction from unrooted device backups
- ✅ App data access by other apps (Android/iOS: OS sandboxing + encryption). **JVM/Desktop caveat:** the OS secret store is per-OS-user and shared across that user's processes — set a unique `KSafeConfig.appNamespace` so a different desktop app run by the same user can't collide with or overwrite this app's keys (Web is isolated per origin by the browser).
- ✅ Reinstall data leakage (automatic cleanup)
- ✅ Tampering detection (GCM authentication tag). Once a store has been rotated, the tag also authenticates the entry's routing metadata, so an entry can't be relocated, swapped, or re-tiered between keys — see **Envelope versions** above
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
- Use `KSafeSecurityPolicy.Strict` for high-security apps (banking, medical, enterprise). Read the limitation note above first: the checks are heuristics, and `BLOCK` makes the `KSafe(...)` call throw, so it needs a `try`/`catch`
- Use `KSafeMemoryPolicy.ENCRYPTED` for highly sensitive data such as tokens and passwords. It keeps values as ciphertext in RAM and decrypts on every read, so a memory dump yields ciphertext; the default `LAZY_PLAIN_TEXT` keeps the plaintext of any key that has been read once for the life of the instance
- Use `KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE` when encrypted data is read repeatedly during UI rendering (Compose recomposition, SwiftUI re-render). It adds a plaintext side cache that expires after `plaintextCacheTtl` (5 seconds by default), so repeated reads skip decryption but the plaintext does not live forever. Both policies are chosen per instance, through the `KSafe(...)` factory's `memoryPolicy` parameter; on web the policy is ignored and values are always held as plaintext, because WebCrypto is asynchronous only
- Gate critical operations behind a biometric prompt. `ksafe-biometrics` is a standalone, process-wide gate with real OS prompts on Android (BiometricPrompt), iOS/macOS (LocalAuthentication), JVM Desktop on macOS (Touch ID) and Windows (Windows Hello), and the web (WebAuthn platform authenticators). JVM Desktop on Linux has no portable prompt API, so the call returns `true` without prompting — do not rely on it as a gate there. See [BIOMETRICS.md](BIOMETRICS.md)
- For long-lived secrets, enable [key rotation](KEY_ROTATION.md) so a key that ages, or that you suspect is compromised, is retired without data loss
- Keep the credentials that mint other credentials on your server. A refresh token or a signing key stored on the device can be replayed by anyone who reaches the device's unlocked state; a short-lived, server-issued token cannot
- Delete what a session no longer needs. `delete(key)` removes the value and its metadata, and for a `HARDWARE_ISOLATED` entry — which owns its own key — that key too. A `DEFAULT` entry rides the store's shared master key, so deleting it removes the ciphertext but leaves that shared key in place for the other entries

### Key Rotation & Key Lifetime

By default KSafe never starts a new key generation on its own (`KSafeKeyRotationPolicy.Never`) — a pass is always something you ask for. That is the safest default, because rotation only pays off against a specific threat — a key that has aged out of a compliance window, or one you suspect is compromised — and until you opt in, every store stays byte-compatible with pre-3.0.0.

```kotlin
// Manual, whole-store rotation
val result: KSafeRotationResult = ksafe.rotateKeys()
//   result.rotated / .skipped / .failed / .keyGeneration

// Or automatic: KSafe checks the generation's age once per startup, in the
// background, and never blocks startup or reads
val ksafe = KSafe(
    context = context,
    config = KSafeConfig(
        keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(90.days)
    )
)
```

**Scope.** `rotateKeys()` is whole-store; there is no per-key rotation. Stored **values are sacred** — a `getOrCreateSecret` secret keeps its exact bytes, and only the key wrapping it changes. `skipped` collects the entries a pass left alone: one whose own write won a race with the pass, and one the pass could not decrypt at that moment (a locked device, say). Either way the entry stays readable.

**How a pass runs (3.1.0+).** KSafe persists the new store-wide generation together with `r:1`, meaning "in progress", then re-encrypts each entry one at a time through a compare-and-set serialized on the write consumer that owns the store. Keys the pass supersedes are kept until nothing still reads through them, then swept. Only afterwards does the record become `r:0`, meaning "completed". No per-entry journal or rollback log is needed.

**If it is interrupted.** A crash leaves a readable store holding a mix of generations, and the next `KSafe` instance resumes that same generation automatically, under every policy — including `Never`.

**Retries.** A pass that completed but left retryable `skipped` entries also records `rp:N`, a budget taken from `KSafeConfig.keyRotationRetryAttempts` (3 by default; 0 disables retries). The running instance does not loop. Each later instance claims at most one retry, durably rewriting `r:0,rp:N` to `r:1,rp:N-1` before doing any work, so a crash cannot refill the budget. A retry keeps the same generation and the same `MaxAge` birth timestamp; if a fresh `MaxAge` rotation is already due, that takes precedence over the retry. Entries in `failed` never arm a retry.

**Upgrading from 3.0.0.** A record written by 3.0.0 has no `r` field. The first 3.1.0 startup stamps it `r:0` and does no rotation work, rather than guessing whether that older pass had crashed.

Full model, guarantees, and the "what *deleted* means" cryptographic-erasure discussion: **[KEY_ROTATION.md](KEY_ROTATION.md)**.

### Hardware Isolation

**What "hardware-backed" actually means, per platform.** At the `DEFAULT` tier, Android generates the per-datastore master key inside the TEE as a **non-exportable** key: it never leaves the chip. That master key is a *key-encryption key* (KEK). It wraps a *data-encryption key* (DEK) that KSafe unwraps **once** into app memory and then uses for ordinary in-process AES-GCM. So the *durable* custody stays hardware-backed — disk theft and backups yield only ciphertext plus a TEE-wrapped DEK — while the working key lives in process memory after first use. This is the same envelope model as EncryptedSharedPreferences and Tink, and the same one KSafe's own Apple and JVM engines already use.

**Requesting a dedicated chip.** `KSafeEncryptedProtection.HARDWARE_ISOLATED` asks for StrongBox on Android or the Secure Enclave on Apple — a chip physically separate from the main processor — and falls back to the platform default where there is none, with no code change. On Android a `HARDWARE_ISOLATED` write runs the per-operation AES inside StrongBox itself, so the key bytes never enter app memory. On Apple the Secure Enclave holds elliptic-curve keys only, so KSafe uses *envelope encryption*: an EC P-256 key pair inside the Enclave wraps and unwraps the AES key — via ECIES, the standard way to wrap a symmetric key with an EC key pair — and the AES key is still unwrapped into memory for CryptoKit. Without hardware isolation, AES keys are ordinary Keychain items: still encrypted by the OS and protected by the device passcode.

Keeping the working key out of app memory is an Android-only guarantee, and two settings ask for it: `HARDWARE_ISOLATED`, and `requireUnlockedDevice = true`, which keeps even a `DEFAULT` write on the per-call Keystore path instead of the software DEK. On Apple and JVM the AES key is always unwrapped into process memory to do the work.

Isolated key generation is slower and every operation on the key costs more, so reserve the tier for master passphrases and identity keys. The extra read cost is largely hidden by the in-memory cache, which serves most reads without touching the key at all.

The full per-platform KEK/DEK breakdown lives in **[ARCHITECTURE.md](ARCHITECTURE.md)**; latency figures (the TEE round-trip cost of the pre-DEK design, etc.) are in **[BENCHMARKS.md](BENCHMARKS.md)**.

```kotlin
// Property delegate — reads from the cache, writes fire-and-forget
var secret by ksafe("", mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))

// Suspending write: call from a coroutine, returns once the value is committed
ksafe.put("secret", value, mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))

// Non-suspending write: returns at once, persists in the background
ksafe.putDirect("secret", value, mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))

// Or freeze the tier at the type level (3.1.0+): no mode parameter exists to get wrong
val vault = KSafeHardwareIsolated(ksafe)
vault.put("secret", value)   // suspending, same as ksafe.put above
```

**Mode-typed views and the security model (3.1.0+).** `KSafePlain` / `KSafeEncrypted` / `KSafeHardwareIsolated` freeze the write mode at the type level, which removes the wrong-argument failure mode from call sites. Two boundaries keep the model honest. The guarantee is **write-side only**: reads never take a mode and auto-detect each entry's protection, so a plain-typed view will happily read an encrypted entry. And `KSafeHardwareIsolated` expresses the same *request* semantics as `HARDWARE_ISOLATED` above, including the automatic fallback and its reporting through `protectionInfo` / `getKeyInfo`. See [USAGE.md](USAGE.md#mode-typed-views-310--ksafeplain--ksafeencrypted--ksafehardwareisolated).

**Moving an existing entry to hardware isolation.** The tier is decided by the write, not by the store, so an entry moves when you write it again. Read the value, then write it back through a `HARDWARE_ISOLATED` write (or a `KSafeHardwareIsolated` view): the entry is re-encrypted under its own StrongBox / Secure Enclave key, minted on that write, and its metadata is rewritten to match. Nothing needs to be deleted, and the shared `DEFAULT` key that other entries still use is left in place. Entries you never rewrite keep decrypting under the key they were written with.

### Per-Key Metadata

Each key stores one metadata entry, `__ksafe_meta_{key}__`, holding compact JSON:

- `v` → envelope version of **that entry**, not of the store: `2` for an entry written at generation 1, `3` for one written at generation ≥ 2. A rotated store is expected to hold a **mix** — an entry a rotation skipped or failed keeps decrypting under its recorded generation until a later pass rewrites it. See [ARCHITECTURE.md](ARCHITECTURE.md#on-disk-format).
- `p` → protection-tier *literal string*: `"NONE"`, `"DEFAULT"` or `"HARDWARE_ISOLATED"`. The `KSafeProtection` enum itself only has `DEFAULT` and `HARDWARE_ISOLATED`; the literal `"NONE"` is what gets persisted for plaintext entries, and it surfaces as `KSafeProtection? = null` through `getKeyInfo().protection`.
- optional `u` → unlock policy; `"unlocked"` when `requireUnlockedDevice = true`.
- optional `g` → key generation, written only once the entry has been rotated to generation ≥ 2. Absent means generation 1.
- optional `sa` → written as `1` only when the entry is both `HARDWARE_ISOLATED` and `requireUnlockedDevice = true`. It records that the entry's key sits under the strict alias variant, so a later read looks it up in the right place.

This metadata is what read auto-detection and `getKeyInfo()` work from.
Legacy metadata (`__ksafe_prot_{key}__`) is still read for backward compatibility and cleaned on next write/delete.

### Querying Device Security Capabilities

KSafe exposes properties and methods to query what security hardware is available on the device, and to inspect both the **protection tier** (what the caller requested) and **storage location** (where the key material actually lives) of individual keys.

Three surfaces answer three different questions, all detailed in **[PROTECTION_INFO.md](PROTECTION_INFO.md)**:

- **`ksafe.deviceKeyStorages`** — what the *device* can do (e.g. `{HARDWARE_BACKED, HARDWARE_ISOLATED}` on a StrongBox/SE device; `{SOFTWARE}` on JVM and web).
- **`ksafe.getKeyInfo(key)`** — the tier, storage `level`, and `keyGeneration` of a *specific* key (returns `null` if the key doesn't exist).
- **`ksafe.protectionInfo`** — what *this instance* is running at right now, including `intendedLevel` vs `effectiveLevel` (protection *strength*) and `isEncryptionOperational` (see below).

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

#### `isEncryptionOperational` — startup preflight

`protectionInfo.isEncryptionOperational` is the cross-platform "will an encrypted write actually persist?" gate, distinct from protection *strength*. It is `true` wherever encryption works — **including the weaker-but-working JVM software-vault fallback and the iOS-Simulator sandbox fallback**. It is `false` only in the two non-operational states, where every encrypted read/write throws:

- **`web_crypto_subtle_unavailable`** — the page is served outside a secure context, so `crypto.subtle` is absent (serve over HTTPS or a `localhost` origin to restore it).
- **`jvm_os_vault_degraded`** — an OS vault *exists* but is unreachable at startup (locked Keychain/keyring, headless launch), so KSafe refuses to mint keys rather than overwrite the real OS key on a later healthy launch.

A JVM host with *no* OS vault at all (`jvm_os_vault_unavailable`) is operational — it runs on the software fallback instead. Gate app startup on `isEncryptionOperational` when your data must be encrypted; the full note-code model lives in [PROTECTION_INFO.md](PROTECTION_INFO.md).

### Legacy Key Migration (v1.6.x → v1.7.0 canonical keys)

Nothing here needs action. This describes how a store written by KSafe 1.6.x or earlier keeps working; a store created on 1.7.0 or later only ever contains the canonical shapes.

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

#### macOS
* Same Keychain engine and same `…ThisDeviceOnly` accessibility as iOS, with Secure Enclave-backed wrapping for `HARDWARE_ISOLATED` writes on Macs that have an Enclave (pre-T2 Intel Macs and VMs do not, and fall back to the Keychain)
* **The login Keychain is shared per user, not per app.** Unlike iOS, a macOS Keychain item is not walled off from the user's other applications, so read the tier as "protected by the user's login", not "protected from other software the user runs"
* For the same reason the orphaned-Keychain-entry sweep does **not** run on macOS: it could not tell KSafe's own leftovers from another app's live keys, so Keychain items whose data is gone are left in place
* Values are stored under `NSApplicationSupportDirectory`, like iOS
* The root and emulator checks always report clean here — see the table at the top of this document

#### JVM/Desktop
* AES-GCM encryption via standard javax.crypto (`BITS_256` default; `BITS_128` optional)
* The AES key is held by the host **OS secret store** — Windows DPAPI, macOS Keychain, or Linux Secret Service (libsecret) — via the `JvmKeyVault` abstraction (JNA). The key is bound to the OS user login
* When no secret store is reachable (e.g. headless Linux with no keyring), it falls back to a key Base64-encoded in the DataStore file under `~/.eu_anifantakis_ksafe/` (POSIX `0700` on that directory) and logs a one-time security warning
* **No-`sun.misc.Unsafe` fallback (2.1.1+):** on a trimmed Compose Desktop release distributable that omits `jdk.unsupported`, KSafe persists through a JSON file instead of DataStore, under the same AES-256-GCM, with the key in an owner-only file (`…ksafe-keys.json`, POSIX `0600`, inside the `0700` data directory) — the same `SOFTWARE` tier as the no-keyring case above. The key is recoverable by anyone who can read that file, so a copied home directory or a backup carries the key along with the data; adding the `jdk.unsupported` module back migrates the data forward and restores OS-backed custody. Full risk + mechanism: [JVM_PROTECTION.md](JVM_PROTECTION.md#compose-desktop-release-distributables-jdkunsupported)
* Keys written by KSafe ≤ 2.0 are migrated into the OS store on first read (scrubbed only after read-back verification). Opt out with `-Dksafe.jvm.keyVault=software`
* Suitable for desktop applications and server-side use
* Full per-platform deep dive — what each store actually is, threat model, fallback behaviour, self-test, namespace resolution: **[docs/JVM_PROTECTION.md](JVM_PROTECTION.md)**
* Instance-level diagnostic that captures which vault was actually selected (and surfaces any fallback to plaintext): **`KSafe.protectionInfo`** — see **[docs/PROTECTION_INFO.md](PROTECTION_INFO.md)**

#### Web (Kotlin/WASM + Kotlin/JS)
* AES-GCM encryption via WebCrypto **SubtleCrypto** on both browser targets (`BITS_256` default; `BITS_128` optional)
* The AES key is a **non-extractable `CryptoKey`** (`extractable = false`) whose live key object is persisted in **IndexedDB** — the raw key bytes are never exposed to JS. Values are stored in `localStorage`. The key is created on the first encrypted write, so a store that only ever writes plaintext has no IndexedDB record at all. Both targets share the same origin/IndexedDB, so data written from one reads back from the other; a legacy ≤2.0 `localStorage` key is imported as non-extractable and the `localStorage` entry deleted on first access
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

A read that fails is either **permanent** or **transient**, and KSafe treats the two differently.

**Permanent failures** — corrupted data, or a key that is definitively gone — return the caller's default value on every read path, so your app keeps working.

**Transient failures** — a locked device, a busy Keystore or Keychain — depend on which read API you used:

| API | On a transient failure |
|-----|------------------------|
| `get()` (suspending) | Throws, so you can await unlock and retry |
| `getDirect()`, property delegates | Returns the default; there is no seam to retry from without blocking the caller |
| `getFlow()` and everything built on it (`getStateFlow`, Compose state) | Emits nothing, so a collector keeps whatever it last saw, and retries internally on a backoff that grows to about half a minute until the entry is decryptable again |

**Locked device with `requireUnlockedDevice = true`.** On Android and Apple the key cannot be used while the device is locked, and the split above applies: `get()` throws `IllegalStateException` (its message names the locked Keystore or Keychain, so you can show a "device is locked" state and retry after unlock), `getDirect()` and property delegates return the default, and `getFlow()` retries. JVM and web have no device-lock concept — the entry is stored as an ordinary encrypted entry — so this case does not arise there.

### Reinstall Behavior

KSafe ensures clean reinstalls on all platforms:
* **Android:** Keystore entries automatically deleted on uninstall. If Auto Backup restores the DataStore file without Keystore keys, orphaned ciphertext is detected and removed on next startup.
* **iOS:** Orphaned Keychain entries (keys without data) detected and cleaned on first use. Orphaned ciphertext (data without keys) detected and cleaned on startup.
* **JVM:** Orphaned ciphertext detected and cleaned on startup if encryption key files are lost.

> **Note on unencrypted values:** The orphaned-ciphertext cleanup below only considers canonical entries (`__ksafe_value_{key}`) whose metadata marks them encrypted. Values written with `mode = KSafeWriteMode.Plain` are never touched, and neither are pre-2.0 entries stored under the legacy `encrypted_` prefix — those are preserved rather than reclaimed. On Android, if `android:allowBackup="true"` is set in the manifest, Auto Backup may restore unencrypted DataStore entries after reinstall with stale values from the last backup snapshot.

### iOS Keychain Cleanup Mechanism

* **Snapshot-based:** on first data load KSafe reads the current DataStore snapshot and derives the live key-ID set from the value/metadata entries
* **Orphan Detection:** scans app-scoped Keychain generic-password items and Secure Enclave EC keys against that set (master-key sentinels preserved; in-flight writes excluded)
* **Automatic Removal:** deletes library-written Keychain/SE entries whose DataStore counterpart is gone
* **Scope & fail-safe:** skipped on macOS (shared per-user login Keychain) and when the snapshot is empty but scoped Keychain entries exist

### Orphaned Ciphertext Cleanup (All Platforms)

When a key is gone but its ciphertext is still stored, that entry can never be read again. On startup KSafe finds those entries by trying to decrypt each one:
* **Missing-key failure** (the encryption key is gone or absent): the entry is removed. Other decryption failures — a wrong or invalidated key, which surfaces as a GCM bad-tag error — return the default gracefully and are **not** deleted, because the key may come back
* **Temporary failure** (device locked): skipped, retried on the next launch
* **Never swept:** `getOrCreateSecret` slots and pre-2.0 entries stored under the legacy `encrypted_` prefix. Reclaiming a secret slot would turn its refuse-to-overwrite guard into a silently regenerated passphrase, orphaning whatever that secret encrypts
* Runs once per startup, after the access-policy migration and only once the first storage snapshot has populated the cache — sweeping an empty pre-load snapshot would reap every live key. Under `lazyLoad`, where no background reader runs, the first access triggers it off-thread instead

### Known Limitations

* **iOS:** Keychain access may require device to be unlocked depending on `requireUnlockedDevice` setting (default: accessible after first unlock). The **Simulator** may fall back to a sandbox file store (`SOFTWARE`) when it has no entitlement; real devices are unaffected
* **Android:** Some devices may not have hardware-backed keystore; `setUnlockedDeviceRequired` requires API 28+. Before Android 15 (API 35) the platform's `setUnlockedDeviceRequired(true)` additionally had documented bugs on API 28-34: removing the lock screen can silently delete such keys (the affected values then self-heal to their defaults via the missing-key sweep), and the Keystore cannot mint such a key at all while no secure lock screen is configured. KSafe applies the flag only when `requireUnlockedDevice = true` is explicitly requested (default is `false`) and honours it wherever the platform can. On API 28-34 with no secure lock screen there is nothing to lock against, so the strict key is minted without the flag (the write still takes the per-call TEE path, never the software DEK), and the degrade is reported in `protectionInfo.notes` as `android_lock_screen_absent` for as long as that key is the one in use — KSafe records the relaxed mint, so the note survives the user later setting a lock screen instead of vanishing exactly when it starts to matter. The decision is re-taken only at the next key generation, and rotation is opt-in (`KSafeConfig.keyRotationPolicy` defaults to `Never`): an app that wants the unlock binding back after a lock screen appears calls `rotateKeys()` once, or configures a rotation policy. Weigh the caveat before enabling the policy broadly on pre-35 fleets
* **JVM:** No TEE/HSM. The key is held by the OS secret store (DPAPI / macOS Keychain / libsecret), bound to the OS user login; the no-keyring fallback keeps the key inside the data directory and relies on OS file permissions (POSIX `0700` on that directory; on the JSON-file fallback the key file itself is `0600`). A key migrated into the OS store becomes unrecoverable if that store is later lost (different OS account, keyring/keychain reset) — inherent to OS-bound storage. If an OS vault exists but is unreachable at startup, KSafe fails closed (`jvm_os_vault_degraded`, `isEncryptionOperational == false`) rather than silently downgrading
* **Web (wasmJs + js):** No hardware security. The AES key is a non-extractable WebCrypto `CryptoKey` in IndexedDB (not exportable by JS); values are in `localStorage`. Both IndexedDB and `localStorage` can be cleared by the user. Outside a secure context there is no `crypto.subtle`, so encrypted ops fail (`web_crypto_subtle_unavailable`). The security checks (root, debugger, debug build, emulator) are all no-ops on both targets — a browser exposes no such signal, so every check reports clean
* **All Platforms:** Encrypted data is lost if encryption keys are deleted (by design for security — see [KEY_ROTATION.md](KEY_ROTATION.md) on what "deleted" means as cryptographic erasure)

***

## Cryptographic Utilities

KSafe exposes two crypto primitives that back its own internals:

- **`secureRandomBytes(size)`** — a cross-platform CSPRNG (cryptographically secure random number generator) delegating to each platform's strongest source: `SecureRandom` on JVM/Android, `SecRandomCopyBytes` on Apple, `crypto.getRandomValues()` on web. This is the same primitive KSafe uses internally for nonces and key generation. It lives in the `internal` package, so the import is `eu.anifantakis.lib.ksafe.internal.secureRandomBytes`.
- **`getOrCreateSecret(key, …)`** — generates a cryptographically secure random secret on first call and returns the same one thereafter, stored under KSafe's encryption. Defaults: `key = "main_db"`, `size = 32` bytes (256-bit), `protection = HARDWARE_ISOLATED`, `requireUnlockedDevice = false`. It **refuses to overwrite** a secret it can't read back (locked vault, invalidated key) rather than silently minting a new one and orphaning data (e.g. a SQLCipher database). Under [key rotation](KEY_ROTATION.md) the secret's **value is preserved** — only the wrapping key changes.

```kotlin
// A 32-byte database passphrase, created once and stable for the life of the install.
// Suspending, so call it from a coroutine.
val passphrase: ByteArray = ksafe.getOrCreateSecret("main_db")

// A one-off random value, e.g. a salt you will store yourself
val salt: ByteArray = secureRandomBytes(16)
```

`getOrCreateSecret` throws `IllegalStateException` if a secret exists but cannot be read back — a locked vault, or a key the OS invalidated. Retry once the vault is reachable; do not catch it and generate a replacement, or whatever the old secret encrypted becomes unreadable.

Custom sizes and the Room + SQLCipher / SQLDelight passphrase recipes are in **[USAGE.md](USAGE.md)**.

***
