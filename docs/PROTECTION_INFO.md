# Protection Info

`KSafe.protectionInfo` is an instance-level diagnostic that tells your app
**exactly what encryption-key custody this `KSafe` is actually running with**,
right now, in this process — including any runtime fallback that happened
during construction.

It complements the two pre-existing surfaces:

| Question | Answered by |
|---|---|
| What's the strongest protection this **device** could provide? | [`KSafe.deviceKeyStorages`](SECURITY.md) — capability probe |
| What protection did this **specific key** get when stored? | [`KSafe.getKeyInfo(key)`](SECURITY.md) — per-key audit |
| **What protection is this `KSafe` instance running at right now?** | **`KSafe.protectionInfo`** — instance audit |

The instance-level audit is the one that catches **silent fallbacks**: a JVM
desktop app that dropped from "Linux Secret Service" to "plaintext file
fallback" because no keyring was reachable, an iOS simulator running without a
Secure Enclave, a Windows machine where DPAPI somehow failed its self-test.

---

## The model

### `KSafeProtectionLevel` — a universally-ordered scale

```kotlin
enum class KSafeProtectionLevel {
    SOFTWARE,             // Key in a software file; OS perms only. JVM fallback.
    SANDBOX_PROTECTED,    // Web (browser origin); JVM (OS user account)
    HARDWARE_BACKED,      // Android TEE; Apple Keychain (default)
    HARDWARE_ISOLATED,    // Android StrongBox; Apple Secure Enclave envelope
}
```

Four values, strictly ordered: higher ordinal = harder for an attacker to
recover the key. Comparable across every platform with a single ordinal
comparison.

> **About data vs. key.** This scale describes the protection of the
> encryption **key**, not the data. KSafe always encrypts payload data with
> AES-256-GCM regardless of level. Even at the weakest rung (`SOFTWARE`) the
> data on disk is still AES-256-GCM ciphertext — what varies across levels
> is how hard it is for an attacker to recover the **key** that decrypts
> that ciphertext. (There is no instance-level "plaintext data" state;
> per-write `KSafeWriteMode.Plain` is a per-value concept surfaced through
> [`KSafeKeyInfo`](SECURITY.md), not through this scale.)

> Distinct from [`KSafeKeyStorage`](SECURITY.md), which is a *device
> capability* vocabulary (`SOFTWARE | HARDWARE_BACKED | HARDWARE_ISOLATED`).
> `KSafeProtectionLevel` is about *negotiated runtime custody* and is the
> value type used by `KSafeProtectionInfo`.

#### Why these specific four rungs?

| Level | Threat it stops |
|---|---|
| `SOFTWARE` | (almost none — key bytes are recoverable from the DataStore file by anyone with disk read as the same OS user; backups and copies expose it intact) |
| `SANDBOX_PROTECTED` | Direct disk read of the key; stolen-disk theft; cross-sandbox access (other origin / other OS user); accidental backups. Same-sandbox code (same origin tab / same-OS-user process) can still ask the runtime for the key. |
| `HARDWARE_BACKED` | Above, plus key extraction from app memory — key operations happen on-chip; raw key never enters userspace. |
| `HARDWARE_ISOLATED` | Above, plus side-channel attacks on the main SoC — key lives on a physically separate chip. |

The `SANDBOX_PROTECTED` rung deliberately lumps two different sandbox
mechanisms because they're peer-strength against the threats this scale
distinguishes:

- **Web (browser-origin sandbox):** WebCrypto enforces non-extractability; the
  key is bound to the origin. The browser's own storage-encryption key is
  wrapped by the OS keyring on every major desktop, so a stolen disk without
  OS login is useless.
- **JVM (OS-user-account sandbox):** DPAPI / Keychain / Secret Service binds
  the key to the OS user login. Stolen disk / other user / different machine
  cannot recover.

Different *boundary* (origin vs. user account), same *strength*. A consumer
that needs to distinguish the two (e.g., a desktop-only app refusing browser
contexts) does it by platform targeting, not by this scale.

`HARDWARE_ISOLATED` is **never** an instance-level baseline today — it's
reachable only via per-write `KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)`.
It earns its slot on the scale so the ceiling isn't artificially capped and so
per-key reporting can use the same vocabulary in the future.

### `KSafeProtectionInfo` — the audit record

```kotlin
data class KSafeProtectionInfo(
    val intendedLevel: KSafeProtectionLevel,
    val effectiveLevel: KSafeProtectionLevel,
    val custody: String,
    val notes: List<String>,
)
```

| Field | Meaning |
|---|---|
| `intendedLevel` | Strongest level this platform's engine targets as its **baseline** at construction time. |
| `effectiveLevel` | Level KSafe actually negotiated. The value to gate on for "is my protection good enough?". |
| `custody` | Human-readable description of where keys actually live. **Display, never parse.** |
| `notes` | Stable lowercase_snake codes describing how/why the effective level differs from intended. Empty when nothing notable. |

When `effectiveLevel == intendedLevel`, the engine got what it wanted. When
`effectiveLevel < intendedLevel`, a runtime fallback happened — `notes`
explains why.

---

## Per-platform truth table

| Platform / outcome | `intendedLevel` | `effectiveLevel` | `custody` | `notes` |
|---|---|---|---|---|
| Android (TEE only) | `HARDWARE_BACKED` | `HARDWARE_BACKED` | `"Android Keystore (TEE)"` | `[]` |
| Android (StrongBox capable) | `HARDWARE_BACKED` | `HARDWARE_BACKED` | `"Android Keystore (TEE; StrongBox available per-write)"` | `[]` |
| iOS / macOS native (SE present) | `HARDWARE_BACKED` | `HARDWARE_BACKED` | `"Apple Keychain (Secure Enclave available per-write)"` | `[]` |
| iOS / macOS native (no SE) | `HARDWARE_BACKED` | `HARDWARE_BACKED` | `"Apple Keychain"` | `["apple_secure_enclave_absent"]` |
| JVM, Windows DPAPI healthy | `SANDBOX_PROTECTED` | `SANDBOX_PROTECTED` | `"Windows DPAPI (CryptProtectData, current-user)"` | `[]` |
| JVM, macOS Keychain healthy | `SANDBOX_PROTECTED` | `SANDBOX_PROTECTED` | `"macOS Keychain (Security.framework, login keychain)"` | `[]` |
| JVM, Linux Secret Service healthy | `SANDBOX_PROTECTED` | `SANDBOX_PROTECTED` | `"Linux Secret Service (libsecret, login keyring)"` | `[]` |
| JVM, OS vault self-test failed | `SANDBOX_PROTECTED` | **`SOFTWARE`** | `"DataStore (software, plaintext — no OS protection)"` (refers to the key, not the data) | `["jvm_os_vault_unavailable"]` |
| JVM, user opted out via `-D` / env | `SANDBOX_PROTECTED` | **`SOFTWARE`** | `"DataStore (software, plaintext — no OS protection)"` (refers to the key, not the data) | `["jvm_user_opted_out"]` |
| Web (wasmJs + js) | `SANDBOX_PROTECTED` | `SANDBOX_PROTECTED` | `"WebCrypto non-extractable key in IndexedDB"` | `[]` |

Observations:

- **`HARDWARE_ISOLATED` never appears in this table** at the instance level. By design — it's a per-write upgrade, not a baseline.
- **Android `intendedLevel` is `HARDWARE_BACKED` even on StrongBox devices.** StrongBox is available *per write*, not as a baseline. Use `deviceKeyStorages` to learn whether StrongBox is available.
- **Web and JVM-vault both report `SANDBOX_PROTECTED`** because they're peer-strength: both protect against stolen-disk theft and cross-sandbox access, both are vulnerable to same-sandbox code.

---

## Defined `notes` codes

Codes are stable across minor versions. Consumers should ignore unknown codes
rather than reject them (new codes may be added without a major version bump).

| Code | Platform | Meaning |
|---|---|---|
| `jvm_os_vault_unavailable` | JVM | OS-vault self-test failed: no libsecret daemon, locked Keychain, JNA link error, etc. Falls back to `DataStoreKeyVault` (plaintext). |
| `jvm_user_opted_out` | JVM | `-Dksafe.jvm.keyVault=software` or env `KSAFE_JVM_KEY_VAULT=software` set. Fallback was requested, not forced. |
| `android_strongbox_absent` | Android | Device lacks StrongBox. Informational at instance level; only meaningful for per-write `HARDWARE_ISOLATED`. (Currently the Android factory does not emit this code at the instance level since baseline is unaffected — reserved for future use.) |
| `apple_secure_enclave_absent` | Apple | Device lacks Secure Enclave (simulator, pre-T2 Intel Mac). Informational at instance level; only meaningful for per-write `HARDWARE_ISOLATED`. |

---

## Consumer usage

### 1. Startup gate

Production app refuses to launch under degraded protection:

```kotlin
val info = ksafe.protectionInfo
check(info.effectiveLevel >= info.intendedLevel) {
    "KSafe protection degraded: " +
        "intended=${info.intendedLevel}, effective=${info.effectiveLevel}, " +
        "custody=${info.custody}, notes=${info.notes}"
}
```

### 2. Threshold-based gating

Pick the bar your threat model demands — every check is a single ordinal
comparison across all platforms:

```kotlin
val info = ksafe.protectionInfo

// Refuse the software-only key custody fallback (JVM with no OS vault)
check(info.effectiveLevel > KSafeProtectionLevel.SOFTWARE)

// Require sandbox-mediated protection (Web origin or OS user account)
check(info.effectiveLevel >= KSafeProtectionLevel.SANDBOX_PROTECTED)

// Require hardware-rooted custody (Android / Apple only)
check(info.effectiveLevel >= KSafeProtectionLevel.HARDWARE_BACKED)
```

### 3. Telemetry

Every field is a stable, low-cardinality identifier:

```kotlin
val info = ksafe.protectionInfo
analytics.log(
    "ksafe_protection",
    mapOf(
        "intended_level" to info.intendedLevel.name,
        "effective_level" to info.effectiveLevel.name,
        "custody" to info.custody,
        "notes" to info.notes.joinToString(","),
    ),
)
```

### 4. UI badge in a settings screen

```kotlin
val info = ksafe.protectionInfo
val badge = when (info.effectiveLevel) {
    KSafeProtectionLevel.SOFTWARE           -> "Software fallback (unsafe)"
    KSafeProtectionLevel.SANDBOX_PROTECTED  -> "Sandbox-protected"
    KSafeProtectionLevel.HARDWARE_BACKED    -> "Hardware-protected"
    KSafeProtectionLevel.HARDWARE_ISOLATED  -> "Hardware-isolated"
}
```

### 5. Diagnostic logging on first run

```kotlin
val info = ksafe.protectionInfo
log.info {
    buildString {
        appendLine("KSafe protection summary:")
        appendLine("  intended:   ${info.intendedLevel}")
        appendLine("  effective:  ${info.effectiveLevel}")
        appendLine("  custody:    ${info.custody}")
        if (info.notes.isNotEmpty()) {
            appendLine("  notes:      ${info.notes.joinToString(", ")}")
        }
    }
}
```

---

## Acting on protection at runtime

The gating example above (refuse to launch) is the simplest case. The deeper
value of `protectionInfo` is **driving feature-level decisions** from
`effectiveLevel` — the actual, negotiated custody level, not what you asked
for. Because `effectiveLevel` is fixed for the instance's lifetime (captured
at construction), one read is enough: propagate the value or a derived policy,
and every downstream branch stays consistent.

A few patterns this enables beyond the startup gate:

### Refuse to persist at all

Some data is too sensitive to write unless you got the custody you wanted.
Keep it in process memory for the session instead of degrading silently to
the file:

```kotlin
when {
    ksafe.protectionInfo.effectiveLevel >= KSafeProtectionLevel.HARDWARE_BACKED -> {
        ksafe.put(
            "biometric_template",
            template,
            KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED),
        )
    }
    else -> {
        inMemoryOnly["biometric_template"] = template   // session-only; lost on process death
    }
}
```

### Tighten the re-auth window

Lower achieved protection → demand fresh authentication more often. The
window shrinks as the trust surface widens:

```kotlin
val reAuthAfter = when (ksafe.protectionInfo.effectiveLevel) {
    KSafeProtectionLevel.SOFTWARE           -> Duration.ZERO        // every sensitive op
    KSafeProtectionLevel.SANDBOX_PROTECTED  -> 5.minutes
    KSafeProtectionLevel.HARDWARE_BACKED    -> 30.minutes
    KSafeProtectionLevel.HARDWARE_ISOLATED  -> 4.hours
}
```

### Disable one feature, keep the rest working

A banking app might keep the general UI live but disable a single high-trust
feature when the device can't store its credentials safely — better than
refusing to launch at all:

```kotlin
val canRememberCardDetails =
    ksafe.protectionInfo.effectiveLevel >= KSafeProtectionLevel.HARDWARE_BACKED

if (canRememberCardDetails) {
    showRememberCardCheckbox()
} else {
    showNote("Card details cannot be remembered on this device.")
}
```

### UX honesty banner

When you do degrade gracefully, tell the user the truth instead of pretending
nothing happened:

```kotlin
if (ksafe.protectionInfo.effectiveLevel == KSafeProtectionLevel.SOFTWARE) {
    showBanner(
        "Your device cannot store this securely. " +
            "We'll keep it for this session only.",
    )
}
```

### Combining intended vs. effective

`intendedLevel` and `effectiveLevel` together let you express "I want to know
specifically when we *fell short*" — distinct from "I always want at least X":

```kotlin
val info = ksafe.protectionInfo
val degraded = info.effectiveLevel < info.intendedLevel
if (degraded) {
    // We aimed higher than we got — log loudly, surface to support, etc.
    crashReporter.report(
        "ksafe_protection_degraded",
        extras = mapOf(
            "intended" to info.intendedLevel.name,
            "effective" to info.effectiveLevel.name,
            "custody" to info.custody,
            "notes" to info.notes.joinToString(","),
        ),
    )
}
```

This is the difference between "you can't run on this device" (an absolute
floor on `effectiveLevel`) and "this specific device experienced a fallback
we should know about" (a delta between `intendedLevel` and `effectiveLevel`).
Most production apps want both: an absolute floor for hard refuses, plus a
delta check for support escalation.

---

## How it relates to the other surfaces

| Surface | Granularity | Question |
|---|---|---|
| `deviceKeyStorages: Set<KSafeKeyStorage>` | Device | "What CAN the device offer?" |
| `protectionInfo: KSafeProtectionInfo` | Instance / process | "What is THIS engine running at right now?" |
| `getKeyInfo(key)?.level: KSafeProtectionLevel` | Per-key | "What did THIS specific write end up using?" |

> **`KSafeKeyInfo` shares the same `KSafeProtectionLevel` scale.** As of 2.1
> the per-key audit record returned by `getKeyInfo(key)` exposes a
> `level: KSafeProtectionLevel` field alongside the legacy `storage`
> ([`KSafeKeyStorage`](SECURITY.md)). `level` uses the same ordinal scale as
> `protectionInfo.effectiveLevel`, so a single threshold works at both the
> instance level and the per-key level:
>
> ```kotlin
> // Instance-level: refuse to launch if engine isn't sandbox-or-better.
> check(ksafe.protectionInfo.effectiveLevel >= KSafeProtectionLevel.SANDBOX_PROTECTED)
>
> // Per-key: refuse to USE this specific token if it didn't end up hardware-backed.
> val tokenLevel = ksafe.getKeyInfo("auth_token")?.level
> check(tokenLevel != null && tokenLevel >= KSafeProtectionLevel.HARDWARE_BACKED)
> ```

A typical production flow uses all three:

1. **At app install**, read `deviceKeyStorages` once to decide whether to offer
   `HARDWARE_ISOLATED` write modes in the UI.
2. **At app startup**, read `protectionInfo` once, gate on `effectiveLevel`,
   and emit a telemetry event with `custody` + `notes`.
3. **On audit / debug screens**, call `getKeyInfo(key)` per-key to verify that
   sensitive writes actually got the protection tier their write mode
   requested.

---

## See also

- **[SECURITY.md](SECURITY.md)** — the broader security model, threat model, encryption internals, and existing `KSafeKeyStorage` / `KSafeKeyInfo` APIs.
- **[JVM_PROTECTION.md](JVM_PROTECTION.md)** — the per-platform deep dive on the JVM key vaults whose status `protectionInfo` reports.
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — where the new types fit in the module / Ring structure.
