# Protection Info

`KSafe.protectionInfo` is an instance-level diagnostic that tells your app
**exactly what encryption-key custody this `KSafe` is actually running with**,
right now, in this process — including any fallback that happened at
construction *or* later in the process lifecycle.

Prior to 2.1.1 the property was captured once at construction. From 2.1.1
it's recomputed on every access, so a JVM runtime degrade (e.g. a JNA call
that fails mid-process with a `LinkageError` and flips to the software vault —
see
[`JVM_PROTECTION.md`](JVM_PROTECTION.md#compose-desktop-release-distributables-jdkunsupported))
shows up on the next read without a process restart. Android custody can't
change after construction, so its provider returns a fixed snapshot. Apple and
Web recompute cheaply on every access, because their custody *can* degrade later
in the process — an iOS-Simulator Keychain fallback engages lazily on the first
entitlement-blocked key op, and a browser's `crypto.subtle` availability tracks
the page's security context — either can flip `effectiveLevel` to `SOFTWARE`
after construction, and the per-access re-check surfaces it. All of these are
cheap flag reads: there is no per-access cost worth worrying about.

It complements the two pre-existing surfaces:

| Question | Answered by |
|---|---|
| What's the strongest protection this **device** could provide? | [`KSafe.deviceKeyStorages`](SECURITY_MODEL.md) — capability probe |
| What protection did this **specific key** get when stored? | [`KSafe.getKeyInfo(key)`](SECURITY_MODEL.md) — per-key audit |
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
> AES-GCM — `KSafeAesKeySize.BITS_256` by default, or `BITS_128` via
> `KSafeConfig.aesKeySize` on every platform — regardless of level. Existing
> keys retain their size until rotation. Even at
> the weakest rung (`SOFTWARE`) the
> data on disk is still AES-GCM ciphertext — what varies across levels
> is how hard it is for an attacker to recover the **key** that decrypts
> that ciphertext. (There is no instance-level "plaintext data" state;
> per-write `KSafeWriteMode.Plain` is a per-value concept surfaced through
> [`KSafeKeyInfo`](SECURITY_MODEL.md), not through this scale.)

> Distinct from [`KSafeKeyStorage`](SECURITY_MODEL.md), which is a *device
> capability* vocabulary (`SOFTWARE | HARDWARE_BACKED | HARDWARE_ISOLATED`).
> `KSafeProtectionLevel` is about *negotiated runtime custody* and is the
> value type used by `KSafeProtectionInfo`.

#### Why these specific four rungs?

| Level | Threat it stops |
|---|---|
| `SOFTWARE` | (almost none — key bytes are recoverable from the on-disk software key file by anyone with disk read as the same OS user; backups and copies expose it intact) |
| `SANDBOX_PROTECTED` | Direct disk read of the key; stolen-disk theft; cross-sandbox access (other origin / other OS user); accidental backups. Same-sandbox code (same origin tab / same-OS-user process) can still ask the runtime for the key. |
| `HARDWARE_BACKED` | Above, plus extraction of the *durable* key from disk, backups, or a powered-off device — it is wrapped by a non-exportable hardware key (TEE / Keychain / OS vault), so what's at rest is useless without the device. The working AES key is unwrapped into app memory for userspace crypto (the standard envelope model — Apple/JVM always, Android since 2.1.2), so a *live* process-memory compromise is **not** stopped at this rung — that's `HARDWARE_ISOLATED`. |
| `HARDWARE_ISOLATED` | Above, plus side-channel attacks on the main SoC — the key lives on a physically separate chip. On **Android StrongBox/TEE** the per-operation AES runs on-chip, so the key bytes never enter RAM and a live process-memory compromise is stopped here. On **Apple** only the EC wrapping key lives on the Secure Enclave (which is EC-only); the working AES DEK is still unwrapped into RAM and AES-GCM runs in CryptoKit, so this rung does *not* fully stop a live-memory compromise on Apple — only on Android StrongBox/TEE. |

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
    val kSafeVersion: String,   // 2.1.1+: same as KSafe.VERSION, single source of truth in gradle.properties
) {
    // Computed val (new in 3.0.0): true wherever encrypted ops actually work,
    // including the weaker-but-working JVM-software and iOS-Simulator fallbacks.
    val isEncryptionOperational: Boolean
}
```

| Field | Meaning |
|---|---|
| `intendedLevel` | Strongest level this platform's engine targets as its **baseline** at construction time. |
| `effectiveLevel` | Level KSafe actually negotiated. The value to gate on for "is my protection good enough?". |
| `custody` | Human-readable description of where keys actually live. **Display, never parse.** |
| `notes` | Stable lowercase_snake codes on the negotiation outcome — how/why the effective level differs from intended, or a custody detail worth disclosing at the intended level. Empty when nothing is notable. |
| `kSafeVersion` | Published version of the linked KSafe artifact (e.g. `"3.0.0"`). Same value as the public [`KSafe.VERSION`] constant. Useful in demo / sample apps that load multiple KSafe versions side-by-side, in audit logs, and in crash telemetry. (Added in 2.1.1.) |
| `isEncryptionOperational` | **(New in 3.0.0.)** Computed `val` — the cross-platform *"will an encrypted write actually succeed?"* preflight, distinct from protection **strength**. `true` wherever encryption works, **including** the weaker JVM-software and iOS-Simulator sandbox fallbacks; `false` only when a `notes` code marks the engine non-operational (see below). |

When `effectiveLevel == intendedLevel`, the engine got what it wanted. When
`effectiveLevel < intendedLevel`, a runtime fallback happened — `notes`
explains why. A fallback is **not** the same as a failure: use
`isEncryptionOperational` (not the level inequality) to answer *"will encrypted
ops succeed?"*.

> **Note.** [Key rotation](KEY_ROTATION.md) (generation counter, the v3
> authenticated envelope after the first `rotateKeys()`) changes neither
> `effectiveLevel` nor `custody` — the key still lives in the same custody; only
> the wrapping key and envelope binding change. `protectionInfo` reports custody
> strength, independent of generation.

> **Two different questions, two different gates — don't conflate them.**
> `effectiveLevel < intendedLevel` answers *"is protection at its intended strength?"*
> A fallback can still be fully **operational**: a JVM software vault and an
> iOS-Simulator sandbox store both report `SOFTWARE` and encrypt/decrypt fine. To
> answer *"will encrypted reads/writes actually succeed?"*, gate on
> `isEncryptionOperational`, **not** the level. Using the level inequality for this
> would wrongly reject every iOS-Simulator run and every headless desktop that fell
> back to the software vault — all of which encrypt fine.
>
> ```kotlin
> val info = ksafe.protectionInfo
>
> // "Will encrypted reads/writes actually SUCCEED?" — operational preflight.
> if (!info.isEncryptionOperational) {
>     // Non-operational: web served without crypto.subtle, or a JVM OS vault that
>     // exists but is unreachable at startup. Encrypted ops will THROW here.
> }
>
> // "Is protection at its intended STRENGTH?" — a different question.
> // A software fallback is operational (isEncryptionOperational == true) yet weaker
> // than intended (effectiveLevel < intendedLevel). Don't answer the first with this.
> val degraded = info.effectiveLevel < info.intendedLevel
> ```
>
> `isEncryptionOperational` is the convenience form of "no non-operational `notes`
> code present," so consumers don't hardcode the code strings. There are exactly two
> non-operational codes (`web_crypto_subtle_unavailable`, `jvm_os_vault_degraded`); it
> stays `true` for every other outcome, including the weaker-but-working JVM-software
> and iOS-Simulator fallbacks.

---

## Per-platform truth table

| Platform / outcome | `intendedLevel` | `effectiveLevel` | `custody` | `notes` |
|---|---|---|---|---|
| Android (TEE only) | `HARDWARE_BACKED` | `HARDWARE_BACKED` | `"Android Keystore (TEE; relaxed DEFAULT values use a TEE-wrapped AES key held in memory)"` | `["android_strongbox_absent", "relaxed_default_uses_software_dek"]` |
| Android (StrongBox capable) | `HARDWARE_BACKED` | `HARDWARE_BACKED` | `"Android Keystore (TEE; StrongBox available per-write; relaxed DEFAULT values use a TEE-wrapped AES key held in memory)"` | `["relaxed_default_uses_software_dek"]` |
| iOS / macOS native (SE present) | `HARDWARE_BACKED` | `HARDWARE_BACKED` | `"Apple Keychain (Secure Enclave available per-write)"` | `[]` |
| iOS / macOS native (no SE) | `HARDWARE_BACKED` | `HARDWARE_BACKED` | `"Apple Keychain"` | `["apple_secure_enclave_absent"]` |
| iOS Simulator, Keychain entitlement missing | `HARDWARE_BACKED` | **`SOFTWARE`** | `"Sandbox file key store (iOS Simulator fallback — Keychain entitlement missing)"` | `["apple_keychain_entitlement_missing", "apple_secure_enclave_absent"]` |
| JVM, Windows DPAPI healthy | `SANDBOX_PROTECTED` | `SANDBOX_PROTECTED` | `"Windows DPAPI (CryptProtectData, current-user)"` | `[]` |
| JVM, macOS Keychain healthy | `SANDBOX_PROTECTED` | `SANDBOX_PROTECTED` | `"macOS Keychain (Security.framework, login keychain)"` | `[]` |
| JVM, Linux Secret Service healthy | `SANDBOX_PROTECTED` | `SANDBOX_PROTECTED` | `"Linux Secret Service (libsecret, login keyring)"` | `[]` |
| JVM, no OS vault reachable (software fallback — **operational**) | `SANDBOX_PROTECTED` | **`SOFTWARE`** | `"DataStore (software, plaintext — no OS protection)"` (refers to the key, not the data) | `["jvm_os_vault_unavailable"]` |
| JVM, OS vault exists but unreachable at startup (**non-operational** — encrypted ops throw) | `SANDBOX_PROTECTED` | **`SOFTWARE`** | `"DataStore (software, plaintext — no OS protection)"` — the store is held but KSafe refuses to mint a key into it | `["jvm_os_vault_degraded"]` |
| JVM, user opted out via `-D` / env (software fallback — **operational**) | `SANDBOX_PROTECTED` | **`SOFTWARE`** | `"DataStore (software, plaintext — no OS protection)"` (refers to the key, not the data) | `["jvm_user_opted_out"]` |
| Web (wasmJs + js), secure context | `SANDBOX_PROTECTED` | `SANDBOX_PROTECTED` | `"WebCrypto non-extractable key in IndexedDB"` | `[]` |
| Web (wasmJs + js), non-secure context | `SANDBOX_PROTECTED` | **`SOFTWARE`** | `"WebCrypto (crypto.subtle) unavailable — not a secure context; encrypted reads/writes will fail. …"` | `["web_crypto_subtle_unavailable"]` |

Observations:

- **`HARDWARE_ISOLATED` never appears in this table** at the instance level. By design — it's a per-write upgrade, not a baseline.
- **Android `intendedLevel` is `HARDWARE_BACKED` even on StrongBox devices.** StrongBox is available *per write*, not as a baseline. Use `deviceKeyStorages` to learn whether StrongBox is available.
- **Web and JVM-vault both report `SANDBOX_PROTECTED`** because they're peer-strength: both protect against stolen-disk theft and cross-sandbox access, both are vulnerable to same-sandbox code.
- **The JVM software-fallback `custody` string names the backend that holds the key.** It reads `"DataStore (software, …)"` on the DataStore backend, but `"JSON file (software, …)"` (`<base>.ksafe-keys.json`) on the jlink-trimmed no-`Unsafe` backend. Treat `custody` as display-only either way.

---

## Defined `notes` codes

Codes are stable across minor versions. Consumers should ignore unknown codes
rather than reject them (new codes may be added without a major version bump).

Exactly two codes are **non-operational** — they mean "encrypted ops will not
succeed" and drive `isEncryptionOperational == false`: `web_crypto_subtle_unavailable`
and `jvm_os_vault_degraded`. Every other code is a weaker-but-working state.

| Code | Platform | Operational? | Meaning |
|---|---|---|---|
| `jvm_os_vault_unavailable` | JVM | **Yes** — software fallback works | No OS secret store is reachable on this host (no libsecret daemon, unsupported OS). Keys fall back to `DataStoreKeyVault` (plaintext key). Weaker than intended, but encrypted ops still succeed. |
| `jvm_os_vault_degraded` | JVM | **No** — encrypted ops throw | An OS secret store **exists** but failed its startup self-test (locked Keychain/keyring, headless launch, JNA link error). To avoid overwriting the real OS key on a later healthy launch, KSafe refuses to mint keys, so encrypted reads/writes fail until the store is reachable. Retry once unlocked, or set `-Dksafe.jvm.keyVault=software` to accept the software fallback. |
| `jvm_user_opted_out` | JVM | **Yes** — software fallback requested | `-Dksafe.jvm.keyVault=software` or env `KSAFE_JVM_KEY_VAULT=software` set. Fallback was requested, not forced. |
| `android_strongbox_absent` | Android | Yes | Device lacks StrongBox; emitted by the Android factory whenever the probe comes back negative. Informational at instance level (the `HARDWARE_BACKED` baseline is unaffected); only meaningful for per-write `HARDWARE_ISOLATED`. |
| `relaxed_default_uses_software_dek` | Android | Yes | Always present on Android. Relaxed `DEFAULT` encrypted values use an AES key that the non-exportable Keystore master key wraps but which is unwrapped into process memory after first use; `HARDWARE_ISOLATED` and `requireUnlockedDevice` writes keep the per-op TEE path. Custody stays hardware-rooted, so the level is unchanged — the note exists so `protectionInfo` discloses the in-memory key. |
| `apple_secure_enclave_absent` | Apple | Yes | Device lacks Secure Enclave (simulator, pre-T2 Intel Mac). Informational at instance level; only meaningful for per-write `HARDWARE_ISOLATED`. |
| `apple_keychain_entitlement_missing` | Apple (iOS Simulator only) | Yes — sandbox fallback works | The Keychain rejected the process with `errSecMissingEntitlement` (-34018) — the app has no signing team / Keychain Sharing capability, common on unsigned Simulator builds. Keys fall back to a sandbox file store so encrypted writes keep working; fix the Xcode signing setup to test real Keychain behavior. Never emitted on a real device — there a -34018 still fails loudly. |
| `web_crypto_subtle_unavailable` | Web (wasmJs + js) | **No** — encrypted ops fail | The page is not a secure context, so `crypto.subtle` (WebCrypto) is absent and **every encrypted read/write fails** — encryption is non-operational here, not merely weak. Serve over HTTPS or from a `localhost` origin to restore it. |

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
for. From 2.1.1, `effectiveLevel` is recomputed per access (so a JVM runtime
degrade is visible without restart); in practice it's stable across the
process lifetime on every platform except JVM, and even there it only changes
at most once (an OS-vault failure is sticky). One read at startup is enough
for most flows; bind it to UI / metrics if you want it to track a possible
mid-process JVM degrade automatically.

Two representative patterns follow. For the wider catalogue — re-auth-window
tightening, feature-gating a single high-trust flow, UX honesty banners — see
[USAGE.md](USAGE.md).

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

The three surfaces — `deviceKeyStorages` (device capability), `protectionInfo`
(this instance right now), and `getKeyInfo(key)` (per-key) — are compared in the
[table at the top of this document](#protection-info). This section adds the
per-key detail and the flow that combines all three.

> **`KSafeKeyInfo` shares the same `KSafeProtectionLevel` scale.** As of 2.1
> the per-key audit record returned by `getKeyInfo(key)` exposes a
> `level: KSafeProtectionLevel` field alongside the legacy `storage`
> ([`KSafeKeyStorage`](SECURITY_MODEL.md)). `level` uses the same ordinal scale as
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

- **[SECURITY_MODEL.md](SECURITY_MODEL.md)** — the broader security model, threat model, encryption internals, and existing `KSafeKeyStorage` / `KSafeKeyInfo` APIs.
- **[JVM_PROTECTION.md](JVM_PROTECTION.md)** — the per-platform deep dive on the JVM key vaults whose status `protectionInfo` reports (including the `jvm_os_vault_degraded` fail-closed behaviour).
- **[KEY_ROTATION.md](KEY_ROTATION.md)** — key generations and the v3 authenticated envelope, which change neither `effectiveLevel` nor `custody`.
- **[USAGE.md](USAGE.md)** — the wider catalogue of runtime-gating patterns driven by `effectiveLevel`.
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — where the new types fit in the module / Ring structure.
