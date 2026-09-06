# Protection Info

`KSafe.protectionInfo` tells you where this `KSafe` instance keeps its
encryption key right now, in this process — including any fallback it had to
take. *Custody* means who holds the key and what an attacker has to break to
get at it. The stored data is always AES-GCM ciphertext; custody is about the
key that decrypts it.

Here is what a healthy desktop (JVM) app on macOS prints. The values differ per
platform — the [truth table](#per-platform-truth-table) lists them all:

```kotlin
val info = ksafe.protectionInfo

println(info.effectiveLevel)          // SANDBOX_PROTECTED
println(info.custody)                 // macOS Keychain (Security.framework, login keychain)
println(info.notes)                   // []
println(info.isEncryptionOperational) // true
```

`ksafe` here is an instance from the platform `KSafe(...)` factory — see
[SETUP.md](SETUP.md) and [USAGE.md](USAGE.md) for building one.

It complements two other surfaces:

| Question | Answered by |
|---|---|
| What's the strongest protection this **device** could provide? | [`KSafe.deviceKeyStorages`](SECURITY_MODEL.md) — capability probe |
| What protection did this **specific key** get when stored? | [`KSafe.getKeyInfo(key)`](SECURITY_MODEL.md) — per-key audit |
| **What protection is this `KSafe` instance running at right now?** | **`KSafe.protectionInfo`** — instance audit |

`deviceKeyStorages` speaks a different vocabulary from the other two, so never
compare it to them numerically: it reports `KSafeKeyStorage`, which has no
sandbox rung, so on JVM desktop and web it is always `{SOFTWARE}` even while
`effectiveLevel` reports `SANDBOX_PROTECTED`. `protectionInfo` and
`getKeyInfo(key)` both speak `KSafeProtectionLevel` and *are* comparable.

The instance-level audit is the one that catches **silent fallbacks**: a JVM
desktop app that dropped from "Linux Secret Service" to a plaintext key file
because no keyring was reachable, an iOS Simulator running without a Secure
Enclave, a Windows machine where DPAPI failed the check KSafe runs against it at
start-up. Each of those names is explained under
[Why these specific four rungs?](#why-these-specific-four-rungs).

## It is recomputed on every read

`protectionInfo` is not captured once at construction. Every read rebuilds it
from live state, so a degrade that happens after startup shows up on the next
read with no process restart:

- **JVM** — the OS key vault can die mid-process, when its native library fails
  to link; KSafe then runs on the software vault for the rest of the run. See
  [`JVM_PROTECTION.md`](JVM_PROTECTION.md#compose-desktop-release-distributables-jdkunsupported).
- **Apple** — the iOS-Simulator fallback engages on the first Keychain call the
  Simulator blocks, which is usually after construction.
- **Web** — every read re-asks the browser whether `crypto.subtle` is exposed to
  the page. That answer follows the page's security context, so in practice it
  is settled before the first read and stays put.
- **Android** — custody itself cannot change, but the `notes` list is rebuilt
  each time, because the `android_lock_screen_absent` disclosure depends on the
  device's current lock-screen state and on which key is in use.

A read is cheap on every platform, but it is not free on Android: it asks the
system whether the device has a secure lock screen, and the first read after
construction may also read the store once. Read it at startup and keep the
result; re-read when you want to see a later degrade.

---

## The model

### `KSafeProtectionLevel` — a universally-ordered scale

```kotlin
enum class KSafeProtectionLevel {
    // Key bytes in a plain file, OS permissions only — the JVM and iOS-Simulator
    // fallbacks. Also reported when web encryption is unavailable, and for a plaintext entry.
    SOFTWARE,
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
> that ciphertext. (No instance ever reports "plaintext data" — that is a
> per-write choice, `KSafeWriteMode.Plain`. A plaintext entry does appear on
> this scale through [`getKeyInfo(key)`](SECURITY_MODEL.md): it reports
> `protection = null` and `level = SOFTWARE`, so a per-key threshold rejects it
> like any other unprotected key.)

> Distinct from [`KSafeKeyStorage`](SECURITY_MODEL.md), which is a *device
> capability* vocabulary (`SOFTWARE | HARDWARE_BACKED | HARDWARE_ISOLATED`).
> `KSafeProtectionLevel` is about *negotiated runtime custody* and is the
> value type used by `KSafeProtectionInfo`.

#### Why these specific four rungs?

The rungs name real hardware and OS features. In one line each:

- **TEE** (Android) — a secure area of the main chip. The Keystore runs key
  operations inside it and never hands the key bytes to your app.
- **StrongBox** (Android) — a separate security chip, present on some devices.
- **Keychain** (Apple) — the OS-managed secret store.
- **Secure Enclave** (Apple) — Apple's separate security chip. It holds
  elliptic-curve keys only, so KSafe uses it to wrap an AES key rather than to
  hold one.
- **DPAPI / login Keychain / Secret Service** (JVM desktop) — the Windows,
  macOS and Linux stores that tie a secret to the logged-in OS user.
- **WebCrypto** (browser) — the browser's crypto API. KSafe creates the key
  non-extractable, so page code can use it but cannot read its bytes.

| Level | Threat it stops |
|---|---|
| `SOFTWARE` | Almost none. The key bytes sit in a file any process running as this OS user can read, and copies and backups carry them intact. |
| `SANDBOX_PROTECTED` | Reading the key off the disk, a stolen disk, another origin or another OS user, and accidental backups. Code inside the same sandbox — a script on the same origin, a process as the same OS user — can still ask the runtime to use the key. |
| `HARDWARE_BACKED` | All of the above, plus recovering the stored key from disk, backups or a powered-off device: it is wrapped by a key the hardware will not export, so what is at rest is useless without the device. |
| `HARDWARE_ISOLATED` | All of the above, plus attacks on the main chip — the key lives on a physically separate one. |

Two exceptions are worth stating plainly.

At `HARDWARE_BACKED` the working AES key is unwrapped into your process's
memory to do the actual encryption — the standard envelope model, used by Apple
and JVM always, and by Android since 2.1.2 for ordinary encrypted writes (an
Android write that asks for `requireUnlockedDevice` keeps its key inside the
chip instead). An attacker who can read live process memory is therefore **not**
stopped at this rung.

At `HARDWARE_ISOLATED` that changes only on Android: StrongBox and the TEE run
the AES operation on-chip, so the key bytes never enter RAM. On Apple only the
wrapping key lives on the Secure Enclave; the AES key it protects is still
unwrapped into memory and the encryption runs in CryptoKit. So this rung stops
a live-memory compromise on Android, not on Apple.

The `SANDBOX_PROTECTED` rung deliberately covers two different sandbox
mechanisms, because they are peer-strength against the threats this scale
distinguishes:

- **Web (browser-origin sandbox):** the key is created non-extractable and
  bound to the page's origin, so page code — including injected script — can
  use it but cannot read its bytes or reach it from another origin.
- **JVM (OS-user-account sandbox):** DPAPI / Keychain / Secret Service binds
  the key to the OS user login. A stolen disk, another user or another machine
  cannot recover it.

Different *boundary* (origin vs. user account), same *strength*. An app that
needs to tell the two apart does it by platform targeting, not by this scale.

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
| `intendedLevel` | The baseline this platform aims for. Fixed per platform and never changes at runtime: `HARDWARE_BACKED` on Android and Apple, `SANDBOX_PROTECTED` on JVM desktop and web. |
| `effectiveLevel` | Level KSafe actually negotiated. The value to gate on for "is my protection good enough?". |
| `custody` | Human-readable description of where keys actually live. **Display, never parse.** |
| `notes` | Stable lowercase_snake codes on the negotiation outcome — how/why the effective level differs from intended, or a custody detail worth disclosing at the intended level. Empty when nothing is notable, except on Android, which always reports at least `relaxed_default_uses_software_dek`. |
| `kSafeVersion` | Published version of the linked KSafe artifact. Same value as the public `KSafe.VERSION` constant. Useful in demo / sample apps that load multiple KSafe versions side-by-side, in audit logs, and in crash telemetry. (Added in 2.1.1.) |
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
| Android API 28-34, no secure lock screen | `HARDWARE_BACKED` | `HARDWARE_BACKED` | as in the two rows above | as in the matching row above, plus `"android_lock_screen_absent"` |
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
- **The JVM software-fallback `custody` string names the backend that holds the key.** It reads `"DataStore (software, …)"` on the DataStore backend, but `"JSON file (software, …)"` (`<base>.ksafe-keys.json`) on a desktop runtime trimmed of `sun.misc.Unsafe`, which DataStore needs (see [JVM_PROTECTION.md](JVM_PROTECTION.md#compose-desktop-release-distributables-jdkunsupported)). Treat `custody` as display-only either way.
- **The iOS-Simulator fallback says "sandbox" in its custody text but reports `SOFTWARE`.** The key bytes sit in a plain file in the app's container, readable by anyone with access to that directory on the host Mac. `SANDBOX_PROTECTED` is reserved for a key the runtime will not hand over at all.

---

## Defined `notes` codes

Codes are stable across minor versions. Ignore codes you do not recognise
rather than failing on them — new ones can appear in a minor release.

Four terms recur below. *Minting* is creating a new key. The *start-up check*
is a canary write-read-delete KSafe performs against an OS key vault before it
trusts the vault with real keys. A *DEK* (data-encryption key) is the AES key
that actually encrypts your values; it is itself wrapped by a key the platform
key store will not export. A *relaxed* `DEFAULT` write is an ordinary encrypted
write — one that asked neither for `HARDWARE_ISOLATED` nor for
`requireUnlockedDevice`, so its key stays usable while the device is locked.

Exactly two codes are **non-operational** — they mean "encrypted ops will not
succeed" and drive `isEncryptionOperational == false`: `web_crypto_subtle_unavailable`
and `jvm_os_vault_degraded`. Every other code is a weaker-but-working state.

| Code | Platform | Operational? | Meaning |
|---|---|---|---|
| `jvm_os_vault_unavailable` | JVM | **Yes** — software fallback works | No OS key vault is in use: none exists for this operating system, the one that does could not be built, or its native library could not link — at start-up or later in the process. Keys go to the software vault — the DataStore key file, or a plain JSON key file on a trimmed desktop runtime (see [JVM_PROTECTION.md](JVM_PROTECTION.md#compose-desktop-release-distributables-jdkunsupported)) — so encrypted reads and writes keep working at weaker custody. |
| `jvm_os_vault_degraded` | JVM | **No** — encrypted ops throw | An OS key vault **exists and links**, but failed its start-up check: a locked Keychain, a login keyring not yet reachable, a headless launch. The real keys are almost certainly inside it, so KSafe refuses to mint keys into the software vault — a fresh key there would overwrite the real one on the next healthy launch. Encrypted reads and writes fail until the vault is reachable. Retry once it is unlocked, or set `-Dksafe.jvm.keyVault=software` to accept the software fallback. (A vault whose native library cannot link is a different outcome and reports `jvm_os_vault_unavailable`.) |
| `jvm_user_opted_out` | JVM | **Yes** — software fallback requested | `-Dksafe.jvm.keyVault=software` or env `KSAFE_JVM_KEY_VAULT=software` is set. The fallback was asked for, not forced. |
| `android_strongbox_absent` | Android | Yes | The device has no StrongBox chip, or runs below Android 9, where StrongBox does not exist. Informational at instance level — the `HARDWARE_BACKED` baseline is unaffected; it only matters for a per-write `HARDWARE_ISOLATED`. |
| `android_lock_screen_absent` | Android | Yes | The device has no secure lock screen, and below API 35 the Keystore cannot mint a key bound to an unlock that does not exist — so `requireUnlockedDevice` keys are minted without `setUnlockedDeviceRequired`. Those writes still take the per-operation TEE path, never the in-memory DEK. Re-evaluated on every `protectionInfo` read, and reported while *either* the next mint would be relaxed *or* the key in use was minted that way. Keystore parameters are fixed at mint time, so adding a lock screen does not re-bind an existing key: the note stays until a new key generation replaces it. Rotation is opt-in (`KSafeConfig.keyRotationPolicy` defaults to `Never`), so call `rotateKeys()` once, or configure a policy, to get the binding back. Only API 28-34 without a secure lock screen starts emitting it; a device that later upgrades to API 35+ keeps reporting it while that key is still in use. |
| `relaxed_default_uses_software_dek` | Android | Yes | Always present on Android. Relaxed `DEFAULT` encrypted values use an AES key that the non-exportable Keystore key wraps but which is unwrapped into process memory after first use; `HARDWARE_ISOLATED` and `requireUnlockedDevice` writes keep the per-operation TEE path. Custody is still hardware-rooted, so the level is unchanged — the note exists so `protectionInfo` discloses the in-memory key. |
| `apple_secure_enclave_absent` | Apple | Yes | The device has no Secure Enclave (Simulator, pre-T2 Intel Mac). Informational at instance level; it only matters for a per-write `HARDWARE_ISOLATED`. |
| `apple_keychain_entitlement_missing` | Apple (iOS Simulator only) | Yes — sandbox fallback works | The Keychain rejected the process with `errSecMissingEntitlement` (-34018) — the app has no signing team or Keychain Sharing capability, common on unsigned Simulator builds. Keys fall back to a file in the app's container so encrypted writes keep working; fix the Xcode signing setup to test real Keychain behaviour. Never emitted on a real device — there a -34018 still fails loudly. |
| `web_crypto_subtle_unavailable` | Web (wasmJs + js) | **No** — encrypted ops fail | The page is not a secure context, so `crypto.subtle` (WebCrypto) is absent and **every encrypted read and write fails** — encryption is non-operational here, not merely weak. Serve over HTTPS or from a `localhost` origin to restore it. |

---

## Consumer usage

The consumer is your app — the code calling KSafe. Five ways it reads
`protectionInfo`.

### 1. Startup gate

Refuse to launch when protection came out weaker than this platform aims for:

```kotlin
val info = ksafe.protectionInfo
check(info.effectiveLevel >= info.intendedLevel) {
    "KSafe protection degraded: " +
        "intended=${info.intendedLevel}, effective=${info.effectiveLevel}, " +
        "custody=${info.custody}, notes=${info.notes}"
}
```

This gate asks about **strength**, and it is strict: it also fails on an iOS
Simulator without Keychain entitlements and on a desktop that fell back to the
software vault — both of which encrypt and decrypt correctly. Use it in
production builds, not development ones. When the question is whether encrypted
writes will work at all, gate on `isEncryptionOperational` instead.

### 2. Threshold-based gating

Pick the bar your threat model demands — every check is one ordinal comparison,
the same on every platform:

```kotlin
val info = ksafe.protectionInfo

// Refuse software-only key custody: a JVM host with no OS vault, an iOS
// Simulator with no Keychain entitlement, a page with no crypto.subtle.
check(info.effectiveLevel > KSafeProtectionLevel.SOFTWARE)

// Require sandbox-mediated protection (browser origin or OS user account).
// Android and Apple hardware clear this bar too; a JVM host needs a healthy
// OS vault, and a web page needs a secure context.
check(info.effectiveLevel >= KSafeProtectionLevel.SANDBOX_PROTECTED)

// Require hardware-rooted custody. Only Android and Apple can ever pass this.
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
    // Never reached at instance level; the branch keeps the `when` exhaustive.
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

The gating example above is the simplest case. The more useful move is to let
`effectiveLevel` — the custody you actually got, not the one you asked for —
drive feature decisions.

One read at startup is enough for most apps: `effectiveLevel` does not change
during a run on Android, on Apple hardware, or on web. It can change on a JVM
desktop, when the OS key vault dies mid-process, and on an iOS Simulator, when
the first blocked Keychain call engages the file fallback — both changes are
one-way and stick for the rest of the run. Bind the value to your UI or metrics
if you want such a change to show up without a restart.

Two patterns follow.

### Refuse to persist at all

Some data is too sensitive to write unless you got the custody you wanted. Keep
it in memory for the session rather than writing it under weaker custody:

```kotlin
// put suspends until the write is committed, so this lives in a coroutine.
suspend fun storeTemplate(template: String) {
    if (ksafe.protectionInfo.effectiveLevel >= KSafeProtectionLevel.HARDWARE_BACKED) {
        ksafe.put(
            "biometric_template",
            template,
            KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED),
        )
    } else {
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
> `level: KSafeProtectionLevel` field alongside `storage`
> ([`KSafeKeyStorage`](SECURITY_MODEL.md)), which is deprecated in favour of
> `level` and goes away in 4.0.0. `level` uses the same ordinal scale as
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

- **[SECURITY_MODEL.md](SECURITY_MODEL.md)** — the broader security model, threat model, encryption internals, and the `KSafeKeyStorage` / `KSafeKeyInfo` APIs.
- **[JVM_PROTECTION.md](JVM_PROTECTION.md)** — the per-platform deep dive on the JVM key vaults whose status `protectionInfo` reports (including the `jvm_os_vault_degraded` fail-closed behaviour).
- **[KEY_ROTATION.md](KEY_ROTATION.md)** — key generations and the v3 authenticated envelope, which change neither `effectiveLevel` nor `custody`.
- **[USAGE.md](USAGE.md)** — the general usage guide: building an instance, the write modes, and the rest of the API.
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — where these types sit in the module structure, plus the protection-tier honesty pattern and the operational preflight.
