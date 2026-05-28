# JVM Key Protection

This document explains how KSafe protects its AES-256-GCM data-encryption key on
the JVM target, on every host platform it supports, and what happens when no
OS-backed secret store is reachable.

> Scope: this is about **where the raw key bytes live on disk and which process
> is allowed to recover them**. The encryption itself (AES-256-GCM with a
> per-record 12-byte IV) is identical across all three OSes — only key custody
> changes.

---

## The problem

Unlike Android (Keystore, optionally StrongBox-isolated) and iOS/macOS native
(Keychain + Secure Enclave), the **JVM has no standard hardware keystore**.
Through KSafe 2.0, the AES key was simply Base64-encoded into the same
DataStore preferences file as the ciphertext it was meant to protect:

```
<user.home>/.eu_anifantakis_ksafe/
└── ksafe.preferences_pb     ← ciphertext AND Base64(key) side by side
```

Anyone who could read that one file as the same user could decrypt every
record. Stolen disks, accidental backups, rsync-to-Dropbox, file-sharing slips
— all leaked the key.

From 2.1.0, KSafe instead hands the raw key bytes to the host OS's per-user
secret store at first use, and the DataStore file then holds **ciphertext
only**. The custody chain becomes:

```
KSafe → JvmKeyVault (selected per-OS) → OS secret store
```

Implementation: `ksafe/src/jvmMain/.../internal/keyvault/`. Selection happens
once per engine instance in `JvmKeyVaultProvider.pick()`.

---

## Selection flow

```
                            ┌─ os.name contains "win"      → WindowsDpapiKeyVault
                            │
JvmKeyVaultProvider.pick()──┼─ os.name contains "mac"|"darwin" → MacosKeychainKeyVault
                            │
                            ├─ os.name contains "nux"|"nix"|"aix" → LinuxSecretServiceKeyVault
                            │
                            └─ anything else, or JNA/link failure → null
                                                                       │
                                                                       ▼
                                          selfTest(canary put/get/delete) ── pass ──► use it
                                                                       │
                                                                      fail ──► DataStoreKeyVault (warn once)
```

Every OS-backed vault runs a **self-test** before being accepted: it stores a
5-byte canary (`"KSafe"`), reads it back, and deletes it. If anything in that
round-trip fails (no daemon running, locked keychain, missing library, broken
JNA link), selection silently falls back to `DataStoreKeyVault` and prints
one warning per process to `System.err`.

---

## Platform: Windows — DPAPI

**Class:** `WindowsDpapiKeyVault`
**API:** `CryptProtectData` / `CryptUnprotectData` via JNA's `jna-platform`
(`com.sun.jna.platform.win32.Crypt32Util`).

**What DPAPI is.** The Data Protection API is a Windows OS service that
encrypts ("wraps") a byte array using a key chain ultimately derived from the
current user's login credentials. Crucially, **DPAPI doesn't store anything** —
it just hands you an opaque ciphertext blob that only the same Windows user on
the same machine can later unprotect.

**How KSafe uses it.**

1. On first key creation, KSafe generates 32 random bytes of AES key material.
2. It hands those bytes to `CryptProtectData` (current-user scope, the
   `Crypt32Util` default).
3. The returned wrapped blob is Base64-encoded and persisted in the DataStore
   file under the key `ksafe_dpapi_<appNamespace>_<alias>`.
4. On read, the inverse: load the blob, `CryptUnprotectData` → raw key.

Storing the wrapped blob in a file is safe because the blob is cryptographically
useless to anyone who is not logged in as that specific Windows user on that
specific machine. Copying `ksafe.preferences_pb` to a different account or a
different PC does not get you the key.

**What it defends against:**

- Offline disk theft (the laptop is gone, the user isn't logged in).
- Accidental backups, file copies, syncs — the blob is encrypted.
- Read access from another user on the same Windows machine (different login
  → different DPAPI key chain).

**What it does NOT defend against:**

- Code running as the same Windows user while logged in. DPAPI transparently
  unprotects for any process running as the owning user. The library does not
  prompt or require additional consent.
- A Windows administrator with active session-hijack capabilities (token
  impersonation, LSASS dumps).
- Loss of the user's Windows password without a recovery key — recovery here
  is a Windows concern, not a KSafe one.

---

## Platform: macOS — login Keychain

**Class:** `MacosKeychainKeyVault`
**API:** `SecKeychainAddGenericPassword` / `…Find…` / `SecKeychainItemDelete`
via JNA bindings to `Security.framework`.

**What the Keychain is.** macOS's per-user encrypted store for credentials and
small secrets. On Apple Silicon and T2 Intel Macs the keychain's key hierarchy
is gated by the **Secure Enclave Processor (SEP)** — the master key never
leaves dedicated hardware. On older Intel Macs without a T2, the keychain is
encrypted with a key derived from the user's login password (and unlocked at
login).

**How KSafe uses it.**

1. KSafe stores the 32-byte AES key as a **generic password** item with:
   - `service`: `eu.anifantakis.ksafe[.<appNamespace>]`
   - `account`: the bare alias
   - `passwordData`: the raw key bytes (no separate file persistence at all)
2. On read, `SecKeychainFindGenericPassword` returns the bytes directly from
   the Keychain.
3. On replace, KSafe deletes-then-adds (simplest correct upsert without
   building a `SecKeychainAttributeList`).

> **API choice.** KSafe uses the classic `SecKeychain*` generic-password API,
> which Apple marks deprecated in favour of the modern `SecItem*`
> data-protection API. It is still fully functional on current macOS, and is
> dramatically simpler to bind from JVM (plain C strings + byte buffers vs.
> constructing CoreFoundation dictionaries). The chosen scope is *standard
> login/data-protection Keychain, not Secure Enclave for the raw key* — a JVM
> process cannot reuse KSafe's Kotlin/Native Secure Enclave path anyway, since
> that path runs entirely outside the JVM.

**What it defends against:**

- Offline disk theft. The Keychain file (`~/Library/Keychains/login.keychain-db`)
  is encrypted; without the login password (or, on SEP devices, without the
  hardware-bound key chain), the key is unrecoverable.
- Backups, file copies, syncs — same reason.
- Other macOS users on the same Mac — separate Keychains.

**What it does NOT defend against:**

- Code running as the same user while logged in. macOS will, *by default*,
  silently fulfil the lookup. Apps that signed the original item can be
  granted ACL access; KSafe does not currently set a custom ACL, so any
  process running as the same user can request the key. (A first-time
  unfamiliar caller may trigger a Keychain-access prompt on some
  configurations.)
- A root user on the Mac — root can dump Keychain unlock material from RAM.

---

## Platform: Linux — Secret Service / libsecret

**Class:** `LinuxSecretServiceKeyVault`
**API:** `secret_password_store_sync` / `_lookup_sync` / `_clear_sync` via JNA
bindings to `libsecret-1` (loaded as `Native.load("secret-1", …)`).

**What the Secret Service is.** It's a three-layer stack, not a single thing:

1. **Specification.** `org.freedesktop.secrets` — a D-Bus interface defined at
   freedesktop.org. Just a contract.
2. **Daemon.** A process that implements the spec and actually owns the
   secrets. On GNOME this is `gnome-keyring-daemon`; on KDE it's `kwalletd`
   (with the secrets bridge); KeePassXC and Bitwarden CLI can also expose the
   same interface. Started at session login by the desktop environment.
3. **Client library.** `libsecret` (the C library KSafe calls via JNA). Apps
   never touch keyring files directly; they send D-Bus messages and the daemon
   answers.

The daemon stores secrets in an encrypted file on disk, typically
`~/.local/share/keyrings/login.keyring`. The encryption key is derived from
the user's **login password** via PBKDF2/scrypt. On most desktop distros,
PAM hands that password to the daemon at login time so the "login" keyring
auto-unlocks without a second prompt.

**How KSafe uses it.**

1. The 32-byte AES key is Base64-encoded (because `libsecret`'s password APIs
   take NUL-terminated C strings, not raw byte buffers).
2. `secret_password_store_sync` stores it in the default login keyring under
   schema `eu.anifantakis.ksafe`, with one attribute:
   `alias = "<appNamespace>/<alias>"`.
3. `secret_password_lookup_sync` retrieves it by the same attribute.
4. `secret_password_clear_sync` removes it.

The DataStore file on Linux contains **only ciphertext** — nothing key-related
at all once migration completes.

**What it defends against (vs. Base64 in a file):**

| Threat | Before (Base64 in DataStore) | After (Secret Service) |
|---|---|---|
| Stolen / lost unencrypted disk | Key plaintext in file → instant decrypt | Keyring file encrypted with login-password-derived key |
| Accidental backup, rsync, Dropbox sync | Backup contains the plaintext key | Backup contains the encrypted keyring; useless without the login password |
| User logged out / screen locked | Key still on disk in plaintext | Daemon can drop the master key from RAM; secret unrecoverable until re-unlock |
| Different user on the same machine | If file perms slipped → readable | Per-user keyring + encryption-at-rest |

**What it does NOT defend against:**

- **Root.** Root can `ptrace` the daemon, dump `/proc/<pid>/mem`, or just
  become the user. Same on every OS — Windows SYSTEM and macOS root have
  equivalent powers.
- **Same-user malicious code while logged in.** D-Bus on a vanilla desktop
  Linux has no robust per-app sandbox. Once the keyring is unlocked, any
  process running as your UID can ask the daemon for the secret and the
  daemon hands it over. Flatpak/Snap add Portal-mediated isolation *inside*
  their sandboxes; outside, it's UID-based.
- **A keylogger that captured the login password.** That unlocks the
  keyring.

**Availability is not guaranteed on Linux.** Headless servers, minimal
container images, and SSH sessions frequently have:

- No `libsecret` installed.
- No `dbus-daemon` running for the user.
- No `gnome-keyring` / `kwalletd` at all.

In any of those cases `Native.load("secret-1", …)` or the self-test will fail
and KSafe falls back to the legacy plaintext store with a one-time warning.

---

## The fallback: `DataStoreKeyVault`

**Class:** `DataStoreKeyVault`
**Used when:** the host OS isn't one of the three above; OR JNA cannot link
the native library; OR no Secret Service daemon is reachable; OR the Keychain
is locked; OR the self-test fails for any reason; OR the user explicitly
opts out (see below).

**What it does.** Identical to KSafe ≤ 2.0: the raw AES key is Base64-encoded
and written into the DataStore file under the prefix `ksafe_key_`.

**Security:** none beyond OS file permissions. Anyone who can read the file
as the same user has the key. This is exactly the threat the OS vaults were
introduced to remove — `DataStoreKeyVault` is kept for two reasons:

1. **Migration source.** When an OS-backed vault is selected for the first
   time on a host that has 2.0-era data on disk, KSafe reads the existing
   key from the legacy location, copies it into the OS store, and removes
   the legacy entry. This guarantees zero data loss across the upgrade.
2. **Last-resort fallback.** Without this, KSafe would simply fail on
   headless Linux servers, locked-down corp Windows images, etc. The
   library prefers to keep working with a *loud, one-time security warning*
   over refusing to run.

**The warning.** Printed once per JVM process to `System.err` when fallback
triggers:

> KSafe SECURITY WARNING: no OS secret store is available on this JVM host
> (os="…"). Encryption keys will be stored Base64-encoded in the DataStore
> file, protected only by OS file permissions and recoverable by anyone who
> can read that file as this user. Install/enable a keyring (Linux:
> gnome-keyring/ksecretservice) or run on a host with DPAPI (Windows) /
> Keychain (macOS) for OS-backed key protection.

---

## Explicit opt-out

Set either of these to force the legacy software store *without* triggering
the fallback warning:

```
-Dksafe.jvm.keyVault=software        # JVM system property (takes precedence)
KSAFE_JVM_KEY_VAULT=software         # environment variable
```

Accepted values (case-insensitive): `software`, `datastore`, `off`, `false`,
`none`.

**When to use it:**

- CI / unit tests that don't want to be prompted by the macOS Keychain or to
  pollute a developer's login keyring.
- Servers that have a keyring available but where you explicitly do not want
  KSafe to use it (policy decision, debugging).
- Reproducing legacy 2.0 behaviour for diagnostic purposes.

KSafe's `jvmTest` suite sets this property by default so the test JVM never
touches the real OS secret store. The CI keyvault-integration job clears it
(via `KSAFE_KEYVAULT_IT`) to exercise the real store paths.

---

## App namespace (multi-app isolation)

The OS secret store is **per-OS-user and shared by every process running as
that user**. Without isolation, two different desktop apps both using KSafe
would collide on the same alias.

KSafe folds an app namespace into the OS-vault destination only:

| Vault | Namespacing |
|---|---|
| Windows DPAPI | DataStore key prefix: `ksafe_dpapi_<ns>_<alias>` |
| macOS Keychain | Service name: `eu.anifantakis.ksafe.<ns>` (account = bare alias) |
| Linux Secret Service | Attribute value: `<ns>/<alias>` |
| Legacy `DataStoreKeyVault` | **Not namespaced** — its `ksafe_key_` layout is the frozen 2.0 on-disk format and the migration source |

Resolution priority for the namespace (first non-blank wins):

1. `KSafeConfig.appNamespace` set in code.
2. `-Dksafe.appNamespace` JVM system property.
3. `KSAFE_APP_NAMESPACE` environment variable.
4. Best-effort auto-derivation from `sun.java.command` (main class name or
   jar basename).
5. Literal `"shared"` (impossible to be blank).

The resolved value is sanitised to `[A-Za-z0-9._-]` and truncated to 120
characters so it is safe as a Keychain service name, DataStore key, and
Secret Service attribute value. Production apps should set
`KSafeConfig.appNamespace` explicitly — the auto-derivation favours stability
(launcher names are stable across runs) over uniqueness (two apps with the
same main class would still collide).

---

## Summary matrix

| Aspect | Windows | macOS | Linux | Fallback |
|---|---|---|---|---|
| Store | DPAPI-wrapped blob in DataStore file | Login Keychain (no separate file) | Login keyring via libsecret daemon | Base64 in DataStore file |
| Underlying unlock | Windows login credentials | Login password / SEP hardware | Login password (PAM-unlocked) | None (file perms only) |
| Hardware-isolated key? | No | Yes on Apple Silicon / T2; No on older Intel | No | No |
| Stolen-disk safe? | Yes | Yes | Yes | **No** |
| Backup/copy safe? | Yes | Yes | Yes | **No** |
| Same-user code safe? | No | No (sometimes prompts) | No | No |
| Root/admin safe? | No | No | No | No |
| Headless / no GUI session? | Usually works | Usually works | Often fails → fallback | Always works |

---

## Verifying which vault is active

From 2.1.x the active vault is also surfaced through the public, cross-platform
diagnostic [`KSafe.protectionInfo`](PROTECTION_INFO.md):

```kotlin
val info = ksafe.protectionInfo
// JVM-vault healthy:    effectiveLevel = SANDBOX_PROTECTED, custody = "Linux Secret Service (...)", notes = []
// JVM fallback:         effectiveLevel = SOFTWARE,          custody = "DataStore (software, ...)",  notes = ["jvm_os_vault_unavailable"]
// JVM user opted out:   effectiveLevel = SOFTWARE,          custody = "DataStore (software, ...)",  notes = ["jvm_user_opted_out"]
```

Use that API in production code (gating, telemetry, UI badges). The internal
engine accessors below are kept for tests only — they're not part of the public
API surface.

The active vault's `name` and `isOsBacked` properties are surfaced for
diagnostics on the engine (not part of KSafe's public API — they are
internal-visible for tests). Possible `name` values:

- `Windows DPAPI (CryptProtectData, current-user)`
- `macOS Keychain (Security.framework, login keychain)`
- `Linux Secret Service (libsecret, login keyring)`
- `DataStore (software, plaintext — no OS protection)` ← fallback

If you see the last one in production on a host that should have an OS
keyring, check:

- The fallback warning will be in your process stderr on first key access.
- Linux: is `libsecret-1` installed? Is `gnome-keyring-daemon` running for
  this user? `secret-tool lookup x x` should not error.
- macOS: is the login keychain unlocked? Did a prompt appear and get
  dismissed?
- Windows: DPAPI is part of the OS — fallback here usually means JNA
  failed to load `Crypt32`, which points to a JRE/JNA packaging problem.

---

## Compose Desktop release distributables: `jdk.unsupported`

**`modules("jdk.unsupported")` is REQUIRED for Compose Desktop release
distributables — without it KSafe cannot persist data.**

If you ship a Compose Desktop app via `runReleaseDistributable`,
`packageReleaseDistributable`, or `createReleaseDistributable`, the build
uses `jlink` to assemble a **trimmed custom JRE** bundled inside your app.
`jlink` only includes JDK modules it can statically detect in your
bytecode. **Two** things KSafe depends on need `sun.misc.Unsafe` (which
lives in `jdk.unsupported`), and neither is statically detectable:

1. **JNA** — used by the OS keyvaults (Keychain / DPAPI / Secret Service).
   KSafe *handles* this: from 2.1.x the engine catches the `LinkageError`,
   degrades key custody to the software vault, and warns.
2. **Jetpack DataStore's embedded protobuf** — KSafe's storage backend on
   JVM/Desktop. `androidx.datastore.preferences.protobuf.MessageSchema`
   references `sun.misc.Unsafe`. KSafe **cannot** work around this — the
   failure is inside DataStore, on a background coroutine.

### Why the symptom varies: crash vs. silently dropped writes

KSafe's write path is **`encrypt` (JNA) → then `DataStore.write` (protobuf)**.
That ordering, combined with whether your bundled DataStore can do protobuf
I/O without `sun.misc.Unsafe`, decides what you see:

- **Older DataStore builds that tolerate a missing `Unsafe`** (the original
  [#32](https://github.com/ioannisa/KSafe/issues/32) report): pre-2.1.x,
  `encrypt` hit JNA first → `processBatch` caught it and **dropped the
  write** → DataStore was never reached → **no crash, data silently not
  persisted.** With 2.1.1's keyvault fallback, `encrypt` now succeeds via
  the software vault, the write reaches DataStore, and (because that build
  tolerates no-`Unsafe`) **data persists** — so the fallback genuinely
  fixes #32 *on those builds*.
- **DataStore builds whose protobuf hard-requires `Unsafe`** (including the
  version KSafe currently bundles): DataStore throws
  `NoClassDefFoundError: sun/misc/Unsafe` on the first read/write and the
  **app crashes**, regardless of the keyvault fallback. Note that 2.1.1's
  fallback, by letting `encrypt` succeed, lets the write *reach* DataStore —
  so you now see DataStore's loud crash (with KSafe's `FATAL RISK` warning
  pointing at the fix) rather than a silent drop. That is the better
  outcome: a diagnosable failure beats silent data loss, and the only real
  resolution in both cases is to add the module.

So `jdk.unsupported` is **mandatory for the app to function**, not just for
OS-level key protection. The keyvault fallback only fully rescues the cases
where JNA fails *but DataStore works* (headless Linux with no keyring, a
locked keychain, or a DataStore build that tolerates missing `Unsafe`).

From 2.1.1, KSafe prints a clear `KSafe FATAL RISK: sun.misc.Unsafe …`
warning at `KSafe(...)` construction when the class is missing, so the
otherwise-cryptic async DataStore crash (or silent drop) is diagnosable up
front, on every environment.

**The fix** — declare the module(s) in your app's Compose Desktop block:

```kotlin
compose.desktop {
    application {
        nativeDistributions {
            // `jdk.unsupported` — REQUIRED. DataStore's protobuf and JNA
            //                    both need sun.misc.Unsafe. Without it the
            //                    app crashes (DataStore) on first read/write.
            // `java.management` — only required when a non-IGNORE
            //                    `KSafeSecurityPolicy` is in use (e.g.
            //                    `KSafeSecurityPolicy.WarnOnly` /
            //                    `Strict`). `SecurityChecker` reads
            //                    `java.lang.management.ManagementFactory`
            //                    to detect a debugger. Omit if you stay
            //                    on the default IGNORE-everything baseline.
            modules("jdk.unsupported", "java.management")
            // …your other settings
        }
    }
}
```

From 2.1.1, `SecurityChecker` degrades gracefully when its underlying JDK classes are unavailable: a release distributable built without `java.management` no longer prevents `KSafe(...)` construction — the security probes return their honest "unknown" default (`false`) instead. List the module in your `modules(...)` block when you want the probes to actively detect a debugger / debug build.

This applies on **every OS** (macOS, Windows, Linux), not only the one
the report came in from — JNA needs `sun.misc.Unsafe` regardless of which
OS vault it ends up calling. The non-release `run` / `runDistributable`
tasks are unaffected because they execute against your full local JDK,
where every module is already present.

You can also let Gradle figure out the full module list for you:

```bash
./gradlew :<your-app>:suggestRuntimeModules
```

The task prints exactly the `modules(...)` call your release distributable
needs based on the dependency tree.

### Working example: KSafeDemo

A live, end-to-end example lives in the
[**KSafeDemo**](https://github.com/ioannisa/KSafeDemo) repo:

- **The build wiring** — see `composeApp/build.gradle.kts` inside the
  `compose.desktop { application { nativeDistributions { … } } }` block,
  where `modules("jdk.unsupported")` is declared with the rationale
  inline.
- **The user-visible verification** — open the demo and navigate to the
  **Security screen**
  (`composeApp/src/commonMain/kotlin/eu/anifantakis/ksafe_demo/screens/security/SecurityScreen.kt`).
  That screen renders `KSafe.protectionInfo`. When the module is included
  the card is green and `custody` is the OS vault name (e.g. *"macOS
  Keychain (Security.framework, login keychain)"*). Remove the
  `modules("jdk.unsupported")` line, rebuild
  `runReleaseDistributable`, and the card turns red with note
  `jvm_os_vault_unavailable` — the runtime fallback in action.
- **Cross-references in the demo** — header comment in
  `composeApp/src/jvmMain/kotlin/eu/anifantakis/ksafe_demo/main.kt`
  points back here, so a developer who lands in the JVM entrypoint
  first sees the connection.
