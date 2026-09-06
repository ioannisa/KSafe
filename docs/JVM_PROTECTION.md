# JVM Key Protection

This document explains how KSafe protects its AES-GCM data-encryption key on the
JVM target (256-bit by default, 128-bit if you set `KSafeConfig.aesKeySize`), on
every host platform it supports, and what happens when no OS-backed secret store
is reachable.

> Scope: this is about **where the raw key bytes live on disk and which process
> is allowed to recover them**. The encryption itself (AES-GCM with a per-record
> 12-byte IV) is identical across all three OSes — only key custody changes.

---

## The problem

Unlike Android (Keystore, optionally StrongBox-isolated) and iOS/macOS native
(Keychain + Secure Enclave), the **JVM has no standard hardware keystore**.
KSafe writes its records through DataStore, the Jetpack storage library; on the
JVM one KSafe store is one file on disk. Through KSafe 2.0, the AES key was
Base64-encoded into that same file, next to the ciphertext it was meant
to protect:

```
<user.home>/.eu_anifantakis_ksafe/
└── eu_anifantakis_ksafe_datastore.preferences_pb   ← ciphertext AND Base64(key) side by side
```

Anyone who could read that one file as the same user could decrypt every
record. Stolen disks, accidental backups, rsync-to-Dropbox, file-sharing slips
— all leaked the key.

From 2.1.0, KSafe instead hands the raw key bytes to the host OS's per-user
secret store at first use. After that the DataStore file holds no usable key: on
macOS and Linux it holds no key material at all, and on Windows only a
DPAPI-wrapped blob that is useless on another account or another machine. The
custody chain becomes:

```
KSafe → JvmKeyVault (selected per-OS) → OS secret store
```

Implementation: `ksafe/src/jvmMain/.../internal/keyvault/`. Selection happens
once per engine instance in `JvmKeyVaultProvider.pick()`.

> **Key rotation.** After `rotateKeys()`, each generation's master key is
> custodied through this *same* per-OS vault under a generation-suffixed alias
> (`__ksafe_master__.g<N>`); old generations are retired via the ordinary
> per-alias `delete`, and everything the store owns is dropped with it on
> `clearAll`. See [`KEY_ROTATION.md`](KEY_ROTATION.md).

---

## Selection flow

KSafe picks one key vault per store, once, while `KSafe(...)` is constructing.
"Vault" here means only *where the raw AES key bytes are kept* — the data itself
always goes to the same place.

```
JvmKeyVaultProvider.pick()
│
├─ -Dksafe.jvm.keyVault=software (or the env var)  ─►  software vault, no warning
│
├─ os.name contains "win"              →  WindowsDpapiKeyVault       ─┐
├─ os.name contains "mac"|"darwin"     →  MacosKeychainKeyVault      ─┼─►  self-test
├─ os.name contains "nux"|"nix"|"aix"  →  LinuxSecretServiceKeyVault ─┘
│
└─ any other OS, or the vault cannot be constructed  ─►  software vault

self-test  (every OS vault runs it)
│
├─ passes                      ─►  use the OS vault
├─ native library cannot link  ─►  software vault
└─ any other failure           ─►  FAIL CLOSED
```

Every OS-backed vault runs a **self-test** before KSafe accepts it: it stores a
canary — a throwaway five-byte value, `"KSafe"` — under a random one-off alias,
reads it back, and deletes it. The alias is random because the OS stores are
shared machine-wide: a fixed one would let two apps self-testing at the same
moment overwrite each other's canary and both conclude the vault is broken.

The three outcomes are not the same tier. (`protectionInfo` below is the runtime
diagnostic every KSafe instance exposes — see **Verifying which vault is active**
for how to read it.)

| Outcome | What KSafe does | `protectionInfo` reports | Encrypted reads / writes |
|---|---|---|---|
| No OS vault could be built — the host OS is none of the three, or the vault object could not be constructed | Uses the software vault | `SOFTWARE`, note `jvm_os_vault_unavailable` | Work |
| The vault was built, but the native library behind it could not be loaded into the process (a `LinkageError`) | Uses the software vault | `SOFTWARE`, note `jvm_os_vault_unavailable` | Work. A value whose key stayed behind in the now-unreachable OS store reads back as its default for as long as the bridge is dead, and its ciphertext is kept rather than deleted. Keys minted this session are provisional: the OS key takes the alias back when the bridge loads again, and from then on both keys are tried on read |
| The vault was built and its native library loaded, but the canary round-trip failed | **Fails closed**: keeps the software store but refuses to mint keys through it | `SOFTWARE`, note `jvm_os_vault_degraded`, `isEncryptionOperational = false` | Reads return their defaults; writes throw |

Why the last row is different. A locked Keychain, a login keyring not yet
reachable on D-Bus (the Linux message bus the keyring daemon listens on), or an
SSH/headless launch all mean the OS store *exists* and almost certainly holds
your real keys — it will answer again after a healthy login. Minting keys into
the software store meanwhile would leave the store with two competing keys, and
a key lookup that finds nothing there is ambiguous: the startup orphan sweep —
the one-time pass that deletes ciphertext whose key is gone — could then delete
data that is still recoverable. So KSafe refuses to mint until the OS store
answers.

In the first row there is no OS key at all, so the software store is simply this
host's home. In the second row the OS vault may still hold keys it cannot hand
over, so a key minted while the bridge is dead is **provisional**: the first
launch that loads the bridge again hands any alias the OS vault still answers
for back to the OS key. Both keys are kept, nothing is deleted, and a read whose
tag check fails under one key is retried under the other — so nothing written
before, during or after the failure is lost. Re-write those values when you want
them all under the OS key again. That handover prints one more `System.err`
warning, once per store file (every instance over the same file shares one
engine) and naming only the first alias it applies to. Each of the three
outcomes prints one `System.err` warning per JVM process; the explicit opt-out
below prints none. See [`PROTECTION_INFO.md`](PROTECTION_INFO.md) for
`isEncryptionOperational`.

---

## Platform: Windows — DPAPI

**Class:** `WindowsDpapiKeyVault`
**API:** `CryptProtectData` / `CryptUnprotectData` via JNA's `jna-platform`
(`com.sun.jna.platform.win32.Crypt32Util`). JNA is Java Native Access — the
library KSafe uses to call the OS's own C APIs from the JVM. All three OS vaults
go through it.

**What DPAPI is.** The Data Protection API is a Windows OS service that
encrypts ("wraps") a byte array using a key chain ultimately derived from the
current user's login credentials. Crucially, **DPAPI doesn't store anything** —
it just hands you an opaque ciphertext blob that only the same Windows user on
the same machine can later unprotect.

**How KSafe uses it.**

1. On first key creation, KSafe generates the AES key bytes — 32 of them at the
   default 256-bit size.
2. It hands those bytes to `CryptProtectData` (current-user scope, the
   `Crypt32Util` default).
3. The returned wrapped blob is Base64-encoded and persisted in the DataStore
   file under the key `ksafe_dpapi_<appNamespace>_<alias>`.
4. On read, the inverse: load the blob, `CryptUnprotectData` → raw key.

Storing the wrapped blob in a file is safe because the blob is cryptographically
useless to anyone who is not logged in as that specific Windows user on that
specific machine. Copying that `.preferences_pb` file to a different account or
a different PC does not get you the key.

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

1. KSafe stores the AES key bytes (32 of them at the default 256-bit size) as a
   **generic password** item with:
   - `service`: `eu.anifantakis.ksafe.<appNamespace>` — `eu.anifantakis.ksafe.shared`
     when you set no namespace
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
  silently fulfil the lookup. macOS can restrict a Keychain item to the apps on
  its access-control list (ACL), so only those apps get it without a prompt.
  KSafe does not set one, so any process running as the same user can request
  the key. (A first-time unfamiliar caller may trigger a Keychain-access prompt
  on some configurations.)
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
`~/.local/share/keyrings/login.keyring`. The encryption key is derived from the
user's **login password** by a deliberately slow password-stretching function
(PBKDF2 or scrypt), which makes guessing the password expensive. On most desktop
distros the login stack (PAM) hands that password to the daemon at login time,
so the "login" keyring auto-unlocks without a second prompt.

**How KSafe uses it.**

1. The AES key bytes (32 of them at the default 256-bit size) are Base64-encoded
   (because `libsecret`'s password APIs take NUL-terminated C strings, not raw
   byte buffers).
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

Those situations end two different ways. If `libsecret` itself cannot be loaded,
there is no OS store to protect, so KSafe uses the software vault and keeps
working, with a one-time warning. If `libsecret` loads but the keyring is
unreachable — no D-Bus session, or a keyring that is still locked — the store
exists and probably holds your keys, so KSafe fails closed instead: encrypted
reads return their defaults and encrypted writes throw until the keyring
answers. See **Selection flow**.

---

## The fallback: `DataStoreKeyVault`

**Class:** `DataStoreKeyVault`
**Used when:** the host OS isn't one of the three above; OR the native vault
cannot be constructed or its native library cannot be linked; OR you explicitly
opt out (see below). On the no-`sun.misc.Unsafe` JSON-file backend the software
vault is `FileKeyVault` instead — same tier, keys in a plain `…ksafe-keys.json`
file rather than in the DataStore file.

> Note: a vault that was constructed and whose native library *did* load, but
> whose self-test failed — a locked Keychain, a keyring not yet on D-Bus — does
> **not** land here. That path fails closed (`jvm_os_vault_degraded`,
> `isEncryptionOperational = false`) rather than quietly downgrading to plaintext
> key storage — see **Selection flow** above.

**What it does.** Identical to KSafe ≤ 2.0: the raw AES key is Base64-encoded
and written into the DataStore file under the prefix `ksafe_key_`.

**Security:** none beyond OS file permissions. Anyone who can read the file
as the same user has the key. This is exactly the threat the OS vaults were
introduced to remove — `DataStoreKeyVault` is kept for two reasons:

1. **Migration source.** When an OS-backed vault is selected for the first
   time on a host that has 2.0-era data on disk, KSafe reads the existing key
   from the legacy location and copies it into the OS store — then reads it back
   and compares it byte for byte, and only then removes the legacy entry. A
   keyring that accepts a write without storing it therefore cannot destroy the
   only copy. This runs lazily, per key, on first read, plus once at startup as
   a background sweep so a key that is never read again doesn't leave its
   plaintext in the file.
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

Vault selection prints two other one-time `System.err` warnings, each at most
once per JVM process (they guard distinct, non-fallback conditions):

- **`warnOsVaultUnavailableOnce`** — an OS vault exists and links, but failed its
  construction-time canary round-trip (locked Keychain, keyring not yet on D-Bus,
  an SSH/headless launch). This is the **fail-closed** path, not a fallback:
  KSafe will *not* store keys in plaintext this session, because a second key in
  the software store competes with the real one and the orphan sweep could then
  delete recoverable ciphertext. Encrypted reads return their defaults and
  encrypted writes fail until the OS store is reachable again
  (`jvm_os_vault_degraded`, `isEncryptionOperational = false`). The message
  points at `-Dksafe.jvm.keyVault=software` for deliberately choosing software
  storage instead.
- **`warnRuntimeDegrade`** — the native library behind the OS vault could not be
  loaded. Either the self-test itself threw a `LinkageError` /
  `ExceptionInInitializerError`, or the vault self-tested clean and a later
  get/put/delete threw one. `degradeToLegacy` then routes to the software vault
  for the rest of the process. Because the OS vault is dead in-process there is
  no reachable OS key to shadow, so persisting to the legacy store is safe here.
  The message names the usual causes — a stripped or anti-virus-blocked JNA
  native library, a temp directory JNA cannot unpack into, or a runtime missing
  `jdk.unsupported` — and stresses that DataStore needs that same module; see
  [`jdk.unsupported`](#compose-desktop-release-distributables-jdkunsupported)
  below. A runtime that has no `sun.misc.Unsafe` at all never gets this far:
  KSafe detects that while constructing and takes the JSON-file backend, whose
  key vault is `FileKeyVault`.

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

**Keys already in the OS store stay there.** While the flag is set KSafe never
opens the OS vault, so a value encrypted under one of those keys reads back as
its default — and its ciphertext is left intact rather than reclaimed by the
startup orphan sweep. Remove the flag and those values are readable again,
unless a write in the meantime minted a competing key for the same alias — the
conflict described next.

**Coming back.** A session that ran opted-out mints its keys in the software
store. When you remove the flag, KSafe migrates such a key into the OS store —
unless the OS store already holds a *different* key for the same alias. Then it
keeps both keys, continues with the software one, and prints a one-time warning
naming the alias. No key is destroyed, but while the software one is in charge
the values encrypted under the OS key read as their defaults. The fix is to write
the values you want to keep once more, so they exist under the key now in use.

---

## App namespace (multi-app isolation)

The OS secret store is **per-OS-user and shared by every process running as that
user**. Android and iOS give each app its own sandbox; a desktop OS does not.
Without isolation, two different desktop apps both using KSafe would collide on
the same alias — and, sharing an alias, would read each other's values.

An app namespace is one short id you choose (a reverse-DNS name works well). It
scopes the destination inside the OS vault — and, when you set it in code, the
directory the data files live in as well:

```kotlin
val ksafe = KSafe(config = KSafeConfig(appNamespace = "com.example.myapp"))
```

| Vault | Namespacing |
|---|---|
| Windows DPAPI | DataStore key prefix: `ksafe_dpapi_<ns>_<alias>` |
| macOS Keychain | Service name: `eu.anifantakis.ksafe.<ns>` (account = the bare alias) |
| Linux Secret Service | Attribute value: `<ns>/<alias>` |
| Legacy `DataStoreKeyVault` | **Not namespaced** — its `ksafe_key_` layout is the frozen 2.0 on-disk format and the migration source |

The namespace is never empty on the JVM. With nothing configured it is the
literal `shared`, so the default Keychain service is
`eu.anifantakis.ksafe.shared`, the default DPAPI prefix `ksafe_dpapi_shared_`,
and the default Secret Service attribute `shared/<alias>`.

It also moves the data files, but only when you set it **in code**: with
`KSafeConfig.appNamespace` the store file goes to `<baseDir>/<ns>/` instead of
straight into `<baseDir>`, and a store already sitting in `<baseDir>` is copied
forward into that directory once (the originals are left in place), so adding a
namespace to an app that already shipped loses nothing. The system-property and
environment-variable tiers below scope the OS vault but leave the data files
where they are.

Resolution priority for the namespace — `resolveJvmAppNamespace`, first non-blank
wins (**four tiers**):

1. `KSafeConfig.appNamespace` set in code.
2. `-Dksafe.appNamespace` JVM system property.
3. `KSAFE_APP_NAMESPACE` environment variable.
4. Literal `"shared"` (`DEFAULT_JVM_NAMESPACE`, impossible to be blank) — the
   default every app that sets nothing shares, which is why two such apps on one
   machine can read each other's values.

The resolved value goes through one normalisation (`canonicalNamespaceToken`):
surrounding whitespace and leading dots are stripped, anything outside
`[A-Za-z0-9._-]` becomes `_`, and the sanitised part is capped at 120 characters
— so it is safe as a Keychain service name, DataStore key, and Secret Service
attribute value. When that rewrite actually changed something, the token carries
a `-<16 hex>` FNV-1a digest of the value as it stood before the rewrite (after
the stripping), so a token can reach 137 characters and two different configured
namespaces can never collapse onto one identity; an already-clean namespace is
left exactly as written.

> **No `sun.java.command` derivation.** Earlier builds had a fifth live tier that
> auto-derived a namespace from the launcher (main-class name or jar basename).
> It was removed: the launcher token changes between runs and releases, so a
> moving default would silently orphan every key on upgrade, hide the data, and
> let the orphan sweep delete it. That derivation now survives **only as a
> read-side migration source**, so a key stored under it can still be recovered
> on read (see **Legacy-namespace recovery** below). Nothing writes new keys
> there. Because there is no auto-uniqueness anymore, production apps that share
> a per-user store with other KSafe apps should set `KSafeConfig.appNamespace`
> explicitly.

---

## Legacy-namespace recovery

*You only need this section if your app already shipped with KSafe and its
namespace has changed since — for example you added `KSafeConfig.appNamespace` to
a release that did not have one.*

A key is filed in the OS vault under whichever namespace was in effect when it
was written. If the namespace changes, a lookup under the new one finds nothing:
every decrypt fails and the startup orphan sweep deletes the ciphertext. KSafe
guards against that with a read-side recovery path, active only when the picked
vault is OS-backed.

- **What it probes.** When a lookup under the current namespace misses, KSafe
  repeats it against the namespaces an older release could have used, in this
  order: the one this same configuration resolved to before the token rules were
  tightened; the ones `-Dksafe.appNamespace` / `KSAFE_APP_NAMESPACE` would have
  given, when a `KSafeConfig.appNamespace` now outranks them and the property or
  variable is still set; the launcher-derived one earlier builds computed from
  `sun.java.command`; and finally `shared`. The current namespace is skipped, and
  the probes are built lazily, only in production wiring.
- **A hit is migrated forward.** KSafe copies the key into the active namespace
  and reads it back to confirm. The recovered bytes are returned either way, so
  this session decrypts even if the copy failed — the migration retries next
  time.
- **The old entry is only sometimes removed.** It is deleted only from the
  launcher-derived namespace, which no live app can still own. `shared`, the
  pre-tightening namespace and the ones the property or the environment variable
  would have given are never deleted: another process, or a not-yet-upgraded copy
  of this same app, may still be reading its own data through them, and moving
  the key would orphan that data.
- **Deleting a key reaches into those namespaces too.** KSafe removes it from
  the ones it may reclaim; where a copy has to be left standing, it writes a
  tombstone — a marker meaning "this key was deleted here" — under the current
  namespace, and recovery honours that marker. Otherwise deleting a key and
  creating it again would resurrect the pre-upgrade one.
- **An outage is not an absence.** When an OS vault is unreachable it throws
  "vault unavailable" rather than reporting "no key"; recovery passes that
  through, so the orphan sweep sees a store it must not touch instead of a key it
  may reclaim.

---

## Summary matrix

| Aspect | Windows | macOS | Linux | Software fallback |
|---|---|---|---|---|
| Where the key lives | DPAPI-wrapped blob inside the DataStore file | Login Keychain — no key bytes in any KSafe file | Login keyring via the libsecret daemon — no key bytes in any KSafe file | Base64 in the DataStore file, or in `…ksafe-keys.json` |
| What unlocks it | The Windows login | The login password, or SEP hardware on Apple Silicon / T2 | The login password (PAM-unlocked at login) | Nothing — file permissions only |
| Key held by a security chip? | No | Yes on Apple Silicon / T2, no on older Intel. KSafe still reports `SANDBOX_PROTECTED`: the JVM has no key hardware of its own, it borrows the Keychain's | No | No |
| Safe against a stolen disk? | Yes | Yes | Yes | **No** |
| Safe against a backup or a copied home directory? | Yes | Yes | Yes | **No** |
| Safe against code running as the same OS user? | No | No (may prompt) | No | No |
| Safe against root / an administrator? | No | No | No | No |
| Headless / no GUI session | Usually works | Usually works | Often fails. No libsecret → software fallback; libsecret but no reachable keyring → fail closed | Always works |

The two "same OS user" and "root / administrator" rows say "No" everywhere, and
that is not KSafe-specific: an OS secret store hands its secrets to any process
running as the owning user, by design. What the OS stores buy you is the rows
above them — the key stops being a file someone can copy.

---

## Verifying which vault is active

The active vault is reported by the public, cross-platform diagnostic
[`KSafe.protectionInfo`](PROTECTION_INFO.md). Read it after construction:

```kotlin
val info = ksafe.protectionInfo
if (!info.isEncryptionOperational) {
    // An OS store exists but is unreachable: encrypted reads return their
    // defaults and encrypted writes throw. Ask the user to log in / unlock.
}
println("${info.effectiveLevel} — ${info.custody} — ${info.notes}")
```

The four JVM outcomes:

| Situation | `effectiveLevel` | `custody` | `notes` | `isEncryptionOperational` |
|---|---|---|---|---|
| OS vault healthy | `SANDBOX_PROTECTED` | the vault name, e.g. `Linux Secret Service (libsecret, login keyring)` | `[]` | `true` |
| No OS vault reachable | `SOFTWARE` | `DataStore (software, …)`, or `JSON file (software, …)` on the no-`Unsafe` backend | `["jvm_os_vault_unavailable"]` | `true` |
| OS vault present but unreachable | `SOFTWARE` | `DataStore (software, …)` | `["jvm_os_vault_degraded"]` | `false` |
| You opted out | `SOFTWARE` | `DataStore (software, …)` | `["jvm_user_opted_out"]` | `true` |

Three of those rows report `SOFTWARE`, but only the degraded one is
**non-operational** — gate on
[`isEncryptionOperational`](PROTECTION_INFO.md), not on `effectiveLevel`, to tell
"weaker but working" from "encrypted ops will throw".

Use that API in production code (gating, telemetry, UI badges); the decision
patterns are in [`PROTECTION_INFO.md`](PROTECTION_INFO.md). The active vault's
`name` / `isOsBacked` are also surfaced on the engine for tests
(internal-visible, not public API). Possible `name` values:

- `Windows DPAPI (CryptProtectData, current-user)`
- `macOS Keychain (Security.framework, login keychain)`
- `Linux Secret Service (libsecret, login keyring)`
- `DataStore (software, plaintext — no OS protection)` ← DataStore fallback / opt-out
- `JSON file (software, plaintext — no OS protection)` ← `FileKeyVault`, the no-`Unsafe` JSON-file path

If you see one of the software names in production on a host that should have an
OS keyring, check:

- The one-time warning is on your process's stderr. The selection warnings are
  printed while `KSafe(...)` is constructing, not on first key access; only the
  runtime-degrade one is printed later, by the key access that hits the failure.
- Linux: is `libsecret-1` installed? Is `gnome-keyring-daemon` running for this
  user? `secret-tool lookup x x` should not error.
- macOS: is the login keychain unlocked? Did a prompt appear and get dismissed?
- Windows: DPAPI is part of the OS — a fallback here usually means JNA failed to
  load `Crypt32`, which points to a JRE/JNA packaging problem.

---

## Compose Desktop release distributables: `jdk.unsupported`

**Add `modules("jdk.unsupported")` to Compose Desktop release distributables** —
and `"java.management"` too if you set a `KSafeSecurityPolicy` other than the
default. `jdk.unsupported` is what gives KSafe **OS-backed key custody** (macOS
Keychain / Windows DPAPI / Linux Secret Service). Without it KSafe still persists
and still encrypts, but the AES key drops to a file beside the data — see **The
risk of the software key tier** below — so add it for any production build.

Compose Desktop's release packaging tasks (`createReleaseDistributable`,
`packageRelease…`, `runReleaseDistributable`) use `jlink` to bundle a **trimmed
JRE**, including only JDK modules it can statically detect. Two things KSafe uses
need `sun.misc.Unsafe` (in `jdk.unsupported`) and neither is statically
detectable: **JNA** — the library KSafe uses to call the OS's own C APIs, so all
three OS vaults — and **Jetpack DataStore's embedded protobuf**, its normal
storage serializer (`androidx.datastore.preferences.protobuf.MessageSchema`).

### What changes without the module (2.1.1+)

At construction KSafe probes for `sun.misc.Unsafe`; if it's absent it switches
to a no-`Unsafe` backend instead of letting the protobuf crash. **Only the key
location changes — the storage engine and the encryption do not:**

- **Storage** is still Jetpack **`datastore-core`** (the same library behind the
  normal path — same atomic writes, single-process coordinator, corruption
  handling, fsync). Only the *serializer* differs: a custom JSON one
  (`DataStoreJsonStorage`) instead of the Preferences protobuf, so the classes
  that need `Unsafe` are never loaded. (It uses the `java.io` serializer path,
  not okio — okio 3.x's multi-release jar fails bytecode verification on a
  trimmed runtime.)
- **Encryption** is still **AES-GCM** (256-bit by default) via `javax.crypto`,
  unchanged.
- **The AES key** drops from the OS secret store to a local file
  (`FileKeyVault` — Base64 in `…ksafe-keys.json`, written owner-only `0600`
  inside the `0700` data directory). This is KSafe's existing **`SOFTWARE`**
  tier — the *same* one it already falls back to when no OS keyring is
  reachable, not a new or worse degrade.
  `protectionInfo.effectiveLevel` reports `SOFTWARE` (note
  `jvm_os_vault_unavailable`) and a one-time `KSafe NOTICE` explains it.

### The risk of the software key tier

In this mode `~/.eu_anifantakis_ksafe/` (POSIX `0700`) holds two files:

- `…ksafe.json` — the data: encrypted values as Base64 **ciphertext**, plus
  metadata. (Values written `KSafeWriteMode.Plain` are cleartext — they opted
  out of encryption.)
- `…ksafe-keys.json` — the key vault: the raw AES key, **Base64-encoded in the
  clear** (Base64 is encoding, not encryption).

The data file alone doesn't expose encrypted secrets — they're ciphertext. But
**anyone who can read both files has the key *and* the ciphertext and can
decrypt everything**; the only barrier is the file permissions (`0700` on the
directory, `0600` on the key file). The realistic exposure is off-host or
same-user — an unencrypted backup, a copied/synced home directory, a stolen
drive without full-disk encryption, or a process running as the same OS user.
The key travels with the data. OS-backed custody closes exactly this: DPAPI
wraps the key to the Windows login, the macOS Keychain stores it device-bound,
libsecret keeps it in the login keyring — none recoverable by reading a file. (Same posture KSafe has always documented
for its software fallback and its pre-2.0 JVM scheme.)

### Adding the module later migrates your data forward

When you add the module and rebuild, the next launch runs on the OS-backed path
and KSafe migrates the fallback data forward automatically: each entry is
decrypted with the software key and re-encrypted under a freshly minted
OS-backed key (protection level + metadata preserved; the just-used fallback
values win, so a value you changed on the fallback carries across). The source
files are renamed to `*.migrated` — recoverable, and drained once per fallback
period: if a later build loses the module again, the new fallback file is drained
on the launch after you restore it.

<details>
<summary>History: the pre-2.1.1 #32 crash-vs-silent-drop</summary>

Before the fallback, the symptom varied by DataStore build (write path is
`encrypt` (JNA) → `DataStore.write` (protobuf)): a build tolerating missing
`Unsafe` dropped the write silently (the original
[#32](https://github.com/ioannisa/KSafe/issues/32) report), while a build whose
protobuf hard-requires it crashed on the first read. 2.1.1's JSON fallback loads
no protobuf, so neither happens.
</details>

**Recommended setup** — declare the module(s) in your app's Compose Desktop block:

```kotlin
compose.desktop {
    application {
        nativeDistributions {
            // `jdk.unsupported` — STRONGLY RECOMMENDED. DataStore's protobuf
            //                    and JNA both need sun.misc.Unsafe. With it you
            //                    get OS-backed key custody. Without it KSafe
            //                    still persists (same DataStore engine + AES-GCM;
            //                    the AES key just drops to a 0600 file — the
            //                    SOFTWARE tier) and migrates forward when you
            //                    add it.
            // `java.management` — only useful when you set a
            //                    `KSafeSecurityPolicy` other than the default
            //                    (e.g. `WarnOnly` / `Strict`).
            //                    `SecurityChecker` reads
            //                    `java.lang.management.ManagementFactory` to
            //                    detect a debugger; without the module that
            //                    probe answers "no debugger" instead of
            //                    failing. Omit it if you stay on the default
            //                    IGNORE-everything baseline.
            modules("jdk.unsupported", "java.management")
            // …your other settings
        }
    }
}
```

From 2.1.1, `SecurityChecker` degrades gracefully when its underlying JDK classes
are unavailable: a release distributable built without `java.management` no
longer prevents `KSafe(...)` construction — the security probes return their
honest "unknown" default (`false`) instead. List the module in your `modules(...)`
block when you want the probes to actively detect a debugger / debug build.

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
