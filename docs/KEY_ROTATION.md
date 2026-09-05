# Key Rotation

*Rotation requires KSafe 3.0.0+. Automatic same-generation crash resume and persisted
retry of temporarily skipped entries require 3.1.0+. Available on every platform:
Android, iOS/macOS, JVM Desktop, JS/WasmJS.*

KSafe can re-encrypt everything it stores under fresh key material — on demand with one call, or automatically under a declarative policy. Values never change and nothing needs migration; only the keys and each entry's encryption envelope do.

- [Why rotate (and why it's off by default)](#why-rotate-and-why-its-off-by-default)
- [On-demand: `rotateKeys()`](#on-demand-rotatekeys)
- [Automatic: `KSafeKeyRotationPolicy.MaxAge`](#automatic-ksafekeyrotationpolicymaxage)
- [Semantics and guarantees](#semantics-and-guarantees)
- [Authenticated envelope (v3)](#authenticated-envelope-v3)
- [What "deleted" actually means (cryptographic erasure)](#what-deleted-actually-means-cryptographic-erasure)
- [Observability](#observability)
- [Edge cases & caveats](#edge-cases--caveats)

## Why rotate (and why it's off by default)

On every KSafe platform the key material is hardware- or OS-protected and does not expire, so
starting a new rotation is **not** a security necessity — it is a hygiene/compliance control:
many security programs (PCI DSS, SOC 2, internal crypto policies) require data-at-rest keys to
be rotated on a schedule, and rotating after a suspected device compromise re-keys everything
in one move. That is why the default is `KSafeKeyRotationPolicy.Never`: KSafe never creates a
new generation behind your back. It only finishes one the application already started if a
crash interrupted it, or retries temporarily skipped work at the same generation.

## On-demand: `rotateKeys()`

```kotlin
val result = ksafe.rotateKeys()

println("now on key generation ${result.keyGeneration}")
println("rotated=${result.rotated} skipped=${result.skipped} failed=${result.failed}")
```

One suspend call re-encrypts every encrypted entry under a brand-new key generation and deletes every superseded key that nothing references anymore. Plaintext entries are untouched (they have no key). Call it from a background coroutine on large stores — the cost is one decrypt + one encrypt per encrypted entry. The route matters: Android `DEFAULT` does the bulk payload crypto in userspace with its already-unwrapped DEK, while hardware-isolated entries pay secure-hardware operations per entry (see [What it costs](#what-it-costs)).

Rotation needs an operational encryption backend to mint the new generation; if [`isEncryptionOperational`](PROTECTION_INFO.md) is `false` (e.g. a web page outside a secure context, or a JVM whose OS vault is unreachable), there is no fresh key to rotate to and the pass has nothing it can safely re-encrypt under.

The result is a simple tally:

| Field | Meaning |
|---|---|
| `rotated` | Entries now encrypted under the new generation |
| `skipped` | Entries left on their previous generation this pass — a strict (`requireUnlockedDevice`) entry while the device was locked, or an entry a concurrent write superseded (the write wins). Still fully readable; KSafe marks them for the next instance |
| `failed` | Entries whose decrypt/re-encrypt failed definitively. Rotation leaves their bytes and metadata untouched and does not arm automatic retry. A decrypt failure can mean the old key is gone or the ciphertext is corrupt; an encrypt failure may happen after a successful old-key decrypt, so the counter alone does not prove whether the original entry is readable. Investigate the cause; `skipped`, not `failed`, is the retry-later bucket |
| `keyGeneration` | The store's generation after the pass; new writes encrypt under it |

A second concurrent `rotateKeys()` on the same instance throws `IllegalStateException` (single-flight).

## Automatic: `KSafeKeyRotationPolicy.MaxAge`

```kotlin
import kotlin.time.Duration.Companion.days

val ksafe = KSafe(
    config = KSafeConfig(
        keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(90.days),
        keyRotationRetryAttempts = 3, // default; 0 disables next-instance retries
    )
)
```

With `MaxAge`, KSafe checks once per startup — in the background, never blocking startup or
reads — whether the current key generation is older than allowed, and runs a full rotation
pass if so. The age is measured from the last rotation; for a store that has never rotated,
from the first launch under the policy (the birth is stamped then — pre-existing installs
don't retroactively appear "old"). In 3.1.0+, a pass that returns with `skipped` entries has
completed, but it is not forgotten: KSafe persists `rp:N`, where `N` is the configured number
of automatic next-instance retries (3 by default). The current instance starts no timer and
performs no second pass. Each **new KSafe instance** consumes at most one attempt and retries
the same generation immediately, without changing the generation-birth clock. Set
`keyRotationRetryAttempts = 0` to arm no retry budget. If a later run has already crossed
`MaxAge`, the normal fresh-generation rotation takes precedence and moves the older entries
directly into it. A manual `rotateKeys()` can still re-attempt sooner.
A pass interrupted before returning is different; its persisted `r:1` state makes the next
instance resume that already-active generation unconditionally.

`Never` (the default) never starts a **new** rotation automatically; `rotateKeys()` remains
available. In 3.1.0+, it does not disable lifecycle completion: an interrupted pass resumes
immediately, and normally skipped work may consume the configured bounded budget on later
instances. Neither path starts a new generation.

## Semantics and guarantees

**Crash-safe and automatically resumable (3.1.0+).** Every entry's metadata records *which key
generation decrypts it*. A rotation first persists the new generation together with a tiny
lifecycle field, `"r":1` (`rotation in progress`), then walks the entries; each entry flips to
the new generation atomically (value + metadata in one commit). There is no all-or-nothing
switch: a crash mid-rotation leaves a mixed-generation store where **every entry stays
readable**, because old generations stay alive while any entry references them.

When the next KSafe instance is created, startup sees the marker and resumes the **same**
generation in the background — it does not create another generation. This is independent of
`MaxAge`: it also happens under the default `Never` policy. Only after the entry pass and the
superseded-master sweep have both completed does KSafe change the state to `"r":0`
(`completed`). Consequently, recovery also covers the narrow crash window after the last entry
moved but before old-key cleanup. This is not a per-entry transaction journal or rollback log;
it is one lifecycle field in the existing store-generation record. Repeating the remaining
work is safe and idempotent.

A pass that returns normally records `"r":0`: that was a completed pass, not a crash. When it
contains retryable `skipped` entries, the same record also carries `"rp":N`: the remaining
automatic retry budget, not a timestamp. The current instance returns and does no more rotation
work. On the next construction KSafe atomically changes `r:0,rp:N` to `r:1,rp:N-1` **before**
retrying entries still behind the current generation. If the device remains locked, completion
persists the reduced positive budget for the following instance; after the last attempt it
removes `rp`. A crash after the claim leaves `r:1` and the already-decremented count. Ordinary
crash recovery finishes that claimed attempt, but never refills the budget—even `r:1,rp:0`
can resume only that final attempt.

There is one priority rule: if `MaxAge` is configured and the generation is already due when
that next instance starts, KSafe runs the normal fresh-generation rotation instead of first
retrying the old target. That pass scans every older entry, so it absorbs the pending work
without paying for two consecutive whole-store passes.

`failed` alone does not create `rp`: it is definitive, not a retry-later classification, and
may mean the entry is permanently unreadable. When one pass contains both skipped and failed
entries, the skipped work arms the retry; failed entries may be encountered again as part of
that scan, but they do not re-arm the budget once no retryable entry remains.

`keyRotationRetryAttempts` is captured when a normally completed pass arms its budget.
Changing a later instance to `0` suppresses automatic consumption while that configuration is
active; it does not erase the persisted budget. This lets an application pause and later
re-enable recovery without losing the fact that work remains. Manual rotation is always
available regardless of the setting.

> **Safe upgrade from 3.0.0.** Released 3.0.0 records contain `g` and `ts`, but no `r`.
> Absence cannot tell 3.1.0 whether the old rotation completed or the process died. KSafe
> therefore never guesses: on the first 3.1.0 startup it adds `"r":0`, preserves the existing
> generation and timestamp, and does **no** resume, generation bump, entry rewrite, key sweep,
> or same-launch `MaxAge` pass. Normal policy applies from the following launch. If 3.0.0 really
> crashed and left old/new generations mixed, both remain readable; a later explicit
> `rotateKeys()` or due `MaxAge` pass moves the older entries normally. Only a pass that 3.1.0+
> itself started can have `"r":1` and be auto-resumed.

**Concurrent writes always win.** Each entry's rotation commits under a compare-and-swap on its stored ciphertext, serialized with user writes on KSafe's single write consumer. If a write lands first, the rotation of that entry is skipped (it will re-encrypt under the new generation anyway, or be picked up next pass); if the rotation lands first, a queued write simply overwrites it. A rotation can never resurrect an older value.

**Values are sacred.** Rotation changes key material and envelopes — never data. In particular, `getOrCreateSecret` secrets keep their **value** (rotating a database passphrase would lose the database); only the key wrapping them changes.

**Free envelope upgrades.** Entries still on the legacy (pre-2.x) envelope are upgraded to the current envelope format as part of rotating.

**Strict entries need an unlocked device.** A `requireUnlockedDevice = true` entry can only be decrypted (and therefore rotated) while the device is unlocked. Locked ones are counted as `skipped`; their old key is retained, and later KSafe instances retry them while the bounded budget remains. A manual `rotateKeys()` can retry sooner.

**A key-store outage pauses, it doesn't fail.** If the OS key store is momentarily unreachable mid-rotation (a locked keyring, a headless launch, a device that just locked), the affected entries are reported as `skipped`, not `failed` — they stay on their current generation and the next-instance retry picks them up when the vault is available again. `failed` means a genuine, definitive problem (the key is gone), not a transient one.

## What it costs

Rotation is one decrypt plus one encrypt per encrypted entry — but *whose* crypto does the work differs by an order of magnitude between the two protection tiers, and that difference is the single biggest thing to know before rotating a large store.

Measured on a Samsung Galaxy S24 Ultra (SM-S928B), release-mode instrumented run:

| Store | Entries | `rotateKeys()` | Per entry |
|---|---|---|---|
| `Encrypted()` (DEFAULT) | 100 | ~0.2 s | ~2 ms |
| `Encrypted()` (DEFAULT) | 200 | ~0.3 s | ~1.6 ms |
| `Encrypted()` (DEFAULT) | 500 | ~1.1 s | ~2.3 ms |
| `Encrypted(HARDWARE_ISOLATED)` | 50 | **~19 s** | **~400 ms** |

The 175× gap is not KSafe overhead — it is where the AES runs. A DEFAULT entry re-encrypts in **userspace**, against the software DEK the TEE-held KEK unwrapped once at startup. A `HARDWARE_ISOLATED` entry owns a **per-entry key inside the secure element**, so every operation is a round trip into it. On the same device, timing the primitives directly:

| Operation | StrongBox | TEE |
|---|---|---|
| Generate an AES key | 67 ms | 12 ms |
| AES-GCM encrypt | **140 ms** | 7 ms |
| AES-GCM decrypt | **150 ms** | 5 ms |

Rotating one `HARDWARE_ISOLATED` entry is decrypt (150) + keygen (67) + encrypt (140) ≈ **357 ms of hardware time** — which accounts for essentially the whole measured 400 ms. Concurrency does not help: the secure element serializes, so widening KSafe's in-flight window changes DEFAULT throughput several-fold and leaves `HARDWARE_ISOLATED` exactly where it was.

**The practical rule:** `HARDWARE_ISOLATED` is for the handful of secrets that genuinely warrant a dedicated hardware key — a vault token, a signing seed. It is not a stronger default to sprinkle over ordinary data. A hundred `HARDWARE_ISOLATED` entries is a ~40-second rotation, and the same hardware cost is paid on every read and write of those entries too, not only when rotating.

Absolute numbers move with device, thermal state and store size (each commit rewrites the whole store, so per-entry cost drifts as the store grows). Treat the table as orders of magnitude and the ratio between the tiers as the durable signal. Either way: call `rotateKeys()` from a background coroutine on any store big enough to notice.

## Authenticated envelope (v3)

Rotating a store also upgrades its encryption envelope to **v3**, which adds AES-GCM **authenticated associated data (AAD)**. Every v3 ciphertext authenticates — without encrypting — a binding to:

- a **domain separator** (`ksafe.aad.v3` — also pinning the envelope format, so format confusion between versions fails authentication),
- the **store identity** — on Android, Apple and JVM the store file's path with the OS-managed home replaced by `~` (the app data dir, `NSHomeDirectory()`, `user.home`; a store outside that home keeps its absolute path), and on Web the store `fileName` (an empty string for the default store) — blocking cross-store transplantation even where key material coincidentally coincides. Home-relative is deliberate: an iOS app-container UUID changes on every update, an Android app can move to adoptable storage, a JVM home can be renamed — an absolute path would fail every rotated entry's authentication after such a move. Relocating a store to a *different* directory (or, on JVM, changing its `baseDir`) still changes its AAD identity and invalidates existing v3 ciphertexts; merely re-spelling the same path (a symlink, a `..` segment, a relative `baseDir`) does not — both path and home are canonicalized first. On JVM the *pre-namespace* `baseDir` is used, so the supported add-an-`appNamespace`-later migration — which copies the file into a namespace subdirectory — keeps them readable,
- the entry's **identity** (its user key),
- its **protection tier** (`DEFAULT` or `HARDWARE_ISOLATED` — plaintext entries are unencrypted and carry no AAD),
- its **unlock policy** (`requireUnlockedDevice`), and
- its **key generation** (so pointing an entry at an older/wrong key fails authentication rather than attempting the decrypt).

The `appNamespace` is deliberately **not** in the AAD: it may legitimately change across upgrades (the supported add-a-namespace-later migration would break if the AAD pinned the old value), and its protection is the **key separation** it already enforces — two namespaces never share key material, so a cross-namespace transplant already fails at the key, one layer below the AAD.

The effect: an attacker with raw file access can no longer **relocate** a ciphertext to a different entry, or **tamper** the metadata that decides where/how it decrypts, and have it come back as valid plaintext. Any such change breaks the GCM authentication tag, so the read **fails closed** to the caller's default instead of decrypting in the wrong context.

This is opt-in through rotation by design: a **generation-1 (un-rotated) store keeps the exact pre-3.0.0 v2 bytes for its existing entries**, so upgrading — and even downgrading again before any rotation — is free for them. (One exception outside rotation's scope: a *new or rewritten* strict `HARDWARE_ISOLATED` entry keys under 3.0.0's strict alias variant even at generation 1, with the same downgrade consequence as rotated entries — see below.) Identity authentication begins at the store's **first rotation** (generation ≥ 2), so v3 costs nothing extra. If your threat model includes an attacker who can read and rewrite the on-disk store, **rotate once** to switch it on.

> **Downgrade warning — rotation (and any strict write) is a one-way door.** A pre-3.0.0
> binary can't resolve rotated or strict-variant keys, and its **startup orphan sweep
> permanently deletes the rows and metadata it can't decrypt** — typically on the first
> launch. Upgrading back restores access only if that sweep never ran. Back up before any
> planned downgrade.

Not covered by AAD: it authenticates *placement and routing*, not *existence*. An attacker who can write the store can still delete an entry or roll it back to an earlier ciphertext they previously observed for **that same entry** — AAD binds the ciphertext to its slot, not to a version counter. Detecting rollback/deletion needs an external integrity layer (e.g. a signed manifest), which KSafe does not provide.

## What "deleted" actually means (cryptographic erasure)

KSafe is honest about deletion because the platforms are not uniform, and "gone" is a spectrum:

**Key material** (the thing that matters most — without the key, ciphertext is noise):

| Platform | Where the key lives | What delete does | Physical-erasure proof |
|---|---|---|---|
| Android | Keystore/StrongBox (TEE/SE), + a wrapped software DEK in the store | `KeyStore.deleteEntry` + DEK-record removal | The TEE/SE key is destroyed by the secure element; **strong**. The wrapped DEK sits in the app DataStore (see below). |
| iOS / macOS | Keychain (Secure Enclave for `HARDWARE_ISOLATED`) | `SecItemDelete` | Keychain honours the delete; SE keys are destroyed in hardware; **strong**. |
| JVM Desktop | OS vault — DPAPI / login Keychain / libsecret — or a software fallback file | vault delete, or file overwrite | OS-vault delete is as strong as the OS store; the **software fallback** is a plaintext key file with no secure-erase guarantee (see below). |
| Web | Non-extractable `CryptoKey` in IndexedDB | `IDBObjectStore.delete` | The key is non-extractable (never exposed to JS), and the record is deleted; **medium** — browser storage reclamation is not a secure wipe. |

**Ciphertext and the store file:** `deleteKey` and `clearAll` remove the *records*, but KSafe cannot guarantee the *bytes* are physically overwritten. `clearAll()` empties the backing store through its normal API (DataStore `clear()`, `localStorage`/IndexedDB deletes); it deliberately does **not** try to shred or unlink the live store file out-of-band (doing so races concurrent writes and corrupts the store). An empty store holds no ciphertext or key material, but the underlying medium — a journaling filesystem, an SSD with wear-levelling, a backup snapshot, an OS free-list — may retain recoverable remnants that no userspace library can reach.

**The honest guarantee, and why it's enough:** KSafe relies on **cryptographic erasure** — destroy the key, and the ciphertext is unrecoverable regardless of what byte-level remnants survive. This is the standard model for at-rest encryption (NIST SP 800-88 "Cryptographic Erase"). Rotation strengthens it: after `rotateKeys()`, the superseded master(s) for entries that were actually re-encrypted are deleted, so **their pre-rotation ciphertext is cryptographically dead** even if its bytes physically persist. A superseded master is kept as long as any entry still references it — so if a rotation skipped or failed some entries (or a store below the target generation is still awaiting the next pass), that generation's key stays alive and its pre-rotation ciphertext remains decryptable until a later rotation supersedes those entries too. The two places where key material itself may leave a byte-level remnant are the **JVM software-fallback key file** (used only when no OS vault is available — a plaintext key on disk) and **web IndexedDB** (a non-extractable key, so the bytes are never plaintext to begin with). If your threat model requires provable physical erasure of key material, use a platform with a hardware-backed store (Android/iOS/macOS, or a JVM host with an OS vault) — not the software fallback.

## Observability

```kotlin
val info = ksafe.getKeyInfo("apiToken")
println(info?.keyGeneration)   // 1 = never rotated; higher after rotateKeys()
```

`KSafeKeyInfo.keyGeneration` reports the generation that decrypts a specific entry, so you can verify a rotation reached everything (any entry still below `KSafeRotationResult.keyGeneration` will be picked up by the next pass).

Background recovery logs
`KSafe: resumed interrupted key rotation at generation N (rotated X, skipped Y, failed Z).`
after a successful resume. A `MaxAge`-started pass keeps its corresponding
`KSafe: MaxAge key-rotation pass -> …` message. A completed-partial retry logs
`KSafe: retried incomplete key rotation at generation N (rotated X, skipped Y, failed Z).`

## Edge cases & caveats

- **Downgrading below 3.0.0 after a rotation (or after any 3.0.0 strict `HARDWARE_ISOLATED` write) is destructive — back up first.** A 2.2.x binary can't resolve generation-suffixed or strict-variant keys, and its startup **orphan sweep permanently deletes the rows and metadata** it can't decrypt — typically on the first launch. Upgrading back restores access only if that sweep never ran. Never-rotated stores with no strict writes are unaffected (generation 1 uses the exact same key names as 2.2.x). Treat the first rotation and the first strict write as one-way doors.
- **Multiple instances / processes on the same file:** public KSafe instances in the same
  process share the backend's commit mutex, so their entry commits and key sweeps are
  serialized; duplicate resume attempts are idempotent. In-process siblings also keep their
  own writes readable across a rotation, and a key a live sibling still reads through is left
  alone by the sweep and reaped by a later pass once that sibling has adopted or closed.
  A mutex cannot cross an OS-process boundary, however.
  Do not rotate the same physical store concurrently from an app process
  and an extension/widget/second process; nominate one process for manual and `MaxAge`
  rotation.
- **`clearAll()`** wipes every generation's keys (best-effort: a platform-vault deletion failure is logged, not thrown — the data wipe itself fails loudly) and resets the store to generation 1. A rotation pass still in flight when the wipe lands is fenced: its remaining entries are reported `skipped` and nothing from the pre-wipe pass is stamped onto the reset store.
- **Generation upper bound**: the generation counter is capped at 10 000 (about 27 years of daily rotation). `rotateKeys()` at the cap throws `IllegalStateException` instead of overflowing; `clearAll()` resets the counter to 1.
- **Cost recap**: one decrypt + one encrypt per encrypted entry, chunked and bounded internally. On mobile hardware-backed tiers this is keystore-IPC-bound — a store with hundreds of entries takes seconds of background time, which is why `MaxAge` runs off the critical path and why `rotateKeys()` is a `suspend` function.
