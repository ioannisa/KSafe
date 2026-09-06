# Key Rotation

*Rotation requires KSafe 3.0.0+. Automatic same-generation crash resume and persisted
retry of temporarily skipped entries require 3.1.0+. Correct rotation across two live
instances on the same store requires 3.2.0+. Available on every platform: Android,
iOS/macOS, JVM Desktop, JS/WasmJS.*

KSafe can re-encrypt everything it stores under fresh key material — on demand with one call, or automatically under a declarative policy. Values never change and nothing needs migration; what changes is the keys, the encrypted bytes they produce, and the small record that says how each value was encrypted.

- [Why rotate (and why it's off by default)](#why-rotate-and-why-its-off-by-default)
- [On-demand: `rotateKeys()`](#on-demand-rotatekeys)
- [What it costs](#what-it-costs)
- [Automatic: `KSafeKeyRotationPolicy.MaxAge`](#automatic-ksafekeyrotationpolicymaxage)
- [Semantics and guarantees](#semantics-and-guarantees)
- [Authenticated envelope (v3)](#authenticated-envelope-v3)
- [What "deleted" actually means (cryptographic erasure)](#what-deleted-actually-means-cryptographic-erasure)
- [Observability](#observability)
- [Edge cases & caveats](#edge-cases--caveats)

## Why rotate (and why it's off by default)

Three terms this page uses constantly:

- **Key generation** — a number, starting at 1, that names the set of encryption keys a store is
  currently writing under. `rotateKeys()` raises it by one and mints fresh keys for it. Every entry
  records the generation that decrypts it, so a store can hold several generations at once and stay
  entirely readable.
- **Envelope** — the on-disk shape of one encrypted value: the ciphertext plus the small metadata
  record saying which key and which format wrote it. Rotation rewrites envelopes; it never touches
  the value inside.
- **Master key** — the key that ordinary encrypted (`DEFAULT`) entries share instead of owning one
  each; `HARDWARE_ISOLATED` entries get a key each. Every generation mints its own master — on
  Android and Apple two of them, one for entries that require an unlocked device and one for the
  rest — and an old master is deleted only once nothing still references it.

KSafe keeps key material where the platform keeps it: the Keystore on Android, the Keychain on
Apple, the OS vault (DPAPI, login Keychain, Secret Service) on JVM Desktop, and a non-extractable
browser key in IndexedDB on web. On a JVM host with no OS vault at all it falls back to a
software key file. None of it expires, so starting a new generation is **not** a security
necessity — it is a hygiene/compliance control: many security programs (PCI DSS, SOC 2, internal
crypto policies) require data-at-rest keys to be rotated on a schedule, and rotating after a
suspected device compromise re-keys everything in one move.

That is why the default is `KSafeKeyRotationPolicy.Never`: KSafe never creates a new generation
behind your back. It only finishes one the application already started if a crash interrupted it,
or retries temporarily skipped work at the same generation.

## On-demand: `rotateKeys()`

```kotlin
val result = ksafe.rotateKeys()   // suspend

println("now on key generation ${result.keyGeneration}")
println("rotated=${result.rotated} skipped=${result.skipped} failed=${result.failed}")
```

One suspend call re-encrypts every encrypted entry under a brand-new key generation and deletes every superseded key that nothing references anymore. Plaintext entries are untouched — they have no key. Call it from a background coroutine on large stores: the pass costs one decrypt plus one encrypt per encrypted entry, and each `HARDWARE_ISOLATED` entry also mints a fresh key of its own. How much that costs depends almost entirely on the entry's protection tier — see [What it costs](#what-it-costs).

Rotation does not check the encryption backend first. It bumps the generation, then walks the
entries. Two situations leave encryption broken, and
[`isEncryptionOperational`](PROTECTION_INFO.md) is `false` in both: a web page served outside a
secure context, where the browser withholds `crypto.subtle` (`protectionInfo.notes` carries
`web_crypto_subtle_unavailable`), and a JVM whose OS key vault is present but failed its self-test
(`jvm_os_vault_degraded`). Either way the pass rewrites nothing — the store is left on the new
generation, and every entry stays readable under its old key once the backend works again — but the
tally differs: the degraded JVM vault leaves its entries `skipped`, because an unreachable vault is
treated as temporary, while the web page leaves them `failed`. Read `isEncryptionOperational` before
calling if you would rather not start the pass at all. A JVM host with no OS vault at all is a
different case: it reports `jvm_os_vault_unavailable`, keeps working on software keys, and rotates
normally.

The result is a simple tally:

| Field | Meaning |
|---|---|
| `rotated` | Entries now encrypted under the new generation |
| `skipped` | Entries left on their previous generation this pass, and still fully readable. Causes: a **strict** entry — one written with `requireUnlockedDevice = true`, so its key refuses to work while the device is locked — encountered while the device was locked; a key store that was momentarily unreachable; an entry a concurrent write superseded (the write wins); and an entry fenced by a `clearAll()` or another instance's rotation landing mid-pass. This is the retry-later bucket |
| `failed` | Entries whose decrypt or re-encrypt failed definitively — the old key is gone, the ciphertext is corrupt, the entry carries an envelope version this build does not know, or the browser is withholding `crypto.subtle` (see above). Rotation leaves their bytes and metadata untouched and arms no retry. A `failed` entry is not proof the value is lost: a store-level commit failure counts here too, and it leaves the entry readable under its old key. Investigate the cause |
| `keyGeneration` | The store's generation after the pass; new writes encrypt under it |

`skipped` is not lost work. When a pass finishes with `skipped > 0` and
`KSafeConfig.keyRotationRetryAttempts` is above `0`, KSafe records a retry budget on the store, and
later instances re-scan for entries still below the current generation — see
[Automatic](#automatic-ksafekeyrotationpolicymaxage).

`rotateKeys()` throws `IllegalStateException` and leaves the store untouched in three cases: a
rotation is already running on this instance (one pass at a time), the store's persisted rotation
record is one this build does not understand, or the generation counter is already at its maximum.

## What it costs

Rotation is one decrypt plus one encrypt per encrypted entry, plus a freshly minted key for each `HARDWARE_ISOLATED` entry — but *whose* crypto does the work differs by more than two orders of magnitude between the two protection tiers, and that difference is the single biggest thing to know before rotating a large store.

Measured on a Samsung Galaxy S24 Ultra (SM-S928B), release-mode instrumented run:

| Store | Entries | `rotateKeys()` | Per entry |
|---|---|---|---|
| `Encrypted()` (DEFAULT) | 100 | ~0.2 s | ~2 ms |
| `Encrypted()` (DEFAULT) | 200 | ~0.3 s | ~1.6 ms |
| `Encrypted()` (DEFAULT) | 500 | ~1.1 s | ~2.3 ms |
| `Encrypted(HARDWARE_ISOLATED)` | 50 | **~19 s** | **~400 ms** |

The 175× gap is not KSafe overhead — it is where the AES runs. Android keeps Keystore keys in
isolated hardware: the TEE (Trusted Execution Environment) on every modern device, and on some
devices the further-isolated StrongBox secure element. Code outside can ask that hardware to
perform an operation but never sees the key, which is why every operation is a round trip into it.

A relaxed `DEFAULT` entry (the common case, with `requireUnlockedDevice` left off) avoids those
round trips: it re-encrypts in **userspace**, against a software data key (a DEK, *data encryption
key*) that a Keystore-held wrapping key (a KEK, *key encryption key*) unwrapped once at startup. A
strict `DEFAULT` entry does not take that route: it stays on the per-call Keystore path and pays a
hardware round trip each way. A `HARDWARE_ISOLATED` entry owns a **per-entry key inside the secure
hardware**, so decrypting, minting and re-encrypting it are three round trips. On the same device,
timing the primitives directly:

| Operation | StrongBox | TEE |
|---|---|---|
| Generate an AES key | 67 ms | 12 ms |
| AES-GCM encrypt | **140 ms** | 7 ms |
| AES-GCM decrypt | **150 ms** | 5 ms |

Rotating one `HARDWARE_ISOLATED` entry is decrypt (150) + keygen (67) + encrypt (140) ≈ **357 ms of hardware time** — which accounts for essentially the whole measured 400 ms. On a device with no StrongBox the request lands on the TEE instead (`android_strongbox_absent` in `protectionInfo.notes`), which is far cheaper but still a key per entry. Concurrency does not help: the secure element serializes, so widening KSafe's in-flight window changes DEFAULT throughput several-fold and leaves `HARDWARE_ISOLATED` exactly where it was.

**The practical rule:** `HARDWARE_ISOLATED` is for the handful of secrets that genuinely warrant a dedicated hardware key — a vault token, a signing seed. It is not a stronger default to sprinkle over ordinary data. A hundred `HARDWARE_ISOLATED` entries is a ~40-second rotation, and the same hardware cost is paid on every read and write of those entries too, not only when rotating.

Absolute numbers move with device, thermal state and store size (each commit rewrites the whole store, so per-entry cost drifts as the store grows). Treat the table as orders of magnitude and the ratio between the tiers as the durable signal. Either way: call `rotateKeys()` from a background coroutine on any store big enough to notice.

## Automatic: `KSafeKeyRotationPolicy.MaxAge`

```kotlin
import kotlin.time.Duration.Companion.days

val ksafe = KSafe(
    // Android takes the context first: KSafe(context, config = KSafeConfig(...))
    config = KSafeConfig(
        keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(90.days),
        keyRotationRetryAttempts = 3, // default; 0 disables next-instance retries
    )
)
```

`maxAge` must be positive; the `MaxAge` constructor throws `IllegalArgumentException` otherwise.

With `MaxAge`, KSafe checks once per startup — on a background coroutine, after the store's first
load, never blocking startup or reads (with `lazyLoad = true` it runs after the first access
instead) — whether the current key generation is older than allowed, and runs a full rotation pass
if so. The age is measured from the last rotation; for a store that has never rotated, from the
first launch under the policy, since the birth is stamped then. Pre-existing installs do not
retroactively appear "old".

In 3.1.0+, a pass that returns with `skipped` entries has completed, but it is not forgotten: KSafe
persists a bounded retry budget on the store, `keyRotationRetryAttempts` deep (3 by default). The
current instance starts no timer and performs no second pass. Each **new KSafe instance** consumes
at most one attempt and retries the same generation immediately, without changing the clock
`MaxAge` measures against. Set `keyRotationRetryAttempts = 0` if you would rather rotate deferred
entries on your own schedule than have an arbitrary later launch pay for a whole-store scan. If a
later run has already crossed `MaxAge`, the normal fresh-generation rotation takes precedence and
moves the older entries directly into it. A manual `rotateKeys()` can always re-attempt sooner. A
pass interrupted before returning is different: it is recorded as still in progress, and the next
instance resumes that already-active generation unconditionally.

`Never` (the default) never starts a **new** rotation automatically; `rotateKeys()` remains
available. In 3.1.0+, it does not disable lifecycle completion: an interrupted pass resumes on the
next instance, and normally skipped work may consume the configured bounded budget on later
instances. Neither path starts a new generation. The full state table is in
[Semantics and guarantees](#semantics-and-guarantees).

## Semantics and guarantees

**Crash-safe and automatically resumable (3.1.0+).** Every entry's metadata records *which key
generation decrypts it*. A rotation first persists the new generation together with a tiny
lifecycle field, `"r":1` (`rotation in progress`), then walks the entries; each entry flips to
the new generation atomically (value + metadata in one commit). There is no all-or-nothing
switch: a crash mid-rotation leaves a mixed-generation store where **every entry stays
readable**, because old generations stay alive while any entry references them.

Only after the entry pass and the superseded-master sweep have both completed does KSafe change the
state to `"r":0` (`completed`). Recovery therefore also covers the narrow crash window after the
last entry moved but before old-key cleanup. This is not a per-entry transaction journal or
rollback log; it is one lifecycle field in the existing store-generation record, and repeating the
remaining work is safe and idempotent.

A completed pass that left retryable `skipped` entries writes `"rp":N` beside `"r":0` — the
remaining automatic retry budget, not a timestamp. The current instance returns and does no more
rotation work. Everything a later launch can do follows from that one record:

| Persisted state | What the next KSafe instance does |
|---|---|
| No record at all | Nothing to recover. Under `MaxAge` the clock the policy measures against is stamped now, so a pre-existing install does not retroactively look "old" |
| `g` and `ts` only (a 3.0.0 record) | Adopts it as `r:0`, changes nothing else, and defers normal policy to the following launch |
| `r:1` | Resumes that **same** generation, whatever the policy — this is a crash, not a completed pass |
| `r:0` | A completed pass. Under `MaxAge`, a fresh rotation starts if the generation is older than `maxAge`; otherwise nothing happens |
| `r:0`, `rp:N` (N > 0) | Claims one attempt by changing the record to `r:1`, `rp:N-1` **before** any work, then retries entries still below the current generation. Two things override that: if `MaxAge` is already due, the fresh-generation rotation runs instead and absorbs the pending work; if this instance's `keyRotationRetryAttempts` is `0`, nothing runs and the budget stays on disk |
| Anything else | Preserved untouched. Rotation refuses and reports it, and every launch refuses identically until the record is repaired |

That claim of an attempt is durable and written before the work, so a crash cannot refill the
budget: it leaves `r:1` and the already-decremented count, and ordinary crash recovery finishes the
claimed attempt rather than granting a new one. Even
`r:1,rp:0` can resume only that final attempt. `failed` alone never arms `rp`: it is definitive,
not a retry-later classification. When one pass contains both skipped and failed entries, the
skipped work arms the retry; failed entries may be met again during that scan, but they do not
re-arm the budget once no retryable entry remains.

`keyRotationRetryAttempts` is captured when a normally completed pass arms its budget.
Setting a later instance to `0` suppresses automatic consumption while that configuration is
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

**Concurrent writes always win.** Each entry's rotation is committed only if the ciphertext on disk
is still exactly the bytes the rotation decrypted, and rotations queue behind ordinary writes in
the same single writer. If a write lands first, that entry's rotation is skipped (it will
re-encrypt under the new generation anyway, or be picked up next pass); if the rotation lands
first, a queued write overwrites it. A rotation can never resurrect an older value.

**Values are sacred.** Rotation changes key material and envelopes — never data. In particular, a
`getOrCreateSecret` secret — a random value KSafe mints once and hands back forever, typically a
database passphrase — keeps its **value**; regenerating one would orphan whatever it encrypts. Only
the key wrapping it changes.

**Free envelope upgrades.** Entries still on the legacy (pre-2.x) envelope are upgraded to the current envelope format as part of rotating.

**Strict entries need an unlocked device.** A strict entry (`requireUnlockedDevice = true`) can only be decrypted, and therefore rotated, while the device is unlocked. Locked ones are counted as `skipped`; their old key is retained, and later KSafe instances retry them while the bounded budget remains. A manual `rotateKeys()` can retry sooner. On Android API 28-34 with no secure lock screen the strict key is minted without its unlock binding (`android_lock_screen_absent` in `protectionInfo.notes`, and the note keeps being reported while that key is in use). Only a new generation re-takes the decision, and rotation is opt-in — the default `keyRotationPolicy` is `Never` — so once the user sets a lock screen, call `rotateKeys()` once (or configure a policy) to get the binding back.

**A key-store outage pauses, it doesn't fail.** If the OS key store is momentarily unreachable mid-rotation (a locked keyring, a headless launch, a device that just locked), the affected entries are reported as `skipped`, not `failed` — they stay on their current generation and the next-instance retry picks them up when the vault is available again. `failed` means a genuine, definitive problem (the key is gone), not a transient one.

## Authenticated envelope (v3)

Rotating a store also upgrades its encryption envelope to **v3**, which adds AES-GCM **associated data (AAD)** — extra bytes the cipher authenticates but does not encrypt, so changing them makes the decrypt fail instead of returning wrong plaintext. Every v3 ciphertext authenticates a binding to:

- a **domain separator** (`ksafe.aad.v3` — also pinning the envelope format, so format confusion between versions fails authentication),
- the **store identity** — on Android, Apple and JVM the store file's path with the OS-managed home replaced by `~` (the app data dir, `NSHomeDirectory()`, `user.home`; a store outside that home keeps its absolute path), and on Web the store `fileName`, the constructor argument naming one store (an empty string for the default store) — blocking cross-store transplantation even where key material coincidentally coincides. Home-relative is deliberate: an iOS app-container UUID changes on every update, an Android app can move to adoptable storage, a JVM home can be renamed — an absolute path would fail every rotated entry's authentication after such a move. Two spellings of the same file resolve to one identity: KSafe resolves links to the real path where the platform can, canonicalizes otherwise, and keeps the nearest older spelling as a *fallback identity* that a decrypt retries under, so entries written before a spelling changed still open and the next write or rotation re-binds them. Moving a store to a *different* directory (or, on JVM, changing its `baseDir` — the constructor argument choosing which directory the store file lives in) is a real identity change and does invalidate existing v3 ciphertexts. On JVM the identity uses the *pre-namespace* `baseDir`, so the supported migration that adds an `appNamespace` later — the constructor argument that separates one app's data and keys from another's on JVM and Web, where the OS store and the browser origin are shared — can copy the file into a namespace subdirectory and leave those entries readable,
- the entry's **identity** (its user key),
- its **protection tier** (`DEFAULT` or `HARDWARE_ISOLATED` — plaintext entries are unencrypted and carry no AAD),
- its **unlock policy** (`requireUnlockedDevice`), and
- its **key generation** (so pointing an entry at an older/wrong key fails authentication rather than attempting the decrypt).

The `appNamespace` is deliberately **not** in the AAD: it may legitimately change across upgrades (the supported add-a-namespace-later migration would break if the AAD pinned the old value), and its protection is the **key separation** it already enforces — two namespaces never share key material, so a cross-namespace transplant already fails at the key, one layer below the AAD.

The effect: an attacker with raw file access can no longer **relocate** a ciphertext to a different entry, or **tamper** the metadata that decides where/how it decrypts, and have it come back as valid plaintext. Any such change breaks the GCM authentication tag, so the read **fails closed** to the caller's default instead of decrypting in the wrong context.

This is opt-in through rotation by design: a **generation-1 (un-rotated) store keeps the exact pre-3.0.0 v2 bytes for its existing entries**, so upgrading — and even downgrading again before any rotation — is free for them. (One exception outside rotation's scope: a *new or rewritten* strict `HARDWARE_ISOLATED` entry keys under 3.0.0's strict alias variant even at generation 1, with the same downgrade consequence as rotated entries — see below.) Identity authentication begins at the store's **first rotation** (generation ≥ 2), so v3 costs nothing extra. If your threat model includes an attacker who can read and rewrite the on-disk store, **rotate once** to switch it on.

> **Downgrade warning — rotation (and any strict write) is a one-way door.** A pre-3.0.0
> binary can't resolve rotated or strict-variant keys, and its **startup orphan sweep** — the
> pass every KSafe release runs at startup to reclaim ciphertext whose decryption key is
> definitively gone — **permanently deletes the rows and metadata it can't decrypt**, typically
> on the first launch. Upgrading back restores access only if that sweep never ran. Back up
> before any planned downgrade.

Not covered by AAD: it authenticates *placement and routing*, not *existence*. An attacker who can write the store can still delete an entry or roll it back to an earlier ciphertext they previously observed for **that same entry** — AAD binds the ciphertext to its slot, not to a version counter. Detecting rollback/deletion needs an external integrity layer (e.g. a signed manifest), which KSafe does not provide.

## What "deleted" actually means (cryptographic erasure)

KSafe is honest about deletion because the platforms are not uniform, and "gone" is a spectrum:

**Key material** (the thing that matters most — without the key, ciphertext is noise):

| Platform | Where the key lives | What delete does | Physical-erasure proof |
|---|---|---|---|
| Android | Keystore/StrongBox (the TEE or the secure element), + a wrapped software DEK in the store | `KeyStore.deleteEntry` + DEK-record removal | The hardware-held key is destroyed inside that hardware; **strong**. The wrapped DEK sits in the app DataStore (see below). |
| iOS / macOS | Keychain (Secure Enclave for `HARDWARE_ISOLATED`) | `SecItemDelete` | Keychain honours the delete; SE keys are destroyed in hardware; **strong**. |
| JVM Desktop | OS vault — DPAPI / login Keychain / libsecret — or a software fallback file | vault delete, or file overwrite | OS-vault delete is as strong as the OS store; the **software fallback** is a plaintext key file with no secure-erase guarantee (see below). |
| Web | Non-extractable `CryptoKey` in IndexedDB | `IDBObjectStore.delete` | The key is non-extractable (never exposed to JS), and the record is deleted; **medium** — browser storage reclamation is not a secure wipe. |

**Ciphertext and the store file:** `delete()` and `clearAll()` remove the *records*, but KSafe cannot guarantee the *bytes* are physically overwritten. `clearAll()` empties the backing store through its normal API (DataStore `clear()`, `localStorage`/IndexedDB deletes); it deliberately does **not** try to shred or unlink the live store file out-of-band (doing so races concurrent writes and corrupts the store). An empty store holds no ciphertext or key material, but the underlying medium — a journaling filesystem, an SSD with wear-levelling, a backup snapshot, an OS free-list — may retain recoverable remnants that no userspace library can reach.

**The honest guarantee, and why it's enough:** KSafe relies on **cryptographic erasure** — destroy the key, and the ciphertext is unrecoverable regardless of what byte-level remnants survive. This is the standard model for at-rest encryption (NIST SP 800-88 "Cryptographic Erase"). Rotation strengthens it: after `rotateKeys()`, the superseded master(s) for entries that were actually re-encrypted are deleted, so **their pre-rotation ciphertext is cryptographically dead** even if its bytes physically persist. A superseded master is kept as long as any entry still references it — so if a rotation skipped or failed some entries (or a store below the target generation is still awaiting the next pass), that generation's key stays alive and its pre-rotation ciphertext remains decryptable until a later rotation supersedes those entries too. The two places where key material itself may leave a byte-level remnant are the **JVM software-fallback key file** (used only when no OS vault is available — a plaintext key on disk) and **web IndexedDB** (a non-extractable key, so the bytes are never plaintext to begin with). If your threat model requires provable physical erasure of key material, use a platform with a hardware-backed store (Android/iOS/macOS, or a JVM host with an OS vault) — not the software fallback.

## Observability

```kotlin
val info = ksafe.getKeyInfo("apiToken")
println(info?.keyGeneration)   // 1 = never rotated; higher after rotateKeys()
```

`KSafeKeyInfo.keyGeneration` reports the generation that decrypts a specific entry, so you can
verify a rotation reached everything. `getKeyInfo` reads through the same in-memory cache as
`getDirect` (the non-suspending read), so on web it returns `null` until the first load finishes —
see `awaitCacheReady()` in [USAGE.md](USAGE.md). An entry still below
`KSafeRotationResult.keyGeneration` is picked up by the next pass, but under the default `Never`
policy, with no retry budget armed and no interrupted pass to resume, no pass runs on its own; call
`rotateKeys()` again.

Acting on a result:

```kotlin
val result = ksafe.rotateKeys()
when {
    result.failed > 0 -> println("${result.failed} entries could not be rotated — check the key store")
    result.skipped > 0 -> println("${result.skipped} entries deferred; a later instance retries them")
    else -> println("store fully on generation ${result.keyGeneration}")
}
```

Rotation work that runs in the background reports what it did:

| Message | When |
|---|---|
| `KSafe: resumed interrupted key rotation at generation N (rotated X, skipped Y, failed Z).` | A crashed pass was finished at the same generation |
| `KSafe: retried incomplete key rotation at generation N (rotated X, skipped Y, failed Z).` | One attempt from the retry budget was spent |
| `KSafe: MaxAge key-rotation pass -> generation N (rotated X, skipped Y, failed Z).` | `MaxAge` came due and started a fresh generation |
| `KSafe: MaxAge key-rotation pass superseded pending retry -> generation N (…).` | The same, on an instance that also had a retry pending |
| `KSafe: scheduled key rotation failed (…)` | The background pass threw. Logged as a warning, and it says whether a later launch will retry |

## Edge cases & caveats

- **Downgrading below 3.0.0 after a rotation, or after any strict `HARDWARE_ISOLATED` write, is
  destructive — back up first.** See the downgrade warning under
  [Authenticated envelope (v3)](#authenticated-envelope-v3). Never-rotated stores with no strict
  writes are unaffected: generation 1 uses the exact same key names as 2.2.x.
- **Multiple instances / processes on the same file (3.2.0+; Android, iOS/macOS, JVM Desktop):**
  public KSafe instances in the same process share one storage backend per file, so their entry
  commits and key sweeps are serialized on one lock, and duplicate resume attempts are idempotent.
  Siblings keep their own writes readable across a rotation — a rotated entry is moved onto the new
  generation in their caches too — and a key a live sibling still reads through is left alone by the
  sweep and reaped by a later pass once that sibling has adopted it or closed. `clearAll()` clears
  every sibling's caches with it. On web each instance owns its own store handle and none of this
  applies, so keep one instance per store there. A lock cannot cross an OS-process boundary on any
  platform: do not rotate the same physical store concurrently from an app process and an
  extension/widget/second process — nominate one process for manual and `MaxAge` rotation.
- **`clearAll()`** wipes every generation's keys (best-effort: a platform-vault deletion failure is logged, not thrown — the data wipe itself fails loudly) and resets the store to generation 1. A rotation pass still in flight when the wipe lands is fenced: its remaining entries are reported `skipped` and nothing from the pre-wipe pass is stamped onto the reset store.
- **Generation upper bound**: the generation counter is capped at 10 000 (about 27 years of daily rotation). `rotateKeys()` at the cap throws `IllegalStateException` instead of overflowing; `clearAll()` resets the counter to 1.
- **Cost recap**: one decrypt plus one encrypt per encrypted entry, plus a freshly minted key for
  each `HARDWARE_ISOLATED` entry. Entries are processed in bounded chunks, which caps how much of
  the store is held decrypted in memory at once. On mobile hardware-backed tiers this is
  keystore-IPC-bound — a store with hundreds of entries takes seconds of background time, which is
  why `MaxAge` runs off the critical path and why `rotateKeys()` is a `suspend` function.
