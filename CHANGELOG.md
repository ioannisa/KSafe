# Changelog

All notable changes to KSafe will be documented in this file.

## [2.1.4] - 2026-07-02

Security and data-integrity hardening release. It **completes the 2.1.3 `requireUnlockedDevice` fix** (2.1.3 covered only the direct-read path) and closes a set of multi-instance, multi-tab, and biometric edge cases surfaced by two further deep audits. **Drop-in upgrade from 2.1.3** — on-disk format is unchanged and existing data keeps working without migration.

### Highlights

- **`requireUnlockedDevice = true` is now enforced on EVERY read path, not just `getDirect`.** 2.1.3 made a locked-device read bypass the in-memory caches and hit the OS hardware — but only for `get`/`getDirect`. **Flow / StateFlow / Compose-observe reads** (`asFlow`, `asStateFlow`, `asMutableStateFlow`, `getFlow`, and the `:ksafe-compose` live-observe states) still decrypted a strict entry from the cached key, and the eager **`PLAIN_TEXT`** memory policy still served its plaintext from RAM — both a bypass on Apple. 2.1.4 routes strict entries through the native store on all of these. **Upgrade recommended for iOS/macOS apps that observe `requireUnlockedDevice` values via flows.** See **Fixed**.
- **Web: `KSafeConfig.appNamespace` now isolates the data store, not just the key.** Previously appNamespace namespaced only the IndexedDB key record; two same-origin setups with the same `fileName` but different `appNamespace` shared the same `localStorage` slots and overwrote each other with mutually-undecryptable ciphertext. The data namespace is now isolated by `appNamespace` too (existing data migrated forward). See **Fixed**.
- **Android: co-existing same-file instances no longer lose a write that races another instance's `clearAll()`.** See **Fixed**.
- **Web: a tab keeps working after another tab logs out.** After a cross-tab `clearAll()`/key deletion, a surviving tab used to fail every encrypted write with "web key missing" until reload; it now regenerates the key and self-heals. See **Fixed**.
- **Biometrics: a cached PIN/password success can no longer satisfy a biometrics-only (`allowDeviceCredentialFallback = false`) call**, and a cancelled prompt no longer strands the next caller. See **Fixed**.

### Fixed

- **`requireUnlockedDevice` lock policy was still bypassable on flow-based and `PLAIN_TEXT` reads (Apple).** The 2.1.3 native-decrypt-on-locked guarantee is now a common-layer invariant: a strict entry is always held as **ciphertext** in the in-memory cache (on every memory policy, including `PLAIN_TEXT`/`LAZY_PLAIN_TEXT`) and re-decrypted through the engine — which passes the `requireUnlockedDevice` intent — on each read. `KSafeCore.getFlowRaw`, the startup orphan-sweep probe, and the background cache preload now all thread that intent, so `asFlow`/`asStateFlow`/`asMutableStateFlow`/`getFlow` and the Compose live-observe states can no longer serve a strict value from RAM while the device is locked. A strict entry also never enters the plaintext side cache, and a non-strict→strict rewrite evicts any prior side-cache entry. (Android was already safe — strict entries use the per-call TEE path.)
- **Web (Kotlin/JS + Wasm): `appNamespace` did not isolate the localStorage data store.** Two same-origin KSafe setups with the same `fileName` but different `appNamespace` collided on the same data slots. The data namespace is now `ksafe.<appNamespace>@<fileName>:` when an `appNamespace` is set (prefix-free: `@` is outside both the fileName alphabet and the sanitized namespace charset), with a one-time migration carrying data written under the previous un-namespaced prefix forward. The default (no `appNamespace`) layout is unchanged.
- **Android: a `clearAll()` on one instance could permanently orphan a concurrent encrypted write from a co-existing instance on the same file.** Same-file instances share one engine and its unwrapped-DEK cache; a sibling's `clearAll()` could wipe the persisted wrapped DEK + KEK after another instance had read the cached DEK but before its ciphertext committed, leaving that acknowledged write undecryptable. The engine now re-persists the data-encryption key (re-wrapping it under a fresh KEK if needed) whenever it detects the shared DEK was torn down mid-encrypt, so the just-written value stays recoverable. (The inherent last-writer-wins nature of two instances racing `clearAll()` on one file remains — this closes the *unrecoverable* case.)
- **Web (Kotlin/JS + Wasm): a surviving tab failed every encrypted write after another tab deleted the key.** The cross-tab `BroadcastChannel` eviction only cleared the JS in-memory cache, not the Kotlin engine's per-instance "key ensured" set, so after another tab's `clearAll()`/logout the surviving tab short-circuited key creation and threw "web key missing" on every write until reload (silently, for fire-and-forget `putDirect`). The engine now self-heals: on a "key missing" it drops the stale marker, regenerates the key in IndexedDB, and retries once.
- **Apple (iOS/macOS): tightening `requireUnlockedDevice` on an existing `HARDWARE_ISOLATED` key had no effect.** The unlock policy was applied only at key creation; rewriting an existing per-entry key with a stricter policy left its Keychain `kSecAttrAccessible` unchanged, so the tightened policy was silently unenforced. The rewrite now re-asserts the accessibility attribute. The re-assertion is best-effort — it never fails an otherwise-successful write and is retried on the next write if a transient error occurs.
- **A value could be resurrected in memory after being deleted, or a newer write's metadata clobbered, during the post-commit cache repair (all platforms).** The optimistic-cache repair that restores state a concurrent `clearAll()` wiped is a check-then-act against a key's latest-writer token; a delete or newer write landing in that window could be undone in memory (a resurrected delete), and the rollback that guards against it could remove a newer writer's protection/metadata because those values aren't unique. The rollback is now atomic-per-value: it removes metadata only when it also removed its own (unique-ciphertext) cache value, so an acknowledged delete is never resurrected and a newer writer's state is never clobbered. (In-memory only; disk was always correct and a restart healed it.)
- **Compose / Core: live external-change observation could stop reflecting updates permanently after an idempotent write.** A `mutableStateOf(..., scope = …)` / `rememberKSafeState(observeExternalChanges = true)` state, and the core `asMutableStateFlow`, latch a guard while a user write propagates to disk so a stale snapshot can't revert it. An idempotent write (`value = X` when already `X`) or an `A→B→A` toggle produces no distinct disk echo, so the guard never cleared and **all** later external changes were suppressed for the state's lifetime. The guard now tracks the storage-synced baseline and is not held when a write nets to no change. (Known minor limitation: if an intermediate value of an `A→B→A` sequence reached disk in a separate batch, a stale snapshot can briefly, self-correctingly revert the value — never data loss.)
- **JVM/Desktop: the `-Dksafe.jvm.keyVault=software` opt-out could let the startup orphan sweep delete recoverable data.** On a store that previously used the OS vault, opting out returned the software store without marking the OS-vault keys as merely unreachable, so the orphan sweep saw "no key" for entries whose key lives only in the OS vault and deleted their ciphertext. The opt-out now marks such reads "unavailable" (the sweep preserves the ciphertext) while still minting new keys into the software store. (Trade-off: orphan-ciphertext reclamation is disabled under the opt-out — harmless clutter, never data loss.)
- **`ksafe-biometrics`: a cached device-credential success could satisfy a biometrics-only call, and cancelling a prompt could strand the next caller.** The authorization-session cache is now keyed by auth strength via an injective scheme on **both Android and Apple** (previously Android-only and non-injective, so a scope literally ending in a strictness marker could collide), so a cached PIN/password (`allowDeviceCredentialFallback = true`) success can never be reused for a later `allowDeviceCredentialFallback = false` call. Separately, a cancelled Android `BiometricPrompt` is now dismissed (`cancelAuthentication`) — an orphaned prompt no longer rebinds to the next caller and satisfy it under the wrong security configuration.

### Changed

- **`ksafe-biometrics` prompt-cancellation and session-strength logic is shared and platform-consistent.** The strength discriminator lives in the common `BiometricAuthSession.sessionKey`, so Android and Apple keep identical cache-slot semantics.

### Tests

- The iOS Keychain memory-leak regression test now uses a **strict** threshold on the non-throwing `deleteKey` path (below the leak's ~5 MB signature so a regression actually fails the build) and a separate loose threshold only on the throwing `decrypt` path, whose Kotlin/Native 2.3+ exception stack traces inflate peak RSS independently of the bridging leak under test.

## [2.1.3] - 2026-06-17

Security patch release for aggressive memory caching bypassing the `requireUnlockedDevice` hardware lock policy.

### Fixed
- **`requireUnlockedDevice = true` security policy could be bypassed due to in-memory caching (All Platforms).** A key-value pair written with the `requireUnlockedDevice = true` flag is designed to be inaccessible while the user's device is locked. However, because `KSafeCore` maintained a fast, optimistic `plaintextCache` and `memoryCache`, a read on a locked device could return the secret value directly from process memory if it had been cached while the device was previously unlocked. The in-memory read bypassed the hardware OS security modules entirely. Furthermore, the platform-specific encryption engines (`AndroidKeystoreEncryption` and `AppleKeychainEncryption`) also aggressively cached raw AES bytes or Data Encryption Keys (DEKs) in memory, which could short-circuit hardware lock checks even if the core cache was bypassed.
  - **The Fix:** A coordinated cache bypass architecture has been implemented across all layers. `KSafeCore` now consults the metadata for a key *before* checking the `plaintextCache`. If the key requires an unlocked device, it completely ignores the in-memory cache and forces a native decryption request. The native engine interface now receives the `requireUnlockedDevice` intent. On Android, this forces the `AndroidKeystoreEncryption` engine to bypass its software DEK cache and hit the Keystore hardware directly, which natively throws a `UserNotAuthenticatedException` on locked devices. On Apple platforms, `AppleKeychainEncryption` bypasses its `keyBytesCache` and queries the Keychain, which enforces `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Highly sensitive keys are now guaranteed to be cryptographically enforced by the underlying OS hardware on every read, fixing the lock bypass vulnerability on both Android and iOS.

## [2.1.2] - 2026-06-10

Android performance, numeric type-coercion, and data-loss hardening release. **Drop-in upgrade from 2.1.1** — on-disk format is unchanged and existing data keeps working without migration.

### Highlights

- **Android: `ENCRYPTED`-memory "decrypt on every read" is now userspace AES — ~570× faster on real hardware.** Before 2.1.2 each `ENCRYPTED`-memory read ran its AES-GCM *inside* the Android Keystore (TEE), so every read was a hardware round-trip: **~8 ms/op on a Galaxy S24 Ultra** (an emulator's software keystore hid this — it looked like ~0.2 ms). 2.1.2 keeps the per-datastore master key (the **KEK**) non-exportable in the TEE but uses it to wrap a **data-encryption key (DEK)** that is unwrapped **once** into process memory; per-value AES-GCM then runs in userspace. Measured on an S24 Ultra, `ENCRYPTED` Direct read dropped **8.25 ms → 0.0144 ms**, which **flips KSafe from ~143×/161× *slower* than EncryptedSharedPreferences / KVault to ~3.4×/2.6× *faster*** on the apples-to-apples decrypt-every-read path. This brings Android in line with the Apple (CryptoKit) and JVM (JCE) engines, which already held raw key bytes in memory and did userspace AES. **Most relevant if you use `KSafeMemoryPolicy.ENCRYPTED` for frequently-read secrets.**
- **`HARDWARE_ISOLATED` and the strict `requireUnlockedDevice` master are unchanged.** Both keep their key inside the TEE and decrypt there on every op — the DEK fast path applies only to the relaxed (`requireUnlockedDevice = false`) `DEFAULT` master, which is usable while the device is locked anyway, so no security property is lost there.
- **No migration, no data loss.** DEK ciphertext is self-describing (a `MAGIC || VERSION` header), so the engine reads pre-2.1.2 TEE ciphertext via the original path and new ciphertext via the DEK path — both coexist. Existing values are upgraded lazily on their next write, exactly like the v1→v2 envelope migration.
- **Cross-type numeric reads no longer silently lose data.** A persisted primitive can now be read back as any other numeric type — the full `Int`/`Long`/`Float`/`Double` matrix coerces when the value is faithfully representable (e.g. a key shipped as `ksafe(0f)` later read as `Double`, or `ksafe(0)` read as `Long`). Previously the unencrypted path coerced `Int↔Long` but **not** `Float↔Double` — those returned the default (silent data loss on Android / iOS / macOS / JVM; web was unaffected). See **Fixed**.
- **JVM: a transient OS key-vault outage at startup no longer destroys data.** A momentarily-unreachable Keychain / Secret Service / DPAPI (locked keychain, login keyring not yet up, SSH / headless launch) previously made KSafe silently fall back to the software vault *and treat that as healthy*, which could permanently delete still-recoverable ciphertext and even overwrite the real OS-vault key on the next launch. KSafe now distinguishes "OS vault present but unreachable" from "no OS vault" and fails safe instead of destructively. **Upgrade strongly recommended for JVM / Compose Desktop consumers using OS-backed key custody.** See **Fixed**.
- **A failed write no longer corrupts the rest of the batch — or lies about it afterwards.** One failing encrypt (e.g. a `requireUnlockedDevice` write while the device is locked) used to drop *every* write that happened to share the same coalescing window — including unrelated keys and plain writes — and the failed value kept being served from the in-memory cache for the rest of the process even though it never reached disk. Failures are now isolated per entry and the optimistic cache is rolled back on failure. See **Fixed**.
- **`getOrCreateSecret` no longer silently rotates an unreadable secret under `PLAIN_TEXT`.** Under `KSafeMemoryPolicy.PLAIN_TEXT`, a secret that couldn't be decrypted at cold start (locked device / unavailable vault / corrupt blob) was treated as absent and replaced — permanently orphaning anything encrypted under it (e.g. a SQLCipher database). It now correctly refuses to rotate and surfaces the condition. See **Fixed**.

### Changed

- **Android `AndroidKeystoreEncryption` adds a software-DEK fast path for relaxed `DEFAULT` encryption.** A random AES key (the DEK, sized per `KSafeConfig.keySize`) is generated once per safe, wrapped (AES-GCM) by the non-exportable Keystore master key (the KEK), and persisted as a single reserved Base64 entry (`__ksafe____DEK____`) **in the safe's own DataStore** — KSafe uses no `SharedPreferences` anywhere, not even for the DEK. The `__ksafe_` prefix keeps the entry in KSafe's internal namespace (the same convention as per-key metadata), so the core never surfaces it as a user value and `clearAll()` wipes it with everything else. It is unwrapped once into an in-process cache (mirroring the Apple engine's `keyBytesCache`), after which every encrypt/decrypt of a relaxed-`DEFAULT` value is pure-CPU AES-GCM with no Keystore/TEE round-trip. DEK ciphertext carries a 5-byte `MAGIC("KSD1") + VERSION` header; `decrypt` routes by that header (with a GCM-auth fallback to the legacy TEE path), so the change needs no envelope-version bump and no common-code change. `deleteKey` drops the cached DEK and the KEK; the *persisted* DEK is cleared + regenerated under a fresh KEK when its KEK is permanently invalidated **or** the stored wrapped DEK fails to unwrap (corrupt blob / KEK mismatch) — so a damaged DEK self-heals on the next write instead of failing forever — and is wiped by `clearAll()`, but **never** by deleting an individual key, so removing one entry can't brick the rest. The engine is constructed with a DataStore-backed `WrappedDekStore` (internal); an internal `useSoftwareDek` flag exists as a test / escape hatch and is **not** exposed publicly.
  - **Security trade-off (Android only):** the relaxed-`DEFAULT` DEK lives in process memory after first use — the same posture as `EncryptedSharedPreferences` / Tink and KSafe's own Apple and JVM engines (and the `PLAIN_TEXT`/`LAZY_PLAIN_TEXT` plaintext caches). The KEK never leaves the TEE. Apps that require key material to never reside in app memory should use `KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)` or `requireUnlockedDevice = true`, both of which keep the per-call TEE path.
  - **Lazy DEK creation:** the DEK is generated + persisted on the **first real encrypt**, not at construction. Prewarm now warms only the wrapping KEK (via the new `KSafeEncryption.prewarmKey`, which the Android engine overrides), so an unencrypted-only safe never writes a DEK and construction performs no DataStore I/O for the DEK. Other engines keep the prior prewarm behavior through the interface's default.

- **Android DataStore lifecycle is now robust to close-then-recreate on the same file.** The factory tracks each datastore's owning `CoroutineScope`; when a safe is recreated on a path whose previous owner is still tearing down, it awaits that scope's completion (bounded) before opening a new `DataStore` — DataStore frees a file only once its scope's `Job` completes. This removes an intermittent `IllegalStateException: There are multiple DataStores active for the same file` under rapid re-init (instrumented tests, DI hot-reload).

- **`KSafe.protectionInfo` (Android) custody text now discloses the in-memory DEK.** The custody string notes that relaxed `DEFAULT` values use a TEE-wrapped AES key held in memory, and a `relaxed_default_uses_software_dek` note is added, so `protectionInfo` stays truthful. `intendedLevel` / `effectiveLevel` remain `HARDWARE_BACKED` (the key custody is still hardware-rooted via the KEK).

### Fixed

- **Unencrypted `Float`↔`Double` reads silently returned the default (data loss); the full numeric matrix now coerces.** `KSafeCore.convertStoredValue` (commonMain) — the read path for plain, typed-DataStore primitives — had `Int↔Long` coercion arms but no `Float↔Double` ones, so a key written as `Float` and later read as `Double` (or vice-versa) hit `else -> defaultValue` and lost the stored value. This affected **Android, iOS, macOS, and JVM** (all store primitives typed via DataStore); the **web** target was unaffected because its values round-trip through `localStorage` as strings, which the existing `String` arms already coerce. The branch now coerces the whole `Int`/`Long`/`Float`/`Double` matrix, following the original `Long→Int` rule: widening is exact (or, for large magnitudes, loses only precision); narrowing or decimal→integer coerces **only when the value is faithfully representable** — an out-of-range integer, an overflowing decimal, or a decimal with a fractional part read as an integer falls back to the caller's default rather than silently truncating or wrapping. **No migration needed** — existing on-disk values read correctly the moment a key's declared type changes. (The encrypted path was already type-tolerant via type-tagless JSON.)

- **JVM (critical): a transient OS key-vault outage at construction could permanently destroy keys and data.** `JvmKeyVaultProvider.pick()` runs each OS vault (Windows DPAPI / macOS Keychain / Linux Secret Service) through a write→read-back→delete self-test at construction. If that self-test failed for a *transient* reason — a locked macOS Keychain, a Linux login keyring not yet on D-Bus (SSH / headless / session-autostart before unlock) — selection silently fell back to the legacy software vault with the degrade flag left **unset**, i.e. treated as a healthy choice. Two independent permanent-data-loss paths followed: (1) `KSafeCore`'s startup orphan sweep saw `"No encryption key found"` for entries whose key lives only in the now-unreachable OS vault and **deleted the still-recoverable ciphertext and metadata from disk**; (2) the construction-time master-key prewarm minted a fresh "junk" key into the legacy DataStore migration source, which the **next, healthy** launch's legacy-first migration then copied **over the real OS-vault key** (delete-then-add), making everything encrypted under it permanently undecryptable. A constructible-but-unreachable OS vault is now flagged distinctly from "no OS vault is present here": reads of an unresolvable key report `"unavailable"` (not `"absent"`), so the orphan sweep leaves the ciphertext intact until the vault is reachable again; and key *creation* refuses to mint into the legacy migration source while the OS vault is unreachable (failing closed, with an actionable one-time warning and the `-Dksafe.jvm.keyVault=software` opt-out), so no junk key can later overwrite the real one. The runtime-`LinkageError` degrade path (a jlink runtime missing `jdk.unsupported`) and the 2.0 → 2.1 legacy-key migration are unchanged. The self-test canary now also uses a **unique alias per attempt**: the OS stores are per-user and shared by every KSafe process and instance on the machine, so the old fixed alias let two concurrent self-tests interleave (one's cleanup deleted the other's canary between its write and read-back) — two apps launching at login, or one app constructing two instances in parallel, could fail a perfectly healthy vault's self-test and put that session into the fail-safe state for no reason. Affects JVM / Compose Desktop consumers using OS-backed key custody (shipped 2.1.0 / 2.1.1).

- **A single failing encrypt dropped every other write in the coalesced batch.** The write coalescer (`KSafeCore.processWrites`, commonMain) encrypted a batch's entries inside one `coroutineScope` with `awaitAll`, whose fail-fast cancels the siblings — so one throwing `encryptSuspend` (e.g. a `requireUnlockedDevice = true` write while the device is locked, or any transient Keystore/Keychain error) propagated out **before** `applyBatch` ran, silently discarding every other write that merely landed in the same ~16 ms coalescing window, including plain writes and encrypted writes to unrelated keys. Encryption is now isolated per entry: a failing encrypt drops only its own key and completes only that caller exceptionally, while every other write in the batch still commits.

- **A failed write left its never-persisted value served from the cache for the rest of the process.** Both the suspend and fire-and-forget put paths mutate the optimistic in-memory cache (and protection metadata, and the dirty-key set) **before** the disk commit, and nothing rolled them back when the batch failed — so subsequent reads returned the value that never reached disk until the process restarted (the dirty flag pinned it past every reconciliation snapshot), and after restart it silently reverted. Failures now roll back the affected keys' optimistic state (memory cache, the plaintext side-cache used by `ENCRYPTED_WITH_TIMED_CACHE` / `LAZY_PLAIN_TEXT`, protection metadata, and dirty flags) so reads fall back to the prior persisted value, or the default — on both a per-entry encrypt failure and a whole-batch `applyBatch` failure. Fire-and-forget `putDirect` failures, previously fully silent, now emit a `SEVERE` log. The rollback is **ownership-gated**: each write claims its key before its optimistic state, and a failed write only reverts a key it is still the latest writer for — so rolling back can never strip the in-flight state of a *newer* write to the same key issued while the failed batch was processing (the newer write's own commit, or failure, resolves the key).

- **`getOrCreateSecret` silently rotated an existing-but-unreadable secret under `KSafeMemoryPolicy.PLAIN_TEXT`.** The "never silently rotate" guard distinguishes "secret absent" from "secret present but unreadable" via `getKeyInfo`, which decided existence solely from the in-memory cache. Under `PLAIN_TEXT` the cache is built by decrypting every encrypted entry at cold start and **dropping any that fails to decrypt** (locked device, temporarily-unavailable vault, corrupt/tampered blob) from the cache — so a still-present secret read as *absent*, the guard fell through, and a brand-new secret was minted whose write **overwrote the old ciphertext**, permanently orphaning everything encrypted under it (e.g. a SQLCipher database keyed by that secret). `getKeyInfo` now also consults the protection-metadata map, which tracks on-disk existence independently of whether the value can currently be decrypted and of the memory policy, so the guard correctly throws instead of rotating. The other three memory policies cache ciphertext (so the entry stayed present) and were already protected; `PLAIN_TEXT` was the gap.

- **Android: co-existing `KSafe` instances on the same file could open a second DataStore — or have their store cancelled when another instance closed.** The factory dedupes the per-file `DataStore` so repeated construction (DI re-init, multiple holders) doesn't trip DataStore's "multiple DataStores active for the same file" guard, but the dedup had two races: (1) the cache insert was non-atomic (`getOrPut`), so two instances constructed concurrently on the same file could each open a `DataStore` and the second tripped the guard — swallowed by the cache-load path, leaving that instance to return defaults and drop its writes; and (2) only the instance that *created* the DataStore cancelled its scope on `close()`, so closing that one instance cancelled the DataStore out from under any other still-live instance on the same file (its subsequent reads/writes then hit a cancelled scope). The factory now shares a single **ref-counted** per-file backend behind a per-path lock: creation is atomic (never two DataStores for one file) and the scope is torn down only when the **last** instance on that path closes.

- **JVM/Desktop: two `KSafe` instances on the same file — or a quick `close()`-then-recreate — silently broke reads and writes.** Unlike Android, the JVM factory created a fresh `DataStore` on every construction with **no per-file dedup**, so a second live instance on the same `fileName` tripped DataStore's "multiple DataStores active for the same file" guard inside its collector (swallowed → the instance returned defaults and dropped its writes), and an immediate recreate after `close()` raced DataStore's file release (it frees a file only once the owning scope completes). The JVM factory now uses the same ref-counted, per-file backend as Android: atomic creation, a bounded await on a prior owner's teardown before reopening, and teardown only on the last close — so concurrent same-file instances and `close()`→recreate both work. Both the normal DataStore backend and the no-`sun.misc.Unsafe` JSON-file fallback are covered.

- **Apple (iOS/macOS): concurrent first-time key creation could clobber the key and silently lose data.** `AppleKeychainEncryption` had no lock serializing key creation, even though `KSafeCore` relies on each engine doing so (Android and JVM both do). On first launch — or after `clearAll()` — the construction-time master-key prewarm races the first batch of `DEFAULT` writes, which encrypt up to 8 entries in parallel against the **same** per-datastore master alias. Two threads could both find no key, both generate one, and the delete-then-add Keychain store let the second overwrite the first **after** the first had already produced ciphertext under its key — so that value became permanently undecryptable (and, being a GCM-authentication failure rather than a "key not found", it wasn't even reclaimed by the orphan sweep). Key creation is now serialized (a reentrant lock with a double-checked cache), so concurrent callers resolve to a single shared key; the lock-free read path and the in-memory key cache are unchanged. Also hardened: a Secure-Enclave store failure no longer silently falls back to a divergent plain key under the same identifier. Affects all Apple targets (shipped 2.1.0 / 2.1.1); **upgrade recommended if you target iOS/macOS and use the default (`DEFAULT`) encryption.**

- **macOS: the Keychain orphan sweep could delete another KSafe-using app's keys every launch.** The once-per-launch sweep that reclaims Keychain entries with no surviving DataStore counterpart ran on macOS too, although it is only safe where the Keychain is **app-private** (the iOS/iPadOS/tvOS/watchOS sandbox). On macOS, items live in the shared per-user **login keychain** under a fixed service name with no app identity, so if two macOS apps both use KSafe under the same user account, one app's startup sweep would enumerate the other's items, classify them as orphans (absent from *its own* DataStore), and delete their keys — permanently corrupting the other app's `HARDWARE_ISOLATED` / legacy data on every launch. The sweep is now **disabled on macOS** (it stays active on the sandboxed Apple platforms); stale macOS Keychain entries are harmless clutter, reclaimed by `clearAll()`. Note: KSafe still uses a shared per-user Keychain namespace on macOS, so two apps configured with the same `fileName` can still collide when *writing* keys — per-app Keychain isolation (access groups) remains on the roadmap.

- **Apple (iOS): the startup Keychain orphan sweep no longer deletes a key for a write made concurrently with it.** The sweep builds its set of live keys from a single DataStore snapshot taken at entry, then enumerates and deletes — so a key the engine had just created for an in-flight write (a `HARDWARE_ISOLATED` or per-entry key whose DataStore commit lands after that snapshot, e.g. a refresh-token write at launch) could be classified as an orphan and destroyed, leaving the just-written value undecryptable and reaped on the next launch. The sweep now consults the same in-flight ("dirty") key set the rest of KSafe uses and skips any key with a write in progress, so a concurrent write at startup is never mistaken for an orphan. Affects iOS apps that write encrypted values during launch (shipped 2.1.x).

- **All platforms: a write racing an in-flight `clearAll()` was unreadable for the rest of the session, despite committing successfully.** `clearAll()` is serialized with concurrent writes (a write ordered after it survives the wipe — the canonical logout-then-write-fresh-session-state pattern). The disk side honored that ordering, but the in-memory side didn't: a put's optimistic cache and routing metadata are set at call time, the wipe then cleared them unconditionally, and nothing ever restored them — the post-commit cache swap found its expected entry gone, and in-flight markers are deliberately permanent, so reconciliation skipped the key forever. The write completed, its awaiter succeeded, the value was on disk — and every read returned the caller's default until the app restarted (with read-modify-write callers then able to clobber the on-disk value). After its disk commit, a write that is still its key's **latest writer** (the same ownership rule the failure rollback uses) now re-asserts its in-memory state atomically — a slot wiped by the clearAll is restored, while a slot occupied by an even newer write's value is never touched. Affects all platforms, any `put` concurrent with `clearAll()` (shipped 2.1.x).

- **All platforms: types with primitive-kind custom serializers (`Duration`, `Uuid`, kotlinx-datetime, hand-written `PrimitiveSerialDescriptor` serializers) crashed on plain-mode reads.** The plain write path dispatches on the value's *runtime* type, so e.g. a `Duration` (not a runtime `String`) was JSON-encoded before storing — but the read path dispatched on the serializer's *descriptor kind*, and `Duration`'s serializer is STRING-kind, so the read returned the stored JSON verbatim (quote characters included) and the caller's reified cast threw `ClassCastException`. INT/LONG-kind custom serializers failed the same way. The same value round-tripped fine *encrypted* (that path always JSON-decodes) — a silent mode-dependent behavior split. The read now takes the primitive fast-path only for the **built-in** primitive serializers (matching exactly what the write path stores raw); everything else round-trips through JSON, symmetrically with how it was written. Affects all platforms, `KSafeWriteMode.Plain` (shipped 2.1.x).

- **All platforms: a read racing a write to the same key could pin a stale value in the plaintext side cache (`ENCRYPTED_WITH_TIMED_CACHE` / `LAZY_PLAIN_TEXT`).** After decrypting a value, the read path repopulated the plaintext side cache with what it had just decrypted — with no guard against a `put` (or `delete`) that landed *during* the decrypt, whose fresh side-cache entry was then overwritten with the stale pre-write plaintext. Under `LAZY_PLAIN_TEXT` the side cache never expires and the key is excluded from reconciliation after a write, so every subsequent read served the stale value for the rest of the session even though the memory cache and disk held the new one; under `ENCRYPTED_WITH_TIMED_CACHE`, for up to the TTL. The write-back is now guarded: it only lands if the primary cache still holds the exact ciphertext that was decrypted — the same compare-and-set discipline the write coalescer already used for the primary cache. Affects the side-cache memory policies on all platforms (shipped 2.1.x).

- **Web (Kotlin/JS + Wasm): nested store names shared and destroyed each other's data, and a store named `"default"` collided with the unnamed instance.** The localStorage namespace prefix (`ksafe_<fileName>_`) was not prefix-free: `KSafe("user")`'s `startsWith` scoping ingested `KSafe("user_cache")`'s entries under garbled keys, and `KSafe("user").clearAll()` **permanently deleted the entire sibling store**. Separately, `KSafe(fileName = "default")` produced byte-for-byte the same prefix as the unnamed `KSafe()` while using *different* crypto aliases — two logically distinct stores silently clobbering one shared slot with mutually undecryptable ciphertext. The data namespace is now prefix-free (`ksafe.<name>:` — the delimiter characters cannot appear in a fileName, so no store's prefix can prefix another's), with a one-time migration that carries existing data forward: each canonical entry is copied to the new location, verified, and only then removed — and the canonical-shape gate makes the migration order-independent for nested names (a store never steals its longer-named sibling's entries). The encryption key records deliberately stay in their original namespace: their IndexedDB record names embed it, and moving them would orphan every existing key. Affects web apps using nested fileNames, a store named `"default"`, or `clearAll()` near such stores (shipped 2.1.0).

- **Apple: "iOS app on Mac" no longer false-positives as a jailbroken device, which bricked `Strict`-policy apps on Apple Silicon Macs.** iPhone/iPad apps run on M-series Macs by default for App Store apps ("iOS app on Mac"), executing the iOS binary against the real macOS filesystem — where the jailbreak path probes trivially match (`/bin/sh`, `/usr/bin/ssh`, … exist on every Mac). The existing macOS short-circuit didn't apply because the platform check is a *compile-time* constant of the iOS slice, and the simulator check sees no `SIMULATOR_*` env vars there — so a perfectly clean Mac was classified as jailbroken: with the documented `KSafeSecurityPolicy.Strict` preset ("recommended for banking, enterprise, and high-security apps") construction threw `SecurityViolationException` and secure storage was entirely unusable on Apple Silicon Macs; `Warn` policies fired spurious callbacks (which apps commonly answer by logging the user out). The rooted-device check now also short-circuits when `NSProcessInfo.iOSAppOnMac` reports the iOS-on-Mac environment (selector-guarded for older iOS versions, which cannot be iOS-on-Mac; and exception-guarded so a security probe can never crash construction). Affects iOS apps with a rooted-device policy of `BLOCK`/`WARN` running on Apple Silicon Macs (shipped 2.1.1).

- **Apple (iOS/macOS): a transient Secure-Enclave unwrap failure on a non-English device could destroy `HARDWARE_ISOLATED` data.** When a `HARDWARE_ISOLATED` key's AES key is unwrapped through its Secure-Enclave key, a transient failure (device locked at the moment of unwrap, SE busy, `securityd` hiccup) must be propagated and retried — never treated as corruption, because the SE private key is non-exportable and deleting it makes every value encrypted under it permanently undecryptable. KSafe decided "transient vs permanent" by matching the English substrings "device is locked" / "interaction" against the CFError's **localized** description. On a non-English device that description is localized (or the generic "OSStatus error -25308."), so a genuinely transient failure matched neither word, was misclassified as permanent corruption, and triggered **destructive key regeneration** — deleting the SE key and the wrapped blob, after which the orphan sweep removed the now-undecryptable ciphertext. Classification is now keyed on the locale-independent **OSStatus code** (`errSecInteractionNotAllowed`, `errSecNotAvailable`, `errSecAuthFailed`, `errSecUserCanceled` are treated as transient — conservatively biased toward preserving the key), with the English wording kept only as a fallback for KSafe's own explicitly-worded errors. The same check now also gates the Secure-Enclave-vs-plain fallback, so a transient failure can't be mistaken for "Secure Enclave unavailable" and silently downgraded to a divergent plain key either. And the **decrypt path** is covered too: a transient Secure-Enclave unwrap during a *read* used to surface as an unrecognized error message, which the common read layer misclassified as permanent — `getDirect` silently returned the caller's default for a `HARDWARE_ISOLATED` secret and `getFlow` emitted it to collectors, instead of retrying/skipping. Transient-classified Secure-Enclave failures now carry the wording the read layer's transient check recognizes, so reads retry and flows skip the emission, exactly as they already did for locked-device Keychain errors. Affects iOS/macOS apps using `HARDWARE_ISOLATED` on non-English devices (shipped 2.1.0).

- **All platforms: a corrupt DataStore file now recovers to an empty store instead of crashing or silently defaulting forever.** The Android, JVM, and Apple backends created their `DataStore` with no corruption handler, so a corrupt `.preferences_pb` (interrupted write, disk fault, partial restore) threw `CorruptionException` on every read for the life of the process: the background cache collector crashed (uncaught in its scope — an app crash on Android), and `getDirect` / delegate reads silently returned defaults while suspend `get()` threw — the two APIs disagreeing about the same failure, with the corruption masked exactly where KSafe otherwise promises no silent loss. Each backend now installs a corruption handler that copies the unreadable file aside (a `.corrupt-*` quarantine, recoverable) and continues from an empty store — the same posture the JSON-fallback backend already had. The store is immediately usable again, and the corrupt bytes are preserved for forensic recovery rather than discarded. Affects Android / iOS / macOS / JVM (shipped 2.1.0).

- **A successful write is no longer reported as failed when the post-commit key cleanup hiccups.** A `delete` (or an overwrite that drops a per-entry key) commits its storage change and *then*, as best-effort cleanup, deletes the now-unused Keystore/Keychain key. A failure in that trailing delete was propagated as a batch failure — so an awaiting `delete()` / `put()` caller was told its operation failed even though it had already persisted, and the in-cache plaintext→ciphertext swap was skipped. The post-commit key deletion is now best-effort: a stranded engine key (harmless — reclaimed by the orphan sweep) never fails an already-committed write.

- **Transient Apple Keychain read errors are now retried/skipped instead of silently returning the default.** KSafe's "is this decrypt failure transient?" check matched Android's `Keystore` wording but not Apple's `Keychain`, so a transient iOS/macOS Keychain error (e.g. a momentarily inaccessible item) was treated as permanent: a one-shot `get` returned the default and a `Flow` emitted it, rather than surfacing a retryable condition. The check now recognizes `Keychain` too (KSafe's own definitive "no key" / "vault unavailable" results are still classified non-transient).

- **JVM/Desktop (no-`sun.misc.Unsafe` fallback): the software key file is now fsync'd before the atomic rename.** `FileKeyVault` wrote the AES keys to a temp file and atomically renamed it into place without forcing the bytes to disk first. On a power loss / OS crash right after the rename, a journaling filesystem can persist the rename before the file's data blocks, leaving a **zero-length** key file — and since that file holds the only copy of the master key, a blank file reads as "no keys", so the startup orphan sweep then deletes every encrypted entry. The temp file is now fsync'd before the move (the same durability step `datastore-core` takes for the value file), so the keys are durable before the rename is visible.

- **Compose: the cold-start self-heal can no longer clobber a concurrent user write off-thread.** For `mutableStateOf(...)` without an explicit `scope`, the one-shot self-heal runs on a background dispatcher while the property setter runs on the caller's thread. The flag that records "the user has already written" wasn't declared `@Volatile`, so the background thread could miss the setter's update and overwrite the user's value with the persisted default — leaving the Compose state showing the default while disk held the user's value, until the screen was recreated. The flag is now `@Volatile`, giving the cross-thread visibility that prevents the clobber.

- **JVM/Desktop: a stale-fallback re-migration could silently roll back newer writes on every launch.** When an app that had persisted through the no-`sun.misc.Unsafe` JSON fallback later started on the OS-backed DataStore path, the one-time forward migration drained the fallback into the OS store, then archived the fallback files (a `.migrated` marker) so it never ran again. But if a single entry was **permanently** unmigratable — a corrupt fallback ciphertext, or a `.ksafe-keys.json` lost/restored from an older copy missing one key — it was treated as a retryable failure, so the source was never archived. The construction-time gate (fallback file exists **and** no marker) then re-ran the blocking migration **on every launch**, re-draining the frozen fallback values over whatever the user had since written through the OS-backed store — a silent data rollback, forever. The migration now distinguishes **permanent** failures (a corrupt/unkeyed *source* entry — skipped, since it would fail identically every launch) from **transient** ones (the OS key vault momentarily unavailable). A permanent failure no longer blocks archiving, so the migration runs once and never re-drains; a transient failure aborts the whole pass (nothing written, nothing archived), so the retry next launch is a clean full migration with no partial state to roll back. And the **retry itself is now overwrite-safe**: after a transiently-failed attempt the session keeps running on the OS-backed store, so values the user writes *after* the failed attempt are newer than the frozen fallback. The failed attempt records the target's per-key state (a `.migration-pending` snapshot, removed on success, also wiped by `clearAll()`), and the retry skips any key whose target value changed since — the user's newer value wins (the fallback copy stays recoverable in the archive) while untouched keys still migrate. Affects apps that ran the JSON fallback and later added `jdk.unsupported` (shipped 2.1.1).

- **`ksafe-biometrics` (Android): two concurrent biometric prompts hung the first caller forever.** Each `verifyBiometric` / `verifyBiometricDirect` built a fresh `BiometricPrompt` with no mutual exclusion. The androidx `BiometricPrompt` is backed by a single activity-scoped view-model whose client callback is **overwritten** on each construction (and a second `authenticate()` while a prompt is already showing is silently dropped), so two overlapping calls — two biometric-gated reads launched in parallel, or a double-tap — stomped each other: the user saw one prompt, only the **second** caller's coroutine was resumed, and the **first suspended forever** (there's no timeout), permanently stalling any flow awaiting it. Prompt presentation is now serialized through a process-wide gate: concurrent callers queue and each prompt is shown only after the previous one resolves; a cancelled caller releases the gate so it can never strand the next. (No public API change.)

- **`ksafe-biometrics` (Android): `verifyBiometricDirect` now delivers its result on the main thread.** The callback fired on a background thread (the verify coroutine runs on `Dispatchers.Default`), while the Apple implementation delivers on the main thread — so a View-based consumer that touched the UI from the callback crashed with "Only the original thread that created a view hierarchy can touch its views" (Compose consumers happened to tolerate it). `onResult` is now posted to the main looper, matching Apple.

- **`ksafe-biometrics` (Android + Apple): a no-cache (`duration <= 0`) authorization no longer primes the session cache, so a later wider window can't reuse it.** The cache *read* correctly required `BiometricAuthorizationDuration.duration > 0` before skipping a prompt, but the cache *write* recorded a successful auth for **any** non-null duration — including the `duration = 0` / negative value a caller passes precisely to opt out of caching. A path that authenticated with a 0-or-short duration therefore seeded a session timestamp, and a later call on the **same scope** with a longer duration was silently granted without a prompt, because the freshness window applied was the *later* call's. The cache write now also requires `duration > 0`, matching the read — a non-caching authorization stays non-caching.

- **`ksafe-biometrics` (Android + Apple): a `null` (global) scope and an empty-string scope no longer share one authorization session.** Both the cache lookup and write mapped a null scope to `""`, so a caller passing `scope = ""` (a valid, distinct scope — e.g. a scope computed from possibly-empty input) shared the **same** session slot as every global-scope (`null`) caller: a global authorization could satisfy an empty-scope call and vice versa, breaking the documented per-scope isolation for that pair. Scopes are now namespaced so `null` and `""` (and every caller string) occupy distinct slots.

- **JVM/Desktop: the auto-derived key namespace changed with the launcher, deleting encrypted data on a versioned-jar upgrade.** With `KSafeConfig.appNamespace` left unset (the default), the OS key-vault namespace (Keychain service / DPAPI prefix / Secret Service attribute) was derived from `sun.java.command` — the jar filename or main-class token. That token isn't stable: `java -jar myapp-1.2.3.jar` → `myapp-1.2.4.jar` on the next release, or an IDE/Gradle run vs a packaged run, each produce a **different** namespace. But the default-config data file is **not** namespaced, so the ciphertext stayed in one shared file while the keys moved to a new namespace — every existing key became invisible, and the startup orphan sweep then **permanently deleted all encrypted entries** from the shared file. In effect every versioned-jar release silently wiped the user's encrypted data. The default namespace is now a **stable constant**, never derived from the launcher; `KSafeConfig.appNamespace` / `-Dksafe.appNamespace` / `KSAFE_APP_NAMESPACE` still set it explicitly (and an explicit value also namespaces the data file, so file and keys move together). **Upgrade migration:** an app shipped on 2.1.0/2.1.1 with a *stable* launcher (a jpackage main class, a non-versioned jar) holds its real keys under the old derived namespace — so on a lookup miss under the new constant namespace, KSafe probes that legacy location (the 2.1.0/2.1.1 derivation, reproduced exactly) and migrates the key over: written to the new namespace, read-back-verified, and only then deleted from the old one; a migration hiccup still serves the key for the session and retries on a later launch. Without this probe the upgrade itself would have orphaned those keys and the startup sweep would have deleted the data. Affects JVM/Desktop apps on the default configuration (shipped 2.1.0 / 2.1.1).

- **Web (Kotlin/JS + Wasm): two browser tabs racing on first launch could mint divergent keys, losing one tab's encrypted writes.** The IndexedDB get-or-create for the non-extractable WebCrypto key was check-then-act across separate transactions (`get` → `generateKey` → `put`) with no atomic guard. Two same-origin tabs opening for the first time — or after `clearAll()`, each driven by the construction-time key prewarm — could both read "no key", both generate one, and both write; the later write wins in IndexedDB, but the **losing tab keeps its own non-extractable key in page memory** and encrypts that session's values with it. After a reload those values can't be decrypted by the surviving key (the losing key, being non-extractable, died with the page) and are silently dropped. Key creation now uses an **atomic IndexedDB `add`**: if another context wins the race, this one gets a constraint error and adopts the winner's key, so all tabs converge on a single key. Affects same-origin multi-tab / multi-window first launches (shipped 2.1.0).

- **Web (Kotlin/JS + Wasm): a failed `localStorage` write could permanently lose an unrelated key's value during rollback.** `localStorage` has no transaction API, so a multi-key write batch snapshots each touched key's prior value and restores them if any operation fails (typically `QuotaExceededError` mid-batch). But the restore ran in arbitrary map order and **swallowed** its own failures: near the quota, restoring a large *deleted* key's prior value could be attempted **before** removing a *newly-added* key that had consumed the freed space — that restore then hit the same quota, was silently ignored, and the deleted key's value was gone, even though the batch reported an atomic failure (so the caller assumed nothing changed). Rollback now **removes every touched key first** (freeing all the space the partial batch used, so the prior values — which fit before the batch — fit again), then restores them, and **surfaces** any restore that still fails instead of hiding it. Affects web apps writing near the `localStorage` quota (shipped 2.1.0).

- **Web (Kotlin/JS + Wasm): a key deleted in one tab is now invalidated in the others, instead of leaving them encrypting under a dead key.** Each tab caches the WebCrypto `CryptoKey` in page-local memory. When one tab cleared a key (`clearAll()` / logout deletes it from IndexedDB), other open tabs kept the stale handle and went on encrypting with it — writing ciphertext under a key that no longer exists durably, so after a reload those writes silently failed to decrypt and fell back to defaults. Tabs now coordinate over a `BroadcastChannel`: deleting a key evicts it from every other tab's in-memory cache, so their next encrypt re-reads IndexedDB and either picks up a re-created shared key or fails loudly — never silently loses the write. (Where `BroadcastChannel` is unavailable, behavior is unchanged.) Affects same-origin multi-tab usage that deletes keys (shipped 2.1.0).

- **Android (`ksafe-biometrics`): a cached biometric authorization could outlive its window across device sleep.** 2.1.1 moved the authorization TTL (`BiometricAuthorizationDuration`) from the wall clock to a monotonic clock to stop backward-jump exploits — but on Android that monotonic source (`System.nanoTime()` / `TimeSource.Monotonic`, `CLOCK_MONOTONIC`) **freezes while the device is in deep sleep**. So a 60-second window effectively became "60 seconds of *awake* time": authenticate, lock/pocket the phone, and tens of minutes of real time later the cached authorization was still considered valid and the prompt was skipped — defeating `allowDeviceCredentialFallback = false` within the stretched window. The TTL now uses `SystemClock.elapsedRealtime()` (`CLOCK_BOOTTIME`), which is both monotonic (keeps the backward-jump protection) **and** counts time spent asleep. Apple is unaffected — Darwin's `CLOCK_MONOTONIC` already advances during sleep. Affects Android apps using `BiometricAuthorizationDuration` (shipped 2.1.1).

- **Compose (`ksafe-compose`): live external-change observation could clobber the user's own in-flight edits.** A `mutableStateOf(..., scope = …)` or `rememberKSafeState(observeExternalChanges = true)` collects the key's `getFlow` and applied **every** emission to the state. But `getFlow` is derived from disk snapshots, which lag an optimistic write by the coalescing window + commit (+ decrypt). So while the user dragged a slider or typed into a `TextField`, a snapshot carrying the **older** value could arrive and revert the visible state mid-gesture — in a `TextField` the next `onValueChange` then built on the reverted text, silently dropping typed characters. Live observation now suppresses emissions **precisely while the user's own write is propagating to disk**: a stale snapshot can't revert the in-flight write, and once the observed flow catches up with the written value (the write's own echo arrives), reflection of genuinely newer external changes resumes — so a long-lived screen keeps tracking background syncs and other screens' writes instead of freezing on its last local edit. A pure-observer state the user never writes reflects external changes as before. Conservative residuals keep the user's value rather than risking a revert: a write whose batch fails never echoes, and a `neverEqualPolicy` (or `referentialEqualityPolicy` over deserialized values) never matches its echo — suppression then stays in place. Affects Compose states created with a `scope` / `observeExternalChanges = true` (shipped 2.1.x).

- **Compose (`ksafe-compose`): `rememberKSafeState` kept reading/writing the original `KSafe` instance after the instance (or write mode) was swapped.** `rememberKSafeState` memoized its state on the storage `key` alone — but the state's read/write/observe lambdas capture the `KSafe` receiver and `mode` from the composition that first created it. A screen that swapped instances at runtime — e.g. a multi-account app doing `val ksafe = remember(account) { KSafe(context, account.id) }` and `var draft by ksafe.rememberKSafeState("", key = "draft")` — recomposed with the **new** instance but got back the **old** memoized state: reads kept showing the previous account's value and every write persisted into the previous account's store (a silent cross-store leak), or, if the old instance had been `close()`d, writes were enqueued into a cancelled core and silently dropped. Toggling `mode` (Plain↔Encrypted) had the same staleness. The state and its observer are now keyed on **every parameter the memoized state bakes in** — the instance identity, `mode`, `policy` (it is baked into the underlying Compose state and gates persistence, so a changed policy must rebuild), and `defaultValue` (captured by the initial read and the observed flow, so a changed default must re-resolve instead of being silently ignored) — as well as the storage key. A composable invoked with the same stable arguments never rebuilds: the standard policies are singletons, and defaults compare with `equals()` (the normal `remember`-key contract — constants and data classes are stable). The `mutableStateOf` property-delegate API is unaffected — its delegate is created once per property, not memoized across recompositions. Affects `rememberKSafeState` callers that change any of these parameters at runtime (shipped 2.1.x).

- **Core: `asMutableStateFlow` had the same stale-echo clobber.** The `MutableStateFlow` from `KSafe.asMutableStateFlow(...)` observes the key's disk-derived flow and applied **every** emission, so setting `.value` (or `emit` / `tryEmit` / `compareAndSet`) and then receiving a snapshot emitted before that write committed reverted the StateFlow for all collectors — and if the write's batch failed it stayed reverted, permanently disagreeing with `getDirect`. It now uses the same precise guard as the Compose fix above: a stale observer emission no longer overrides a value written **through** the StateFlow while that write propagates, and once the flow catches up with the written value, newer external changes reflect again — matching the documented external-change contract. A StateFlow the caller only reads from reflects external changes as before. (`getStateFlow` is a read-only observer, so the write-clobber doesn't apply; the batch-rollback fix above keeps it converged after a failed write.) Shipped 2.1.x.

- **A transient decrypt failure during flow observation could crash the app (encrypted keys, Android).** `getFlow` — and everything built on it (`asMutableStateFlow`, `getStateFlow`, the Compose live-observe states) — decrypts the observed key on every DataStore snapshot. A **transient** failure there (most commonly an Android Keystore key written with `requireUnlockedDevice = true` / `KSafeConfig(requireUnlockedDevice = true)` being read while the device is locked) was rethrown from inside the flow. For the long-lived observers the library launches on a `viewModelScope` / Recomposer, that exception was **uncaught**: locking the device and then committing **any** other key (which emits a fresh snapshot) crashed the process and permanently stopped observation. Such an emission is now **skipped** — the flow stays alive and keeps its last value, and the next decryptable snapshot updates it. (`getDirect` is unchanged; it keeps its own transient handling for direct callers.) Shipped 2.1.x.

- **A write made concurrently with the background cache refresh / startup orphan sweep could be silently reverted (all platforms).** The collector that mirrors disk into the in-memory cache, and the once-per-launch sweep that reclaims ciphertext whose key is gone, could both race a write to the same key. The sweep didn't consult the in-flight ("dirty") key set at all, so a value a `put` committed between the sweep's probe and its delete could be deleted from disk and cache after the `put` had already returned success. And the cache refresh decided whether a key was in-flight from a snapshot taken at the **start** of the refresh, but wrote the value into the cache much later (after per-key decrypts) — so a write arriving in that window was overwritten with the stale on-disk value and, because in-flight flags are intentionally never cleared, never re-merged (the cached value stayed stale for the rest of the process even though disk held the new value). Both paths now re-check the **live** in-flight set immediately before mutating: the sweep skips a key that became in-flight, and the refresh skips merging the old value for one. The same live re-check also guards the refresh's **routing-metadata** syncs (the per-key protection and encryption-envelope maps): without it, a write that *changed a key's protection* during the refresh window — e.g. rewriting a plain value as encrypted — had its fresh routing metadata reverted to the pre-write disk state, after which reads consulted the wrong slot (stale value or the default) for the rest of the session. Read-your-write holds across a concurrent refresh/sweep, for values and routing metadata alike. Shipped (all platforms).

- **Apple (iOS/macOS): two `KSafe` instances on the same file — or a quick `close()`-then-recreate — silently broke reads and writes.** Like the JVM gap above, the Apple factory created a fresh `DataStore` per construction with no per-file dedup and cancelled its scope on `close()` without awaiting teardown. A second instance on the same file (DI re-init, SwiftUI recreation) tripped DataStore's "multiple DataStores active for the same file" guard — swallowed, so that instance served defaults and dropped writes — and an immediate recreate after `close()` raced the file release. The Apple factory now uses the same ref-counted, per-file backend as Android and JVM: one shared `DataStore` (and Keychain engine) per path, a bounded await on a prior owner's teardown before reopening, and scope teardown only on the last close. Affects iOS/macOS apps that construct more than one instance per file or recreate after close (shipped 2.1.x).

- **JVM/Desktop (no-`sun.misc.Unsafe` JSON fallback): a transient read error could wipe the entire store on the next write.** The fallback's JSON serializer caught any `IOException` while reading the file and returned an empty store. A missing file never reaches that code (DataStore handles it upstream), so the only failures it caught were **mid-read errors on an existing file** (disk error, network filesystem, AV interference) — and DataStore then cached "empty" as the current state, so the next write atomically overwrote the real file with empty, **silently destroying every entry**. The read error now propagates instead: DataStore doesn't write the file on a failed read, so the data is left intact and the next read recovers. Genuine corruption (unparseable content) still routes to the corruption handler that quarantines the file. Affects the JVM JSON-fallback path (shipped 2.1.1).

- **JVM/Desktop: a runtime OS key-vault failure (Windows/macOS) now degrades safely instead of leaking a raw error.** When an OS key vault becomes unreadable at runtime — Windows DPAPI can no longer unprotect the stored key (a Windows password reset, or a profile copied to another machine) or the macOS login Keychain is locked/inaccessible (SSH session, FileVault edge cases) — those vaults previously threw a raw platform exception. The Linux vault already mapped such failures to KSafe's "key vault unavailable" contract; Windows and macOS now do too. The effect is consistent and non-destructive: encrypted reads return their defaults, the startup orphan sweep **leaves the still-recoverable ciphertext on disk** (it is not mistaken for a missing-key orphan), and encrypted writes fail closed rather than fabricating a divergent key — so once the vault is reachable again (password fixed, keychain unlocked) the data decrypts normally. A genuinely absent key is still reported as absent (unchanged). This extends the runtime half of the same protection added above for construction-time vault outages. Affects JVM/Desktop with OS-backed key custody on Windows/macOS (shipped 2.1.0).

- **JVM/Desktop: `clearAll()` now wipes leftover fallback files that held recoverable secrets.** When data had previously been migrated forward from the no-`sun.misc.Unsafe` JSON fallback, the migration left `*.ksafe.json.migrated` (the old ciphertext) and `*.ksafe-keys.json.migrated` (the **plaintext** software AES keys that decrypt it) archived in the storage directory — alongside any `*.corrupt-<timestamp>` quarantine copies the fallback store makes. `clearAll()` deleted only the live store, so those archives survived the wipe and anyone with file access could decrypt every pre-migration secret offline. `clearAll()` now also deletes these residual `.migrated` / `.corrupt-*` files (matched precisely by the safe's own file prefix, so a different safe's files in the same directory are untouched). Affects JVM/Desktop apps that ran the JSON fallback and later called `clearAll()` (shipped 2.1.1).

- **JVM/Desktop: data written during a *second* JSON-fallback period now migrates forward.** The one-time fallback→OS-backed migration is gated so it doesn't re-run, but the gate keyed off the existence of the `.migrated` archive — which is permanent. So in the documented toggle sequence (ship without `jdk.unsupported` → data in the fallback → add the module → migrates → drop the module again, e.g. a build regression or a dev alternating IDE/packaged runs → fresh fallback data written → re-add the module), the migration saw the leftover archive and **skipped permanently**, silently stranding everything written during that second fallback period. The gate now migrates whenever the live fallback file is **newer than the last migration**, so a fresh fallback period carries forward — while a stale leftover (older than the marker) is still skipped, so the migration doesn't needlessly re-run. Affects JVM/Desktop apps that toggled `jdk.unsupported` off and on again (shipped 2.1.1).

### Tests

- **`AndroidSoftwareDekTest`** (androidDeviceTest, 10 cases, verified on a Galaxy S24 Ultra): each backs the engine with its own temporary DataStore. Relaxed-`DEFAULT` round-trip + DEK header + wrapped-DEK persistence as a reserved DataStore entry; **cross-version read** (pre-2.1.2 TEE ciphertext stays readable after upgrade, and new DEK ciphertext coexists with it); the strict `requireUnlockedDevice` master and `HARDWARE_ISOLATED` stay on the TEE path (no header, no DEK entry); deleting the master KEK — or an out-of-band DEK loss — surfaces the canonical "no key" message for orphan reclamation; deleting an **unrelated** key never removes the shared per-safe DEK; prewarm warms only the KEK and writes **no** DEK (lazy creation), which the first real encrypt then persists; a corrupt stored DEK self-heals (regenerates) on the next encrypt instead of failing; and a concurrency stress that confirms a burst of first-writes generates exactly one DEK.
- **`AndroidDataStoreLifecycleTest`** (androidDeviceTest, verified on a Galaxy S24 Ultra): a 30× close→recreate loop on the same datastore file — encrypted write, read-back, `close()` — that locks in the factory's await-prior-scope fix (no `multiple DataStores active for the same file`) and confirms data persists across recreates.

- **`JvmNumericTypeMigrationTest`** (jvmTest, 27 cases) characterises and locks in numeric cross-type reads: what each primitive persists as, `Int↔Long` and `Float↔Double` coercion (plain + encrypted), the full integer↔decimal matrix, overwriting a key with a different numeric type (the typed-DataStore `(name, type)` purge leaves no duplicate), and the out-of-range / fractional fallbacks. Exercises the shared `commonMain` coercion that Android / iOS / macOS run verbatim.

- **`JvmKeyVaultMigrationTest`** (jvmTest, +5 cases) covers the construction-time OS-vault-unavailable path via a new self-test seam: a failed self-test flags the vault unavailable and falls back to legacy for the session; a healthy candidate still selects the OS vault; key creation refuses to mint into the legacy migration source while the vault is unavailable (no junk key written); an unresolvable key reports `"unavailable"` rather than the orphan-sweep delete message; and a genuine pre-2.0 legacy key still decrypts (and is left in place) when the OS vault is unreachable. The existing runtime-degrade and migration cases are unchanged.

- **`JvmKeyVaultMigrationTest`** (jvmTest, +1 case) — two concurrent self-tests against the same shared per-user OS store no longer fail each other: a competitor's full put/get/delete cycle is driven from inside our canary write, and the healthy vault must still be selected with nothing flagged unavailable (red under the old fixed canary alias).

- **`JvmKeyVaultMigrationTest`** (jvmTest, +5 more cases) — the 2.1.0/2.1.1 → 2.1.2 namespace-upgrade recovery: a key stored under the old derived namespace is recovered and migrated on a new-namespace miss (red without the probe, failing with the orphan-sweep-triggering "No encryption key found"); a failed migration write still serves the key and preserves the only copy; a true miss with nothing to probe keeps the "No encryption key found" contract; `deleteKey` also scrubs the derived-namespace location so a recreate can't resurrect the old key; and the legacy derivation is pinned byte-for-byte against the released 2.1.1 behavior.

- **`JvmBatchFailureIsolationTest`** (jvmTest, 6 cases) covers per-entry encrypt isolation and optimistic-cache rollback across `ENCRYPTED`, `ENCRYPTED_WITH_TIMED_CACHE`, and `LAZY_PLAIN_TEXT`: a failed write rolls back so reads return the default; a failed overwrite restores the prior value (including evicting the plaintext side-cache); one failing encrypt does not drop the unrelated plain and encrypted keys sharing its batch; and a failed write's rollback does not strip the optimistic state of a *newer* same-key write fired during the failing batch (the racing write is issued from inside the failing encrypt, its commit latch-gated so only its optimistic state can satisfy the read — red under unconditional rollback).

- **`JvmGetOrCreateSecretTest`** (jvmTest, +1 case) — under `PLAIN_TEXT`, a secret that can't be decrypted on a later cold start makes `getOrCreateSecret` throw rather than rotate, and the original secret is intact once the vault recovers (three-instance create → unreadable-cold-start → recover).

- **`JvmMultiInstanceTest`** (jvmTest, 2 cases) — two live instances on the same file both persist their writes (read back via a fresh instance), and a 20× `close()`→recreate loop on the same file persists data; locks in the JVM per-file dedup + bounded prior-scope await.

- **`AndroidMultiInstanceTest`** (androidDeviceTest, verified on a Galaxy S24 Ultra) — a co-existing same-file instance keeps reading **and writing** after another instance on the same file closes (the ref-counted scope is not torn down until the last instance closes).

- **`IosKeychainConcurrencyTest`** (iosTest) — 16 concurrent first-creations of one alias must resolve to exactly **one** key (red without the new creation lock, where racing creators clobber). Real Keychain round-trips can't run in the Kotlin/Native test runner (no entitlements), so the engine's generic-password access is exercised through an injected in-memory store.

- **`MacosKeychainSweepTest`** (macosTest, runs natively on macOS) — proves the orphan sweep is a no-op on macOS (it never reads storage or the Keychain), and pins the platform decision (disabled on macOS; enabled on iOS/tvOS/watchOS).

- **`JvmFallbackMigrationTest`** (jvmTest, +3 cases) — a permanently-undecryptable fallback entry no longer blocks archival (the good entries migrate and the source is archived, so the migration won't re-run and roll back); a transient target-vault failure applies nothing and leaves the source un-archived for a clean retry; and the retry after a transient failure keeps a value the user wrote to the target in between (red under the unconditional "fallback wins" re-drain) while still migrating untouched keys, archiving the source, and clearing the pending state.

- **`BiometricPromptGateTest`** (`ksafe-biometrics` jvmTest) — the prompt gate never lets two prompts run at once (red without the lock), and a cancelled holder releases the gate so the next caller proceeds.

- **`BiometricAuthSessionTest`** (`ksafe-biometrics` commonTest) — pins the two shared session-cache decisions: a `duration <= 0` is never cacheable (red if the write path reverts to gating on non-null), and a `null` scope, an empty-string scope, and distinct caller scopes all resolve to distinct cache slots that no caller string can forge (red if scopes revert to `scope ?: ""`).

- **`LocalStorageRollbackTest`** (`ksafe` webTest, runs on both `jsBrowserTest` and `wasmJsBrowserTest`) — drives the quota-rollback through a fake char-capped store so the mid-rollback quota condition is deterministic: a deleted key's prior value is restored rather than lost to the freed-space ordering (red under arbitrary-order restore), and an unrestorable prior is surfaced rather than swallowed (red under the old `runCatching`).

- **`JvmClearAllRaceRepairTest`** (jvmTest, 4 cases) — a put racing an in-flight `clearAll()` (fired deterministically from inside the wipe's pre-clear engine-key deletion) reads back correctly once committed, across `ENCRYPTED`, `PLAIN_TEXT`, and `LAZY_PLAIN_TEXT` policies and for both encrypted and plain writes (all four red without the owner-gated post-commit repair).

- **`KSafeTest`** (commonTest, +3 cases on every target incl. the Android device suite) — `Duration` round-trips in Plain and Encrypted modes, and a hand-written `PrimitiveSerialDescriptor` custom-serializer type round-trips in Plain mode (red under the descriptor-kind-only read dispatch, failing with the exact `ClassCastException` the finding traced).

- **`JvmSideCacheWriteBackRaceTest`** (jvmTest, 2 cases) — a put landing *during* a read's decrypt keeps its side-cache value under **both** side-cache policies, `LAZY_PLAIN_TEXT` and `ENCRYPTED_WITH_TIMED_CACHE` (the racing put fires from inside the engine's decrypt; both red under the unguarded write-back).

- **`WebPrefixIsolationTest`** (`ksafe` webTest, 4 cases on both browser targets) — `clearAll()` on a store leaves its nested-named sibling's on-disk data intact (read back through a fresh instance, so the optimistic cache can't mask a wipe); a store's snapshot doesn't ingest a sibling's entries under garbled keys; `"default"`-named and unnamed stores keep distinct on-disk values; and the legacy-prefix migration moves a store's own canonical entries (copy → verify → delete) while leaving the nested sibling's for its own migration. The first three are red under the old `ksafe_<name>_` scheme.

- **`MacosSecUnwrapClassificationTest`** (`ksafe` macosTest, runs natively on `macosArm64Test`) — pins the Secure-Enclave transient-vs-permanent decision on the OSStatus code: a locked-device / not-available / auth-failed / user-cancelled failure is transient even with non-English localized text (red under the old substring match), a decode error stays permanent so genuine corruption still self-heals, and KSafe's own worded messages still classify via the fallback. Also pins the decrypt-path contract: a transient-classified Secure-Enclave failure message carries the brand the common read layer's transient check recognizes (red without the branding), while a permanent failure stays unbranded so reads still fall through.

- **`JvmAppNamespaceTest`** (jvmTest, +1 case) — the default key namespace is stable across `sun.java.command` changes (two jar versions plus an IDE main class all resolve to the same value, never derived from the launcher token).

- **`WebKeyStoreIntegrationTest`** keeps passing against **real IndexedDB + WebCrypto** in Chrome (`jsBrowserTest` + `wasmJsBrowserTest`), exercising the now-`add`-based key creation, cross-instance reload, and legacy-`localStorage` migration. (The cross-*tab* race needs two browser contexts and is verified by reasoning, not an automated test.)

- **`ObserveFromStorageTest`** (`ksafe-compose`) now asserts live-mode emissions apply **until** the user writes through the state, after which a stale flow echo no longer clobbers the user's value — and that once the write's own echo arrives (the flow caught up), newer external changes reflect again, with a fresh write re-arming the guard (red under the old permanent latch).

- **`KSafeStateFlowClobberTest`** (commonTest, 4 cases) — `asMutableStateFlow` applies observer emissions until the user writes through it, then a stale echo no longer clobbers (covers the `compareAndSet` write path too); after the write's echo arrives, newer external changes reflect again, and a second write re-arms the guard until its own echo (both red under the old permanent latch).

- **`JvmObservableFlowResilienceTest`** (jvmTest) — a transient decrypt failure during flow collection is skipped rather than thrown, and the flow survives it to emit the next decryptable value after recovery.

- **`JvmCollectorWriteRaceTest`** (jvmTest, +1 case) — a write performed *during* the cache refresh's decrypt window is not clobbered by the stale on-disk value (drives the race deterministically from inside the engine's `decrypt`); and a *protection-changing* write landing in the same window keeps its fresh routing metadata instead of having it reverted to the stale disk state (red with the frozen-snapshot-only metadata guard).

- **`MacosMultiInstanceTest`** (macosArm64Test, runs natively) — two instances on the same file both read and write, and a close→recreate loop persists; red without the per-file dedup (fails with "multiple DataStores active for the same file").

- **`JvmJsonSerializerReadFailureTest`** (jvmTest) — a transient read failure propagates instead of yielding an empty store (red without the fix), while valid / blank / corrupt content keep their correct behavior.

- **`JvmKeyVaultMigrationTest`** (+2 cases) — a vault that fails at runtime with the "unavailable" contract makes a decrypt report "unavailable" (not the orphan-delete message, so ciphertext is preserved) and makes an encrypt fail closed without minting a key.

- **`JvmClearAllResidualFilesTest`** (jvmTest) — `clearAll()` deletes the `.migrated` (ciphertext + plaintext-keys) and `.corrupt-*` residue, while leaving a different safe's files in the same directory intact.

- **`JvmFallbackMigrationTest`** (+1 case) — a fresh fallback file newer than an existing `.migrated` marker migrates forward (the second-fallback-period toggle case).

- **`WebKeyStoreIntegrationTest`** keeps passing against real IndexedDB/WebCrypto in Chrome with the cross-tab eviction wiring in place (the cross-*tab* invalidation needs two browser contexts and is verified by reasoning).

- **`KeychainOrphanClassificationTest`** (+1 case) — a key flagged as in-flight is preserved by the sweep's classification even when absent from the live key set (the concurrent-write guard).

- **`JvmCorruptStoreRecoveryTest`** (jvmTest) — a corrupt `.preferences_pb` is quarantined and the store recovers to empty (reads return defaults, a fresh write round-trips), instead of throwing on every read.

- **`JvmDeleteKeyCleanupFailureTest`** (jvmTest) — a `delete()` whose post-commit engine key-delete throws still completes and the value is gone from storage (the committed write isn't reported as failed).

- **`JvmObservableFlowResilienceTest`** (+1 case) — a transient Apple-Keychain-shaped decrypt error is classified transient (skipped on the flow) rather than emitted as the default.

### Documentation

- **Benchmarks refreshed to real-device numbers.** `docs/BENCHMARKS.md`, `README.md`, `docs/COMPARISON.md`, and `docs/USAGE.md` now report a **Samsung Galaxy S24 Ultra** (release build, 500 iterations) instead of an emulator, with the 2.1.2 DEK fast path reflected — including the corrected "userspace decrypt on Android" story and the reversal against EncryptedSharedPreferences / KVault on encrypted reads. `docs/ARCHITECTURE.md`'s pure-CPU-decrypt note now correctly attributes Android's userspace decrypt to 2.1.2 (it round-tripped the TEE before).

## [2.1.1] - 2026-06-03

Hardening and diagnostic-API release. **Drop-in upgrade from 2.1.0** — on-disk format is unchanged.

### Highlights

- **Apple: a silent data-loss bug is fixed — the Keychain orphan sweep no longer deletes the v2 master key.** On iOS / macOS the once-per-process startup sweep deleted the per-datastore master key that every `DEFAULT`-protected value shares, so on the launch after the first `DEFAULT` write **all `DEFAULT`-encrypted data became undecryptable and was reaped**. The sweep now reserves the master. **Upgrade urgently if you target Apple platforms and use the default (`DEFAULT`) encryption.** See **Fixed**.
- **Apple: `secureRandomBytes` reads from `SecRandomCopyBytes`.** The Apple Security framework's CSPRNG — the same source backing `SecKey*` key generation and CryptoKit — is now wired through KSafe's AES-256 master-key generation path directly. **Recommended upgrade for all Apple-target consumers.**
- **JVM: KSafe persists without `jdk.unsupported` — and migrates forward when you add it.** Compose Desktop release distributables that omit the `jdk.unsupported` module no longer crash or drop writes ([#32](https://github.com/ioannisa/KSafe/issues/32)): KSafe detects the missing `sun.misc.Unsafe` at construction and keeps persisting through the same DataStore engine (`datastore-core` + a custom JSON serializer instead of the protobuf) under the same AES-256-GCM — only the AES key drops to a local `0700` file (a software key vault), KSafe's existing `SOFTWARE` tier. Only OS-backed key custody is deferred, surfaced through `KSafe.protectionInfo`. When you later add the module, KSafe **migrates the fallback data forward automatically** — re-encrypting it under a freshly minted OS-backed key. The module stays strongly recommended for production (OS-backed key custody), it's just no longer mandatory for the app to function.
- **`KSafe.protectionInfo` is now a live diagnostic.** Recomputed on every access, so a JVM mid-process degrade is visible without restarting the app.
- **`KSafe.VERSION` and `KSafeProtectionInfo.kSafeVersion`** expose the linked artifact's version at runtime — useful for demo/sample apps, diagnostic UIs, and audit logs.
- **Android: root detection now recognizes rooted emulators/builds — without flagging non-rooted ones.** `isDeviceRooted()` silently returned `false` on rooted `userdebug` emulators (stock Google-APIs images ship `su` and allow `adb root`) because its file and `getprop`-subprocess probes are blocked by the post-Android-11 app sandbox and it never recognised the `userdebug` build *type*. Detection now keys off the sandbox-readable `Build.TYPE` (`userdebug`/`eng`) and reads system properties in-process — and deliberately ignores the `dev-keys` tag, which modern Google images use on non-rooted `user` builds too, so `user`-build emulators (Google Play / foldable images) are correctly reported as not-rooted. Matters for anyone relying on `KSafeSecurityPolicy.Strict` / `WarnOnly` or a custom root policy. See **Fixed**.

### Added

- **`KSafe.VERSION`** — public companion-object `val` returning the linked artifact version (e.g. `"2.1.1"`). Useful for demo / sample apps that load multiple KSafe versions side-by-side and need to confirm at runtime which one is linked, as well as for diagnostic UIs and telemetry.

- **`KSafeProtectionInfo.kSafeVersion`** — new field mirroring `KSafe.VERSION` on every instance, so audit code can capture version + custody + notes in one snapshot. Default value (`KSAFE_VERSION`) keeps existing `KSafeProtectionInfo(...)` construction sites source-compatible.

- **Single source of truth for the version string.** A new root `gradle.properties` entry `ksafe.version=2.1.1` feeds:
  - the Maven coordinates of `:ksafe`, `:ksafe-compose`, and `:ksafe-biometrics` (each module's `build.gradle.kts` reads `providers.gradleProperty("ksafe.version")`),
  - the generated `KSafeBuildConfig.kt` in `:ksafe`'s `commonMain` (a `generateKSafeBuildConfig` task writes `internal const val KSAFE_VERSION` into a generated source dir), and
  - `KSafe.VERSION` / `KSafeProtectionInfo.kSafeVersion`.

  Bumping the property in one place propagates to artifact + runtime + diagnostic. Pinned by `KSafeVersionTest` (3 tests): the constant matches the property, `protectionInfo.kSafeVersion` mirrors `KSafe.VERSION`, and the version is SemVer-shaped.

- **JVM no-`sun.misc.Unsafe` fallback + automatic forward migration** ([#32](https://github.com/ioannisa/KSafe/issues/32)). When `sun.misc.Unsafe` (JDK module `jdk.unsupported`) is absent — the typical Compose Desktop release distributable whose `jlink` runtime was trimmed — `KSafe(...)` selects a software backend instead of crashing:
  - **Storage** → `DataStoreJsonStorage`: Jetpack `datastore-core` driving a custom JSON serializer, so the DataStore *Preferences* protobuf (the sole `sun.misc.Unsafe` user) is never loaded. It keeps DataStore's atomic-write / single-process-coordinator / corruption-handling / fsync machinery. (Uses datastore-core's `java.io` serializer path, not okio — okio 3.x's multi-release jar fails bytecode verification on the trimmed runtime.)
  - **Keys** → `FileKeyVault`: the AES key in a local JSON file at POSIX `0700`, software-protected.

  Data persists (AES-256-GCM throughout); `protectionInfo.effectiveLevel` reports `SOFTWARE` with note `jvm_os_vault_unavailable`, and a one-time `KSafe NOTICE` describes the fallback. When `jdk.unsupported` is later added, a **one-time forward migration** drains the fallback into the OS-backed DataStore on first launch — decrypting each entry with the software key, re-encrypting under a freshly minted OS-backed key, preserving protection level + metadata, with the just-used fallback values winning — then renames the source files to `*.migrated` (recoverable, never deleted). Covered by `JvmJsonFileFallbackTest` and `JvmFallbackMigrationTest`.

### Changed

- **Apple `secureRandomBytes` now sources from `SecRandomCopyBytes` (Security framework CSPRNG).** This is the same authoritative random source backing `SecKey*` and CryptoKit on iOS / macOS, providing the strongest cryptographic-quality random number generation the platform offers for KSafe's AES-256 master-key creation. Recommended upgrade for all Apple-target consumers; existing keys remain valid post-upgrade.

- **`KSafe.protectionInfo` reads live engine state.** Recomputed per access — on JVM it reflects the current key-vault custody, so a mid-process degrade (e.g., the runtime fallback below) is visible without a process restart. Android / Apple / Web custody can't change after construction, so their providers return a captured snapshot at zero per-access cost.

- **`KSafeCore.startWriteConsumer` log line on persistent encrypt failure** now includes the exception class name (e.g. `NoClassDefFoundError: sun/misc/Unsafe`) so the message is recognisable as a JDK / packaging problem rather than looking like a stray log line. Awaiting callers still receive the exception via `completeExceptionally` on their `Deferred`.

- **`KSafe` constructor signature** (internal, `@PublishedApi`): `protectionInfo: KSafeProtectionInfo` → `protectionInfoProvider: () -> KSafeProtectionInfo`. External consumers do not call this constructor directly. Inline / reified members do not reference it. All four platform factories were updated in lockstep.

- **JVM `SecurityChecker` is more resilient on trimmed jlink runtimes.** `isDebuggerAttached()` and `isDebugBuild()` now catch `Throwable`, so a missing JDK module on a `jlink`-trimmed JRE (e.g. `java.management` absent from a Compose Desktop release distributable) makes the probes return their honest "unknown" default — `false` — rather than propagating an `Error` to `KSafe(...)` construction. The Apple `SecurityChecker` probes gained the same defensive fail-open guard for symmetry. Pair with `modules("java.management")` in your `nativeDistributions` block when you need the probes to actively detect a debugger (i.e. when using `KSafeSecurityPolicy.WarnOnly`, `Strict`, or any custom policy enabling debugger / debug-build detection).

### Fixed

- **Apple: the Keychain orphan sweep no longer deletes the v2 envelope's shared master key.** The once-per-process startup sweep (`cleanupOrphanedKeychainEntries`) cross-references Keychain items against DataStore's live key set and deletes the rest — but it built that set only from per-value entries, so the per-datastore **master key** (`__ksafe_master__` / `__ksafe_master_locked__`), which every `DEFAULT`-protected value shares, was never "valid" and was deleted on the first launch after a `DEFAULT` write. The DataStore orphan sweep then reaped the now-undecryptable ciphertext — a **silent, total loss of all `DEFAULT`-encrypted data on iOS / macOS**. The sweep now reserves the master sentinels (they are infrastructure, reclaimed only by `clearAll()`); the decision logic was extracted to a pure, cross-platform `keychainOrphanKeyId` covered by `KeychainOrphanClassificationTest` (7 cases). The single most important fix in this release.

- **`getOrCreateSecret` no longer silently rotates a secret it can't read back.** It detected "first use" by reading the stored value and treating an empty result as absent — but a value that *exists* yet can't be decrypted (the OS vault is temporarily unavailable, the backing key was invalidated, or the ciphertext is corrupt) also reads back empty, so it minted a brand-new secret and **permanently orphaned everything encrypted under the old one** (e.g. a SQLCipher database keyed by `getOrCreateSecret` would never open again). It now distinguishes "absent" (generate) from "exists-but-unreadable" via `getKeyInfo` and **throws** in the latter case instead of rotating. Regression test: `JvmGetOrCreateSecretTest` (3 cases). *(New behavior: `getOrCreateSecret` can now throw `IllegalStateException` in that case — see its KDoc.)*

- **Linux: a locked or unreachable login keyring is no longer mistaken for "key absent."** `LinuxSecretServiceKeyVault.get` passed a null `GError` to `secret_password_lookup_sync`, so a Secret Service error (keyring locked, the keyring daemon / D-Bus unreachable) returned `null` — indistinguishable from a genuinely-missing key — which let KSafe's orphan sweep **delete still-recoverable ciphertext**. The lookup now captures the `GError` and, on error, reports "vault unavailable" (which the sweep and read paths treat as non-deletable) rather than "absent."

- **DataStore: switching a key between plain and encrypted no longer leaves a stale, opposite-type value behind.** Plain and encrypted values are written under the same DataStore key but as different value *types*, and a `Preferences.Key` is identified by (name, type) — so a key written once plain and once encrypted left **both** on disk: nondeterministic reads, an incomplete delete, and — switching plain→encrypted — the **plaintext lingering in the file**. `writeOne` now purges any same-name entry before writing, and `removeByName` removes every same-name entry. Regression test: `DataStoreStorageCrossTypeTest` (3 cases).

- **A `delete` and a `HARDWARE_ISOLATED` `put` for the same key in one write-coalescing window no longer orphans the entry.** The coalescer de-duplicated only encrypted writes and then applied every queued op, so a delete + put in the same ~16 ms batch committed the new ciphertext and then ran the delete's per-entry-key deletion — instantly orphaning the value just written. The batch now resolves to the **last op per key** (puts and deletes are each absolute), so the final intent wins.

- **`clearAll()` is now serialized with concurrent writes.** It cleared storage and the in-memory caches directly, racing the background write consumer — so a `put` / `putDirect` issued just before `clearAll()` could be applied *after* the wipe and resurrect data. The wipe now travels through the same FIFO write channel as every other write (handled as a batch boundary), so anything enqueued before it is ordered before the wipe. Regression test: `JvmClearAllSerializationTest` (2 cases). *(Distinct from the per-entry-key `clearAll` fix below.)*

- **JVM: `appNamespace` now isolates the data file, not just the OS-vault keys.** `appNamespace` scoped the Keychain / DPAPI / Secret Service destination but **not** the DataStore file path, and the default storage directory (`~/.eu_anifantakis_ksafe`) is shared per OS user — so two desktop apps sharing a `fileName` clobbered a single file, and one app's `clearAll()` wiped the other's data (their keys were isolated, so each saw the other's entries as undecryptable). An explicitly-set `appNamespace` now places the data files in a per-namespace subdirectory; existing un-namespaced data is **migrated forward automatically** on first run (copied, not moved, so neither app can lose data). Apps that don't set `appNamespace` are unchanged. Regression test: `JvmAppNamespaceFileIsolationTest` (3 cases). **Behavior change: the on-disk path changes for apps that set `appNamespace`.**

- **iOS / macOS biometrics: a cancelled prompt is now aborted and the continuation guarded.** `KSafeBiometrics.platformVerifyBiometric` resumed its `suspendCancellableCoroutine` with no `isActive` check and never invalidated the `LAContext` on cancellation — risking an "already resumed" crash on a repeat callback and an orphaned system prompt when the awaiting coroutine was cancelled. It now registers `invokeOnCancellation { context.invalidate() }` and guards the resume with `continuation.isActive`.

- **Apple: the in-memory cache's `clear()` is now atomic.** `KSafeConcurrentMap.clear()` did a plain volatile write while every other mutator used a compare-and-set retry loop, so a write racing `clearAll()` could resurrect a just-cleared cache entry. `clear()` now uses the same CAS loop.

- **Web: `applyBatch` is now atomic (snapshot + rollback).** `localStorage` has no transactions, so a `QuotaExceededError` (or any failure) partway through a batch left a value persisted **without its metadata** — a half-written entry a later read would misclassify (and hand back as raw ciphertext). The web adapter now snapshots the keys a batch touches and restores them on any mid-batch failure, matching the all-or-nothing semantics the DataStore backends get for free.

- **Biometric authorization caching now uses a monotonic clock.** The "skip the prompt within `authorizationDuration`" cache compared wall-clock timestamps, so moving the device clock backward (NTP correction, manual change) made elapsed time negative and kept a cached authorization valid past its window. The Android and Apple session caches now measure elapsed time with `TimeSource.Monotonic`.

- **Android: rooted / `userdebug` devices are now detected on modern Android (API 30+), without false-positiving `user`-build emulators.** `SecurityChecker.isDeviceRooted()` silently returned `false` on rooted emulators and engineering builds — including stock Google-APIs emulator system images, which ship `su` at `/system/xbin/su` and allow `adb root`. Three independent causes, all stemming from the post-Android-11 app sandbox: (1) the `su` / Magisk / busybox path probes call `File("/system/xbin/su").exists()`, which SELinux denies the `untrusted_app` domain — the binary exists but can't be `stat`'d, and the surrounding `try/catch` swallowed the denial as `false`; (2) the build check matched only the `test-keys` tag and never recognised the `userdebug` build *type* that characterises a rooted Google-APIs image; (3) `ro.debuggable` / `ro.secure` were read with `Runtime.exec("getprop …")`, a subprocess SELinux blocks for app processes. Detection now adds a sandbox-proof signal — the `userdebug` / `eng` build *type* from the public `Build.TYPE` (plus the `test-keys` tag), extracted as the pure, testable `isRootIndicatingBuild(type, tags)` — and reads dangerous props in-process via reflective `android.os.SystemProperties.get` instead of a `getprop` subprocess. It deliberately does **not** treat `dev-keys` as root: modern Google emulator images are signed `dev-keys` for both `user` and `userdebug` builds, so a non-rooted `user`-build emulator (Google Play / "Pixel … Fold" images — no `su`, `ro.debuggable=0`, `adb root` refused) is correctly reported as not-rooted, as are retail `user` / `release-keys` devices. The file / Magisk / package probes are retained for older devices. With the default `IGNORE` policy this only changes what `isDeviceRooted()` reports; under `Strict` (root → `BLOCK`) a rooted device or emulator is now correctly blocked. iOS is unchanged — a simulator is intentionally not treated as jailbroken.

- **JVM: graceful key-vault degradation when JNA can't link at runtime** ([#32](https://github.com/ioannisa/KSafe/issues/32)). When `sun.misc.Unsafe` *is* present at construction but a later JNA call fails (`LinkageError` / `NoClassDefFoundError`), the key-vault path catches it and falls back to the software vault for the rest of the process with a one-time `System.err` warning. `JvmKeyVaultProvider.degradeToLegacy(cause)` flips `active` to the software vault; `JvmSoftwareEncryption` catches the error on the encrypt/decrypt/delete/migrate paths, degrades, and retries. (The more common case — `sun.misc.Unsafe` missing entirely on a trimmed release distributable — is handled by the construction-time software fallback + forward migration described under **Added**, so data persists either way.)

- **JVM: `decrypt` no longer mints a key for orphaned ciphertext.** `JvmSoftwareEncryption.decrypt` previously called `getOrCreateSecretKey`, so decrypting ciphertext whose key was gone (OS-vault wipe / reinstall) created a fresh junk key in the user's OS vault and failed with a GCM tag mismatch instead of "No encryption key found". This (a) polluted the OS vault on every failed decrypt and (b) prevented `KSafeCore.cleanupOrphanedCiphertext` (which matches "No encryption key found" / "key not found") from ever reclaiming JVM orphans. `decrypt` now uses a no-create lookup and throws the same message Android and Apple use. Regression test: `JvmKeyVaultMigrationTest.decryptOfOrphanedCiphertext_throwsKeyNotFound_andMintsNoKey`.

- **`clearAll()` now deletes per-entry encryption keys, not just the master key.** Per-entry keys for `HARDWARE_ISOLATED` entries (and all legacy v1 entries) live outside the DataStore on the OS-vault (Keychain / DPAPI / Secret Service) and web (IndexedDB) backends, which have no startup orphan sweep for engine keys — so clearing storage alone leaked them across `clearAll()` cycles. `clearAll` now enumerates encrypted entries from the protection map and deletes their per-entry engine keys before wiping. Regression test: `JvmV2EnvelopeTest.clearAllDeletesPerEntryHardwareIsolatedKeyNotJustMaster`.

- **Coroutine-cancellation correctness.** `KSafeBiometrics.platformVerifyBiometric` (Android) caught `Exception`, which includes `CancellationException` — a cancelled biometric prompt was silently reported as `false` (auth-denied), breaking structured concurrency. It now rethrows `CancellationException` before the generic catch. The web `WebSoftwareEncryption.migrateLegacyKeysSuspend` `runCatching` was likewise swallowing cancellation and now rethrows it (matching every other `runCatching` in the codebase).

### Tests

- **Android root detection now has direct coverage** (`AndroidSecurityCheckerTest`, 6 cases, `androidDeviceTest` instrumented source set): the pure `isRootIndicatingBuild(type, tags)` predicate flags `userdebug` / `eng` and `test-keys`, while leaving `user` / `release-keys` **and `user`-build `dev-keys` emulators** alone; plus device assertions that a root-capable image (a `userdebug` Google-APIs emulator) is reported rooted and a `user`-build emulator (Google Play / "Pixel … Fold" image) is not. Regression guard for both the false negative and the `dev-keys` false positive.

- **Apple `secureRandomBytes` now has direct coverage** (`MacosSecureRandomTest`, 5 cases): requested-length, rejects non-positive size, never all-zeros, successive draws differ, and a wide byte-range entropy sanity check. This is the regression guard for the `SecRandomCopyBytes` fix above — previously the security-critical Apple key-generation path had zero automated coverage. macOS runs the identical `appleMain` actual that iOS does.
- **Removed two misnamed `JvmSecurityCheckerTest` cases** (`*_isThrowableSafe_regression_issue32_followup`) that only asserted `assertIs<Boolean>` and could not actually exercise the missing-module `Error` path (a standard test JVM always has `java.management`). They duplicated the honest `_returnsBoolean` tests; a test whose name claims a guarantee it can't verify is worse than none. The production guard (`catch (_: Throwable)`) and its end-to-end verification (the demo release distributable) are documented in `docs/JVM_PROTECTION.md`.

### Documentation

- **`docs/JVM_PROTECTION.md`** — section "Compose Desktop release distributables: `jdk.unsupported`" rewritten around the no-`Unsafe` software fallback and the automatic forward migration: what KSafe substitutes when the module is missing (storage + key vault), how data carries forward when you add it, the `java.management` note for non-default security policies, a `suggestRuntimeModules` tip, and the #32 crash-vs-silent-drop history. README and `KSAFE_SKILL.md` reframed to match — the module is **strongly recommended** for OS-backed key custody, no longer described as required for the app to function.
- **README** — short pointer to the section above so people hit the answer before the bug.
- **`THREE_PILARS.md`** — appendix entry `A5` documenting the `jdk.unsupported` requirement.

## [2.1.0] - 2026-05-24

OS-native key custody on JVM and Web, plus a new cross-platform key-protection diagnostic API. **Drop-in upgrade** — on-disk format is unchanged and existing 2.0 keys migrate on first read.

### Highlights

- **JVM keys now live in the OS secret store** — Windows DPAPI, macOS login Keychain, or Linux Secret Service (libsecret) via JNA — instead of Base64'd next to the ciphertext in the DataStore file.
- **Web keys are now non-extractable** by the browser. The WebCrypto `CryptoKey` (`extractable = false`) lives in IndexedDB; raw key bytes are no longer recoverable by XSS, extensions, or profile reads.
- **New `KSafe.protectionInfo` API** — instance-level diagnostic on a universally-ordered scale (`SOFTWARE < SANDBOX_PROTECTED < HARDWARE_BACKED < HARDWARE_ISOLATED`). Drives startup gates, telemetry, UI badges, runtime feature policy.
- **`KSafeKeyInfo.level`** — per-key audit on the same universal scale. Pair it with `protectionInfo` for instance-level *and* per-key threshold checks.
- **Regression fix** — `get` / `getFlow` with a nullable default on `@Serializable` classes ([#31](https://github.com/ioannisa/KSafe/issues/31), thanks @DestBro).

### Security

- **JVM keys now live in the OS secret store.** The AES key is protected by **Windows DPAPI**, the **macOS Keychain**, or the **Linux Secret Service (libsecret)** via JNA, instead of being Base64-encoded next to the data in the DataStore file. When no secret store is reachable (headless Linux with no keyring, JNA link failure, …) KSafe falls back to the legacy in-file scheme and logs a one-time security warning. Keys written by KSafe ≤ 2.0 are **migrated on first read**: copied into the OS store, then removed from the DataStore file **only after the OS store is read back and byte-verified** (a buggy or again-unavailable keyring that silently no-ops cannot destroy the only copy). Migration is **hybrid**: lazy per-key on first read *plus* a one-time best-effort background sweep so a key that's never read again doesn't linger in the file. Opt out with `-Dksafe.jvm.keyVault=software` (or env `KSAFE_JVM_KEY_VAULT=software`).
- **Web keys are now non-extractable.** The browser engine generates an `extractable = false` AES-GCM `CryptoKey` and persists the live key object in **IndexedDB**, instead of exporting the raw key and Base64-ing it into `localStorage`. A legacy `localStorage` key is imported as non-extractable on first access and the `localStorage` entry deleted; previously encrypted data keeps decrypting. Same hybrid lazy + background-sweep migration as JVM.

### Added

- **`KSafe.protectionInfo: KSafeProtectionInfo`** — public, cross-platform diagnostic that reports the key custody this `KSafe` is *actually* running with, including any runtime fallback negotiated at construction. Read once at startup:

  ```kotlin
  val info = ksafe.protectionInfo

  // Gate startup
  check(info.effectiveLevel >= KSafeProtectionLevel.SANDBOX_PROTECTED)

  // Detect silent fallback (effective < intended)
  check(info.effectiveLevel >= info.intendedLevel)

  // Telemetry
  analytics.log("ksafe_protection",
      "level"   to info.effectiveLevel.name,
      "custody" to info.custody,
      "notes"   to info.notes.joinToString(","))
  ```

  Introduces:
    - **`KSafeProtectionLevel`** — universally-ordered scale: `SOFTWARE` < `SANDBOX_PROTECTED` < `HARDWARE_BACKED` < `HARDWARE_ISOLATED`. One ordinal comparison works across every platform.
    - **`KSafeProtectionInfo(intendedLevel, effectiveLevel, custody, notes)`** — `effectiveLevel` is the actionable field; `intendedLevel` is the engine's baseline target so consumers can detect when negotiation fell short. `custody` is a human-readable description (display, never parse); `notes` is a list of stable lowercase_snake codes (`jvm_os_vault_unavailable`, `jvm_user_opted_out`, `apple_secure_enclave_absent`).

  Per-platform population: Android / Apple report `HARDWARE_BACKED` baselines (StrongBox / Secure Enclave remain per-write upgrades via `KSafeWriteMode.Encrypted(HARDWARE_ISOLATED)`); JVM reports `SANDBOX_PROTECTED` when the OS vault is healthy and falls to `SOFTWARE` with the appropriate `notes` code when the vault self-test fails or the user opts out; Web reports `SANDBOX_PROTECTED` (browser-origin sandbox). Full guide and runtime-decision patterns in [`docs/PROTECTION_INFO.md`](docs/PROTECTION_INFO.md).

- **`KSafeKeyInfo.level: KSafeProtectionLevel`** — per-key audit now reports on the same universal scale as `protectionInfo`. Layered checks become possible (gate the engine at startup *and* refuse to use a specific high-sensitivity key if its own custody didn't meet the bar):

  ```kotlin
  val tokenLevel = ksafe.getKeyInfo("auth_token")?.level
  check(tokenLevel != null && tokenLevel >= KSafeProtectionLevel.HARDWARE_BACKED)
  ```

  Gives JVM and Web richer granularity than the legacy `KSafeKeyInfo.storage` — JVM OS-vault keys and Web browser-origin keys now report `SANDBOX_PROTECTED`; only the plaintext-in-file JVM fallback still reports `SOFTWARE`.

- **JNA dependency on the JVM target** (`net.java.dev.jna` + `jna-platform`) for the OS secret-store integration above. JVM / Desktop consumers only.

### Deprecated

- **`KSafeKeyInfo.storage: KSafeKeyStorage`** — superseded by `KSafeKeyInfo.level: KSafeProtectionLevel`. `storage` keeps working with a `@Deprecated(ReplaceWith("level"))` annotation; planned removal in 3.0.

### Fixed

- **`get` / `getFlow` with a nullable default now deserialize `@Serializable` classes correctly** ([#31](https://github.com/ioannisa/KSafe/issues/31), thanks @DestBro). Calling `get(key, null as MyType?)` or `getFlow(key, null as MyType?)` on a `@Serializable` class whose first property is a primitive (e.g. a leading `String`) threw `ClassCastException: java.lang.String cannot be cast to MyType` — a regression introduced in 2.0.0. `primitiveKindOrNull` was descending into the class's first field for a nullable serializer and misclassifying the type as a `String`, so the raw stored JSON was returned instead of being decoded. A non-null default (`get(key, MyType())`) was unaffected.

### Documentation

- **New: [`docs/PROTECTION_INFO.md`](docs/PROTECTION_INFO.md)** — the new `KSafe.protectionInfo` API: model, per-platform truth table, defined `notes` codes, and five runtime-decision patterns (gating, tighter re-auth windows, feature disablement, UX honesty banners, intended-vs-effective delta checks).
- **New: [`docs/JVM_PROTECTION.md`](docs/JVM_PROTECTION.md)** — platform-by-platform deep dive on the JVM OS vaults (DPAPI / Keychain / libsecret): what each store actually is, threat model per OS, the self-test, the software fallback, the opt-out, and the per-app namespace.

### Build

- **Suppressed `IncorrectCompileOnlyDependencyWarning`** for the `compose-runtime` `compileOnly` dependency on Native / JS / Wasm targets. The dep is intentionally `compileOnly` so non-Compose consumers (Ktor servers, CLI tools, plain JVM) don't pull `compose-runtime` onto their runtime classpath — `@Stable` has `BINARY` retention and no runtime cost. Native / JS / Wasm consumers using `:ksafe` without Compose must declare `compose-runtime` themselves to compile against the published klib (accepted trade-off; promoting to `api` would force `compose-runtime` onto every consumer's runtime classpath).

### Upgrade notes

- **No source-level changes required** for existing 2.0 consumers. `ksafe.put` / `ksafe.get` / `by ksafe(0)` and all delegates are unchanged.
- **No on-disk format change.** Existing 2.0 ciphertext continues to decrypt; the AES key migrates to the OS-backed custody automatically on first read.
- The legacy `KSafeKeyInfo.storage` field still works. New code should prefer `level` (IDE quick-fix offers the replacement).

## [2.0.0] - 2026-05-13

Major release: KMP refactor, new macOS and Kotlin/JS targets, biometrics extracted into its own module, and significant performance work on encrypted reads/writes.

The changes listed below are **in addition to** the work shipped in 2.0.0-RC1 and 2.0.0-RC2 — see those sections for the full picture of what 2.0.0 includes.

### Highlights

- **Faster encrypted reads and writes.** A new per-datastore master-key envelope (v2) eliminates Keystore/Keychain IPC on every encrypted read and write. Biggest wins on stores with many encrypted entries.
- **New default memory policy: `LAZY_PLAIN_TEXT`.** Cheap cold start (no bulk decrypt), O(1) reads after first access. Replaces `ENCRYPTED` as the default on Android, iOS, macOS, and JVM.
- **New platforms.** Native macOS (`macosX64`, `macosArm64`) and Kotlin/JS (IR) across all modules.
- **Biometrics is now its own module.** `KSafeBiometrics` ships as the optional `:ksafe-biometrics` artifact — apps without biometrics no longer pull in `androidx.biometric`.
- **Migrated to AGP 9.2 + Gradle 9.4.** All three modules now use the unified KMP library plugin.

### Added

- **`KSafeMemoryPolicy.LAZY_PLAIN_TEXT`** — new default on Android, iOS, macOS, JVM. Keeps ciphertext on cold start, decrypts each key on first read, then caches plaintext for the process lifetime. Web stays `PLAIN_TEXT` (WebCrypto is async-only).
- **Native macOS targets** (`macosX64`, `macosArm64`) across `:ksafe`, `:ksafe-compose`, `:ksafe-biometrics` ([#26](https://github.com/ioannisa/KSafe/issues/26), thanks @tomasjablonskis). Uses the same Keychain + CryptoKit + Secure Enclave path as iOS via shared `appleMain`. Intel Macs without a T2 fall back to plain Keychain.
- **`SecurityChecker` short-circuits on macOS** — the iOS jailbreak heuristics would otherwise flag every Mac as rooted.
- **`macosTest` source set** — 73 new tests plus the full common `KSafeTest` suite.
- **`allowDeviceCredentialFallback` on `verifyBiometric` / `verifyBiometricDirect`** ([#29](https://github.com/ioannisa/KSafe/issues/29), thanks @Trucodisparo). New optional `Boolean` (default `true`). Set `false` to restrict to biometrics only — no PIN/password/pattern fallback. JVM/JS/WasmJS ignore it.

  ```kotlin
  val ok = KSafeBiometrics.verifyBiometric(
      reason = "Confirm payment",
      allowDeviceCredentialFallback = false
  )
  ```

### Fixed

- **Compatibility with `dev.whyoleg.cryptography` 0.6.0** ([#27](https://github.com/ioannisa/KSafe/issues/27), [#30](https://github.com/ioannisa/KSafe/issues/30), via [#28](https://github.com/ioannisa/KSafe/pull/28), thanks @HarukeyUA @chirag38-unity). Resolves the runtime `IrLinkageError` on iOS when a consumer app pulled cryptography-kotlin 0.6.0 transitively.
- **Critical: Secure Enclave key destruction during 1.x → 2.0 migration** *(latent in RC1 and RC2)*. A startup-ordering race could let the orphan-cleanup sweep run against an empty DataStore snapshot and irreversibly destroy Secure Enclave EC private keys. `KSafeCore` now waits for the first `snapshotFlow` emission before migrating; orphan cleanup refuses to delete when DataStore is empty but Keychain has entries. Pinned by `KSafeCoreStartupOrderingTest`.
- **macOS biometrics now work on every Mac.** Switched to `LAPolicyDeviceOwnerAuthentication` on macOS — falls back to login password or Apple Watch on Macs without Touch ID (Mac mini, many Intel Macs). iOS unchanged.
- **`verifyBiometric` (suspend) now dispatches `evaluatePolicy` on Main** on Apple platforms, matching `verifyBiometricDirect`.

### Changed

- **Default memory policy is now `LAZY_PLAIN_TEXT`** (was `ENCRYPTED`) on Android, iOS, macOS, JVM. Apps that need ciphertext-at-rest semantics must opt in explicitly with `KSafeMemoryPolicy.ENCRYPTED` or `ENCRYPTED_WITH_TIMED_CACHE`. Web's forced `PLAIN_TEXT` is unchanged.
- **`PLAIN_TEXT` is now discouraged in KDoc.** Its eager-decrypt-everything cold start is O(n) in encrypted keys and can push first-read latency into ANR territory on large Android stores. `LAZY_PLAIN_TEXT` matches its steady-state read performance with a much cheaper start. `PLAIN_TEXT` is still supported.
- **`IosKeychainEncryption` → `AppleKeychainEncryption`** (and surrounding `Ios*` → `Apple*` renames) to reflect shared iOS + macOS use. `@PublishedApi internal`; only consumer code that references these symbols directly is affected.
- **macOS Keychain prompt — doc-only.** Factory KDoc now flags that unsandboxed Mac apps see a system password prompt on first Keychain access (suppressed by signing with a Keychain access group entitlement).

### Performance

- **v2 envelope** routes every `KSafeProtection.DEFAULT` encrypted write through one of two AES-256 master keys per datastore (a relaxed-accessibility variant and a `requireUnlockedDevice = true` variant), unwrapped once at construction and cached in-process. After warm-up, encrypt and decrypt are pure-CPU AES-GCM — no Keystore/Keychain IPC for the lifetime of the process. `KSafeProtection.HARDWARE_ISOLATED` writes still get a per-entry key (StrongBox / Secure Enclave isolation is the point). Existing `v1` and legacy entries continue to read through the per-entry path unchanged — no migration, no rewrite. Entries written by 2.0 cannot be read by 1.x.
- **Parallel batch encrypt** — encrypted writes in a batch deduplicate by key and run concurrently with a `Semaphore(8)` cap. `ENCRYPTED` memory policy no longer pays a write-time penalty over `PLAIN_TEXT`.
- **Parallel cold-start decrypt** — `updateCache` and `cleanupOrphanedCiphertext` now decrypt concurrently. Cold-start time on a 1500-key encrypted store drops from ~27 ms to under 1 ms.
- **`detectProtection` short-circuit** trusts 2.0 metadata authoritatively when present, saving an allocation and a map lookup per unencrypted read.
- **`AndroidKeystoreEncryption` micro-optimisations** — lazy companion-level `KeyStore`, zero-copy GCM decrypt, single-allocation encrypt buffer, collapsed `containsAlias` + `getKey`/`deleteEntry` IPC round-trips.
- **`AppleKeychainEncryption` key-byte cache** — repeat encrypt/decrypt on the same key short-circuits both `SecItemCopyMatching` and the SE `SecKeyCreateDecryptedData` ECIES unwrap. Brings Apple in line with the per-alias caches Android and JVM already had.
- **Suspend `put` / `delete` now go through the write coalescer.** 500 concurrent suspend writes show 5–27× lower per-op latency depending on encryption mode.
- **`hasAnyEncryptedKey` atomic flag** lets plain-only stores skip the `protectionMap` lookup on every read.
- **Refreshed benchmarks** in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) — median of 4 runs on a Galaxy S24. Suspend-API cells now exercise concurrent coroutines, reflecting real-world usage.

### Tooling

- **AGP `8.13.1` → `9.2.1`, Gradle `8.14.4` → `9.4.1`.** `:ksafe` migrated from `com.android.library` to `com.android.kotlin.multiplatform.library`, aligning all three modules. `androidInstrumentedTest` source set renamed to `androidDeviceTest`. Removed obsolete `gradle.properties` flags now defaulted in AGP 9 (`android.useAndroidX`, `android.nonTransitiveRClass`, `kotlin.kmp.isolated-projects.support`).

### Validation

- `:ksafe:macosArm64Test` — 118 tests (73 new + 45 common).
- `:ksafe:iosSimulatorArm64Test` — 127 tests, no regression.
- Android instrumented tests — 64/64 on emulator and physical Galaxy S24.
- All `linkDebugFramework*` and cross-target compile tasks pass cleanly.
- End-to-end exercised via [KSafeDemo](https://github.com/ioannisa/KSafeDemo) on all six targets.

## [2.0.0-RC2] - 2026-04-28

Four additive public APIs — `KSafe.rememberKSafeState`, `KSafe.asWritableFlow`, `KSafe.close()`, and the internal `observeFromStorage` helper — plus a `CancellationException` hardening pass on `KSafeCore` and `:ksafe-compose`. No breakage, no behavioural change for callers who don't opt in.

### Added

- **`:ksafe-compose` — `rememberKSafeState` composable.** `rememberSaveable { mutableStateOf(…) }` ergonomics that *survive app restarts*, not just configuration changes. Uses the auto-key convention from `ksafe.mutableStateOf` (property name → storage key), defaults to `KSafeWriteMode.Plain`, no detached coroutines (observation lives inside `LaunchedEffect`). Targets the use case where state naturally lives in a composable and routing through a ViewModel would be overkill (bottom-tab index, scroll position, draft input, expanded/collapsed sections):

  ```kotlin
  @Composable
  fun TabbedScreen(ksafe: KSafe) {
      var currentTab  by ksafe.rememberKSafeState(0)    // key = "currentTab"
      var draft       by ksafe.rememberKSafeState("")   // key = "draft"
      // both survive process death and app restart on every target
  }
  ```
- **`KSafe.asWritableFlow`.** New extension that returns a `WritableKSafeFlow<T> : Flow<T>` with a `set(value)` writer. Collapses the previous "two-bindings-to-the-same-key" repository pattern into one declaration. Asymmetric by design — flow read only, no synchronous getter — to keep the contract identical across all targets including web cold-start.
- **`KSafe.close()` — optional instance disposal.** Cancels the write-channel consumer, the snapshot collector, and the DataStore coroutine scope (file watcher, write coordinator, cached-`Preferences` `MutableStateFlow`). On Android, also evicts the per-file entry from the process-static DataStore cache when this instance owned it. Idempotent. Almost always unnecessary — the dominant singleton-per-process usage doesn't need it. Call when you re-create `KSafe` mid-process (account switching, long-running JVM services, dev-time hot-reload). See [docs/SETUP.md](docs/SETUP.md).
- **Internal: `observeFromStorage`.** The previously-duplicated branch logic at `mutableStateOf`'s call site (live-collect when `scope` is supplied; one-shot self-heal on detached `Dispatchers.Default` otherwise) is consolidated into a single `@PublishedApi internal suspend fun`. Both `mutableStateOf` and `rememberKSafeState` route through it. No public-API or behavioural change for existing callers.

### Fixed

- **`CancellationException` no longer swallowed in `KSafeCore` and `:ksafe-compose`.** Every `runCatching { … }` and `catch (Throwable)` inside a coroutine context now rethrows `CancellationException` first. Eliminates spurious `"processBatch failed, dropping N writes: …"` log lines on clean teardown and the occasional one-extra-batch-after-cancel surfacing as `UncaughtExceptionsBeforeTest` in `kotlinx-coroutines-test`. Hardened sites: `startWriteConsumer`, `startBackgroundCollector`, `cleanupOrphanedCiphertext`, `updateCache`, `getFlowRaw`, iOS `cleanupOrphanedKeychainEntriesSafe`, plus defense-in-depth on `resolveFromCache` / `convertStoredValue` / `ensureCacheReadyBlocking`.

---

## [2.0.0-RC1] - 2026-04-26

Major internal refactor (KSafeCore in commonMain, ~5,900 → ~740 lines of platform-shell code) + new standalone `:ksafe-biometrics` module + Kotlin/JS (IR) target with shared `webMain`/`webTest` source sets.

### Breaking changes

- **Biometric authentication extracted into `:ksafe-biometrics`** ([#14](https://github.com/ioannisa/KSafe/issues/14), thanks @Coding-Meet). `verifyBiometric` / `verifyBiometricDirect` / `clearBiometricAuth` / `BiometricAuthorizationDuration` / `BiometricHelper` no longer live on `KSafe`; they belong to a new `KSafeBiometrics` static API published as a separate, optional artifact (`implementation("eu.anifantakis:ksafe-biometrics:2.0.0-RC1")`). `KSafeBiometrics` is a Kotlin `object` (no DI, no `Context`, no init); on Android the library auto-initializes via a `ContentProvider` (same pattern as WorkManager / Firebase). Method names and signatures are preserved; only the receiver and import paths change. Apps not using biometrics no longer pay for `androidx.biometric` / `androidx.fragment`.

### Added

- **Custom storage directory** ([#25](https://github.com/ioannisa/KSafe/pull/25), thanks @DeStilleGast). `KSafe(...)` factories on JVM, Android, and iOS now accept an optional override for the DataStore directory (`baseDir: File?` on JVM/Android; `directory: String?` on iOS). JVM applies POSIX `0700` regardless of which path is used; Android's DataStore cache key now reflects the actual file path so distinct `baseDir`s don't collide.
- **iOS default storage moved to `NSApplicationSupportDirectory`** with automatic 1.x migration. Pre-2.0 stored in `NSDocumentDirectory` (user-visible via iTunes File Sharing, iCloud-syncable by default) — both wrong defaults. New default is the Apple-recommended location for invisible app data. On first launch with no explicit `directory`, KSafe transparently moves a legacy file from the old path. Idempotent, best-effort. KSafe data on iOS is effectively device-local regardless: encryption keys live in the Keychain with `…ThisDeviceOnly` accessibility, so backed-up ciphertext is undecryptable on a restored device.
- **Kotlin/JS (IR) target.** New artifact alongside the existing Kotlin/WASM target — covers browsers without WasmGC (anything older than Chrome 119 / Firefox 120 / Safari 18). Same AES-256-GCM via WebCrypto, same `localStorage` key layout (so switching between targets reads the same data back), same `PLAIN_TEXT`-only memory policy.
- **Shared `webMain` / `webTest` source sets.** The bulk of the previous `wasmJsMain` implementation (`KSafe.web.kt`, `WebSoftwareEncryption.kt`, `SecurityChecker.web.kt`) moved to `webMain`, shared between `jsMain` and `wasmJsMain`. Each target keeps only a small `WebInterop` actual. Full `KSafeTest` suite + a new `WebInteropSmokeTest` now run on **both** targets.
- **Cross-type migration tests** in `commonTest/KSafeTest.kt`: `Int`↔`Long` widening / safe narrowing / out-of-range fallback, both encrypted and plaintext, both fresh and sequential-write-then-read scenarios. Locks in the cross-type safety contract that was previously implicit.
- **iOS Keychain orphan sweep strengthened.** Refactored into a standalone `cleanupOrphanedKeychainEntries` in `iosMain/internal/` that covers both generic-password items (plain AES keys + SE-wrapped blobs) and `kSecClassKey` EC private keys (catches partial `HARDWARE_ISOLATED` writes after a crash). Takes its dependencies as explicit arguments — unit-testable without a full `KSafe` instance.

### Changed

- **Shared `KSafeCore` orchestrator in `commonMain`.** The hot cache, write coalescer, protection-metadata classifier, orphan cleanup, and raw `get/put/delete/getFlow` plumbing — previously duplicated across all four platform shells — live in a single `KSafeCore` class. Per-platform shells dropped from ~5,900 to ~740 lines. Bug fixes and feature additions ship once.
- **`KSafePlatformStorage` interface + shared `DataStoreStorage` adapter.** Android / iOS / JVM all use Jetpack DataStore Preferences, so a single adapter lives in a new `datastoreMain` intermediate source set. Web has its own `LocalStorageStorage`. Splits "where bytes live" from orchestration.
- **`KSafeEncryption` gained suspend variants** (`encryptSuspend` / `decryptSuspend` / `deleteKeySuspend`) with default bodies delegating to blocking. Android / iOS / JVM engines untouched. `WebSoftwareEncryption` overrides the suspend variants with real WebCrypto calls (WebCrypto is async-only). `KSafeCore` calls the suspend path from every coroutine-context site.
- **`KSafe` is now a regular common class** — no more `expect/actual`. Single declaration in `commonMain`, including all inline reified bodies. Construction moves to per-platform top-level `KSafe(...)` factory functions; consumer call site unchanged. The deprecated `useStrongBox` / `useSecureEnclave` flags route through a new `modeTransformer` parameter on `KSafeCore`.
- **Internal types moved to `eu.anifantakis.lib.ksafe.internal`.** `KSafeCore`, `KSafePlatformStorage`, `KSafeEncryption`, `KeySafeMetadataManager`, `SecurityChecker`, `KSafeSecureRandom`, and per-platform engines now live under `.internal`. Public-facing types stay at the root package. No consumer imports break.
- **`wasmJsMain` reduced to a minimal `WebInterop` actual.** Its previous content moved to `webMain`. No public API changes.

### Fixed

- **Serializer-kind dispatch in `convertStoredValue`.** Two bugs with the same root cause (runtime-class dispatch on `defaultValue`): (a) Kotlin/JS Float/Double reads collapsing into the Int branch because `0f is Int` returns `true` on JS; (b) nullable-typed reads with `null` default losing stored primitives because no `is X` branch matched. Dispatch now runs through `primitiveKindOrNull(serializer)`, reading `PrimitiveKind` off the serializer's descriptor.
- **Transient keystore decrypt errors propagate on every platform.** Pre-refactor only Android re-threw `"device is locked"` / `"Keystore"` errors; iOS and JVM swallowed them. `KSafeCore.isTransientDecryptFailure` now runs uniformly so a locked device reliably surfaces to the caller for retry handling.

### Upgrade notes

- **On-disk format and storage API are unchanged.** Existing 1.8.x data reads cleanly; `ksafe.put(...)` / `ksafe.get(...)` / `by ksafe(0)` delegates continue to work.
- **Biometric API moved.** See breaking changes above for the migration to `:ksafe-biometrics`.
- `isStringSerializer` in `internal/KSafeSerializerUtil.kt` is unused after the dispatch fix; kept for one release, will be removed in 2.1.

---

## [1.8.1] - 2026-04-17

### Added

#### Android: `BiometricHelper.confirmationRequired` ([#11](https://github.com/ioannisa/KSafe/pull/11) — thanks @HansHolz09)

Added a `confirmationRequired: Boolean = true` property on `BiometricHelper` that wraps `BiometricPrompt.PromptInfo.Builder.setConfirmationRequired(...)`. Keep the default for sensitive actions — the prompt only resolves after an explicit user confirmation. Set to `false` for passive flows where the biometric match itself should be sufficient.

```kotlin
BiometricHelper.confirmationRequired = false // allow passive face-unlock
```

Note: this flag only affects weak/passive biometric modalities (e.g. face). For `BIOMETRIC_STRONG` modalities like fingerprint, the physical action is the confirmation and this flag has no effect.

### Fixed

#### iOS: Keychain NSString Memory Leak on Background Threads ([#22](https://github.com/ioannisa/KSafe/issues/22))

Fixed a memory leak in `IosKeychainEncryption` where Kotlin → NSString bridging conversions (e.g. inside `CFBridgingRetain(keyId)`) accumulated indefinitely when keychain operations ran on coroutine worker threads. The root cause is that Kotlin/Native emits autorelease-convention NSString allocations for string bridging, and `Dispatchers.Default` / SKIE-bridged Swift `async` worker threads do not have an ambient ObjC autorelease pool to drain them. Over time this surfaced as continuously growing memory in Instruments, dominated by `Kotlin_ObjCExport_CreateRetainedNSStringFromKString` allocations attributed to `IosKeychainEncryption#getExistingKeychainKey` and related paths.

The fix wraps the `memScoped { ... }` body of every keychain-touching internal method in `kotlinx.cinterop.autoreleasepool { ... }` so autoreleased bridged NSStrings drain promptly regardless of which thread the caller is on. No public API changes.

Affected methods (all internal): `createSecureEnclaveKey`, `getSecureEnclaveKey`, `deleteSecureEnclaveKey`, `updateSecureEnclaveKeyAccessibility`, `getExistingKeychainKeyRaw`, `getExistingKeychainKeyPlain`, `getOrCreateKeychainKeyPlain`, `storeInKeychain`, `updateKeychainItemAccessibility`, `deleteFromKeychain`.

A regression test (`IosKeychainEncryptionLeakTest`) was added that runs 5,000 keychain operations on `Dispatchers.Default` and asserts peak RSS growth stays under 2 MB via `getrusage(RUSAGE_SELF)`. Pre-fix the test reports ~7 MB of growth; post-fix it stays within allocator slack.

---

## [1.8.0] - 2026-04-14

### Added

#### Cryptographic Utilities: `secureRandomBytes` & `getOrCreateSecret`

**`secureRandomBytes(size: Int): ByteArray`** — A cross-platform cryptographically secure random byte generator, delegating to each platform's strongest CSPRNG (`java.security.SecureRandom` on Android/JVM, `arc4random_buf` on iOS, `crypto.getRandomValues()` on WASM). This is now also used internally by KSafe's own encryption engines for IV and key generation.

```kotlin
val nonce = secureRandomBytes(16)
val aesKey = secureRandomBytes(32)
```

**`KSafe.getOrCreateSecret(key, size, protection, requireUnlockedDevice): ByteArray`** — A suspend extension that generates a cryptographically secure random secret on first call and retrieves it on subsequent calls. Stored with hardware-backed encryption (`HARDWARE_ISOLATED` by default). Ideal for database encryption passphrases, API signing keys, HMAC keys, or any persistent secret.

```kotlin
// Database passphrase — one line, hardware-backed, generated once
val passphrase = ksafe.getOrCreateSecret("main.db")

// Custom size + protection
val apiKey = ksafe.getOrCreateSecret("api_key", size = 64)
```

#### Flow & StateFlow Property Delegates ([#20](https://github.com/ioannisa/KSafe/issues/20))

Since v1.0.0, KSafe offered `var counter by ksafe(0)` (plain delegates) and `var counter by ksafe.mutableStateOf(0)` (Compose state). Version 1.8.0 adds **`MutableStateFlow` delegates** (`asMutableStateFlow`) as a drop-in replacement for the standard `_state`/`state` pattern, **read-only flow delegates** (`asStateFlow` / `asFlow`), and **cross-screen sync** via `mutableStateOf(scope=)`. All new delegates derive their storage key from the property name (with an optional `key` override), staying consistent with the existing `invoke()` delegate — and the explicit-key `getStateFlow()` / `getFlow()` APIs remain fully supported.

**Core Module — flow delegates**

**1. `asMutableStateFlow` (Read / Write)**

Implements the full `MutableStateFlow` interface — all standard atomic operations work out of the box, persisting to encrypted storage instantly.

```kotlin
// Standard Kotlin pattern
private val _state = MutableStateFlow(MoviesListState())
val state = _state.asStateFlow()

// KSafe equivalent — same pattern, but persisted + reactive to external changes
private val _state by kSafe.asMutableStateFlow(MoviesListState(), viewModelScope)
val state = _state.asStateFlow()
```

```kotlin
@Serializable
data class MoviesListState(
    val loading: Boolean = false,
    val movies: List<Movie> = emptyList(),
    val error: String? = null
)

class MoviesViewModel(private val kSafe: KSafe, private val api: MoviesApi) : ViewModel() {
    // Acts exactly like a standard MutableStateFlow, but fully persisted
    private val _state by kSafe.asMutableStateFlow(MoviesListState(), viewModelScope)
    val state = _state.asStateFlow()

    fun loadMovies() {
        // .update {} persists securely (uses compareAndSet internally)
        _state.update { it.copy(loading = true) }

        viewModelScope.launch {
            try {
                val movies = api.getMovies()
                // .value = ... also persists instantly
                _state.value = _state.value.copy(loading = false, movies = movies)
            } catch (e: Exception) {
                _state.update { it.copy(loading = false, error = e.message) }
            }
        }
    }
}

@Composable
fun MoviesScreen(viewModel: MoviesViewModel) {
    val state by viewModel.state.collectAsState()

    when {
        state.loading -> CircularProgressIndicator()
        state.error != null -> Text("Error: ${state.error}")
        else -> LazyColumn {
            items(state.movies) { movie -> MovieItem(movie) }
        }
    }
}
```

**2. `asStateFlow` & `asFlow` (Read-Only)**

If you only need to read data (or update it manually via `kSafe.put()`), you can use read-only flow delegates.

```kotlin
class SettingsViewModel(private val kSafe: KSafe) : ViewModel() {
    // Hot flow tied to viewModelScope
    val username: StateFlow<String> by kSafe.asStateFlow("Guest", viewModelScope)

    // Cold flow
    val darkMode: Flow<Boolean> by kSafe.asFlow(defaultValue = false)

    // Optional: explicitly override the storage key
    val theme: Flow<String> by kSafe.asFlow(defaultValue = "light", key = "app_theme")

    fun onNameChanged(name: String) {
        viewModelScope.launch { kSafe.put("username", name) }
    }
}
```

**Compose Module — cross-screen reactivity**

The existing `mutableStateOf` now accepts an optional `scope` parameter.

**Without `scope`** (existing behavior) — the state reads from cache at init and persists on write, but it's isolated. If another ViewModel or a background `put()` writes to the same key, this state won't update until the ViewModel is recreated.

**With `scope`** — the state continuously observes the underlying flow. Changes from any source (another screen, another ViewModel, a background coroutine) are reflected in real-time. No manual refreshes or event buses required.

> If you only read/write from a single ViewModel, both behave identically. The `scope` parameter matters when **multiple writers** exist for the same key.

```kotlin
// Dashboard Screen — auto-reflects changes made from other screens
class DashboardViewModel(private val kSafe: KSafe) : ViewModel() {
    var username by kSafe.mutableStateOf("Guest", scope = viewModelScope)
    var notificationsEnabled by kSafe.mutableStateOf(false, scope = viewModelScope)
}

// Settings Screen — writes to the same KSafe instance
class SettingsViewModel(private val kSafe: KSafe) : ViewModel() {
    var username by kSafe.mutableStateOf("Guest", scope = viewModelScope)
    var notificationsEnabled by kSafe.mutableStateOf(false, scope = viewModelScope)
}

// When SettingsScreen writes, DashboardScreen auto-updates — no manual refresh
@Composable
fun DashboardScreen(viewModel: DashboardViewModel) {
    Text("Welcome, ${viewModel.username}")
    if (viewModel.notificationsEnabled) Text("Notifications ON")
}

@Composable
fun SettingsScreen(viewModel: SettingsViewModel) {
    TextField(value = viewModel.username, onValueChange = { viewModel.username = it })
    Switch(
        checked = viewModel.notificationsEnabled,
        onCheckedChange = { viewModel.notificationsEnabled = it }
    )
}
```

**API summary**

| Module | Function | Type | Returns |
|--------|----------|------|---------|
| core | `asFlow(defaultValue, key?)` | Read-only | `Flow<T>` delegate |
| core | `asStateFlow(defaultValue, scope, key?)` | Read-only | `StateFlow<T>` delegate |
| core | `asMutableStateFlow(defaultValue, scope, key?, mode?)` | Read/write + Reactive | `MutableStateFlow<T>` delegate |
| compose | `mutableStateOf(..., scope?)` | Read/write + Reactive | `MutableState<T>` w/ flow observation |

## [1.7.1] - 2025-03-17

### Added

#### Custom JSON Serialization ([#19](https://github.com/ioannisa/KSafe/issues/19))

`KSafeConfig` now accepts a `json` parameter — a fully configured `Json` instance used for all user-payload serialization. This enables support for `@Contextual` types (e.g., `UUID`, `Instant`, `BigDecimal`) and custom `SerializersModule` registration.

```kotlin
val customJson = Json {
    ignoreUnknownKeys = true
    serializersModule = SerializersModule {
        contextual(UUIDSerializer)
        contextual(InstantSerializer)
    }
}

val ksafe = KSafe(
    config = KSafeConfig(json = customJson)
)
```

- Serializers are registered once at the instance level and apply to all operations (`putDirect`, `getDirect`, `put`, `get`, `getFlow`, delegates)
- Internal metadata serialization is unaffected — it uses its own private codec
- Default remains `Json { ignoreUnknownKeys = true }` via `KSafeDefaults.json` — no changes needed for existing code
- `kotlinx-serialization-json` is declared in the library as a **transitive dependency** (`api` scope) — no need to add it manually in your project
- **Note:** Changing the `Json` configuration for an existing `fileName` namespace may make previously stored non-primitive values unreadable

### Fixed

#### WASM: Encrypted `mutableStateOf` Delegates Return Defaults on Page Reload

Fixed a race condition on WASM where `mutableStateOf` Compose delegates could return the default value instead of the persisted encrypted value after a browser refresh. This occurred because WASM's WebCrypto decryption is async-only — if a KSafe instance was created and immediately read from in the same synchronous frame (e.g., via Koin lazy singleton injection into a ViewModel), the cache hadn't loaded yet.

The fix adds reactive self-healing to `KSafeComposeState`: when `getDirect` returns the default, a lightweight coroutine observes `getFlow` and updates the Compose state when the real decrypted value arrives. A `userHasWritten` guard ensures user writes are never overwritten by late-arriving cache data.

This bug was latent since WASM support was added but only surfaced when using multiple KSafe instances (e.g., a second instance with custom JSON serialization), where the second instance had no head start for its async cache loading.

#### Inline Bytecode Bloat ([#16](https://github.com/ioannisa/KSafe/issues/16))

Reduced bytecode generated at each KSafe call site by extracting non-reified logic from `inline` functions into `@PublishedApi internal` helpers. Previously, every `getDirect`/`putDirect` delegate expansion could produce thousands of bytecode instructions because the entire function body was inlined. Now only the `serializer<T>()` call is inlined; the rest is a regular function call to the `*Raw` variant.

#### Relaxed `fileName` Validation

The `fileName` parameter now accepts lowercase letters, digits, and underscores (must start with a letter). Previously only `[a-z]+` was allowed, which was unnecessarily restrictive. The regex is now `[a-z][a-z0-9_]*` across all platforms. Dots, slashes, and uppercase remain forbidden to prevent path traversal and case-sensitivity issues.


---

## [1.7.0] - 2025-03-03

### Added

#### StrongBox Opt-In (Android)

New `useStrongBox: Boolean = false` parameter on the Android `KSafe` constructor. When enabled, AES keys are generated inside the device's StrongBox security chip — a physically separate, tamper-resistant hardware module (available on Pixel 3+, some Samsung flagships, and other devices with StrongBox support).

> **Note:** This constructor parameter is `@Deprecated` — prefer per-property `KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)` instead. See [Deprecated](#deprecated) section.

```kotlin
val ksafe = KSafe(
    context = context,
    useStrongBox = true  // request StrongBox; falls back to TEE if unavailable
)
```

- **Automatic TEE fallback:** If the device lacks StrongBox, `StrongBoxUnavailableException` is caught and the key is regenerated in the standard TEE — no code changes or user-facing errors
- **Existing keys unaffected:** `useStrongBox` only applies to new key generation (`KeyGenParameterSpec.Builder`). Keys already stored in the Keystore are loaded from wherever they were originally generated (TEE or StrongBox) regardless of this setting. This means enabling `useStrongBox = true` on an existing installation won't migrate previously-generated TEE keys to StrongBox — those keys continue working in TEE. To migrate existing data to StrongBox-backed keys, delete the KSafe data (or the specific keys) and reinitialize — new keys will be generated in StrongBox
- **Performance trade-off:** StrongBox key generation is slower (1–5s vs 50–200ms for TEE) and per-operation latency is higher (~10–50ms vs <1ms). KSafe's memory policies mitigate read-side latency since most reads come from the hot cache

#### Secure Enclave Opt-In (iOS)

New `useSecureEnclave: Boolean = false` parameter on the iOS `KSafe` constructor. When enabled, AES encryption keys are wrapped (encrypted) by an EC P-256 key pair that lives inside the Secure Enclave hardware — Apple's dedicated security coprocessor.

> **Note:** This constructor parameter is `@Deprecated` — prefer per-property `KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)` instead. See [Deprecated](#deprecated) section.

```kotlin
val ksafe = KSafe(
    useSecureEnclave = true  // request SE envelope encryption; falls back to plain Keychain if unavailable
)
```

**Envelope encryption architecture:** The Secure Enclave only supports asymmetric keys (EC P-256), not AES. KSafe bridges this gap with envelope encryption:

1. An EC P-256 key pair is created inside the Secure Enclave hardware
2. The AES-256 symmetric key is wrapped (encrypted) by the SE public key using ECIES (`ECIESEncryptionCofactorX963SHA256AESGCM`)
3. The wrapped AES key is stored in the Keychain as a generic-password item
4. On decrypt, the SE private key unwraps the AES key, which then decrypts data via CryptoKit as before

This means the raw AES key bytes are only exposed in app memory during the actual CryptoKit encrypt/decrypt call — they can no longer be extracted directly from the Keychain.

- **Automatic Keychain fallback:** If the Secure Enclave is unavailable (simulator, older device without SE), KSafe catches the error and falls back to plain Keychain storage — same pattern as Android's StrongBox fallback
- **Existing keys unaffected:** `useSecureEnclave` only applies to new key creation. Pre-existing plain Keychain keys are still readable — KSafe checks for legacy (unwrapped) keys before creating new SE-wrapped keys. No automatic migration
- **Memory-safe:** All `SecKeyRef` references from Core Foundation are properly released via `try/finally { CFRelease() }` to prevent memory leaks
- **Performance trade-off:** The SE wrapping/unwrapping step adds latency to key retrieval. KSafe's memory policies and hot cache mitigate this since most reads come from the in-memory cache, not from repeated key unwrapping

#### Type-Safe Write Modes (`KSafeWriteMode`) & Hardware Isolation
The `encrypted: Boolean` parameter on public APIs is deprecated in favor of a strictly type-safe write model:

- `KSafeWriteMode.Plain` — unencrypted persistence
- `KSafeWriteMode.Encrypted(...)` — encrypted persistence with optional hardware isolation and per-entry unlock policy

```kotlin
// Plaintext (no encryption)
var theme by ksafe("dark", mode = KSafeWriteMode.Plain)

// Default encryption
var token by ksafe(
    "",
    mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.DEFAULT)
)

// Hardware isolation + per-entry unlock policy
var pin by ksafe(
    "",
    mode = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
        requireUnlockedDevice = true
    )
)
```

Write APIs now support:
- `putDirect(key, value, mode: KSafeWriteMode)`
- `put(key, value, mode: KSafeWriteMode)`
- delegate/Compose mode overloads

**`HARDWARE_ISOLATED` behavior by platform:**

| Platform | Behavior |
|----------|----------|
| **Android** | Generates AES key in StrongBox (dedicated security chip). Falls back to TEE if StrongBox unavailable. |
| **iOS** | Uses Secure Enclave envelope encryption (SE EC P-256 wraps AES key). Falls back to plain Keychain if SE unavailable. |
| **JVM** | Ignored — always software-backed. |
| **WASM** | Ignored — always WebCrypto. |

**Compose and delegate support:**

```kotlin
// Property delegation (protection applies to writes; reads auto-detect)
var secret by ksafe("", mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))

// Compose state (requires ksafe-compose)
var secret by ksafe.mutableStateOf("", mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))
```

#### Smart Auto-Detecting Reads
Read APIs (`getDirect`, `get`, `getFlow`, `getStateFlow`) no longer require mode/encrypted parameters. KSafe auto-detects encrypted vs plaintext values from persisted metadata, with legacy fallbacks when needed.

```kotlin
// Writes specify protection level
ksafe.putDirect("token", value)                                     // DEFAULT (encrypted)
ksafe.putDirect("setting", value, mode = KSafeWriteMode.Plain)     // unencrypted

// Reads auto-detect — just provide key + default
val token = ksafe.getDirect("token", "")      // auto-detects encrypted
val setting = ksafe.getDirect("setting", "")  // auto-detects unencrypted
val flow = ksafe.getFlow("token", "")         // auto-detects per emission
```

This eliminates the risk of mismatched put/get protection levels and simplifies the read API.

#### Automatic Protection Tier Migration

When the protection level for a key changes between app versions (e.g., upgrading from `DEFAULT` to `HARDWARE_ISOLATED`, or from `Plain` to `Encrypted`), KSafe transparently migrates the data:

- **`getDirect` / `get`**: If the key is not found at the expected storage location, `migrateProtectionInline` checks the alternate location (encrypted ↔ plaintext), reads the value, writes it to the new location at the new protection level, and cleans up the old data — all inline during the read.
- **`putDirect` / `put`**: Before writing, the alternate storage location is cleaned up (old data, old encryption keys) so stale entries don't accumulate.
- **`DEFAULT` ↔ `HARDWARE_ISOLATED`**: Both use the same encrypted storage key, so migration deletes the old encryption key and re-encrypts with a new one at the correct hardware tier.

This means changing a property's protection level in code "just works" — no manual migration step required.

#### Device Key Storage Query API

New read-only properties and methods on `KSafe` that let app code query the hardware security capabilities of the device and inspect both the protection tier and storage location of individual keys:

```kotlin
val ksafe = KSafe(context)

// Device-level: what hardware is available?
ksafe.deviceKeyStorages  // e.g. {HARDWARE_BACKED, HARDWARE_ISOLATED}
ksafe.deviceKeyStorages.max()  // HARDWARE_ISOLATED (highest available)

// Per-key: what protection was requested and where is the key actually stored?
val info = ksafe.getKeyInfo("auth_token")
// info?.protection  → KSafeProtection.DEFAULT (what the caller requested)
// info?.storage     → KSafeKeyStorage.HARDWARE_BACKED (where the key lives)
```

- **`KSafeKeyInfo`** — data class combining `protection: KSafeProtection?` (the tier used when the key was stored, or `null` for plaintext entries) and `storage: KSafeKeyStorage` (where the encryption key material actually resides on this device).
- **`KSafeProtection`** enum: `DEFAULT`, `HARDWARE_ISOLATED` — the read-time protection tier (internal counterpart to `KSafeEncryptedProtection` used in write APIs).
- **`deviceKeyStorages: Set<KSafeKeyStorage>`** — the set of key storage levels the current device supports. Always contains at least one element. Use `deviceKeyStorages.max()` to get the highest available level.
- **`getKeyInfo(key: String): KSafeKeyInfo?`** — returns the protection tier and actual storage location of a specific key, or `null` if the key doesn't exist. On Android/iOS, encrypted keys return `HARDWARE_BACKED` (or `HARDWARE_ISOLATED` if written with `HARDWARE_ISOLATED` and the device supports it). On JVM/WASM, storage is always `SOFTWARE`. Unencrypted keys return `KSafeKeyInfo(null, SOFTWARE)`.

New `KSafeKeyStorage` enum with natural ordinal ordering (`SOFTWARE < HARDWARE_BACKED < HARDWARE_ISOLATED`):

| Value | Meaning | Platforms |
|-------|---------|-----------|
| `SOFTWARE` | Software-only encryption | JVM, WASM |
| `HARDWARE_BACKED` | On-chip hardware (TEE / Keychain) | Android, iOS |
| `HARDWARE_ISOLATED` | Dedicated security chip (StrongBox / Secure Enclave) | Android (if available), iOS (real devices) |

**Platform behavior:**

| Platform | `deviceKeyStorages` |
|----------|---------------------|
| **Android** | Always `{HARDWARE_BACKED}`. Adds `HARDWARE_ISOLATED` if `PackageManager.FEATURE_STRONGBOX_KEYSTORE` is present (API 28+). |
| **iOS** | Always `{HARDWARE_BACKED}`. Adds `HARDWARE_ISOLATED` on real devices (not simulator). |
| **JVM** | `{SOFTWARE}` |
| **WASM** | `{SOFTWARE}` |

Instance-level (not static/companion) because Android needs `Context` for StrongBox detection via `PackageManager`.

#### Centralized Metadata Management (`KeySafeMetadataManager`)

New internal object that centralizes storage key naming, metadata parsing, and legacy format migration across all four platforms:

- **Canonical key format:** values stored at `__ksafe_value_{key}`, metadata at `__ksafe_meta_{key}__` (JSON: `{"v":1,"p":"DEFAULT","u":"unlocked"}`)
- **Legacy compatibility:** reads remain backward-compatible with `encrypted_{key}`, bare `{key}`, and `__ksafe_prot_{key}__` metadata; touched keys are migrated on write/delete
- Handles `classifyStorageEntry()`, `collectMetadata()`, `parseProtection()`, `buildMetadataJson()` for all platforms

### Changed

- **Canonical storage keys:** values are now written under `__ksafe_value_{key}` on all platforms.
- **Single JSON metadata entry per key:** metadata is written under `__ksafe_meta_{key}__`.
- **Legacy compatibility:** reads remain backward-compatible with `encrypted_{key}`, bare `{key}`, and legacy metadata keys; touched keys are migrated/cleaned on write/delete.
- **Per-entry unlock policy:** `requireUnlockedDevice` is now per encrypted write mode (`KSafeWriteMode.Encrypted(...)`), while `KSafeConfig.requireUnlockedDevice` is the default for no-mode encrypted writes.
- **Global access-policy migration removed:** per-instance access-policy marker flow is no longer used.
- **`protectionMap` stores literal strings instead of raw JSON:** `detectProtection()` is called on every `getDirect`/`get` read to determine if a key is encrypted or plaintext. Previously, `protectionMap` stored raw JSON metadata strings, causing `parseProtection()` to parse JSON on every read. Now stores literal strings (`"DEFAULT"`, `"NONE"`, `"HARDWARE_ISOLATED"`) via `protectionToLiteral()` at write time and `extractProtectionLiteral()` at cache load time. Reads always hit `parseProtection()`'s fast-path `when` check — no JSON parsing on the hot path. Applied on all four platforms (Android, JVM, iOS, WASM). Resulted in ~40% improvement in unencrypted read performance.
- **iOS Secure Enclave error messages now include CFError details:** `createSecureEnclaveKeyPair()` and `wrapAesKey()` now include the `NSError.localizedDescription` from the underlying `CFError` in their exception messages. This prevents the string-based fallback logic in `getOrCreateKeychainKey()` from misclassifying transient SE failures (e.g., device locked, interaction not allowed) as "SE unavailable" and silently downgrading to plain Keychain storage. The fallback check also now re-throws errors containing "interaction" (matching `errSecInteractionNotAllowed` from CFError descriptions).
- **Per-key protection metadata for migration safety and auto-detection:** Every write now persists metadata alongside the data, recording the protection level. This metadata serves two purposes: (1) auto-detection on reads — read APIs use it to determine whether to decrypt without caller input, and (2) migration safety — `requireUnlockedDevice` migration uses it to re-encrypt each key at its original hardware isolation level.
- **Dirty-key guard for protectionMap on all platforms:** `updateCache()` (DataStore platforms: Android, JVM, iOS) now skips overwriting `protectionMap` entries for keys with pending writes (dirty keys). On WASM, `loadCacheFromStorage()` skips `protectionMap` entries that were already set by optimistic `putDirect` writes. This prevents stale emissions from clobbering metadata set during the optimistic write window.
- **Android access-policy migration preserves StrongBox backing:** `migrateAccessPolicyIfNeeded()` now reads per-key protection metadata when re-encrypting keys during `requireUnlockedDevice` policy changes. Each key is re-encrypted at its original hardware isolation level. Pre-1.7.0 keys without metadata default to `DEFAULT` (TEE) since hardware isolation was not available before 1.7.0.

### Removed

- **`iosTestApp/`** — iOS test app that imported `ksafe` but never instantiated `KSafe`. Used a plain Swift `Dictionary` instead. Added by an external contributor; superseded by the Kotlin test suite in `ksafe/src/iosTest/` and the [KSafeDemo](https://github.com/ioannisa/KSafeDemo) app
- **`KoinInit.kt`** — Placeholder function (`initKoin()` with a `println`) in `iosMain` that shipped with the iOS framework to all consumers. No functionality
- **`ExampleInstrumentedTest.kt`** — Default Android Studio template test in `ksafe-compose` that only asserted the package name. No KSafe coverage
- **`IosDebugTest.kt`** — Debug-oriented iOS test with `println` hex dumps. All meaningful assertions already covered by `IosKSafeTest` (which extends the shared `KSafeTest` suite)
- **`ACCESS_POLICY_KEY` / `ACCESS_POLICY_UNLOCKED` / `ACCESS_POLICY_DEFAULT` constants** — Replaced by per-key JSON metadata

### Documentation

- Updated README performance benchmarks with v1.7.0 numbers measured on realistic cold-start conditions (disk I/O, not DataStore singleton cache). Updated all performance claims to reflect accurate ratios.

### Deprecated

#### `encrypted: Boolean` parameter (WARNING level)
`encrypted: Boolean` overloads remain available at `DeprecationLevel.WARNING` with IDE `ReplaceWith` guidance to `KSafeWriteMode`.

```kotlin
// Old (deprecated)
ksafe.put("key", value, encrypted = true)

// New
ksafe.put("key", value, mode = KSafeWriteMode.Encrypted())
ksafe.put("key", value, mode = KSafeWriteMode.Plain)
```

Affected APIs: `getDirect`, `putDirect`, `get`, `put`, `getFlow`, `getStateFlow`, property delegation `invoke`, and Compose `mutableStateOf`.

#### `useStrongBox` / `useSecureEnclave` constructor parameters
The instance-level constructor flags `useStrongBox: Boolean` (Android) and `useSecureEnclave: Boolean` (iOS) are `@Deprecated` in favor of per-property `KSafeEncryptedProtection.HARDWARE_ISOLATED` via `KSafeWriteMode`. When set to `true`, they promote all `DEFAULT` encryptions to `HARDWARE_ISOLATED` at the instance level.

### Added (Testing)

- `KSafeProtectionTest` (common) — tests for `KSafeProtection` enum values and `KSafeKeyStorage` ordinal ordering
- `KSafeKeyStorageTest` (JVM) — tests for the Key Storage Query API: `deviceKeyStorages_returnsOnlySoftware`, `enumOrdinalOrdering`, `getKeyInfo_returnsNullForNonExistentKey`, `getKeyInfo_returnsNoneProtectionAndSoftwareForUnencryptedKey`, `getKeyInfo_returnsDefaultProtectionAndSoftwareForEncryptedKey`, `getKeyInfo_protectionMatchesStoredMetadata`
- `IosKeychainEncryptionTest` (iOS) — tests for `keychainLookupOrder()`, `isTransientUnwrapFailure()`, SE tag prefix constants, plus Secure Enclave tests:
  - `testSecureEnclaveThrowsInTestEnvironment` — verifies SE encrypt falls back and throws in entitlement-less test runner
  - `testSecureEnclaveDeleteDoesNotThrow` — verifies SE delete is permissive
  - `documentSecureEnclaveBehavior` — documents envelope encryption architecture and manual test steps
- All existing test suites updated to use new `KSafeWriteMode` API (removed `encrypted: Boolean` parameter from all test calls)

### Build

- Added `kotlin.kmp.isolated-projects.support=auto` to `gradle.properties`

### Fixed

- **`getStateFlow()` brief incorrect emission ([#15](https://github.com/ioannisa/KSafe/issues/15)):** `getStateFlow()` used `defaultValue` as the initial `StateFlow` value, causing a brief emission of the default before the actual stored value arrived from `getFlow()`. Now uses `getDirect(key, defaultValue)` to synchronously resolve the initial value from the memory cache, so the `StateFlow` starts with the correct stored value immediately. *(Thanks @dhng22)*
- **Typed key cleanup correctness:** DataStore cleanup now uses type-agnostic key-name removal (`removeByKeyName`) to reliably remove stale typed legacy entries.
- **iOS Secure Enclave error propagation:** improved CFError forwarding avoids accidental fallback on lock-state related failures.
- **Race-safety and migration robustness:** batch/metadata migration behavior has been hardened for concurrent and legacy upgrade scenarios.
- **Biometric prompt never showing when KSafe is lazily initialized** (e.g. via Koin `single`, Hilt `@Singleton`). `BiometricHelper` relied solely on `ActivityLifecycleCallbacks` to track the current `FragmentActivity`, but when KSafe was created after the Activity had already reached RESUMED state, the callbacks never fired and `waitForFragmentActivity()` timed out after 5 seconds returning `false`. Added `findCurrentActivity()` reflection fallback that discovers the current resumed `FragmentActivity` via `ActivityThread`. The reflection is wrapped in a try-catch and degrades gracefully on non-standard Android builds.
- **`verifyBiometricDirect` dispatcher changed from `Dispatchers.Main` to `Dispatchers.Default`** to avoid calling `BiometricHelper.authenticate()` from the main thread, which its documentation explicitly prohibits.

---

## [1.6.0] - 2025-02-16

### Added

#### WASM/JS Target

KSafe now runs in the browser. New platform source sets (`wasmJsMain`, `wasmJsTest`) and a `ksafe-compose` WASM target bring encrypted key-value storage to Kotlin/WASM.

- **Storage:** Browser `localStorage` via `@JsFun` externals (in `LocalStorage.kt`)
- **Encryption:** WebCrypto AES-256-GCM via `cryptography-provider-webcrypto`
- **Memory policy:** Always `PLAIN_TEXT` internally — WebCrypto is async-only, so all values are decrypted at init and held as plaintext in a `HashMap`
- **Key namespace:** `ksafe_{fileName}_{key}` for data, `ksafe_key_{alias}` for encryption keys
- **Mutex-protected key generation** to prevent race conditions in single-threaded coroutine environments
- **Per-operation error isolation** in batch writes — a single failed operation doesn't discard the entire batch
- **`yield()`-based StateFlow propagation** — required because WASM is single-threaded and has no implicit suspension points like JVM's DataStore I/O
- **No** `runBlocking`, `ConcurrentHashMap`, `Dispatchers.IO`, or `AtomicBoolean` — all replaced with WASM-compatible equivalents
- New WASM-specific `actual` implementations: `KSafe.wasmJs.kt`, `WasmSoftwareEncryption.kt`, `LocalStorage.kt`, `SecurityChecker.wasmJs.kt`

#### StateFlow API

New reactive API for observing KSafe values as flows, available on all four platforms:

- `getFlow(key, defaultValue, encrypted)` — returns a cold `Flow<T>` that emits whenever the underlying value changes
- `getStateFlow(key, defaultValue, encrypted, scope)` — convenience extension that converts the cold flow into a hot `StateFlow<T>` using `stateIn(scope, SharingStarted.Eagerly, defaultValue)`
- Works with both encrypted and unencrypted values
- On DataStore platforms (Android, JVM, iOS), backed by `DataStore.data.map {}` with `distinctUntilChanged()`
- On WASM, backed by a `MutableStateFlow` that is updated on writes

#### ksafe-compose WASM Target

The `ksafe-compose` module now includes a `wasmJs` target, enabling `mutableStateOf` persistence in Compose for Web.

### Fixed

#### Android: DataStore "multiple active instances" crash on DI re-initialization

When using Koin Compose Multiplatform (`KoinMultiplatformApplication {}`), the Koin application context can be recreated on Activity restart (configuration changes such as rotation, locale change, or dark mode toggle). This causes all `single {}` definitions to be re-instantiated, including KSafe. Each new KSafe instance created a new DataStore for the same file, triggering:

```
IllegalStateException: There are multiple DataStores active for the same file
```

**Root cause:** Each `KSafe` constructor eagerly created its own `DataStore` instance. DataStore enforces a single-instance-per-file invariant. When Koin re-created KSafe with the same `fileName`, a second DataStore was created for the same file.

**Fix:** Added a process-level `ConcurrentHashMap<String, DataStore<Preferences>>` cache in the Android `companion object`. If a DataStore already exists for a given file name, it is reused instead of creating a new one. This fix is Android-only because configuration changes (Activity recreation) are an Android-specific lifecycle concept — iOS, JVM, and WASM do not re-initialize their DI containers during normal operation.

#### Key generation race condition (JVM)

Concurrent `putEncrypted` calls for the same key alias could trigger parallel key generation in `JvmSoftwareEncryption`, producing different AES keys. One key would be stored in DataStore while a different one was used to encrypt data, causing permanent data loss on the next read.

**Fix:** Added a `ConcurrentHashMap<String, SecretKey>` in-memory key cache and per-alias `synchronized` locks to `JvmSoftwareEncryption.getOrCreateSecretKey()`. The first caller generates and caches the key; subsequent callers return the cached key immediately.

#### deleteKey race with key cache repopulation (Android + JVM)

`deleteKey()` removed the key from the Keystore/DataStore but not from the in-memory cache (Android) or had no cache at all (JVM). A concurrent `encrypt()` call could re-cache the stale key before the delete completed, causing subsequent encryptions to use a key that no longer existed in persistent storage.

**Fix:** `deleteKey()` now holds the same per-alias lock as `getOrCreateKey()` and removes the key from both the persistent store and the in-memory cache atomically. Applied to both `AndroidKeystoreEncryption` and `JvmSoftwareEncryption`.

#### Replaced `intern()` lock strategy with dedicated lock map (Android + JVM)

Both `AndroidKeystoreEncryption` and `JvmSoftwareEncryption` used `synchronized(identifier.intern())` for per-alias locking. `String.intern()` adds strings to the JVM's permanent string pool, which is never garbage collected. With dynamic key aliases (e.g., per-user keys), this caused unbounded memory growth.

**Fix:** Replaced with `ConcurrentHashMap<String, Any>` lock maps and a `lockFor(alias)` helper. Lock objects are scoped to the encryption engine instance and eligible for GC when the engine is collected.

### Removed

- **`IntegrityChecker`** — Removed from all platforms (Android, iOS, JVM, WASM). This was a wrapper around Google Play Integrity (Android) and Apple DeviceCheck (iOS) that generated tokens for server-side device verification. It had no connection to KSafe's core encrypted storage functionality and added transitive dependencies (`play-integrity`, `play-services-base`) to every consumer. Client-side root/jailbreak detection remains available via `SecurityChecker` and `KSafeSecurityPolicy`.
- Removed `play-integrity` and `play-services-base` dependencies from Android

### Changed

- `datastore-preferences-core` dependency moved from `commonMain` to per-platform source sets (Android, JVM, iOS) — WASM uses `localStorage` and does not depend on DataStore

### Added (Testing)

- `Jvm160FixesTest` — 9 new JVM tests covering the three encryption engine fixes:
  - `testConcurrentEncryptedWritesSameKey_noDataLoss` — verifies concurrent encrypted writes to the same key all produce readable values
  - `testConcurrentEncryptedWritesDifferentKeys_allReadable` — verifies concurrent writes to different keys don't interfere
  - `testKeyGenerationRaceStress` — stress test with 20 threads writing to the same key
  - `testDeleteKeyDoesNotLeaveStaleCache` — verifies deleted keys return default on re-read
  - `testDeleteKeyRaceWithConcurrentEncryption` — verifies delete + encrypt race doesn't corrupt data
  - `testRepeatedDeleteAndRewriteCycles` — 50 cycles of delete + rewrite with integrity checks
  - `testManyUniqueAliasesWork` — 100 unique aliases to verify lock map scalability
  - `testLockMapSerializesPerAlias` — verifies per-alias serialization with concurrent readers/writers
  - `testDynamicStringAliasesShareLock` — verifies dynamically constructed alias strings share the same lock
- `WasmJsKSafeTest` — WASM test suite extending `KSafeTest` with `FakeEncryption` (WebCrypto requires browser)

### Dependencies

- Added `cryptography-provider-webcrypto` for WASM target

---

## [1.5.0] - 2025-02-09

### Added

#### Configurable Device Lock-State Policy: `requireUnlockedDevice`

New `KSafeConfig.requireUnlockedDevice: Boolean = false` property that controls whether encrypted data should only be accessible when the device is unlocked.

| Platform | `false` (default) | `true` |
|----------|-------------------|--------|
| **Android** | Keys accessible at any time | Keys created with `setUnlockedDeviceRequired(true)` (API 28+) |
| **iOS** | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |
| **JVM** | No effect (software-backed keys) | No effect (software-backed keys) |

**Automatic migration:** Changing this value in either direction triggers a one-time migration on the next KSafe initialization:
- **Android:** Existing encrypted values are decrypted with the old key, the old Keystore key is deleted, and values are re-encrypted with a new key that has the updated policy. This applies in both directions (`false→true` and `true→false`). Migration is atomic — the policy marker is only written on success, so a crash safely retries.
- **iOS:** Existing Keychain items have their `kSecAttrAccessible` attribute updated in-place via `SecItemUpdate` (no re-encryption needed). The migration marker is only written if all key updates succeed — if any fail (e.g., device is locked), migration retries on next launch.
- **JVM:** Only the policy marker is written (no lock concept on JVM).

```kotlin
// Require device to be unlocked for all encrypted data access
val ksafe = KSafe(
    context = context,
    config = KSafeConfig(requireUnlockedDevice = true)
)
```

**Breaking change (iOS default behavior):** Previously, iOS always used `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, meaning Keychain items were only accessible when the device was unlocked. With `requireUnlockedDevice = false` (the new default), iOS now uses `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, making items accessible after the first unlock — matching Android's existing behavior and enabling background access patterns.

- New `KSafeEncryption.updateKeyAccessibility()` interface method (default no-op, overridden on iOS)
- Migration marker `__ksafe_access_policy__` stored in DataStore (skipped by `updateCache()` on all platforms)

**Error behavior when locked:** When `requireUnlockedDevice = true` and the device is locked, encrypted reads (`getDirect`, `get`, `getFlow`) and suspend writes (`put`) throw `IllegalStateException` instead of silently returning default values. `putDirect` does not throw — the background write consumer logs the error and drops the batch while staying alive for future writes. On Android, `InvalidKeyException` from `Cipher.init()` is wrapped as `IllegalStateException("device is locked")` and propagated through `resolveFromCache` and `getEncryptedFlow`. Apps can catch this exception to detect and handle locked-device scenarios.

#### New Memory Policy: `ENCRYPTED_WITH_TIMED_CACHE`

A third memory policy that balances security and performance. The primary `memoryCache` still holds ciphertext (like `ENCRYPTED`), but a secondary plaintext cache stores recently-decrypted values for a configurable TTL.

**Why this matters:** Under `ENCRYPTED` policy, every read triggers AES-GCM decryption. In UI frameworks like Jetpack Compose or SwiftUI, the same encrypted property may be read multiple times during a single recomposition/re-render cycle. This causes redundant crypto operations that waste CPU and can drop frames on lower-end devices.

`ENCRYPTED_WITH_TIMED_CACHE` eliminates this: only the first read decrypts; subsequent reads within the TTL window are pure memory lookups. After the TTL expires, the plaintext is evicted and the next read decrypts again.

```kotlin
// Android
val ksafe = KSafe(
    context = context,
    memoryPolicy = KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE,
    plaintextCacheTtl = 5.seconds  // default
)

// JVM
val ksafe = KSafe(
    memoryPolicy = KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE,
    plaintextCacheTtl = 10.seconds
)

// iOS
val ksafe = KSafe(
    memoryPolicy = KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE,
    plaintextCacheTtl = 3.seconds
)
```

**How the three policies compare:**

| Policy | RAM contents | Read cost | Security |
|--------|-------------|-----------|----------|
| `PLAIN_TEXT` | Plaintext (forever) | O(1) lookup | Low — all data exposed in memory |
| `ENCRYPTED` | Ciphertext | AES-GCM decrypt every read | High — nothing plaintext in RAM |
| `ENCRYPTED_WITH_TIMED_CACHE` | Ciphertext + short-lived plaintext | First read decrypts, then O(1) for TTL | Medium — plaintext only for recently-accessed keys, only for seconds |

**Race condition safety:** Reads capture a local reference to the cached entry atomically. There is no background sweeper — expired entries are simply ignored on the next access. Even under concurrent reads and writes, the worst case is a single extra decryption, never a crash or data corruption.

- New `plaintextCacheTtl: Duration` constructor parameter (default: 5 seconds) on all platforms
- Uses `kotlin.time.TimeSource.Monotonic` for cross-platform monotonic timestamps
- Thread-safe: `ConcurrentHashMap` on Android/JVM, `AtomicReference<Map>` on iOS

#### Orphaned Ciphertext Cleanup on Startup

After uninstalling an app and reinstalling, Android Auto Backup restores the DataStore file (containing ciphertext) but **not** the Android Keystore keys (hardware-bound). This leaves orphaned ciphertext that wastes space and creates confusion — encrypted values silently return defaults because the key is gone. On iOS, a similar scenario occurs if Keychain entries are cleared during a device reset.

KSafe now proactively detects and removes orphaned ciphertext on startup. A new `cleanupOrphanedCiphertext()` method runs once in `startBackgroundCollector()` after migration and before the DataStore `collect`:

```kotlin
private fun startBackgroundCollector() {
    CoroutineScope(Dispatchers.Default + SupervisorJob()).launch {
        migrateAccessPolicyIfNeeded()
        cleanupOrphanedCiphertext()   // ← NEW
        dataStore.data.collect { updateCache(it) }
    }
}
```

**How it works:**
1. Reads all DataStore entries with the `encrypted_` prefix
2. Attempts to decrypt each entry using the platform's encryption engine
3. If decryption permanently fails (key gone, invalidated, or wrong key) → marks for removal
4. If decryption temporarily fails (device is locked) → skips, retries next launch
5. Atomically removes all orphaned entries from DataStore and memory cache

**Error classification by platform:**
- **Android:** "device is locked" → skip (temporary). `KeyPermanentlyInvalidatedException`, `AEADBadTagException`, "No encryption key found" → orphaned.
- **iOS:** "device is locked" or "Keychain" errors → skip (temporary). All others → orphaned.
- **JVM:** All decrypt failures → orphaned (no device lock concept).

> **Note on unencrypted values:** This cleanup targets only encrypted entries (those with the `encrypted_` prefix in DataStore). Unencrypted values (`encrypted = false`) are not affected. On Android, if `android:allowBackup="true"` is set in the manifest, Auto Backup may restore unencrypted DataStore entries after reinstall with stale values from the last backup snapshot.

### Fixed

#### iOS Keychain operations now check return values

- `storeInKeychain()` now checks the `SecItemAdd` return value — previously it was silently ignored, meaning key storage could fail without any error
- `updateKeyAccessibility()` now checks the `SecItemUpdate` return value and throws on failure

#### Suspend API no longer blocks the calling dispatcher during encryption/decryption

The suspend functions `put(encrypted = true)` and `get(encrypted = true)` previously called `engine.encrypt()`/`engine.decrypt()` directly on the caller's coroutine dispatcher. If called from `Dispatchers.Main` (e.g., inside `viewModelScope.launch`), the blocking AES-GCM operation would run on the main thread. On Android, first-time Keystore key generation can take 50–200ms — enough to drop frames.

**Before (broken):**
```kotlin
// In ViewModel — encryption runs on Main thread!
viewModelScope.launch {
    ksafe.put("token", myToken, encrypted = true)
}
```

**After (fixed):**
- `putEncrypted` now wraps `engine.encrypt()` in `withContext(Dispatchers.Default)`
- `getEncrypted` now wraps `resolveFromCache()` in `withContext(Dispatchers.Default)`
- Applied consistently across all three platforms (Android, JVM, iOS)
- `Dispatchers.Default` is correct because encryption is CPU-bound, not I/O-bound

**Note:** `putDirect` was already safe — it defers encryption to `processBatch()` on a background scope. This fix brings the suspend API (`put`/`get`) to the same level of thread safety.

#### ENCRYPTED mode plaintext leak via Direct API

`putDirect()` stored plaintext JSON in `memoryCache` for instant read-back, but `processBatch()` never replaced it with ciphertext after encryption completed. Because dirty keys are permanent (by design), `updateCache()` couldn't fix this either. Result: `ENCRYPTED` mode advertised "ciphertext in RAM" but Direct API writes left plaintext in RAM permanently.

**Fixed:** After `processBatch()` encrypts and persists data to DataStore, it now atomically replaces plaintext with ciphertext in the memory cache using compare-and-swap (CAS):
- **Android/JVM**: `ConcurrentHashMap.replace(key, oldValue, newValue)` — atomic, no-op if a newer `putDirect()` wrote a different value
- **iOS**: `AtomicReference.compareAndSet` loop with same "skip if newer write" semantics

A brief plaintext window (~16ms write coalescing) remains inherent to deferred encryption — it keeps `putDirect()` at ~13μs instead of 4-6ms. The suspend API (`put()`) does not have this window; it encrypts immediately via `withContext(Dispatchers.Default)`.

#### Long values silently stored as Int in unencrypted suspend writes (Android + iOS)

`putUnencrypted` coerced small Long values (those fitting in Int range) to Int before storing. On Android, this created a type mismatch — `getUnencryptedKey` correctly selected `longPreferencesKey` but the stored value was an Int. On iOS, both key selection and value were coerced to Int, silently changing the stored type. The in-memory cache masked the issue during runtime (because `resolveFromCache` handles Int-to-Long conversion), but DataStore's typed key system could not round-trip the value correctly from disk after a restart.

**Fixed:** All primitives are now stored as their declared type — a Long stays a Long, an Int stays an Int. No `Number` coercion. JVM was already correct. Existing data is safe: `resolveFromCache` already handles Int-to-Long conversion on read, so old values stored as Int will still be read correctly as Long through the cache layer.

#### Redundant serialization and cache write in `putDirect`

The encrypted branch of `putDirect()` previously called `json.encodeToString()` twice and `updateMemoryCache()` twice with the same value. The shared `toCache` computation was wasted for encrypted writes because the encrypted branch recomputed it independently. Restructured so encrypted and unencrypted branches are fully independent — each computes its own cache value and calls `updateMemoryCache()` once. Applied across all three platforms.

#### Stale comment in `updateCache` (Android + JVM)

A comment in `updateCache()` incorrectly stated "Dirty flags are cleared in processBatch after successful persistence." In reality, dirty flags are intentionally kept permanently to prevent race conditions. Updated the comment to reflect the actual behavior.

#### Background write consumer dies on encryption failure

If `processBatch()` threw an exception (e.g., device locked with `requireUnlockedDevice = true`), the Channel consumer coroutine would crash and never restart — all future `putDirect` writes would silently queue up and never persist. Now `processBatch()` is wrapped in a try-catch: the failed batch is dropped with a log message, and the consumer stays alive for future writes after the device is unlocked.

#### Nullable primitive retrieval returns default instead of stored value (all platforms)

When retrieving an unencrypted primitive with a nullable type and `null` default (e.g., `get<String?>(key, defaultValue = null, encrypted = false)`), KSafe always returned `null` even when a value was stored. The `when(defaultValue)` dispatch in `convertStoredValue` matched `null` against `is String` — which fails because `null` is not a `String` instance — falling through to the `else` branch that attempted JSON deserialization on a plain string like `"hello"`. Since `"hello"` is not valid JSON, deserialization silently failed and the catch returned `null`.

**Fixed:** The `else` branch now tries a direct cast (`storedValue as T`) before JSON deserialization. For primitives (String, Int, Boolean, etc.), the cast succeeds and the value is returned immediately. JSON deserialization is only attempted as a fallback for complex types (data classes). Applied on Android, iOS, and JVM.

#### Cache cleanup evicts newly-written keys (all platforms)

`updateCache()` removed any key from `memoryCache` that wasn't present in the DataStore snapshot. But between `putDirect()` and `processBatch()` flushing to DataStore, newly-written keys exist only in the cache — the DataStore snapshot doesn't contain them yet. A concurrent `updateCache()` would evict these keys, causing the next `getDirect()` to return the default value instead of the just-written value.

**Fixed:** The key-removal filter in `updateCache()` now also checks `dirtyKeys`, preserving any key that has a pending write. Applied on Android, iOS, and JVM.

### Added (Testing)

- `testNewKeysSurviveCacheCleanup` — stress test: 10 writers × 200 iterations verifying that `putDirect` + immediate `getDirect` never returns default (targets the cache cleanup race condition)
- `testOrphanedCiphertextIsCleanedUpOnStartup` — uses a togglable fake engine to simulate lost encryption keys after backup restore; verifies orphaned ciphertext is detected and that unencrypted data is left untouched
- `testValidCiphertextIsNotCleanedUp` — verifies that valid encrypted entries survive the startup cleanup
- `testEncryptedPutGetNeverReturnsDefault` — 5 concurrent readers + writers verifying encrypted values never transiently return defaults

### Dependencies

- `play-services-base` 18.9.0 → 18.10.0
- `vanniktech-mavenPublish` 0.35.0 → 0.36.0

---

## [1.4.2] - 2025-01-26

### Fixed

- **Critical iOS data loss on upgrade from v1.2.0** - Removed erroneous `clearAllKeychainEntriesSync()` function that was wiping all Keychain entries on first launch
  - **Root cause**: The function was based on a flawed premise that v1.2.0 stored "biometric-protected" Keychain entries that needed cleanup
  - **Reality**: v1.2.0 used `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` which is NOT biometric protection—it simply means "accessible when device is unlocked"
  - **Impact**: Users upgrading from v1.2.0 to v1.3.0+ lost all their encrypted data unnecessarily
  - **Fix**: Removed the one-time cleanup that ran on startup. The legitimate `cleanupOrphanedKeychainEntries()` function (which removes Keychain keys without matching DataStore entries after app reinstall) remains intact
  - **Who was affected**: Only users who upgraded FROM v1.2.0 TO any version between v1.3.0–v1.4.1. Users who started fresh on v1.3.0+ or upgraded between v1.3.x/v1.4.x versions were NOT affected
  - **Why in-between upgrades were safe**: The cleanup used NSUserDefaults to track execution via `BIOMETRIC_CLEANUP_KEY`. Once it ran (on first launch after upgrading from v1.2.0), the flag was set and subsequent version upgrades (e.g., v1.3.0→v1.4.0→v1.4.1) skipped the cleanup entirely. The damage only occurred on that single first upgrade from v1.2.0

### Removed

- `clearAllKeychainEntriesSync()` - iOS function that unnecessarily deleted all Keychain entries
- `BIOMETRIC_CLEANUP_KEY` constant - No longer needed without the erroneous cleanup

---

## [1.4.1] - 2025-01-21

### Performance Improvements

KSafe 1.4.1 delivers **massive performance improvements**, making it faster than EncryptedSharedPreferences and KVault for encrypted operations while maintaining hardware-backed security.

#### Benchmark Results (1.4.0 → 1.4.1)

| Metric | 1.4.0 | 1.4.1 | Improvement |
|--------|-------|-------|-------------|
| Unencrypted Write | 0.23 ms | 0.0115 ms | **20x faster** |
| Encrypted Write (ENCRYPTED mem) | 0.44 ms | 0.053 ms | **8x faster** |
| Encrypted Write (PLAIN_TEXT mem) | 0.70 ms | 0.012 ms | **58x faster** |
| Encrypted Write vs ESP | 2.4x slower | **17x faster** | Now beats ESP! |
| DataStore Write Acceleration | 20x | 327x | **16x more** |

#### Comparison with Other Libraries (Unencrypted)

| Library | Read | Write | Notes |
|---------|------|-------|-------|
| SharedPreferences | 0.0006 ms | 0.0152 ms | Android only, no encryption |
| MMKV | 0.0007 ms | 0.0577 ms | Fast, but no KMP, no hardware encryption |
| Multiplatform Settings | 0.0009 ms | 0.0192 ms | KMP, but no encryption |
| **KSafe 1.4.1** | **0.0016 ms** | **0.0115 ms** | KMP + encryption + biometrics |
| DataStore | 1.10 ms | 3.76 ms | Safe but slow |

> **Note:** KSafe unencrypted writes are now **faster than SharedPreferences**!

#### Comparison with Other Libraries (Encrypted)

| Library | Read | Write | vs KSafe |
|---------|------|-------|----------|
| **KSafe (PLAIN_TEXT memory)** | **0.0058 ms** | **0.0123 ms** | — |
| KSafe (ENCRYPTED memory) | 0.0276 ms | 0.0531 ms | *(decrypts on-demand)* |
| KVault | 0.6003 ms | 1.05 ms | KSafe is **103x/85x faster** |
| EncryptedSharedPrefs | 0.6817 ms | 0.2064 ms | KSafe is **117x/17x faster** |

**vs KVault (encrypted KMP storage):**
- **103x faster encrypted reads** (0.60 ms → 0.0058 ms with PLAIN_TEXT memory)
- **85x faster encrypted writes** (1.05 ms → 0.0123 ms)

**vs multiplatform-settings (Russell Wolf):**
- **1.7x faster writes** (0.0192 ms → 0.0115 ms)
- Similar read performance (0.0016 ms vs 0.0009 ms)
- KSafe adds: hardware-backed encryption, biometric auth, auto-serialization

#### Cold Start / Reinitialization Performance

| Library | Keys | Time |
|---------|------|------|
| SharedPreferences | 201 | 0.0315 ms |
| Multiplatform Settings | 201 | 0.0400 ms |
| MMKV | 201 | 0.0402 ms |
| DataStore | 201 | 0.4901 ms |
| **KSafe (ENCRYPTED)** | 603 | **1.26 ms** |
| KVault | 320 | 4.77 ms |
| EncryptedSharedPrefs | 201 | 6.41 ms |
| KSafe (PLAIN_TEXT) | 1206 | 6.49 ms |

> **Note:** KSafe ENCRYPTED mode is **5x faster** to cold-start than PLAIN_TEXT mode (defers decryption until access).

#### Optimizations Implemented

1. **ConcurrentHashMap for Hot Cache**
   - Replaced `AtomicReference<Map>` with `ConcurrentHashMap`
   - O(1) per-key updates instead of copy-on-write
   - Eliminates full map copy on every write

2. **ConcurrentHashMap for Dirty Keys**
   - Replaced `AtomicReference` with CAS loops with `ConcurrentHashMap.newKeySet()`
   - O(1) add/remove operations for tracking pending writes
   - Prevents stale data overwrites during async persistence

3. **Write Coalescing**
   - New `Channel<WriteOperation>` for queuing writes
   - Single consumer coroutine batches operations within 16ms window
   - Multiple writes coalesced into single `DataStore.edit{}` call
   - Reduces disk I/O overhead significantly

4. **Deferred Encryption**
   - Encryption moved from UI thread to background batch processor
   - `putDirect()` queues plaintext, returns immediately
   - `processBatch()` encrypts all pending operations before DataStore write
   - UI thread no longer blocked by Android Keystore operations

5. **SecretKey Caching (Android)**
   - Added `ConcurrentHashMap<String, SecretKey>` cache in `AndroidKeystoreEncryption`
   - Avoids repeated Android Keystore lookups
   - Double-checked locking with `synchronized(keyAlias.intern())`
   - Cache cleared when keys are deleted

6. **Shared Write Scope**
   - Reuses single `CoroutineScope(Dispatchers.IO + SupervisorJob())` for all write operations
   - Avoids object allocation overhead of creating new scope per `putDirect()` call

7. **Simplified Cache Updates**
   - `updateMemoryCache()` now uses O(1) direct `ConcurrentHashMap` operations
   - Eliminated CAS loops and map copying previously required with `AtomicReference<Map>`

### Technical Details

**Write Flow Before (1.4.0):**
```
putDirect() → encrypt (BLOCKING) → launch coroutine → DataStore.edit()
             ↑ 4-6ms on UI thread!
```

**Write Flow After (1.4.1):**
```
putDirect() → update cache → queue WriteOperation → return (~13µs)
                                     ↓
Background: collect 16ms window → encrypt all → single DataStore.edit()
```

### Fixed

- **Critical Data Integrity Fix (Hot Cache)** - Fixed a bug where plaintext values like `"true"`, `"false"`, or numbers (which are valid Base64) were incorrectly attempted to be decrypted during optimistic reads.
  - Previously, "decrypting" these values produced garbage which failed JSON parsing outside the recovery block.
  - Now validates JSON structure post-decryption; invalid results trigger the correct plaintext fallback.
  - Fixes potential read failures for specific primitive values immediately after writing.

- **ConcurrentHashMap iteration race condition (JVM)** - Fixed `NoSuchElementException` crash during rapid concurrent writes

- **HashMap concurrency crash (iOS)** - Fixed `IllegalStateException` ("Have object hashCodes changed?") crash during concurrent cache access
  - Kotlin/Native's HashMap is not thread-safe unlike JVM's ConcurrentHashMap
  - Implemented proper copy-on-write semantics with AtomicReference for all cache mutations
  - Added synchronized access to dirty keys set
  - Background collector can no longer corrupt cache while UI reads values

- **Dirty keys race condition** - Fixed cache corruption where keys could be removed prematurely
  - Dirty flags are now intentionally NOT cleared after persistence
  - Prevents stale DataStore snapshots from overwriting optimistic cache values
  - Trade-off: Small memory overhead (~10KB for 1000 keys) for guaranteed correctness

- **Self-Healing Key Recovery (Android)** - Fixed rare crash when Android Keystore keys become invalidated
  - **This is rare**: KSafe keys are configured WITHOUT these flags:
    - `setUserAuthenticationRequired(true)` - NOT set (keys usable without unlocking device)
    - `setInvalidatedByBiometricEnrollment(true)` - NOT set (keys survive biometric changes)
  - This means KSafe keys are stable and always accessible
  - Invalidation only occurs in edge cases: factory reset, OEM Keystore bugs, or system corruption
  - Now catches `KeyPermanentlyInvalidatedException` during encrypt/decrypt operations
  - **Self-healing behavior**: Automatically deletes invalidated key and regenerates a fresh one
  - Encryption: Seamlessly retries with new key (data preserved)
  - Decryption: Returns default value (old encrypted data cannot be recovered with destroyed key)

- **iOS Keychain error handling** - Improved error handling to prevent silent data loss
  - `errSecItemNotFound` → Creates new key (correct - key doesn't exist)
  - `errSecInteractionNotAllowed` → Throws error (device locked - key exists but inaccessible)
  - Other errors → Throws error with status code (prevents silent key regeneration)
  - Previously, ANY error would silently create a new key, potentially causing data loss

### Added (Testing)

- **Concurrency stress tests** in `JvmKSafeTest`:
  - `testConcurrentPutDirectStress` - 10 writers × 500 iterations
  - `testConcurrentEncryptedPutDirectStress` - 5 writers × 100 encrypted iterations
  - `testConcurrentReadWriteStress` - Simultaneous read/write on shared keys
  - `testDirtyKeysStress` - 20 writers × 1000 iterations targeting dirty key mechanism
- **iOS Keychain error handling tests** in `IosKeychainEncryptionTest`:
  - `testThrowsOnKeychainErrorInTestEnvironment` - Verifies errors throw (not silently create keys)
  - `testDecryptThrowsOnKeychainError` - Verifies decrypt fails safely
  - `testDeleteKeyDoesNotThrow` - Verifies delete is safe (no data loss risk)
  - `testCustomConfigIsAccepted` - Verifies 128-bit and 256-bit config
  - Documentation tests for error codes and device-locked scenario

### Changed

- `WriteOperation.Encrypted` now carries plaintext + keyAlias instead of pre-computed ciphertext
- Encryption happens in `processBatch()` instead of `putDirect()`
- All three platforms (Android, iOS, JVM) use consistent write coalescing architecture

### Documentation

- **Added Direct API recommendation** for bulk/concurrent operations (~950x faster than Coroutine API)
- Added Cold Start / Reinitialization benchmark results
- Added comprehensive comparison table (KSafe vs SharedPreferences vs DataStore vs KVault)
- Added performance benchmarks section with detailed results including KVault
- Added explanation of hot cache architecture
- Updated "Alternatives & Comparison" section with KVault

---

## [1.4.0] - 2025-01-11

### Added

#### Runtime Security Policy
- **New `KSafeSecurityPolicy`** for detecting runtime security threats
- **Configurable actions** - `IGNORE`, `WARN`, or `BLOCK` for each security check:
  - `IGNORE` - No detection performed, no callback invoked
  - `WARN` - Detection runs, callback invoked, app continues normally
  - `BLOCK` - Detection runs, callback invoked, throws `SecurityViolationException`
- **Preset policies** - `Default`, `Strict`, `WarnOnly` for common configurations
  ```kotlin
  val ksafe = KSafe(
      context = context,
      securityPolicy = KSafeSecurityPolicy.Strict
  )
  ```

#### Root & Jailbreak Detection
- **Enhanced Android root detection**:
  - su binary paths (`/system/bin/su`, `/system/xbin/su`, etc.)
  - Magisk paths (`/sbin/.magisk`, `/data/adb/magisk`, etc.)
  - BusyBox installation paths
  - Xposed Framework (files + stack trace detection)
  - Root management apps (Magisk Manager, SuperSU, LSPosed, KingRoot, etc.)
  - Build tags (`test-keys`) and dangerous system properties
- **iOS jailbreak detection**:
  - Cydia, Sileo, and other jailbreak app paths
  - System write access test (fails on non-jailbroken devices)
  - Common jailbreak tool paths (`/bin/bash`, `/usr/sbin/sshd`, etc.)
- ⚠️ **Limitation**: Sophisticated root-hiding tools (Magisk DenyList, Shamiko, Zygisk) may bypass detection

#### Debugger & Emulator Detection
- **Debugger detection** - Detect attached debuggers on all platforms
- **Emulator detection** - Detect emulators/simulators (Android & iOS)
- **Debug build detection** - Detect debug builds

#### Compose Support
- **New `UiSecurityViolation`** - Immutable wrapper for `SecurityViolation` ensuring Compose stability
  ```kotlin
  @Immutable
  data class UiSecurityViolation(val violation: SecurityViolation)
  ```
  - Allows `ImmutableList<UiSecurityViolation>` to skip unnecessary recompositions
  - Located in `ksafe-compose` module

### Added (Testing)
- **Comprehensive test suite** for new security features:
  - `KSafeSecurityPolicyTest` - SecurityAction, SecurityViolation, presets
  - `BiometricAuthorizationDurationTest` - Duration and scope patterns
  - `KSafeMemoryPolicyTest` - Memory policy enum
  - `JvmSecurityCheckerTest` - JVM-specific security behavior
- **ksafe-compose module tests**:
  - `KSafeComposeStateTest` - Compose state integration tests
  - `KSafeMutableStateOfTest` - MutableState behavior tests
  - `AndroidKSafeMutableStateOfTest` - Android instrumented tests
  - `JvmKSafeMutableStateOfTest` - JVM-specific tests

### Changed
- **iOS Simulator uses real Keychain** - Removed `MockKeychain` in favor of actual iOS Keychain APIs
  - Simulator: Software-backed Keychain
  - Real device: Hardware-encrypted Keychain (protected by device passcode)
  - Added threat model and security boundaries
  - Added compatibility matrix
  - Added GCM (Galois/Counter Mode) explanation
  - Added detailed Actions behavior documentation with examples
  - Added non-GMS device compatibility notes
  - Added root detection methods documentation

### Removed
- **`MockKeychain.kt`** - iOS Simulator now uses real Keychain APIs instead of UserDefaults-based mock
- **Irrelevant images** - Removed unnecessary publishing screenshots from repository

---

## [1.3.0] - 2025-12-31

### Added

#### Standalone Biometric Authentication
- **New `verifyBiometric()` suspend function** - Coroutine-based biometric verification
- **New `verifyBiometricDirect()` callback function** - Non-blocking biometric verification for any context
- **Biometric authentication is now decoupled from storage** - Use it to protect any action (API calls, navigation, data display), not just KSafe operations

#### Authorization Duration Caching
- **New `BiometricAuthorizationDuration` data class** for configuring cached authentication:
  ```kotlin
  data class BiometricAuthorizationDuration(
      val duration: Long,       // Duration in milliseconds
      val scope: String? = null // Optional scope identifier
  )
  ```
- **Duration caching** - Avoid repeated biometric prompts by caching successful auth for a specified duration
- **Scoped authorization** - Different scopes maintain separate auth timestamps for fine-grained control
- **Recommended pattern**: Use `viewModelScope.hashCode().toString()` for ViewModel-scoped auth that auto-invalidates when the ViewModel is recreated

#### Authorization Management
- **New `clearBiometricAuth()` function** - Force re-authentication by clearing cached auth
  - `clearBiometricAuth()` - Clear all cached authorizations
  - `clearBiometricAuth(scope)` - Clear only a specific scope

#### Configurable Encryption
- **New `KSafeConfig` data class** for encryption customization
- Configurable AES key size: 128-bit or 256-bit (default)
  ```kotlin
  // Default (AES-256)
  val ksafe = KSafe(context)

  // Custom key size (AES-128)
  val ksafe128 = KSafe(context, config = KSafeConfig(keySize = 128))
  ```

### Changed
- **iOS thread safety improvements** - Biometric callbacks now always execute on Main thread
- **License consistency** - Fixed Maven POM metadata to use Apache-2.0 (matching repository)

---

## [1.2.0] - 2025-01-15

### Added
- **Hybrid "Hot Cache" Architecture** - Zero-latency UI reads with async preloading
- **Memory Security Policy** - Choose between `ENCRYPTED` (max security) or `PLAIN_TEXT` (max performance)
- **Nullable value support** - Correctly store and retrieve `null` values
- **Multiple KSafe instances** - Create separate instances with different file names
- **JVM/Desktop support** - Full support alongside Android and iOS
- **KSafeConfig** - Configurable encryption parameters (key size)
- **Lazy loading option** - Defer data loading until first access

### Changed
- `getDirect()` now performs atomic memory lookup (O(1)) instead of blocking disk read
- `putDirect()` uses optimistic updates - immediate cache update with background persistence
- Eager preloading on initialization by default (use `lazyLoad = true` to defer)

---

## [1.1.0] - 2024-12-01

### Added
- Initial release with encrypted persistence
- Property delegation (`by ksafe(defaultValue)`)
- Compose state support (`by ksafe.mutableStateOf(defaultValue)`)
- Android Keystore and iOS Keychain integration
- Suspend and Direct APIs





:tada: KSafe 1.8.0 is out — Kotlin Multiplatform key-value persistence for Android / iOS / JVM / WASM.

If you haven't seen it: think DataStore, but with a hot in-memory cache in front. That gives you a fully synchronous API (getDirect / putDirect) when you don't want
coroutines, plus suspend get / put when you do. AES-256-GCM with hardware-backed keys by default (Keystore / Keychain / StrongBox / Secure Enclave) — or opt out with a     
single parameter and use KSafe as a fast general-purpose persistence library for plain data.

var token   by ksafe("")                                                           // plain delegate                                                                        
var counter by ksafe.mutableStateOf(0)                                             // Compose state                                                                         
val user:  StateFlow<User>           by ksafe.asStateFlow(User(), scope)           // read-only flow                                                                        
val state: MutableStateFlow<UiState> by ksafe.asMutableStateFlow(UiState(), scope) // read/write flow

What's new in 1.8.0:

• asMutableStateFlow — drop-in for the classic _state / state pattern, persisted + encrypted transparently:                                                                 
private val _state by ksafe.asMutableStateFlow(UiState(), viewModelScope)
val state = _state.asStateFlow()                                                                                                                                            
.update { }, .value = …, compareAndSet all behave exactly as you'd expect — persistence is invisible, and it survives process death.

• getOrCreateSecret("main.db") — one line to get a 256-bit passphrase for Room / SQLCipher / SQLDelight (or an API signing key). Generated once, stored hardware-isolated   
(StrongBox on Android, Secure Enclave on iOS). No more "check if exists, else create and save" boilerplate.

• secureRandomBytes(16) — cryptographically secure random bytes with one API across every target.

• Cross-screen Compose sync via ksafe.mutableStateOf(scope = viewModelScope) — a write in one ViewModel auto-reflects in another.

GitHub: https://github.com/ioannisa/KSafe                                                                                                                                   
Changelog: https://github.com/ioannisa/KSafe/blob/main/CHANGELOG.md