# Encryption Proof

How to verify — and how KSafe's own test suite verifies — that data written through the encrypted path never lands in storage as plaintext. Two layers:

1. **Automated tests** (`*EncryptionProofTest`) that run in CI and assert "no plaintext in the raw storage file / `localStorage` value".
2. **Manual inspection** commands for each platform so you can see the ciphertext yourself.

Both layers turn on one idea: write a value you can recognise again, then search the raw stored bytes for it. The tests write a **sentinel** — a fixed, high-entropy string, picked so it cannot turn up by accident in ciphertext or in the storage format's own framing. Finding the sentinel in the raw bytes means the value reached storage in the clear.

---

## 1. Automated proof tests

Every platform has the same pair of tests:

| Assertion | What it proves |
|---|---|
| Encrypted `put()` → raw storage does **not** contain the plaintext sentinel | Encryption is actually happening on the write path |
| `put(mode = KSafeWriteMode.Plain)` → raw storage **does** contain the sentinel verbatim | That the negative assertion above is worth something. An empty file contains no sentinel either, so without this test a write path that had silently stopped writing would still look like a pass. |

Both tests also round-trip through `get()` to confirm the written value is reversible. The web class adds a third test, `negativeAssertionIsNotVacuous`, which checks that the byte-scan helper still finds a string it should find and misses one it should not — so a broken helper cannot make the other two pass silently.

### Running the tests

```bash
# JVM — uses the production JvmSoftwareEncryption (AES-256-GCM)
./gradlew :ksafe:jvmTest --tests "*.JvmEncryptionProofTest"

# iOS Simulator — injects FakeEncryption because the test runner lacks
# Keychain entitlements (an entitlement-less Simulator hits Keychain
# error -34018 and falls back to FileSimulatorFallbackKeyStore for real ops;
# see IosKeychainEncryptionTest for real-Keychain error-path coverage).
# Still proves the write plumbing never routes plaintext to disk.
./gradlew :ksafe:iosSimulatorArm64Test --tests "*.IosEncryptionProofTest"

# macOS — same plumbing proof, own sentinel constant, temp directory
./gradlew :ksafe:macosArm64Test --tests "*.MacosEncryptionProofTest"

# Kotlin/WASM — runs in headless Chrome via Karma
./gradlew :ksafe:wasmJsBrowserTest --tests "*.WebEncryptionProofTest"

# Kotlin/JS — same test class, other target
./gradlew :ksafe:jsBrowserTest --tests "*.WebEncryptionProofTest"

# Android — instrumented test on a device or emulator (source set
# androidDeviceTest, AGP 9 KMP plugin). Runs against the real Android
# Keystore API; on an emulator that Keystore is software-backed, so only a
# physical device exercises the hardware-backed one.
./gradlew :ksafe:connectedAndroidDeviceTest --tests "*.AndroidEncryptionProofTest"
```

These are the proof tests only. [TESTING.md](TESTING.md) covers the full suites, the useful Gradle flags, and the on-device iOS harness.

### What the test asserts (reference)

Two storage backends are involved, so two shapes of "raw bytes":

- On **Android, iOS, macOS and the JVM**, KSafe persists through DataStore-Preferences — a Jetpack key/value store that writes one binary file per store, named `<store>.preferences_pb`. That file is encoded as protobuf, a compact binary format, and `protoc --decode_raw` prints the key/value pairs inside it without needing a schema (`brew install protobuf`).
- On the **two web targets** there is no file. Rows go into the browser's `localStorage`, the origin-scoped string-to-string map you can read in DevTools.

The sentinel is the high-entropy string `KSAFE_PLAINTEXT_PROOF_SENTINEL_XYZABC_1234567890`; the macOS test uses its own, `KSAFE_PLAINTEXT_PROOF_SENTINEL_MACOS_QWERTY9876543210`. After an encrypted `put(KEY, SENTINEL)`:

- **Android / JVM / iOS / macOS** — the test reads the store's `.preferences_pb` file byte for byte and scans it for the sentinel's UTF-8 bytes. That scan must come back empty. Android reads `filesDir/datastore/`, iOS reads the Simulator container's Application Support directory, macOS reads a temp directory the test creates, and the JVM reads `<user.home>/.eu_anifantakis_ksafe/` — with `user.home` pointed at `ksafe/build/ksafe-test-home` for the run, so the suite can never touch a real store.
- **Kotlin/WASM + Kotlin/JS** — every `localStorage` value under this instance's prefix is read and checked. None may contain the sentinel, and the test also asserts that a value entry was actually written, so an instance that persisted nothing cannot pass.

The counter-test writes with `KSafeWriteMode.Plain` and flips the assertion — the sentinel *must* appear, verbatim. It is there because the negative assertion alone proves too little: if a refactor broke the write path so that nothing reached storage, an empty file would contain no sentinel either and the first test would pass for the wrong reason. The counter-test fails in that case. A refactor that bypassed encryption fails the first test directly.

---

## 2. Manual inspection

Reproducing what the proof tests do, by hand. Useful for blog posts, security reviews, and eyeballing the actual ciphertext shape.

### What lands on disk

Every platform stores the same three kinds of record under the same names. These are the records you will see in a protobuf dump or a `localStorage` listing, whichever platform you are on; the per-platform sections below add what each platform keeps beside them.

| Record | Holds |
|---|---|
| `__ksafe_value_<key>` | The value. A Base64 string — the ciphertext — for an encrypted write. For a `KSafeWriteMode.Plain` write, the value in the clear: in a `.preferences_pb` file a number or a boolean keeps its own type, while `localStorage` holds everything as text. |
| `__ksafe_meta_<key>__` | Compact JSON saying how to read that value back. Never secret. |
| `__ksafe_keygen__` | Plaintext JSON holding the store's key generation and rotation state, e.g. `{"g":2,"ts":1756000000000,"r":0}`. Written by `rotateKeys()`, and once at startup under a `MaxAge` rotation policy. A store that has never rotated and runs no `MaxAge` policy does not have it. |

A metadata record looks like `{"v":2,"p":"DEFAULT"}`. Its fields:

- `"p"` — the key tier the entry was written under: `DEFAULT`, `HARDWARE_ISOLATED`, or `NONE` for a `Plain` write.
- `"u":"unlocked"` — present only when the entry was written with `requireUnlockedDevice = true`. The two web targets drop that request before writing, so the field never appears in `localStorage`.
- `"v"` — the entry's *envelope version*: which shape of ciphertext-plus-metadata this entry is, so a newer KSafe can still read what an older one wrote. `2` for an entry written at key generation 1, `3` for one written at generation 2 or higher.
- `"g":<n>` — the key generation, written only from generation 2 up. Its absence means generation 1.
- `"sa":1` — present only on a `HARDWARE_ISOLATED` entry that also asked for `requireUnlockedDevice = true`. It records that this entry's key sits under a separate, stricter alias, so a later read looks the key up under the right name.

A *generation* is one lifetime of the store's key material; `KSafe.rotateKeys()` mints the next one and re-encrypts under it. `"v":2` is what every release from 2.0 on writes at generation 1 — a `DEFAULT` entry under the store's shared master key, a `HARDWARE_ISOLATED` entry under its own per-entry key. A `"v":3` envelope keeps that routing and additionally binds each ciphertext to the store it belongs to, the key name it was written under, its tier, its unlock policy and its generation. That binding is what makes tampering with a `"v":3` entry fail closed: a ciphertext copied onto another entry, or an entry whose `"p"` or `"u"` was edited in the file, no longer decrypts, and the read returns your default instead of the wrong value.

A completed rotation rewrites every encrypted entry, so afterwards they all read `"v":3`. An encrypted entry still on `"v":2` means the pass was interrupted, or counted that entry under `skipped`/`failed` in its `KSafeRotationResult`; it stays readable under its recorded generation until a later pass rewrites it. `Plain` entries keep `{"v":2,"p":"NONE"}` forever — rotation never touches them, because there is no key to rotate. See [KEY_ROTATION.md](KEY_ROTATION.md).

Older stores use older names. 1.7.x and 1.8.x wrote `"v":1`, meaning a per-entry key derived from the user key. Anything older than 1.7.0 has no metadata record at all: the value sits under `encrypted_<key>` and the tier under `__ksafe_prot_<key>__` as a bare literal such as `DEFAULT`. KSafe reads both shapes, treats them as version 1, and moves each entry onto the current names the first time it is rewritten.

### 2a. Android

```bash
# Assuming a debug build of your app has already written to KSafe:
adb shell run-as <your-package> ls files/datastore/
# Expected: eu_anifantakis_ksafe_datastore.preferences_pb
#     (plus eu_anifantakis_ksafe_datastore_<fileName>.preferences_pb per named instance)

# Dump the raw file:
adb shell run-as <your-package> cat files/datastore/eu_anifantakis_ksafe_datastore.preferences_pb > dump.pb

# Human-readable protobuf structure (install: brew install protobuf):
protoc --decode_raw < dump.pb

# Or just hex-dump:
xxd dump.pb | less
```

You will see the records described in [What lands on disk](#what-lands-on-disk), plus what is specific to Android's key custody:

- **No raw AES key.** Android holds the master key inside the Keystore, backed by the phone's TEE (Trusted Execution Environment — a separate secure processor). No process can read that key out, KSafe included; code can only ask the Keystore to use it.
- On the `DEFAULT` tier KSafe keeps a second, ordinary AES key for the per-value work — a data key — and stores it in DataStore encrypted under the Keystore key, in the reserved `__ksafe____DEK____` entry. That record is useless without the Keystore key, and it exists only to keep per-value encryption off the slow Keystore round-trip. `HARDWARE_ISOLATED` entries — which ask for StrongBox, a separate tamper-resistant chip, and fall back to the TEE on a device that has none — and `requireUnlockedDevice` entries keep no such record at all: every operation goes through the Keystore.
- After a rotation you will also see `__ksafe____DEK____@<alias>` entries, one for each key generation whose master key the store still holds (a finished rotation deletes the masters nothing references any more, and their data-key records with them). The base name stays as it is so existing installs need no migration, and every later generation appends its alias after an `@`. These are wrapped data keys exactly like the base one, not leaked key material.

### 2b. iOS (Simulator)

```bash
# Path to the booted simulator's app data directory:
APP_DATA="$(xcrun simctl get_app_container booted <bundle-id> data)"

# List KSafe's preferences file(s). Since 2.0 KSafe stores here. A file left
# in Documents by an older version is moved across the first time this store
# is opened and no Application Support file exists yet:
ls "$APP_DATA/Library/Application Support/"
# Expected: eu_anifantakis_ksafe_datastore.preferences_pb

# Decode the protobuf:
protoc --decode_raw < "$APP_DATA/Library/Application Support/eu_anifantakis_ksafe_datastore.preferences_pb"
```

Same layout as Android — `__ksafe_value_<key>` (Base64 ciphertext or raw), `__ksafe_meta_<key>__` (JSON). The AES keys live in the iOS Keychain.

### 2c. iOS (Real Device)

Xcode → *Window* → *Devices and Simulators* → select device → select app in the *Installed Apps* list → ⚙️ → *Download Container…* → save the `.xcappdata` bundle. Right-click it in Finder → *Show Package Contents* → `AppData/Library/Application Support/eu_anifantakis_ksafe_datastore.preferences_pb`.

### 2d. JVM / Desktop

```bash
# Default location (outside the project):
ls ~/.eu_anifantakis_ksafe/
# Expected: eu_anifantakis_ksafe_datastore.preferences_pb
#     (plus eu_anifantakis_ksafe_datastore_<fileName>.preferences_pb per named instance)

protoc --decode_raw < ~/.eu_anifantakis_ksafe/eu_anifantakis_ksafe_datastore.preferences_pb
# or:
xxd ~/.eu_anifantakis_ksafe/eu_anifantakis_ksafe_datastore.preferences_pb | less
```

Two settings move the files:

- `baseDir` on the `KSafe(...)` call replaces `~/.eu_anifantakis_ksafe` outright.
- `KSafeConfig.appNamespace` adds a subdirectory under it, so look in `~/.eu_anifantakis_ksafe/<namespace>/`.

And one runtime changes the file names. DataStore's protobuf needs `sun.misc.Unsafe`, an internal JDK class that lives in the `jdk.unsupported` module — and a desktop app shipped with a jlink-trimmed runtime (a Java runtime cut down to the modules the app declares) may not include that module. Without it KSafe persists to a software-encrypted JSON file instead and logs a one-time notice; the store is then `eu_anifantakis_ksafe_datastore[_<fileName>].ksafe.json` and its keys are in `eu_anifantakis_ksafe_datastore[_<fileName>].ksafe-keys.json` beside it. An encrypted value in that JSON file is the same Base64 ciphertext as in a `.preferences_pb`. The JSON backend never uses an OS secret store: its keys always sit in that sidecar, Base64, in software custody.

On the normal DataStore backend, where the key lives depends on what the machine offers, and that is worth checking before you draw conclusions from a dump:

- **An OS secret store is reachable** — Windows DPAPI, the macOS login Keychain, or the Linux Secret Service / libsecret keyring holds the key, and the store file holds only ciphertext.
- **No OS store exists** — KSafe degrades to a software key vault: `KSafe.protectionInfo.effectiveLevel` reads `SOFTWARE` and `notes` carries `jvm_os_vault_unavailable`. This is weaker but still working, so `KSafe.protectionInfo.isEncryptionOperational` — a startup check you can read before trusting the store — stays `true`. The keys are then in the store file itself, Base64, under raw names starting with `ksafe_key_`. Nothing but the directory's owner-only permissions (0700 on POSIX) protects them.
- **An OS store exists but is unreachable** — a locked Keychain or keyring, or a headless session. `notes` carries `jvm_os_vault_degraded` and `isEncryptionOperational` is `false`: KSafe fails closed and encrypted operations throw rather than quietly writing under a weaker key.

See [JVM_PROTECTION.md](JVM_PROTECTION.md) for the full threat model, the jlink-trimmed-runtime case, and the vault self-test, and [PROTECTION_INFO.md](PROTECTION_INFO.md) for `isEncryptionOperational`.

### 2e. Kotlin/WASM + Kotlin/JS (Browser)

Both targets use the exact same `localStorage` layout. In DevTools:

1. **F12** → *Application* tab → *Storage* → *Local Storage* → select your app's origin.
2. Filter rows starting with `ksafe`.

Or, quicker, from the DevTools *Console*:

```javascript
Object.entries(localStorage)
  .filter(([k]) => k.startsWith('ksafe'))
  .forEach(([k, v]) => console.log(k, '=', v));
```

Filter on `ksafe`, not `ksafe.` — a store carried over from an older version still has rows under the older `ksafe_<fileName>_` prefix, and the dotted filter would hide them.

Every data row of the current layout starts with the same prefix: `ksafe.`, then the app namespace and an `@` if `KSafeConfig.appNamespace` is set, then the store's `fileName`, then `:`. So `KSafe(fileName = "vault")` gives `ksafe.vault:`, `KSafe()` gives `ksafe.:`, and `KSafe("vault")` with `appNamespace = "myapp"` gives `ksafe.myapp@vault:`. Under that prefix you will see:

- `<prefix>__ksafe_value_<key>` → Base64 ciphertext for an encrypted write, the raw string for a plain write.
- `<prefix>__ksafe_meta_<key>__` → the JSON metadata described in [What lands on disk](#what-lands-on-disk).
- **No AES key.** The key is a WebCrypto `CryptoKey` created with `extractable = false` and kept in **IndexedDB**, the browser's other client-side database. Its raw bytes never reach JavaScript, so code with full DOM and console access can ask SubtleCrypto to *use* the key but cannot read it out. Ciphertext and key no longer sit side by side.

The listing also shows a few rows named `ksafe.__…__`, such as `ksafe.__legacymigrated__.…`. Those are one-time migration bookkeeping and each holds the string `1` — no data, no key material. They sit outside the store's own prefix on purpose, so that a `clearAll()` cannot erase them and let a migration run again and re-seed data you just wiped.

A store upgraded from an older version shows its age. Two things migrate, on different schedules and from different releases:

- **The key.** Before 2.1.0 the AES key was a raw Base64 string in `localStorage`, under `ksafe_<fileName>_ksafe_key_<alias>` (`ksafe_default_…` for the unnamed store). The first access imports it into IndexedDB as a non-extractable key and deletes the `localStorage` row.
- **The data rows.** The flat `ksafe_<fileName>_` prefix was the live data layout until 2.1.2, and the `<namespace>@` segment was added in 2.2.1. Carrying those rows forward is deliberately more cautious: the copy runs once, gated by a marker, and the source is deleted only when this store is the sole owner of that older prefix. `KSafe()` and `KSafe("default")` share the pre-2.1.2 prefix, and an `appNamespace` migration leaves co-existing namespaces reading the same source, so in those cases the old rows are copied and left in place rather than moved.

See the `Kotlin/WASM` and `Kotlin/JS` rows in [SECURITY_MODEL.md](SECURITY_MODEL.md).

### 2f. macOS (native)

The `macosArm64` / `macosX64` targets share the Apple factory with iOS, so the layout is the same — the file is `eu_anifantakis_ksafe_datastore[_<fileName>].preferences_pb` under `NSApplicationSupportDirectory`, and the AES keys live in the Keychain, as they do on iOS. For an unsandboxed app that directory is `~/Library/Application Support/`; a sandboxed one resolves to its own container. A `directory` passed to `KSafe(...)` replaces it.

```bash
ls ~/Library/Application\ Support/ | grep eu_anifantakis_ksafe
protoc --decode_raw < ~/Library/Application\ Support/eu_anifantakis_ksafe_datastore.preferences_pb
```

This is not the JVM Desktop location. A Compose Desktop app on macOS runs the JVM target and stores under `~/.eu_anifantakis_ksafe/` instead — see [2d. JVM / Desktop](#2d-jvm--desktop).

---

## 3. Caveat: what the proof tests do NOT prove

- They do not exercise the real `AppleKeychainEncryption` or `WebSoftwareEncryption` paths. The Simulator test runner has no Keychain entitlement (it hits error -34018 and would fall back to `FileSimulatorFallbackKeyStore`), so the proof test injects `FakeEncryption`; the web test likewise uses `FakeEncryption` to avoid `runTest` vs. WebCrypto-async issues. `FakeEncryption` is a test engine that transforms bytes with a deterministic, reversible XOR. It is not cryptography and is not meant to be — it is only enough to guarantee that anything that passed through it is no longer the plaintext, which is exactly what the plumbing test measures. Real-crypto coverage for those engines lives in:
  - `ksafe/src/iosTest/.../IosKeychainEncryptionTest.kt` (verifies real-Keychain error handling)
  - `ksafe/src/iosTest/.../IosKeychainEncryptionLeakTest.kt` (real Keychain allocations + autorelease pool behavior)
  - The on-device harness under `ios-device-test/` (`run-xctest.sh` = curated Swift XCTest, `run-full-suite.sh` = full `kotlin.test` via a signed `.app` with real device entitlements; see `ios-device-test/README.md`)
  - The `WebInteropSmokeTest` (exercises real `crypto.getRandomValues()` on both web targets)
  - `ksafe/src/webTest/.../WebKeyStoreIntegrationTest.kt` — real WebCrypto **SubtleCrypto** + a non-extractable `CryptoKey` in IndexedDB, cross-instance reload, and the legacy `localStorage` → IndexedDB migration, run on both `jsBrowserTest` and `wasmJsBrowserTest`
- The JVM proof test runs on real AES-256-GCM, but not on a real key vault. `:ksafe:jvmTest` sets `ksafe.jvm.keyVault=software`, so the key sits in the store file rather than in DPAPI / the login Keychain / the Secret Service — that keeps the suite from prompting for Keychain access on a developer's machine. The OS vaults are covered by the separate integration jobs that set the `KSAFE_KEYVAULT_IT` environment variable; see [TESTING.md](TESTING.md).
- They do not assert on ciphertext *quality* (the production engines use AES-256-GCM from `javax.crypto` / Android Keystore / CryptoKit / WebCrypto — four widely-audited implementations). The proof is specifically about *plumbing*: "does KSafe route your write through the encryption engine, or did a refactor silently bypass it?"

The combination of the plumbing tests here, the engine-specific tests, and the manual inspection commands is what gives the end-to-end guarantee.
