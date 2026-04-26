# Encryption Proof

How to verify — and how KSafe's own test suite verifies — that data written through the encrypted path never lands in storage as plaintext. Two layers:

1. **Automated tests** (`*EncryptionProofTest`) that run in CI and assert "no plaintext in the raw storage file / `localStorage` value".
2. **Manual inspection** commands for each platform so you can see the ciphertext yourself.

---

## 1. Automated proof tests

Each platform has a pair of tests:

| Assertion | What it proves |
|---|---|
| Encrypted `put()` → raw storage does **not** contain the plaintext sentinel | Encryption is actually happening on the write path |
| `put(mode = KSafeWriteMode.Plain)` → raw storage **does** contain the sentinel verbatim | The negative assertion above is meaningful (not passing vacuously because the file is empty) |

Both tests also round-trip through `get()` to confirm the written value is reversible.

### Running the tests

```bash
# JVM — uses the production JvmSoftwareEncryption (AES-256-GCM)
./gradlew :ksafe:jvmTest --tests "*.JvmEncryptionProofTest"

# iOS Simulator — uses FakeEncryption because the test runner lacks
# Keychain entitlements (see IosKeychainEncryptionTest for the real-Keychain
# error-path coverage). Still proves the write plumbing never routes
# plaintext to disk.
./gradlew :ksafe:iosSimulatorArm64Test --tests "*.IosEncryptionProofTest"

# Kotlin/WASM — runs in headless Chrome via Karma
./gradlew :ksafe:wasmJsBrowserTest --tests "*.WebEncryptionProofTest"

# Kotlin/JS — same test class, other target
./gradlew :ksafe:jsBrowserTest --tests "*.WebEncryptionProofTest"

# Android — instrumented, real Keystore, needs a device or emulator
./gradlew :ksafe:connectedDebugAndroidTest --tests "*.AndroidEncryptionProofTest"
```

### What the test asserts (reference)

The sentinel is the high-entropy string `KSAFE_PLAINTEXT_PROOF_SENTINEL_XYZABC_1234567890`. After an encrypted `put(KEY, SENTINEL)`:

- **Android / JVM / iOS** — the `.preferences_pb` file under the app's data directory is read byte-for-byte. A linear byte-scan for the sentinel's UTF-8 bytes must return `false`.
- **Kotlin/WASM + Kotlin/JS** — every `localStorage` value under the instance's `ksafe_<fileName>_` prefix is read and checked. None may contain the sentinel.

The counter-test exercises `KSafeWriteMode.Plain` and flips the assertion — the sentinel *must* appear. If a future refactor accidentally bypassed encryption, the first test would pass but the second's pair would now mismatch the storage shape and you'd see a failure.

---

## 2. Manual inspection

Reproducing what the proof tests do, by hand. Useful for blog posts, security reviews, and eyeballing the actual ciphertext shape.

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

You will see:

- `__ksafe_value_<key>` → a Base64 string (ciphertext) for encrypted writes, or the raw typed value for `KSafeWriteMode.Plain` writes.
- `__ksafe_meta_<key>__` → compact JSON like `{"v":1,"p":"DEFAULT"}` (add `,"u":"unlocked"` if `requireUnlockedDevice = true`).
- No AES key material. The keys live in the Android Keystore, not in DataStore.

### 2b. iOS (Simulator)

```bash
# Path to the booted simulator's app data directory:
APP_DATA="$(xcrun simctl get_app_container booted <bundle-id> data)"

# List KSafe's preferences file(s) — KSafe 2.0 stores in Application Support
# (pre-2.0 used Documents and is auto-migrated on first 2.0 launch):
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
#     (plus a key file per encryption alias, software-backed)

protoc --decode_raw < ~/.eu_anifantakis_ksafe/eu_anifantakis_ksafe_datastore.preferences_pb
# or:
xxd ~/.eu_anifantakis_ksafe/eu_anifantakis_ksafe_datastore.preferences_pb | less
```

Note: unlike the mobile targets, the encryption **key** lives in `~/.eu_anifantakis_ksafe/` as a separate file (software-backed — OS file permissions are the perimeter). That directory should be `0700`. Anyone with read access to your home directory can decrypt the ciphertext. For higher-assurance Desktop scenarios, pair KSafe with an OS keyring or TPM.

### 2e. Kotlin/WASM + Kotlin/JS (Browser)

Both targets use the exact same `localStorage` layout. In DevTools:

1. **F12** → *Application* tab → *Storage* → *Local Storage* → select your app's origin.
2. Filter rows starting with `ksafe_`.

Or, quicker, from the DevTools *Console*:

```javascript
Object.entries(localStorage)
  .filter(([k]) => k.startsWith('ksafe_'))
  .forEach(([k, v]) => console.log(k, '=', v));
```

You will see:

- `ksafe_<fileName>___ksafe_value_<key>` → Base64 ciphertext for encrypted writes, raw string for plain writes.
- `ksafe_<fileName>___ksafe_meta_<key>__` → JSON metadata.
- `ksafe_<fileName>_ksafe_key_<alias>` → the raw AES key, Base64. **This is the browser's storage-tier limitation: WebCrypto keys are software-held in the same `localStorage` origin** — the ciphertext and its key live side by side. Treat WASM/JS persistence as confidentiality-against-other-origins and accidental-log-exposure, not against an attacker with DOM access. See the `Kotlin/WASM` and `Kotlin/JS` rows in [docs/SECURITY.md](SECURITY.md).

---

## 3. Caveat: what the proof tests do NOT prove

- They do not exercise the real `IosKeychainEncryption` or `WebCrypto` paths. The iOS test env has no Keychain entitlement; the web test uses `FakeEncryption` to avoid `runTest` vs. WebCrypto-async issues. Real-crypto coverage for those engines lives in:
  - `ksafe/src/iosTest/.../IosKeychainEncryptionTest.kt` (verifies real-Keychain error handling)
  - `ksafe/src/iosTest/.../IosKeychainEncryptionLeakTest.kt` (real Keychain allocations + autorelease pool behavior)
  - Manual runs through the `iosTestApp` sample with real device entitlements
  - The `WebInteropSmokeTest` (exercises real `crypto.getRandomValues()` on both web targets)
- They do not assert on ciphertext *quality* (the production engines use AES-256-GCM from `javax.crypto` / Android Keystore / CryptoKit / WebCrypto — four widely-audited implementations). The proof is specifically about *plumbing*: "does KSafe route your write through the encryption engine, or did a refactor silently bypass it?"

The combination of the plumbing tests here, the engine-specific tests, and the manual inspection commands is what gives the end-to-end guarantee.
