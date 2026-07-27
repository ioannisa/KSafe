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

# Android — on-device instrumented test (source set androidDeviceTest,
# AGP 9 KMP plugin), real Keystore, needs a device or emulator
./gradlew :ksafe:connectedAndroidDeviceTest --tests "*.AndroidEncryptionProofTest"
```

### What the test asserts (reference)

The sentinel is the high-entropy string `KSAFE_PLAINTEXT_PROOF_SENTINEL_XYZABC_1234567890` (macOS uses its own constant, `KSAFE_PLAINTEXT_PROOF_SENTINEL_MACOS_QWERTY9876543210`). After an encrypted `put(KEY, SENTINEL)`:

- **Android / JVM / iOS / macOS** — the `.preferences_pb` file under the app's data directory (a temp directory for the macOS test) is read byte-for-byte. A linear byte-scan for the sentinel's UTF-8 bytes must return `false`.
- **Kotlin/WASM + Kotlin/JS** — every `localStorage` value under the instance's `ksafe.<appNamespace@><fileName>:` prefix is read and checked. None may contain the sentinel.

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
- `__ksafe_meta_<key>__` → compact JSON like `{"v":2,"p":"DEFAULT"}` (add `,"u":"unlocked"` if `requireUnlockedDevice = true`). The `"v"` field is the envelope version: `"v":1` is the pre-2.x legacy per-entry-alias form (still carried by entries never rewritten); `"v":2` is the shared-master-key envelope used by 2.0–2.2.x and by an un-rotated 3.0.0 generation-1 store; `"v":3` appears once a store has been rotated (`KSafe.rotateKeys()`, generation ≥ 2) and adds a `"g":<generation>` field plus an authenticated envelope binding the ciphertext to the store, key, tier, unlock policy, and generation. A rotated store is expected to contain a **mix** of `"v":2`/`"v":3` entries — older-generation entries stay fully readable until the next rotation rewrites them. See [KEY_ROTATION.md](KEY_ROTATION.md).
- No raw/unwrapped AES key material. The master key (TEE KEK) is non-exportable in the Android Keystore. On the relaxed DEFAULT tier a KEK-wrapped (AES-GCM-encrypted) software DEK is persisted in DataStore under the reserved `__ksafe____DEK____` entry — unusable without the in-Keystore KEK; StrongBox / `requireUnlockedDevice` entries keep no DEK in DataStore at all. After a rotation you will also see `__ksafe____DEK____@<alias>` entries: the base alias keeps the historical fixed key so existing installs upgrade with no migration, and every other alias appends itself after an `@` (`WrappedDekStore.recordKeyFor`). They are wrapped DEKs exactly like the base one, not leaked key material.

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

protoc --decode_raw < ~/.eu_anifantakis_ksafe/eu_anifantakis_ksafe_datastore.preferences_pb
# or:
xxd ~/.eu_anifantakis_ksafe/eu_anifantakis_ksafe_datastore.preferences_pb | less
```

Note: the encryption **key lives in the host OS secret store** — Windows DPAPI, the macOS login Keychain, or the Linux Secret Service / libsecret keyring. The DataStore file holds only ciphertext. When no OS store is reachable, KSafe degrades to a software key vault (`effectiveLevel = SOFTWARE`, note `jvm_os_vault_unavailable`); this is a weaker-but-working fallback, so `KSafe.protectionInfo.isEncryptionOperational` stays `true`. That preflight is `false` only when an OS vault *exists* but is unreachable at startup (a locked Keychain/keyring, headless) — note `jvm_os_vault_degraded`, where KSafe fails closed and encrypted ops throw rather than silently downgrading. See [JVM_PROTECTION.md](JVM_PROTECTION.md) for the full threat model, the trimmed-distributable case, and the self-test, and [PROTECTION_INFO.md](PROTECTION_INFO.md) for `isEncryptionOperational`.

### 2e. Kotlin/WASM + Kotlin/JS (Browser)

Both targets use the exact same `localStorage` layout. In DevTools:

1. **F12** → *Application* tab → *Storage* → *Local Storage* → select your app's origin.
2. Filter rows starting with `ksafe.`.

Or, quicker, from the DevTools *Console*:

```javascript
Object.entries(localStorage)
  .filter(([k]) => k.startsWith('ksafe.'))
  .forEach(([k, v]) => console.log(k, '=', v));
```

You will see (prefix is `ksafe.<appNamespace@><fileName>:`, e.g. `ksafe.vault:`):

- `ksafe.<fileName>:__ksafe_value_<key>` → Base64 ciphertext for encrypted writes, raw string for plain writes.
- `ksafe.<fileName>:__ksafe_meta_<key>__` → JSON metadata.
- **No AES key appears in `localStorage`.** The key is a **non-extractable** WebCrypto `CryptoKey` (`extractable = false`) persisted in **IndexedDB** — the raw key bytes are never exposed to JS and cannot be exfiltrated even with DOM/console access. A lingering row under the old `ksafe_<fileName>_` legacy prefix (from a pre-appNamespace install) is migrated forward on first access — for a unique un-namespaced store the old row is then moved (deleted), but for the shared/default store or an appNamespace migration it is a one-time, marker-gated non-destructive copy that leaves the source in place so co-existing stores/namespaces are not broken. Net: ciphertext and its key no longer live side by side; an attacker with DOM access can *use* the key via SubtleCrypto but cannot read it out. See the `Kotlin/WASM` and `Kotlin/JS` rows in [SECURITY_MODEL.md](SECURITY_MODEL.md).

---

## 3. Caveat: what the proof tests do NOT prove

- They do not exercise the real `AppleKeychainEncryption` or `WebSoftwareEncryption` paths. The Simulator test runner has no Keychain entitlement (it hits error -34018 and would fall back to `FileSimulatorFallbackKeyStore`), so the proof test injects `FakeEncryption`; the web test likewise uses `FakeEncryption` to avoid `runTest` vs. WebCrypto-async issues. Real-crypto coverage for those engines lives in:
  - `ksafe/src/iosTest/.../IosKeychainEncryptionTest.kt` (verifies real-Keychain error handling)
  - `ksafe/src/iosTest/.../IosKeychainEncryptionLeakTest.kt` (real Keychain allocations + autorelease pool behavior)
  - The on-device harness under `ios-device-test/` (`run-xctest.sh` = curated Swift XCTest, `run-full-suite.sh` = full `kotlin.test` via a signed `.app` with real device entitlements; see `ios-device-test/README.md`)
  - The `WebInteropSmokeTest` (exercises real `crypto.getRandomValues()` on both web targets)
  - `ksafe/src/webTest/.../WebKeyStoreIntegrationTest.kt` — real WebCrypto **SubtleCrypto** + a non-extractable `CryptoKey` in IndexedDB, cross-instance reload, and the legacy `localStorage` → IndexedDB migration, run on both `jsBrowserTest` and `wasmJsBrowserTest`
- They do not assert on ciphertext *quality* (the production engines use AES-256-GCM from `javax.crypto` / Android Keystore / CryptoKit / WebCrypto — four widely-audited implementations). The proof is specifically about *plumbing*: "does KSafe route your write through the encryption engine, or did a refactor silently bypass it?"

The combination of the plumbing tests here, the engine-specific tests, and the manual inspection commands is what gives the end-to-end guarantee.
