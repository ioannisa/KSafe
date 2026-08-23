# Testing & Development

by [Mark Andrachek](https://github.com/mandrachek)

### Running tests

```bash
# Run every target's test suite and produce an aggregated report
./gradlew :ksafe:allTests

# JVM (the most exercised suite — runs every test in commonTest + jvmTest)
./gradlew :ksafe:jvmTest

# Android — host-side unit tests (Robolectric is NOT used; these are KMP tests
# running on the local JVM, so anything that needs the Android Keystore must
# be in androidDeviceTest, not here).
./gradlew :ksafe:testAndroidHostTest

# Android — instrumented tests on a connected device or emulator
# (the recommended way to exercise the real Android Keystore code path)
./gradlew :ksafe:connectedAndroidDeviceTest

# Apple — iOS Simulator on Apple Silicon
./gradlew :ksafe:iosSimulatorArm64Test
# Apple — native macOS on Apple Silicon
./gradlew :ksafe:macosArm64Test

# Web — headless browser, both targets share commonTest + webTest
./gradlew :ksafe:wasmJsBrowserTest
./gradlew :ksafe:jsBrowserTest

# Filter a single class on any target — append --tests
./gradlew :ksafe:jvmTest --tests "*.KSafeTest"
./gradlew :ksafe:iosSimulatorArm64Test --tests "*.IosKSafeTest"
```

There is **no standalone `commonTest` task** — common-source tests are compiled into every target's test compilation and run by the target's own test task (e.g. `jvmTest`, `iosSimulatorArm64Test`, `wasmJsBrowserTest`).

`wasmJsBrowserTest` and `jsBrowserTest` share `KSafeTest` and friends through the intermediate `webTest` source set, plus a small `WebInteropSmokeTest` that asserts the interop each target has to supply: localStorage and `currentTimeMillisWeb` are per-target actuals, while `secureRandomBytes` is a shared `webMain` actual over a per-target WebCrypto chunk fill. Headless Chrome is launched by Karma — no manual browser setup required.

The Kotlin/Native test binary the Gradle Apple tasks run in the Simulator is unsigned and has no Keychain entitlement, so its first Keychain call returns `-34018` (`errSecMissingEntitlement`) and KSafe transparently falls back to `FileSimulatorFallbackKeyStore`, a sandbox file store (reported `SOFTWARE` in `protectionInfo`). This is a property of the unsigned test runner, not the Simulator itself: a properly-signed Simulator app (with a signing team / Keychain Sharing capability) keeps the real Keychain, which works in the Simulator. Real devices never take this path — they store Keychain data in a hardware-encrypted container protected by the device passcode. To exercise the real hardware path, use the on-device harness below.

### Useful flags

| Flag | Effect |
|---|---|
| `-PksafeStressScale=<0.01..1.0>` | Scales down the magnitudes in `JvmKSafeTest`'s concurrency-stress tests so the full suite drains on a 2-vCPU CI runner (forwarded to the test JVM as the `ksafe.stressScale` system property). Default (absent) = full local intensity. |
| `-PksafeTorture` | Enables `JvmTortureTest` (skipped otherwise). Runs a randomized concurrency-chaos loop against the store. |
| `-PksafeTortureSeconds=<n>` | Wall-clock seconds the torture loop runs. Default 45. |
| `-PksafeTortureSeed=<seed>` | Reproduces a failed torture run from the seed it printed. |
| `-PksafeTestLog` | Logs each test as it starts (used by the nightly full-suite job) so a hung run's log shows the last STARTED test. Off by default. |
| `KSAFE_KEYVAULT_IT=1` (env) | The keyvault integration CI jobs set this. When present, `jvmTest` does NOT force the software fallback, so the real OS secret store (DPAPI / Keychain / Secret Service) is exercised and `JvmKeyVaultIntegrationTest` activates. Local dev runs leave it unset to avoid Keychain prompts / keyring pollution. |
| `CI=true` (env) | GitHub Actions and most CI providers set this. Enables flaky-test retry only on CI (2 retries per test; `maxFailures=8` distinct failing tests aborts retrying so a genuinely broken suite fails fast; `failOnPassedAfterRetry=false` so a flake that passes on retry keeps the build green but is still listed in the report). Locally retries are off — every test must pass first try. |

### Test data isolation

The JVM test JVM forks per class and overrides `user.home` to `build/ksafe-test-home/` so the suite can never read or delete the real `~/.eu_anifantakis_ksafe` directory. The `doFirst` block in `:ksafe:jvmTest` recursively deletes the isolated dir before each run; nothing outside `build/` is ever touched.

### CI parity guards

- **`verifyWebTestParity`** — fails the build if Kotlin/JS registered fewer tests than wasmJs for the same shared `webTest` class. The legacy Kotlin/JS runner silently drops trailing `@Test` methods on oversized classes; this guard makes the silent drop loud. Split a flagged class into smaller focused classes (see `KSafeNullableDefaultTest` for the pattern).

### On-device iOS testing

The Gradle Apple tasks only reach the Simulator, whose Keychain is the `FileSimulatorFallbackKeyStore` sandbox file store. To exercise the real Secure Enclave + Keychain you need a physical iPhone. The `ios-device-test/` harness does that with two scripts:

- **`./run-xctest.sh`** — a curated Swift XCTest target (`Tests/KSafeDeviceTests.swift`) that links the `iosArm64` framework and runs the real-hardware paths through `getOrCreateSecret`: encrypted round-trips across instances, the `HARDWARE_ISOLATED` Secure-Enclave envelope, `rotateKeys`, `clearAll`, `protectionInfo`, `deviceKeyStorages`. Fast, clean pass/fail. (The reified `put`/`get` aren't callable from Swift, so they're covered by the full suite.)
- **`./run-full-suite.sh`** — the entire existing `commonTest` + `iosTest` `kotlin.test` suite. It builds the Kotlin/Native `iosArm64` test binary (`test.kexe`), wraps it in a signed `.app`, installs it with `devicectl`, and captures the runner output — including the reified `put`/`get` round-trips — on real hardware. Run `run-xctest.sh` once first so Xcode provisions the host bundle it reuses.

On a real signed device, four `IosKeychainEncryptionTest` cases written for the no-entitlement Simulator environment `assertFailsWith` that the Keychain throws `-34018`; on-device the Keychain works, so those asserts fail. That is correct device behaviour, not a KSafe bug: `testThrowsOnKeychainErrorInTestEnvironment`, `testDecryptThrowsOnKeychainError`, `testSecureEnclaveThrowsInTestEnvironment`, `testCustomConfigIsAccepted`.

Full setup (Apple team id, device pinning, provisioning) lives in [`ios-device-test/README.md`](../ios-device-test/README.md).

### Other modules

`:ksafe-compose` and `:ksafe-biometrics` ship their own multiplatform suites (`commonTest` plus per-target source sets). Run them the same way as core:

```bash
./gradlew :ksafe-compose:allTests
./gradlew :ksafe-compose:jvmTest
./gradlew :ksafe-biometrics:allTests
./gradlew :ksafe-biometrics:jvmTest
```

### Key rotation

Rotation (`rotateKeys()`, 3.1.0 automatic same-generation crash resume, the bounded persisted next-instance retry budget for normally `skipped` entries—including custom/zero budgets and decrement-before-work—conservative 3.0.0-record adoption, and the `MaxAge` startup policy) is exercised by the JVM suite and, on real hardware, by the on-device iOS harness above (`run-xctest.sh` calls `rotateKeys`). See [`KEY_ROTATION.md`](KEY_ROTATION.md) for what rotation guarantees and how the generation model behaves under crashes and concurrent writes.
