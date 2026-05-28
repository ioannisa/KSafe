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

`wasmJsBrowserTest` and `jsBrowserTest` share `KSafeTest` and friends through the intermediate `webTest` source set, plus a small `WebInteropSmokeTest` that asserts per-target actuals (localStorage, `currentTimeMillisWeb`, `secureRandomBytes`). Headless Chrome is launched by Karma — no manual browser setup required.

iOS Simulator uses real Keychain APIs but software-backed; real devices store Keychain data in a hardware-encrypted container protected by the device passcode.

### Useful flags

| Flag | Effect |
|---|---|
| `-Pksafe.stressScale=<0.01..1.0>` | Scales down the magnitudes in `JvmKSafeTest`'s concurrency-stress tests so the full suite drains on a 2-vCPU CI runner. Default (absent) = full local intensity. |
| `-PksafeTestLog` | Logs each test as it starts (used by the nightly full-suite job). Off by default. |
| `KSAFE_KEYVAULT_IT=1` (env) | The keyvault integration CI jobs set this. When present, `jvmTest` does NOT force the software fallback, so the real OS secret store (DPAPI / Keychain / Secret Service) is exercised and `JvmKeyVaultIntegrationTest` activates. Local dev runs leave it unset to avoid Keychain prompts / keyring pollution. |
| `CI=true` (env) | GitHub Actions and most CI providers set this. Enables flaky-test retry (max 2 retries per test, 8 max total) — runner-variance flakes pass on retry and are surfaced in the report, real regressions still fail. Locally retries are off. |

### Test data isolation

The JVM test JVM forks per class and overrides `user.home` to `build/ksafe-test-home/` so the suite can never read or delete the real `~/.eu_anifantakis_ksafe` directory. The `doFirst` block in `:ksafe:jvmTest` recursively deletes the isolated dir before each run; nothing outside `build/` is ever touched.

### CI parity guards

- **`verifyWebTestParity`** — fails the build if Kotlin/JS registered fewer tests than wasmJs for the same shared `webTest` class. The legacy Kotlin/JS runner silently drops trailing `@Test` methods on oversized classes; this guard makes the silent drop loud. Split a flagged class into smaller focused classes (see `KSafeNullableDefaultTest` for the pattern).
