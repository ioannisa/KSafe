# Testing & Development

by [Mark Andrachek](https://github.com/mandrachek)

### Running tests

Everything runs through Gradle from the repository root. What you need depends on the line you run: a JDK for the JVM and Android host tests, Chrome for the browser tests, Xcode on a Mac for the Apple tests, and a connected Android device or emulator for the instrumented tests — the ones that run on the device itself instead of on your machine. If you want a single signal, run `./gradlew :ksafe:jvmTest` — it is the largest suite and needs nothing but a JDK.

KSafe's tests live in *source sets*. A source set is a directory of Kotlin files compiled for one platform or shared by several: `commonTest` holds what must hold everywhere, and each platform adds its own — `jvmTest`, `iosTest`, `macosTest`, `webTest`, `androidDeviceTest`. A target's test task compiles `commonTest` together with that target's own source set and runs both.

```bash
# Every suite this machine can run, with one aggregated report.
# Apple targets need a Mac; the instrumented Android suite has its own task (below).
./gradlew :ksafe:allTests

# JVM — the largest suite: all of commonTest plus jvmTest.
./gradlew :ksafe:jvmTest

# Android — host-side unit tests. They run on your local JVM against stub Android
# classes; KSafe does not use Robolectric (a library that simulates the Android
# framework off-device), so the Android Keystore — the operating-system service
# that holds encryption keys — is not there. :ksafe has no Android host source set
# of its own, so this task runs commonTest. Anything that needs a real Keystore
# belongs in androidDeviceTest.
./gradlew :ksafe:testAndroidHostTest

# Android — instrumented tests on a connected device or emulator. The only way to
# run the Android Keystore code path at all; on an emulator that is the emulated
# Keystore, so hardware-backed key behaviour needs a physical phone.
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

On an emulator, set a lock screen and stop the screen from locking before you run the instrumented suite. KSafe creates keys that require an unlocked device; on API 28 through 34 Android will not create such a key unless a secure lock screen exists, and the key can only be used while the device is unlocked. Without these two calls the emulator quietly takes KSafe's degraded no-lock-screen path, and the failures that follow look like KSafe bugs:

```bash
adb shell locksettings set-pin 1234
adb shell svc power stayon true
```

There is **no standalone `commonTest` task** — common-source tests are compiled into every target's test compilation and run by the target's own test task (e.g. `jvmTest`, `iosSimulatorArm64Test`, `wasmJsBrowserTest`).

`wasmJsBrowserTest` and `jsBrowserTest` share `KSafeTest` and friends through the intermediate `webTest` source set. They also share `WebInteropSmokeTest`, which pins down the small interop layer each target has to supply: `localStorage` and `currentTimeMillisWeb` are per-target `actual`s, while `secureRandomBytes` is one shared `webMain` `actual` looping over a per-target WebCrypto chunk fill. Karma — the runner Kotlin uses for browser targets — launches headless Chrome for you, using the launcher in `ksafe/karma.config.d/01-headless.js`. You need a Chrome on the machine; if Karma cannot find it, point the `CHROME_BIN` environment variable at the binary, which is what the CI jobs do.

The Keychain is Apple's operating-system store for small secrets, and it is where KSafe keeps its encryption keys on iOS and macOS. The Kotlin/Native test binary that `iosSimulatorArm64Test` runs is an unsigned, sandboxed process with no reachable Keychain: its reads and writes come back as failures (`errSecNotAvailable` — the Keychain service does not answer this process). KSafe then refuses the operation rather than minting a replacement key, because a silently replaced key reads back as data loss. `macosArm64Test` is not a Simulator run at all: it is a plain macOS binary on your Mac, and it has the same problem with the login Keychain, where a real call would either fail opaquely or pop an interactive password prompt.

So a green Apple run does not prove Keychain behaviour, because the store suites never reach the Keychain. `IosKSafeTest` and `MacosKSafeTest` pass a `FakeEncryption` engine through the internal `testEngine` constructor parameter, so what they prove is store behaviour. Keychain behaviour is covered separately: `IosKeychainEncryptionTest` drives the real engine and asserts what its own environment can actually deliver, while `IosSimulatorFallbackTest` and `MacosSimulatorFallbackTest` inject a Keychain that always refuses, so the refusal path runs the same way whatever the runner's own environment allows. Real Keychain behaviour, and the Secure Enclave (Apple's separate security chip) with it, is proved only by the on-device harness below.

One related path is worth knowing, because you will meet it if you run a KSafe **app** in the Simulator from Xcode with no signing team. There the Keychain refuses the app with `-34018` (`errSecMissingEntitlement`) — an entitlement is a permission baked into an app's code signature, and without the Keychain entitlement Apple denies the process access. KSafe then substitutes `FileSimulatorFallbackKeyStore`, a key file inside the app's sandbox — the Simulator's own Keychain is itself just a file on the host Mac, so this is the same trust tier. `protectionInfo` — the snapshot KSafe exposes describing where its keys actually live — reports the downgrade honestly: `effectiveLevel = SOFTWARE`, custody `Sandbox file key store (iOS Simulator fallback — Keychain entitlement missing)`, note `apple_keychain_entitlement_missing`. Select a signing team, or add the Keychain Sharing capability, and the app keeps the real Keychain, which works in the Simulator. KSafe only ever builds this fallback when `SecurityChecker.isEmulator()` is true, so it can never engage on macOS or on a real device — and it engages on that one `-34018` status alone, which is why it does not rescue the Gradle test runner described above, whose calls fail with `errSecNotAvailable` instead.

### Where the tests live

| Source set | Runs on | Holds |
|---|---|---|
| `commonTest` | every target's test task | Behaviour that must hold everywhere: the abstract `KSafeTest` base, config and alias invariants, rotation lifecycle and key generations, memory policy, protection info, failure classification. Plus the shared helpers `FakeEncryption.kt`, `StatefulFakeEncryption.kt`, `TestData.kt`, `ByteArraySearch.kt`. |
| `jvmTest` | `jvmTest` | The largest platform set: key custody and the fallback for when the operating system's own secret store is unavailable, app namespaces and carry-forward, write coalescing, `clearAll` and rotation races, the JSON storage fallback, plus the opt-in torture and key-vault integration suites. |
| `appleTest`, `iosTest`, `macosTest` | `iosSimulatorArm64Test`, `macosArm64Test` | Keychain and Secure-Enclave decision logic, the Simulator fallback, storage locations, orphan-sweep classification. No real Keychain round-trip happens in these runners — see the note above. |
| `webTest` | `jsBrowserTest`, `wasmJsBrowserTest` | `localStorage` and IndexedDB behaviour, WebCrypto key handling, namespace and prefix isolation, torn-write ordering, and the interop smoke test. |
| `androidDeviceTest` | `connectedAndroidDeviceTest` | Everything that needs a real Android Keystore: StrongBox (Android's separate security chip), the software data-encryption key that ordinary encrypted entries use (it is itself wrapped by a Keystore key, so per-value crypto runs in user space instead of one Keystore round-trip per value), AAD binding (extra data mixed into the encryption so a value cannot be moved between stores), a device with no lock screen, multi-instance behaviour. |

The per-platform test class usually extends the common one — `class IosKSafeTest : KSafeTest()` — and supplies the `KSafe` instance by overriding `newKSafe(fileName)`. For the reasoning behind which suite lives where, see [TOUR.md](TOUR.md).

### Useful flags

Flags go on the same command line as the task: `./gradlew :ksafe:jvmTest -PksafeTorture -PksafeTortureSeconds=120`, or `KSAFE_KEYVAULT_IT=1 ./gradlew :ksafe:jvmTest --tests '*.JvmKeyVaultIntegrationTest'`.

| Flag | Effect |
|---|---|
| `-PksafeStressScale=<0.01..1.0>` | Shrinks the magnitudes of `JvmKSafeTest`'s concurrency-stress tests, which at full intensity enqueue more concurrent writes than a 2-vCPU CI runner can drain. Reaches the tests as the `ksafe.stressScale` system property, floored so a tiny scale cannot no-op a test. Absent = full local intensity; CI passes `0.05`. |
| `-PksafeTorture` | Runs `JvmTortureTest`, a randomized concurrency-chaos loop against the store. Without it the class reports as skipped, not failed. |
| `-PksafeTortureSeconds=<n>` | Wall-clock seconds the torture loop runs. Default 45. Only has an effect together with `-PksafeTorture`. |
| `-PksafeTortureSeed=<seed>` | Replays a failed torture run. The seed is on the first line the test prints (`KSafe torture: seed=… seconds=… workers=…`). Only has an effect together with `-PksafeTorture`. |
| `-PksafeTestLog` | Logs every test as it starts, passes, skips or fails. The CI full-suite jobs keep it on so a hung run's log names the last test that started and never produced a result. Off by default. |
| `-PksafeTestJdk=<major>` | Launches the test JVMs of every module on that JDK through a Gradle toolchain, while Gradle itself keeps running on the JDK that started it. CI passes `11` to guard the advertised JDK 11 floor; the JDK is downloaded if the machine does not already have it. |
| `KSAFE_KEYVAULT_IT` (env) | Any non-blank value. All three modules' `jvmTest` tasks then stop forcing the software key fallback, so the real OS secret store (Windows DPAPI / macOS Keychain / Linux Secret Service) is exercised and `JvmKeyVaultIntegrationTest` runs instead of skipping. The keyvault integration CI jobs set it. Leave it unset locally to avoid Keychain prompts and keyring pollution. |
| `CI=true` (env) | Set by GitHub Actions and most CI providers. Turns on flaky-test retry: 2 retries per test, `maxFailures=8` distinct failing tests stops retrying so a genuinely broken suite fails fast, and `failOnPassedAfterRetry=false` so a flake that passes on retry keeps the build green while still appearing in the report. Applies to the `jvmTest` task of all three modules and to nothing else — the browser, Apple-native and Android instrumented suites never retry. Locally there are no retries: every test must pass first try. |
| `-Dksafe.biometrics.live=1` | `:ksafe-biometrics` only. Enables `DesktopBiometricsTest.livePrompt_realSystemDialog_optIn`, which pops a **real** Touch ID / Windows Hello prompt you have to answer. Off by default, so an unattended run never blocks. |

Tests that need a flag or a particular environment report as **skipped**, not failed: `SkipConditionRunner` marks them ignored and prints the reason (`JvmTortureTest.randomizedConcurrencyTorture skipped: enable with -PksafeTorture`). A skipped test in the report is a gated test, never a broken one.

### Test data isolation

KSafe's default store directory on the JVM is `<user.home>/.eu_anifantakis_ksafe`. A test that does not pass an explicit `baseDir` would therefore read, write and delete a developer's own store — which is exactly what happened before this was in place. So all three modules fork their `jvmTest` JVM with `user.home` pointed at their own `build/ksafe-test-home/`, which transparently redirects that default into `build/`. `:ksafe` additionally forks a fresh JVM per test class, because its concurrency-stress tests accumulate state faster than one JVM's teardown and garbage collection can drain it.

Before each run, `:ksafe:jvmTest` recursively deletes `build/ksafe-test-home/.eu_anifantakis_ksafe` and re-creates the isolated home. Nothing outside `build/` is ever touched.

### CI parity guards

Two build gates a pull request has to pass. Both can be run locally, and both fail for reasons an ordinary test run never surfaces.

- **`verifyWebTestParity`** — `./gradlew :ksafe:verifyWebTestParity --continue`. It runs both browser suites itself, then fails the build if Kotlin/JS registered fewer tests than wasmJs for any class wasmJs ran — every `commonTest` and `webTest` class, with a class missing from the Kotlin/JS results counted as zero. The legacy Kotlin/JS runner silently stops registering the trailing `@Test` methods of an oversized class — they are compiled into the bundle but never run, with no failure, skip or error — while wasmJs runs the full set from identical source. This guard makes that silent drop loud. Fix a flagged class by splitting it into smaller focused classes; `KSafeNullableDefaultTest` is the pattern.
- **`apiCheck`** — `./gradlew apiCheck` compares the public API against the dumps committed under `ksafe*/api/`. After a deliberate API change, run `./gradlew apiDump` on a Mac — only a Mac can compile the Apple targets the klib dump covers — and commit the diff.

### On-device iOS testing

As the note above explains, neither `iosSimulatorArm64Test` nor `macosArm64Test` performs a real Keychain round-trip, and neither holds a real Secure Enclave key. Exercising the real hardware takes a physical iPhone. The `ios-device-test/` harness runs the tests there, with two scripts:

- **`./run-xctest.sh`** — a curated Swift XCTest target (`xcode/Tests/KSafeDeviceTests.swift`) that links the `iosArm64` framework and drives the real-hardware paths: an encrypted secret round-tripping across two instances, the Secure-Enclave (`HARDWARE_ISOLATED`) envelope, `rotateKeys`, `clearAll`, `protectionInfo` and `deviceKeyStorages`. Fast, clean pass/fail. It reaches all of them through `getOrCreateSecret`, because `put` and `get` are `inline fun <reified T>` and Kotlin/Native exposes those to Swift as throwing stubs, so they are not callable from there.
- **`./run-full-suite.sh`** — the whole `commonTest` + `iosTest` `kotlin.test` suite, which cannot run under `xcodebuild test` because it is not XCTest. The script builds the Kotlin/Native `iosArm64` test binary (`test.kexe`), wraps it in a signed `.app`, installs it with `devicectl`, and captures the runner output — including the `put`/`get` round-trips the XCTest target cannot reach. Run `run-xctest.sh` once first: it makes Xcode issue the provisioning profile this script reuses to sign the app.

Expect a fully green run. There is no list of cases to excuse. The `IosKeychainEncryptionTest` cases that assert a Keychain refusal branch on `SecurityChecker.isEmulator()`: in the Simulator they assert the refusal, and on a signed device they assert a full round-trip instead. Any red is a real failure.

Full setup (Apple team id, device pinning, provisioning) lives in [`ios-device-test/README.md`](../ios-device-test/README.md).

### Other modules

`:ksafe-compose` and `:ksafe-biometrics` ship their own multiplatform suites (`commonTest` plus per-target source sets). Run them the same way as core:

```bash
./gradlew :ksafe-compose:allTests
./gradlew :ksafe-compose:jvmTest
./gradlew :ksafe-biometrics:allTests
./gradlew :ksafe-biometrics:jvmTest
```

`:ksafe-biometrics` has one opt-in probe that pops a **real** Touch ID / Windows Hello prompt you have to answer:

```bash
./gradlew :ksafe-biometrics:jvmTest -Dksafe.biometrics.live=1
```

Without that system property, `DesktopBiometricsTest.livePrompt_realSystemDialog_optIn` returns immediately, so an unattended run never blocks.

### Key rotation

Rotation is covered in three places.

`KSafeRotationLifecycleTest` and `KSafeKeyGenerationTest` live in `commonTest`, so they run on every target — the web is single-threaded, Kotlin/Native has its own memory model, and the machinery has to behave on all of them. They carry the cases whose failure would be silent: resuming a pass a crash interrupted, the bounded retry budget for entries a pass had to skip (a pass that cannot re-encrypt an entry marks it `skipped` and retries it a limited number of times on later launches, rather than forever), adopting a rotation record written by an older (3.0.0) release, and the rule that an un-rotated store's on-disk metadata stays byte-identical to pre-rotation releases so nothing churns.

Five suites in `jvmTest` cover the rest:

- **`JvmKeyRotationTest`** — every encrypted entry is re-encrypted under a fresh key generation, values still read back after a cold reopen, superseded keys are deleted once nothing references them, and a user write racing the pass is never clobbered.
- **`JvmKeyRotationPolicyTest`** — the `MaxAge` startup policy rotates in the background once a generation is older than allowed; the default `Never` policy never rotates.
- **`JvmRotationConcurrencyBoundTest`** — a large store rotates completely, with only a bounded number of entries in plaintext at any one moment. Rotation is the one operation that decrypts entries nobody asked for, so how much of the store can be in the clear at once is a property in its own right.
- **`JvmRotationHardeningTest`** — reserved internal key names are rejected at the write and delete API, because one of them derives the same alias as KSafe's master key, and deleting it would destroy the key every default-protection value is encrypted under. Also: two live instances may rotate at once without losing anything, and a key-vault outage mid-pass reports `skipped` rather than `failed`.
- **`JvmSiblingRotationTest`** — a second live instance's own writes are never turned back into their default values by another instance's rotation.

On real hardware, `run-xctest.sh` calls `rotateKeys` on the device and checks the secret survives it.

For what rotation guarantees, and how the generation model behaves under crashes and concurrent writes, see [`KEY_ROTATION.md`](KEY_ROTATION.md).
