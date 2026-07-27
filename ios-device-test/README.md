# KSafe — on-device iOS test harness

Runs KSafe tests on a **physical iPhone** (real Secure Enclave + Keychain), which the standard
Gradle tasks can't do — `iosSimulatorArm64Test` only targets the simulator, where the Keychain
falls back to a sandbox file store (see `SimulatorKeychainFallback`).

## Prerequisites (one-time)

1. Xcode installed; sign into your Apple ID in **Xcode → Settings → Accounts** (any team works —
   a free *Personal Team* is enough for Keychain).
2. Connect the iPhone over USB, unlock it, and **trust** this Mac / the developer certificate
   (Settings → General → VPN & Device Management → your dev app → Trust).
3. Set your team id if it isn't the default: `export DEVELOPMENT_TEAM=XXXXXXXXXX`.
   If more than one iPhone is paired, pin one: `export DEVICE_UDID=<hardware-udid>`
   (list them with `xcrun devicectl list devices`).

## Two ways to run

### `./run-xctest.sh` — curated Swift XCTest (fast, clean pass/fail)

Builds the `iosArm64` framework, generates a throwaway Xcode project (via the `xcodeproj` Ruby
gem, bundled with CocoaPods), links the framework into a unit-test target, and runs
`Tests/KSafeDeviceTests.swift` on the device with `xcodebuild test`. Covers the real-hardware
paths: encrypted secret round-trip across instances, Secure-Enclave (`HARDWARE_ISOLATED`)
envelope, `rotateKeys`, `clearAll`, `protectionInfo`, `deviceKeyStorages`, `getOrCreateSecret`.

> The typed `put`/`get` are `inline fun <reified T>` and are **not callable from Swift**
> (Kotlin/Native exposes them as throwing stubs), so these tests drive the same engine through
> `getOrCreateSecret`. To exercise `put`/`get` on device, use the full suite below.

### `./run-full-suite.sh` — the entire existing kotlin.test suite (~185 tests)

The `commonTest` + `iosTest` suites are `kotlin.test`, not XCTest, so they can't run via
`xcodebuild test`. This script builds the Kotlin/Native `iosArm64` **test binary** (`test.kexe`),
wraps it in a signed `.app`, installs it with `devicectl`, and launches it with `--console` to
capture the runner output. This exercises the full API — including the reified `put`/`get`
round-trips — on real hardware.

Run `./run-xctest.sh` **once first** so Xcode generates a provisioning profile for
`<bundle>.host`; the full-suite script reuses it to sign the `.kexe` app.

#### Expected "failures" on a real device

A handful of `IosKeychainEncryptionTest` cases are written for the **simulator / no-entitlement**
environment and `assertFailsWith` that the Keychain **throws** (-34018). On a real signed device
the Keychain **works**, so `encrypt()` succeeds and those asserts fail — that is *correct* device
behaviour, not a KSafe bug. They are:
`testThrowsOnKeychainErrorInTestEnvironment`, `testDecryptThrowsOnKeychainError`,
`testSecureEnclaveThrowsInTestEnvironment`, `testCustomConfigIsAccepted`. (They pass on the
simulator, their intended environment. To make them device-safe they'd need an `isEmulator` gate.)

## Layout

    common.sh            device/team/identity resolution shared by both scripts
    run-xctest.sh        curated Swift XCTest on device
    run-full-suite.sh    full kotlin.test suite on device (kexe-as-app)
    Info.plist           bundle metadata for the kexe app wrapper
    xcode/gen.rb         generates the XCTest Xcode project (env-driven)
    xcode/Host/          minimal host app (iOS XCTest needs an app to host in)
    xcode/Tests/         the curated Swift XCTest cases

`build/` and `xcode/KSafeDeviceTest.xcodeproj` are generated artifacts (git-ignored).
