# Testing & Development

by [Mark Andrachek](https://github.com/mandrachek)

### Running Tests

```bash
# Run all tests across all platforms
./gradlew allTests

# Run common tests only
./gradlew :ksafe:commonTest

# Run JVM tests
./gradlew :ksafe:jvmTest

# Run Android unit tests (Note: May fail in Robolectric due to KeyStore limitations)
./gradlew :ksafe:testDebugUnitTest

# Run Android instrumented tests on connected device/emulator (Recommended for Android)
./gradlew :ksafe:connectedDebugAndroidTest

# Run iOS tests on simulator
./gradlew :ksafe:iosSimulatorArm64Test

# Run Kotlin/WASM tests in a headless browser
./gradlew :ksafe:wasmJsBrowserTest

# Run Kotlin/JS (IR) tests in a headless browser
./gradlew :ksafe:jsBrowserTest

# Run a specific test class
./gradlew :ksafe:commonTest --tests "*.KSafeTest"
```

**Note:** Both `wasmJsBrowserTest` and `jsBrowserTest` share the `KSafeTest` suite through the intermediate `webTest` source set, plus a small `WebInteropSmokeTest` that asserts per-target actuals (localStorage, `currentTimeMillisWeb`, `secureRandomBytes`). Headless Chrome is launched by Karma — no manual browser setup required.

**Note:** iOS Simulator uses real Keychain APIs (software-backed), while real devices store Keychain data in a hardware-encrypted container protected by the device passcode.

### Building and Running the iOS Test App

#### Prerequisites
```bash
./gradlew :ksafe:linkDebugFrameworkIosSimulatorArm64  # For simulator
./gradlew :ksafe:linkDebugFrameworkIosArm64           # For physical device
```

#### Building for iOS Simulator
```bash
cd iosTestApp
xcodebuild -scheme KSafeTestApp \
           -configuration Debug \
           -sdk iphonesimulator \
           -arch arm64 \
           -derivedDataPath build \
           build
```

#### Installing and Running on Simulator
```bash
xcrun simctl list devices | grep "Booted"
xcrun simctl install DEVICE_ID build/Build/Products/Debug-iphonesimulator/KSafeTestApp.app
xcrun simctl launch DEVICE_ID com.example.KSafeTestApp
```

#### Building for Physical iOS Device
```bash
cd iosTestApp
xcodebuild -scheme KSafeTestApp \
           -configuration Debug \
           -sdk iphoneos \
           -derivedDataPath build \
           build
```

**Important Notes:**
- **Simulator:** Uses real Keychain APIs (software-backed)
- **Physical Device:** Uses hardware-encrypted Keychain (protected by device passcode). Requires developer profile to be trusted in Settings → General → VPN & Device Management

### Test App Features

The iOS test app demonstrates:
- Creating a KSafe instance with a custom file name
- Observing value changes through Flow simulation (via polling)
  - For production apps, consider using [SKIE](https://skie.touchlab.co/) or [KMP-NativeCoroutines](https://github.com/rickclephas/KMP-NativeCoroutines) for easier Flow consumption from iOS
- Using `putDirect` to immediately update values
- Real-time UI updates responding to value changes
