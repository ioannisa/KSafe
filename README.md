# KSafe — Secure Persist Library for Kotlin Multiplatform

_**Effortless Enterprise-Grade Encrypted Persistence for Kotlin Multiplatform and Native Android with Hardware-Backed Security.**_


[![Maven Central](https://img.shields.io/maven-central/v/eu.anifantakis/ksafe.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/eu.anifantakis/ksafe)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


![image](https://github.com/user-attachments/assets/692d9066-e953-4f13-9642-87661c5bc248)

[Demo CMP App Using KSafe](https://github.com/ioannisa/KSafeDemo)

[YouTube Demo](https://youtu.be/mFKGx0DMZEA)

Whether you must squirrel away OAuth tokens in a fintech app or remember the last‑visited screen of your game, KSafe stores the data encrypted with platform-specific secure key storage and hands it back to you like a normal variable.

##### Contributors
Special thanks to [Mark Andrachek](https://github.com/mandrachek) for his contribution!


***


## Why use KSafe?

* **Hardware-backed security** 🔐 AES‑256‑GCM with keys stored in Android Keystore or iOS Keychain for maximum protection.
* **Clean reinstalls** 🧹 Automatic cleanup ensures fresh starts after app reinstallation on both platforms.
* **One code path** No expect/actual juggling—your common code owns the vault.
* **Ease of use** `var launchCount by ksafe(0)` —that is literally it.
* **Versatility** Primitives, data classes, sealed hierarchies, lists, sets; all accepted.
* **Performance** Suspend API keeps the UI thread free; direct API is there when you need blocking simplicity.

## How encryption works under the hood

KSafe provides enterprise-grade encrypted persistence using DataStore Preferences with platform-specific secure key storage.

##### Android
* **Cipher:** AES‑256‑GCM
* **Key Storage:** Android Keystore (hardware-backed when available)
* **Security:** Keys are non-exportable, app-bound, and automatically deleted on uninstall
* **Access Control:** Keys only accessible when device is unlocked

##### iOS
* **Cipher:** AES‑256‑GCM via OpenSSL-3 provider
* **Key Storage:** iOS Keychain Services
* **Security:** Protected by device passcode/biometrics, not included in backups
* **Access Control**: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
* **Reinstall Handling:** Automatic cleanup of orphaned Keychain entries on first use

##### Flow

* **Serialize value → plaintext bytes** using kotlinx.serialization.
* **Load (or generate) a random 256‑bit AES key**  from Keystore/Keychain (unique per preference key)
* **Encrypt with AES‑GCM** (nonce + auth‑tag included).
* **Persist Base64(ciphertext)** in DataStore under `encrypted_<key>`
* **Keys managed by platform** - never stored in DataStore

Because GCM carries its own authentication tag, any tampering with data is detected on decryption. Platform-managed keys provide hardware-backed security where available.

***

## Setup ⚙️
Add the KSafe dependency to your `build.gradle.kts` (or `build.gradle`) file.

### Library Installation

[![Maven Central](https://img.shields.io/maven-central/v/eu.anifantakis/ksafe.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/eu.anifantakis/ksafe)

#### 1 - Add the Dependency

If you want to use the latest stable version
```kotlin
// commonMain or Android-only build.gradle(.kts)
implementation("eu.anifantakis:ksafe:1.1.1")
implementation("eu.anifantakis:ksafe-compose:1.1.1") // ← Compose state (optional)
```

If you want to use the latest pre-release (Release Candidate) version with Desktop support
```kotlin
// commonMain or Android-only build.gradle(.kts)
implementation("eu.anifantakis:ksafe:1.2.0-RC1")
implementation("eu.anifantakis:ksafe-compose:1.2.0-RC1") // ← Compose state (optional)
```

> Skip `ksafe-compose` if your project doesn’t use Jetpack Compose, or if you don't intend to use the library's `mutableStateOf` persistance option

#### 2 - Apply the kotlinx‑serialization plugin

If you want to use the library with data classes, you need to enable Serialization at your project.

Add Serialization definition to your `plugins` section of your `libs.versions.toml`
```toml
[versions]
kotlin = "2.2.10"

[plugins]
kotlin-serialization = { id = "org.jetbrains.kotlin.plugin.serialization", version.ref = "kotlin" }
```

and apply it at the same section of your `build.gradle.kts` file.
```Kotlin
plugins {
  //...
  alias(libs.plugins.kotlin.serialization)
}
```

*** 

#### Library Instantiation with Koin

Koin is the defacto DI solution for Kotlin Multiplatform, and is the ideal tool to provde as a singleton the KSafe library.

```Kotlin
// common
expect val platformModule: Module

// Android
actual val platformModule = module {
  single { KSafe(androidApplication()) }
}

// iOS
actual val platformModule = module {
  single { KSafe() }
}
```

And now you're ready to inject KSafe to your ViewModels :)

*** 

### Usage 🚀

##### Quick Start (One Liner)
`var counter by ksafe(0)`

params:
* `defaultValue` must be declared (type is infered by it)
* `key` if not set the variable name is used as a key
* `encrypted` by default is set to true (uses Keystore/Keychain)

The above wat is easiest to utilize the library with property delegation, that provides out of the box, intuitive way to encrypted persisted values.  All you need is `by ksafe(x)`

```Kotlin
import eu.anifantakis.lib.ksafe.KSafe

class MyViewModel(ksafe: KSafe): ViewModel() {
  var counter by ksafe(0)

  init {
    // then just use it as a regular variable
    counter++
  }
}
```

> **Important:** The property delegate can ONLY use the default KSafe instance. If you need to use multiple KSafe instances with different file names, you must use the suspend or direct APIs (see below).

##### Composable State (One Liner)
`var counter by ksafe.mutableStateOf(0))`

Recomposition‑proof and survives process death with zero boilerplate.

That is a composable state, but to make use of it you need to have imported the second dependency in our installation guide that includes compose.

```Kotlin
import eu.anifantakis.lib.ksafe.KSafe

class MyViewModel(ksafe: KSafe): ViewModel() {
  var counter by ksafe.mutableStateOf(0)
    private set

  init {
    // then just use it as a regular variable
    counter++
  }
}
```

#### Storing complex objects

```Kotlin
@Serializable
data class AuthInfo(
  val accessToken: String = "",
  val refreshToken: String = "",
  val expiresIn: Long = 0L
)

var authInfo by ksafe(AuthInfo())   // encryption + JSON automatically

// Update
authInfo = authInfo.copy(accessToken = "newToken")
```
> ⚠️ Seeing "Serializer for class X' is not found"?
Add `@Serializable` and make sure you have added Serialization plugin to your app

#### Suspend API (non‑blocking)

```Kotlin
// inside coroutine / suspend fn
ksafe.put("profile", userProfile)          // encrypt & persist
val cached: User = ksafe.get("profile", User())
```

#### Direct API (Good for Tests)
```Kotlin
ksafe.putDirect("counter", 42)
val n = ksafe.getDirect("counter", 0)
```

#### Jetpack Compose ♥ KSafe (optional module)
as already mentioned above, Recomposition‑proof and survives process death with zero boilerplate.
```Kotlin
var clicks by ksafe.mutableStateOf(0)  // encrypted backing storage
actionButton { clicks++ }
```

#### Deleting data
```Kotlin
ksafe.delete("profile")       // suspend (non‑blocking)
ksafe.deleteDirect("profile") // blocking
```

When you delete a value, both the data and its associated encryption key are removed from the secure storage (Keystore/Keychain).

#### Using Multiple KSafe Instances
by [Mark Andrachek](https://github.com/mandrachek)

You can create multiple KSafe instances with different file names to separate different types of data (e.g., user preferences vs. app settings vs. cache data):

```Kotlin
class MyViewModel : ViewModel() {
  // Separate instances for different data domains
  private val userPrefs = KSafe(fileName = "userpreferences")
  private val appSettings = KSafe(fileName = "appsettings")
  private val cacheData = KSafe(fileName = "cache")

  // Note: Property delegation only works with the default instance
  // For named instances, use suspend or direct APIs:

  suspend fun saveUserToken(token: String) {
    userPrefs.put("auth_token", token, encrypted = true)
  }

  fun getCachedData(): String {
    return cacheData.getDirect("last_sync", "", encrypted = false)
  }

  suspend fun updateAppTheme(isDark: Boolean) {
    appSettings.put("dark_mode", isDark)
  }
}
```

**Important Instance Management Rules:**
- **Each KSafe instance should be a singleton** - Create once and reuse throughout your app
- **Never create multiple instances pointing to the same file** - This can cause data inconsistency and unexpected behavior
- Use dependency injection (like Koin) to manage instances as singletons:

```Kotlin
// ✅ Good Idea: Singleton instances via DI
val appModule = module {
  single { KSafe() }  // Default instance
  single(named("user")) { KSafe(fileName = "userdata") }
  single(named("cache")) { KSafe(fileName = "cache") }
}

// ❌ Bad Idea: Creating multiple instances for the same file
class ScreenA {
  val prefs = KSafe(fileName = "userdata")  // Instance 1
}
class ScreenB {
  val prefs = KSafe(fileName = "userdata")  // Instance 2 - DON'T DO THIS!
}
```

**File Name Requirements:**
- Must contain only lowercase letters (a-z)
- No numbers, special characters, or uppercase letters allowed
- Examples: `"userdata"`, `"settings"`, `"cache"`
- Invalid: `"userData"`, `"user_data"`, `"user123"`

Each instance creates its own separate DataStore file and encryption keys, allowing you to:
- Organize data by domain or feature
- Clear specific data sets independently
- Apply different encryption strategies per instance

#### Full ViewModel example
```Kotlin
class CounterViewModel(ksafe: KSafe) : ViewModel() {
  // regular Compose state (not persisted)
  var volatile by mutableStateOf(0)
    private set

  // persisted Compose state (AES encrypted)
  var persisted by ksafe.mutableStateOf(100)
    private set

  // plain property‑delegate preference
  var hits by ksafe(0)

  fun inc() {
    volatile++
    persisted++
    hits++
  }
}
```

***

## Security Features
### Platform-Specific Protection

#### Android
* Keys stored in Android Keystore
* Hardware-backed encryption when available
* Keys bound to your application
* Automatic cleanup on app uninstall

#### iOS
* Keys stored in iOS Keychain Services
* Protected by device authentication
* Not included in iCloud/iTunes backups
* Automatic cleanup of orphaned keys on first app use after reinstall

### Error Handling
If decryption fails (e.g., corrupted data or missing key), KSafe gracefully returns the default value, ensuring your app continues to function.

### Reinstall Behavior
KSafe ensures clean reinstalls on both platforms:
* **Android:** Keystore entries automatically deleted on uninstall
* **iOS:** Orphaned Keychain entries detected and cleaned on first use after reinstall

This means users always get a fresh start when reinstalling your app, with no lingering encrypted data from previous installations.

### Technical Details

#### iOS Keychain Cleanup Mechanism
On iOS, KSafe uses a smart detection system:

* **Installation ID:** Each app install gets a unique ID stored in DataStore
* **First Access:** On first get/put operation after install, cleanup runs
* **Orphan Detection:** Compares Keychain entries with DataStore entries
* **Automatic Removal:** Deletes any Keychain keys without matching DataStore data

#### Known Limitations

* **iOS:** Keychain access requires device to be unlocked
* **Android:** Some devices may not have hardware-backed keystore
* **Both:** Encrypted data is lost if encryption keys are deleted (by design for security)

***

## Testing & Development
by [Mark Andrachek](https://github.com/mandrachek)

### Running Tests

KSafe includes comprehensive tests for all platforms. Here are the Gradle commands to run them:

```bash
# Run all tests across all platforms
./gradlew allTests

# Run common tests only
./gradlew :ksafe:commonTest

# Run Android unit tests (Note: May fail in Robolectric due to KeyStore limitations)
./gradlew :ksafe:testDebugUnitTest

# Run Android instrumented tests on connected device/emulator (Recommended for Android)
./gradlew :ksafe:connectedDebugAndroidTest

# Run iOS tests on simulator
./gradlew :ksafe:iosSimulatorArm64Test

# Run a specific test class
./gradlew :ksafe:commonTest --tests "*.KSafeTest"
```

**Note:** iOS tests on simulator use a mock Keychain implementation since Keychain Services are not available in the iOS Simulator. This validates the encryption logic but not the actual Keychain integration.

### Building and Running the iOS Test App

The repository includes an iOS test app that demonstrates KSafe's Flow functionality. You can build and run it from the command line:

#### Prerequisites
```bash
# Build the KSafe framework first
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
# Find running simulator
xcrun simctl list devices | grep "Booted"

# Install app (replace DEVICE_ID with your simulator's ID)
xcrun simctl install DEVICE_ID build/Build/Products/Debug-iphonesimulator/KSafeTestApp.app

# Launch app
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

#### Installing on Physical Device
```bash
# List connected devices
xcrun devicectl list devices

# Install app (replace DEVICE_ID with your device's ID)
xcrun devicectl device install app \
                --device DEVICE_ID \
                build/Build/Products/Debug-iphoneos/KSafeTestApp.app

# Launch app (Note: Requires trusted developer profile on device)
xcrun devicectl device process launch \
                --device DEVICE_ID \
                com.example.KSafeTestApp
```

**Important Notes:**
- **Simulator:** Tests use a mock Keychain implementation for iOS Simulator compatibility
- **Physical Device:** Requires developer profile to be trusted in Settings → General → VPN & Device Management
- **Framework Path:** The Xcode project automatically selects the correct framework (arm64 for device, simulatorArm64 for simulator)

### Test App Features

The iOS test app demonstrates:
- Creating a KSafe instance with a custom file name
- Observing value changes through Flow simulation (via polling)
  - For production apps, consider using [SKIE](https://skie.touchlab.co/) or [KMP-NativeCoroutines](https://github.com/rickclephas/KMP-NativeCoroutines) for easier Flow consumption from iOS
- Using `putDirect` to immediately update values
- Real-time UI updates responding to value changes

***

## Licence

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
