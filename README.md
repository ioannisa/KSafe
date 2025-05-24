# KVault — Secure Persist Library for Kotlin Multiplatform

_**Effortless Enterprise-Grade Encrypted Persistence for Android and Kotlin Multiplatform with Hardware-Backed Security.**_
***

[![Maven Central](https://img.shields.io/maven-central/v/eu.anifantakis/kvault.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/eu.anifantakis/kvault)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

![image](https://github.com/user-attachments/assets/5a4736ec-0e08-444e-90d7-f15fe85d5baa)

[Demo CMP App Using KVault](https://github.com/ioannisa/KVaultDemo)

Whether you must squirrel away OAuth tokens in a fintech app or remember the last‑visited screen of your game, KVault stores the data encrypted with platform-specific secure key storage and hands it back to you like a normal variable.

## Why use KVault?

* **Hardware-backed security** 🔐 AES‑256‑GCM with keys stored in Android Keystore or iOS Keychain for maximum protection.
* **Clean reinstalls** 🧹 Automatic cleanup ensures fresh starts after app reinstallation on both platforms.
* **One code path** No expect/actual juggling—your common code owns the vault.
* **Ease of use** `var launchCount by kvault(0)` —that is literally it.
* **Versatility** Primitives, data classes, sealed hierarchies, lists, sets; all accepted.
* **Performance** Suspend API keeps the UI thread free; direct API is there when you need blocking simplicity.

## How encryption works under the hood

KVault provides enterprise-grade encrypted persistence using DataStore Preferences with platform-specific secure key storage.

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
Add the Reanimator dependency to your `build.gradle.kts` (or `build.gradle`) file.

### Library Installation

[![Maven Central](https://img.shields.io/maven-central/v/eu.anifantakis/kvault.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/eu.anifantakis/kvault)

#### 1 - Add the Dependency
```kotlin
// commonMain or Android-only build.gradle(.kts)
implementation("eu.anifantakis:kvault:1.1.0")
implementation("eu.anifantakis:kvault-compose:1.1.0") // ← Compose state (optional)
```

> Skip `kvault-compose` if your project doesn’t use Jetpack Compose, or if you don't intend to use the library's `mutableStateOf` persistance option

#### 2 - Apply the kotlinx‑serialization plugin

If you want to use the library with data classes, you need to enable Serialization at your project.

Add Serialization definition to your `plugins` section of your `libs.versions.toml` 
```toml
[versions]
kotlin = "2.1.21"

[plugins]
kotlin-serialization = { id = "org.jetbrains.kotlin.plugin.serialization", version.ref = "kotlin" }
```

and apply it at the same section of your `build.gradle.kts` file.
```Kotlin
plugins {
    ...
    alias(libs.plugins.kotlin.serialization)
}
```

*** 

#### Library Instantiation with Koin

Koin is the defacto DI solution for Kotlin Multiplatform, and is the ideal tool to provde as a singleton the KVault library. 

```Kotlin
// common
expect val platformModule: Module

// Android
actual val platformModule get() = module {
    single { KVault(androidApplication()) }
}

// iOS
actual val platformModule get() = module {
    single { KVault() }
}
```

And now you're ready to inject KVault to your ViewModels :)

*** 

### Usage 🚀

##### Quick Start (One Liner)
`var counter by kvault(0)`

params:
* `defaultValue` must be declared (type is infered by it)
* `key` if not set the variable name is used as a key
* `encrypted` by default is set to true (uses Keystore/Keychain)

The above wat is easiest to utilize the library with property delegation, that provides out of the box, intuitive way to encrypted persisted values.  All you need is `by kvault(x)`

```Kotlin
import eu.anifantakis.lib.kvault.KVault

class MyViewModel(kvault: KVault): ViewModel() {
    var counter by kvault(0)

    init {
        // then just use it as a regular variable
        counter++
    }
}
```

##### Composable State (One Liner)
`var counter by kvault.mutableStateOf(0))`

Recomposition‑proof and survives process death with zero boilerplate.

That is a composable state, but to make use of it you need to have imported the second dependency in our installation guide that includes compose.

```Kotlin
import eu.anifantakis.lib.kvault.KVault

class MyViewModel(kvault: KVault): ViewModel() {
    var counter by kvault.mutableStateOf(0)
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

var authInfo by kvault(AuthInfo())   // encryption + JSON automatically

// Update
authInfo = authInfo.copy(accessToken = "newToken")
```
> ⚠️ Seeing "Serializer for class X' is not found"?
Add `@Serializable` and make sure you have added Serialization plugin to your app

#### Suspend API (non‑blocking)

```Kotlin
// inside coroutine / suspend fn
kvault.put("profile", userProfile)          // encrypt & persist
val cached: User = kvault.get("profile", User())
```

#### Direct API (Good for Tests)
```Kotlin
kvault.putDirect("counter", 42)
val n = kvault.getDirect("counter", 0)
```

#### Jetpack Compose ♥ KVault (optional module)
as already mentioned above, Recomposition‑proof and survives process death with zero boilerplate.
```Kotlin
var clicks by kvault.mutableStateOf(0)  // encrypted backing storage
actionButton { clicks++ }
```

#### Deleting data
```Kotlin
kvault.delete("profile")       // suspend (non‑blocking)
kvault.deleteDirect("profile") // blocking
```

When you delete a value, both the data and its associated encryption key are removed from the secure storage (Keystore/Keychain).

#### Full ViewModel example
```Kotlin
class CounterViewModel(kvault: KVault) : ViewModel() {
    // regular Compose state (not persisted)
    var volatile by mutableStateOf(0)
        private set

    // persisted Compose state (AES encrypted)
    var persisted by kvault.mutableStateOf(100)
        private set

    // plain property‑delegate preference
    var hits by kvault(0)

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
If decryption fails (e.g., corrupted data or missing key), KVault gracefully returns the default value, ensuring your app continues to function.

### Reinstall Behavior
KVault ensures clean reinstalls on both platforms:
* **Android:** Keystore entries automatically deleted on uninstall
* **iOS:** Orphaned Keychain entries detected and cleaned on first use after reinstall

This means users always get a fresh start when reinstalling your app, with no lingering encrypted data from previous installations.

### Technical Details

#### iOS Keychain Cleanup Mechanism
On iOS, KVault uses a smart detection system:

* **Installation ID:** Each app install gets a unique ID stored in DataStore
* **First Access:** On first get/put operation after install, cleanup runs
* **Orphan Detection:** Compares Keychain entries with DataStore entries
* **Automatic Removal:** Deletes any Keychain keys without matching DataStore data

#### Known Limitations

* **iOS:** Keychain access requires device to be unlocked
* **Android:** Some devices may not have hardware-backed keystore
* **Both:** Encrypted data is lost if encryption keys are deleted (by design for security)

***

## Licence

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. 

You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
