# KVault — Secure Persist Library for Kotlin Multiplatform

_**Effortless Encrypted Persistence for Android and Kotlin Multiplatform DataStore.**_
***

[![Maven Central](https://img.shields.io/maven-central/v/eu.anifantakis/kvault.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/eu.anifantakis/kvault)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

[Demo CMP App Using KVault](https://github.com/ioannisa/KVaultDemo)

Whether you must squirrel away OAuth tokens in a fintech app or remember the last‑visited screen of your game, KVault stores the data encrypted and hands it back to you like a normal variable.

## Why use KVault?

* **Security first** 🔐 AES‑256‑GCM under the hood, key stored next to ciphertext or in Android KeyStore (optional).

* **One code path** No expect/actual juggling—your common code owns the vault.

* **Ease of use** `var launchCount by kvault(0)` —that is literally it.

* **Versatility** Primitives, data classes, sealed hierarchies, lists, sets; all accepted.

* **Performance** Suspend API keeps the UI thread free; direct API is there when you need blocking simplicity.




## How encryption works under the hood

As already mentioned, KVault handles seamless encrypted persistence using DataStore Preferences.  But how it handles encryption?

##### Android
* **Cipher:** AES‑256‑GCM via `dev.whyoleg.cryptography`
* **Key Storage:** Default: symmetric key is Base64‑encoded inside the same DataStore file.

##### iOS
* **Cipher:** AES‑256‑GCM via the OpenSSL-3 provider compiled in Kotlin/Native
* **Key Storage:** Symmetric key Base64‑encoded next to the ciphertext in a DataStore file located in the app’s Documents directory.

##### Flow

* **Serialize value → plaintext bytes** using kotlinx.serialization.
* **Load (or generate) a random 256‑bit AES key*** scoped to that preference.
* **Encrypt with AES‑GCM** (nonce + auth‑tag included).
* **Persist Base64(ciphertext)** under `encrypted_<key>` and Base64(key) under `symmetric_<key>`.

Because GCM carries its own authentication tag, any tampering with data is detected on decryption. Deleting a symmetric_* entry transparently rotates the key on the next write.

***

## Setup ⚙️
Add the Reanimator dependency to your `build.gradle.kts` (or `build.gradle`) file.

### Library Installation

[![Maven Central](https://img.shields.io/maven-central/v/eu.anifantakis/kvault.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/eu.anifantakis/kvault)

#### 1 - Add the Dependency
```kotlin
// commonMain or Android-only build.gradle(.kts)
implementation("eu.anifantakis:kvault:1.0.2")
implementation("eu.anifantakis:kvault-compose:1.0.2") // ← Compose state (optional)
```

> Skip `kvault-compose` if your project doesn’t use Jetpack Compose.

#### 2 - Apply the kotlinx‑serialization plugin in every module that declares @Serializable classes

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
* `encrypted` by default is set to true

The above is easiest way is to utilize the library with property delegation, that provides out of the box, intuitive way to encrypted persisted values.  All you need is `by kvault(x)`

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
`var counter by kvault.mutableStateOf(0)`

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



