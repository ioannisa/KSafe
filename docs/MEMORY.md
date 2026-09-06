# Memory Security Policy

This doc covers the in-RAM memory policy plus the `KSafeConfig` knobs and lock-state controls you pass at construction time.

## Memory policy

KSafe keeps every value on disk and also in an in-memory cache, so reads are fast. Encrypted values sit on disk as **ciphertext** (the encrypted bytes) and become **plaintext** (the real value) only after decryption. The memory policy decides what the cache holds for the entries you wrote encrypted: the ciphertext, or the decrypted plaintext, and for how long.

Why it matters: anything held as plaintext in RAM can be read by a debugger, a memory dump, or code running inside your own process. Holding ciphertext instead costs a decrypt on every read. The policy is a per-instance choice; you set it once in the `KSafe(...)` call.

Two things the memory policy does **not** change:

- **What is on disk.** An entry written encrypted (the default) stays encrypted on disk under every policy. An entry written with `KSafeWriteMode.Plain` is plaintext on disk and in RAM under every policy, including `ENCRYPTED`. See [USAGE.md](USAGE.md#write-mode-api-per-entry-unlock-policy).
- **Entries written with `requireUnlockedDevice = true`.** They stay ciphertext in RAM and are decrypted again on every read, under every policy, so a locked device can never be answered from RAM. See [Device Lock-State Policy](#device-lock-state-policy).

```Kotlin
val ksafe = KSafe(
    fileName = "secrets",
    memoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT // Default
)
// On Android the factory takes the Context first:
// KSafe(context, fileName = "secrets", memoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT)
```

| Policy | Best for | What the cache holds | Cost of a read | Security |
|--------|----------|----------------------|----------------|----------|
| `LAZY_PLAIN_TEXT` (default) | General purpose: settings, tokens, app state | Ciphertext; the plaintext of a key is added the first time you read or write it, and kept until that key changes | First read of a key decrypts; every later read is a plain memory lookup | Low for keys you have touched — their plaintext stays in RAM the same way it does under `PLAIN_TEXT` |
| `PLAIN_TEXT` (discouraged) | Only when every value must be plaintext-resident from the very first read | Plaintext of every encrypted entry, decrypted at cold start | Plain memory lookup | Low — every value is plaintext in RAM, and a read that arrives during cold start waits for every entry to be decrypted |
| `ENCRYPTED` | Tokens, passwords, financial data | Ciphertext only | AES-GCM decrypt on every read | High — nothing sits decrypted in RAM between reads; a value you have just written is plaintext only until its encrypted write commits (milliseconds) |
| `ENCRYPTED_WITH_TIMED_CACHE` | Compose / SwiftUI screens that read the same encrypted value many times per frame | Ciphertext, plus the plaintext of recently touched keys for `plaintextCacheTtl` (default 5 s) | First read in a window decrypts; later reads within the TTL are memory lookups | Medium — plaintext only for recently touched keys, only for seconds |

Terms used above:

- **Plain memory lookup:** the cost of reading a map; no crypto.
- **AES-GCM decrypt:** the CPU work of turning ciphertext back into a value. Most entries decrypt with a key already held in process memory. Some go to the **platform key store** on every single read instead — the OS-managed key store outside your process (Android Keystore, Apple Keychain, the desktop OS vault, a browser key in IndexedDB) — which costs far more than the decrypt itself: `HARDWARE_ISOLATED` and `requireUnlockedDevice` entries on Android, and `requireUnlockedDevice` entries on Apple.
- **TTL** (time to live): how long a cached plaintext is reused before the next read decrypts again.
- **Cold start:** the first load of the store file after the `KSafe(...)` call.

How the four differ in memory:

- **LAZY_PLAIN_TEXT:** the general-purpose default. Cold start is as cheap as `ENCRYPTED` (no bulk decrypts). The first read of a key decrypts it and keeps the plaintext; a write keeps the plaintext it just wrote. Later reads are as fast as `PLAIN_TEXT`.
- **PLAIN_TEXT:** discouraged. Decrypts every encrypted entry at cold start, and a read that arrives before that finishes waits for all of them — with thousands of encrypted keys on Android that wait is long enough to trigger an ANR ("application not responding"). Only useful when every value must be plaintext-resident from the first read. An entry whose decrypt fails at cold start is silently left out of the cache (no startup exception) and reads back as its default.
- **ENCRYPTED:** maximum security. The cache holds ciphertext and every read decrypts. Nothing sits decrypted in RAM between reads.
- **ENCRYPTED_WITH_TIMED_CACHE:** like `LAZY_PLAIN_TEXT`, but a cached plaintext stops being reused after the TTL. There is no background sweeper: an expired entry is ignored on the next access, not wiped, and stays referenced in RAM until that key is next read (which decrypts again and replaces it), written, deleted, or until `clearAll()`. The TTL bounds reuse, not the in-RAM lifetime. Use it when you need plaintext briefly for UI bursts but do not want it to live in RAM permanently.

Under `LAZY_PLAIN_TEXT` and `ENCRYPTED_WITH_TIMED_CACHE` — the two policies that cache plaintext at all — a cached plaintext is dropped when the key is written, deleted, changed by another instance of the same store, or wiped by `clearAll()`.

One more distinction: the memory policy governs **values**, never the encryption **keys**. Where those keys live — and the fact that on Android the key that actually decrypts ordinary `DEFAULT` entries (the ones not written with `requireUnlockedDevice = true`) is unwrapped from the chip once and then held in process memory — is described in [SECURITY_MODEL.md](SECURITY_MODEL.md#how-encryption-works).

### LAZY_PLAIN_TEXT — The Default

KSafe keeps two maps in memory: the **primary cache**, holding one entry per stored key, and a **plaintext side cache**, used only by `LAZY_PLAIN_TEXT` and `ENCRYPTED_WITH_TIMED_CACHE`. Under `LAZY_PLAIN_TEXT` the primary cache holds an encrypted entry exactly as it sits on disk — the ciphertext, Base64-encoded, Base64 being the text form KSafe stores raw encrypted bytes in. (Under `PLAIN_TEXT` the same map holds the decrypted values instead; that is the whole difference between the two.) Cold start fills only the primary cache.

Cold start therefore treats encrypted entries exactly like `ENCRYPTED`: each one stays as Base64 ciphertext in the primary cache, and no bulk decryption runs at startup. The first time you read a key, KSafe decrypts it once, stores the plaintext in the side cache, and returns it. Every subsequent read for that key hits the side cache directly — no key-store round-trip, no decryption — and is identical in speed to `PLAIN_TEXT`. The one exception, on every policy, is an entry written with `requireUnlockedDevice = true`: it never enters the side cache and is decrypted again on each read.

The decryption cost is therefore **paid per key, on first access, never repeated**. Apps that read every key after construction pay roughly the same total cost as `PLAIN_TEXT`, just spread over time. Apps that only touch a subset of keys pay only for the keys they read. There is no eager up-front cost.

The in-RAM exposure is the same as `PLAIN_TEXT` *for keys you have actually read or written at least once*: the plaintext stays cached until one of the events listed above drops it (a write, a delete, an external change, `clearAll()`), or until the process exits. Keys you never touch never enter the side cache. (A one-time startup integrity sweep may decrypt an entry transiently to detect orphaned ciphertext, but that plaintext is immediately discarded, never cached.) If a value must never sit decrypted in RAM between reads, create that instance with `ENCRYPTED` or `ENCRYPTED_WITH_TIMED_CACHE`.

```kotlin
val ksafe = KSafe(fileName = "general")  // LAZY_PLAIN_TEXT by default

ksafe.getDirect("user_name", "anon")     // first read: 1 decrypt, plaintext cached
ksafe.getDirect("user_name", "anon")     // every read after: pure memory lookup
ksafe.getDirect("seldom_used", "")       // first read of a different key: 1 decrypt
// Keys you never read or write never enter the plaintext side cache. A key you write is
// cached as plaintext from the moment of the write, exactly as if you had read it.
```

### ENCRYPTED_WITH_TIMED_CACHE — The Balanced Policy

Under `ENCRYPTED` policy, every read triggers AES-GCM decryption. In UI frameworks like Jetpack Compose or SwiftUI, the same encrypted property may be read several times during a single re-run of the UI code (a *recomposition* in Compose, a re-render in SwiftUI). `ENCRYPTED_WITH_TIMED_CACHE` eliminates redundant crypto: only the first read decrypts; subsequent reads within the TTL window are pure memory lookups.

```kotlin
val ksafe = KSafe(
    context = context,
    memoryPolicy = KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE,
    plaintextCacheTtl = 5.seconds  // default; how long plaintext stays cached
)
```

Why five seconds: Compose and SwiftUI re-run your UI code every time state changes, often many times per second, and each run may read the same value again. A TTL of a few seconds turns a burst of reads into one decrypt while keeping the plaintext short-lived. Pick a TTL just long enough to cover one screen's burst of reads; a longer TTL buys nothing but a longer exposure.

**How it works internally:**
```
Read 1: decrypt → cache plaintext (TTL=5s) → return       ← one crypto operation
Read 2 (50ms later):  cache hit → return                   ← no decryption
Read 3 (100ms later): cache hit → return                   ← no decryption
...TTL expires...
Read 4: decrypt → cache plaintext (TTL=5s) → return        ← one crypto operation
```

**Thread safety:** a read takes its own reference to the cached entry, so an expiry or a write on another thread cannot change the value it is returning. There is no background sweeper; an expired entry is ignored on the next access. A write landing while a read is still decrypting wins: the read's own cached copy is withdrawn.

## Construction-time settings

### Lazy Loading

By default `KSafe(...)` returns at once and loads the store file in the background, so the first read usually finds the cache ready. `lazyLoad = true` skips that background load.

```Kotlin
val archive = KSafe(
    fileName = "archive",
    lazyLoad = true  // No background load; the first access loads the file
)
```

Use it for a store you may never touch in a session (an archive, a rarely used feature), so its file is not read at startup. What it costs:

- The first access loads the whole file: `getDirect` (the non-suspending read) and property delegates block the calling thread for it, while the suspending `get` waits without blocking. Do not make that first access on the main thread of a store with many encrypted entries.
- No background collector runs for the instance, so the cache is not refreshed from disk in the background.
- The one-time startup cleanup (orphaned-ciphertext sweep, legacy key migration) runs after that first access, off the calling thread.

On **web (js / wasmJs)** `lazyLoad` is accepted for API parity but ignored: the preload always runs. The web target cannot block, so a deferred load would leave `getDirect`, `by ksafe(...)` delegates and Compose state returning their defaults for the whole session. Reading `localStorage` is synchronous, but decrypting its values is not (WebCrypto is async-only), so the preload runs in the background and a read that races it returns the default. On web call `awaitCacheReady()` before the first read — see [SETUP.md](SETUP.md#ksafeawaitcacheready-required-only-on-the-web-targets-wasmjs--js).

### Constructor Parameters

`KSafe(...)` is a factory function, one per platform, so the parameter list differs slightly. The shared parameters:

| Parameter | What it does | Where to read more |
|---|---|---|
| `fileName` | Name of the store; `null` is the default store. Two instances with the same name share the file and its keys. A lowercase letter first, then lowercase letters, digits or underscores. | [SETUP.md](SETUP.md#multiple-instances) |
| `lazyLoad` | Skip the background load; the first access loads the file. | [Lazy Loading](#lazy-loading) |
| `memoryPolicy` | What the cache holds for encrypted entries. | [Memory policy](#memory-policy) |
| `config` | Key size, serializer, default unlock policy, namespace, rotation. | [Encryption Configuration](#encryption-configuration) |
| `securityPolicy` | Root/jailbreak, debugger, debug-build and emulator checks, run once inside this call; a `BLOCK` action throws `SecurityViolationException`. | [SECURITY_MODEL.md](SECURITY_MODEL.md#runtime-security-policy) |
| `plaintextCacheTtl` | Lifetime of a cached plaintext; used only with `ENCRYPTED_WITH_TIMED_CACHE`. | [ENCRYPTED_WITH_TIMED_CACHE](#encrypted_with_timed_cache--the-balanced-policy) |

```Kotlin
// Android
KSafe(
    context: Context,
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,  // only used with ENCRYPTED_WITH_TIMED_CACHE
    useStrongBox: Boolean = false,            // deprecated: promotes every DEFAULT encrypted write to
                                              // HARDWARE_ISOLATED. Ask per write instead, with
                                              // KSafeWriteMode.Encrypted(protection =
                                              // KSafeEncryptedProtection.HARDWARE_ISOLATED),
                                              // or through the KSafeHardwareIsolated view.
    baseDir: File? = null                     // override the default DataStore directory
)

// JVM
KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    baseDir: File? = null                     // override the default DataStore directory
)

// iOS / macOS (shared appleMain factory)
KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    useSecureEnclave: Boolean = false,        // deprecated: promotes every DEFAULT encrypted write to
                                              // HARDWARE_ISOLATED. Ask per write instead, with
                                              // KSafeWriteMode.Encrypted(protection =
                                              // KSafeEncryptedProtection.HARDWARE_ISOLATED),
                                              // or through the KSafeHardwareIsolated view.
    directory: String? = null                 // override the default DataStore directory
)

// Web (Kotlin/WASM + Kotlin/JS)
KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,                                       // accepted for API parity; ignored — the preload always runs
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,  // accepted for API parity; ignored — always PLAIN_TEXT internally
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds                          // accepted for API parity; ignored — PLAIN_TEXT has no plaintext side cache
    // No baseDir / directory: localStorage has no directory concept — instances are isolated
    // by the `ksafe.<appNamespace@><fileName>:` storage-key prefix.
)
```

See also [Custom Storage Directory](SETUP.md#custom-storage-directory) for `baseDir` / `directory`, [SERIALIZATION.md](SERIALIZATION.md) for `json`, [App namespace](JVM_PROTECTION.md#app-namespace-multi-app-isolation) for `appNamespace`, and [KEY_ROTATION.md](KEY_ROTATION.md) for `keyRotationPolicy`.

### Encryption Configuration

```Kotlin
val ksafe = KSafe(
    context = context,
    config = KSafeConfig(
        aesKeySize = KSafeAesKeySize.BITS_256,            // BITS_128 or BITS_256; default BITS_256
        requireUnlockedDevice = false,                    // default unlock policy for writes that pass no mode
        json = KSafeDefaults.json,                        // kotlinx.serialization Json used for stored values
        appNamespace = null,                              // JVM and web only: isolates data and keys of two apps sharing a fileName
        keyRotationPolicy = KSafeKeyRotationPolicy.Never, // Never (default) or MaxAge(Duration)
        keyRotationRetryAttempts = 3                      // retries for entries a completed rotation could not reach; 0 disables
    )
)
```

- `aesKeySize` sets the strength of keys created from now on; existing keys keep their size until `rotateKeys()`. Keep the default unless a policy requires 128-bit keys. The algorithm (AES-GCM) is fixed and not configurable, so no call site can weaken it.
- `requireUnlockedDevice` is the fallback unlock policy for encrypted writes that pass no `mode` — see [Device Lock-State Policy](#device-lock-state-policy).
- `json` serializes the values you store. Changing it later can make already-stored objects unreadable, so treat it as fixed once the app has shipped. See [SERIALIZATION.md](SERIALIZATION.md).
- `appNamespace` matters only on JVM Desktop and web, where the OS secret store or the browser origin is shared between apps; there it namespaces both the data and the keys. It has no effect on Android and iOS. See [SETUP.md](SETUP.md#configuring-ksafe-ksafeconfig) and [JVM_PROTECTION.md](JVM_PROTECTION.md#app-namespace-multi-app-isolation).
- `keyRotationPolicy` and `keyRotationRetryAttempts` schedule re-encryption under a fresh key. Rotation is off by default because the keys are hardware- or OS-protected and do not expire; `rotateKeys()` is always available on demand. `keyRotationRetryAttempts` must not be negative, and each new instance consumes at most one retry. See [KEY_ROTATION.md](KEY_ROTATION.md).

### Device Lock-State Policy

A locked device is one whose screen lock is engaged. `requireUnlockedDevice` decides whether an encrypted entry can be decrypted while the device is locked. It is off by default because background work (push handling, sync) usually needs its data while the screen is locked. An entry written with `requireUnlockedDevice = true` is called a **strict** entry below.

There are two places to set it:

1. **Per entry (recommended):** `KSafeWriteMode.Encrypted(requireUnlockedDevice = ...)` on the write.
2. **Instance default:** `KSafeConfig(requireUnlockedDevice = ...)`. It applies to every encrypted write that passes no `mode`: `put`/`putDirect` without `mode`, and also `by ksafe(...)` delegates, the writable flow delegates (`asWritableFlow`, `asMutableStateFlow`) and Compose state, which all write with `KSafe.defaultWriteMode`.

```kotlin
// Per-entry policy (recommended)
ksafe.put(
    "auth_token",
    token,
    mode = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.DEFAULT,
        requireUnlockedDevice = true
    )
)

// Instance default for writes that pass no mode
val ksafe = KSafe(
    context = context,
    config = KSafeConfig(requireUnlockedDevice = true)
)
```

`requireUnlockedDevice` applies only to encrypted writes; `KSafeWriteMode.Plain` has no such setting.

What it maps to on each platform:

| Platform | `requireUnlockedDevice = true` | `= false` (default) |
|---|---|---|
| Android API 28+ | Key created with `setUnlockedDeviceRequired(true)`; decrypt fails while locked. On API 28-34 with no secure lock screen the key is created without the flag and `protectionInfo.notes` carries `android_lock_screen_absent` until a new key generation re-decides (`rotateKeys()`). | Key usable while locked |
| Android API 24-27 | Not supported by the platform: the key is created without the flag and nothing is reported, so treat the policy as unenforced there | Same |
| iOS / macOS | Keychain item `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: readable while locked, but only after the first unlock since boot |
| JVM Desktop | No device lock state to enforce; the entry is still recorded as strict, so it skips the plaintext caches and decrypts on every read | Ordinary entry |
| Web | The flag is dropped at write time; a browser has no device lock | Ordinary entry |

What a read does while the device is locked and the entry is strict: the suspending `get()` throws so you can await unlock and retry; `getDirect()` and property delegates return the default; `getFlow()` keeps its last value and retries on a slow backoff. See [Error Handling](SECURITY_MODEL.md#error-handling).

Cost: a strict entry never enters the plaintext caches, so it is decrypted again on every read, under every memory policy — and on Android and Apple its key is fetched from the platform key store each time, which is the expensive half.

For the per-key metadata that records the policy see [Key Rotation & Key Lifetime](SECURITY_MODEL.md#key-rotation--key-lifetime); for the Android and iOS caveats see [Known Limitations](SECURITY_MODEL.md#known-limitations).

#### Multiple Safes with Different Lock Policies

You can use multiple instances for hard separation (for example, `secure` and `prefs`), but you do not have to: the policy can be set per write instead, on one instance.

```kotlin
// Android example with Koin
actual val platformModule = module {
    // Sensitive data: only accessible when device is unlocked
    single(named("secure")) {
        KSafe(
            context = androidApplication(),
            fileName = "secure",
            config = KSafeConfig(requireUnlockedDevice = true)
        )
    }

    // General preferences: readable while the device is locked
    // (on iOS/macOS: after the first unlock since boot), e.g. for background sync
    single(named("prefs")) {
        KSafe(
            context = androidApplication(),
            fileName = "prefs",
            config = KSafeConfig(requireUnlockedDevice = false)
        )
    }

    // Tell Koin which instance goes where; see SETUP.md#multiple-instances for the full pattern.
    viewModel {
        MyViewModel(
            secureSafe = get(named("secure")),
            prefsSafe = get(named("prefs"))
        )
    }
}

// Usage in ViewModel
class MyViewModel(
    private val secureSafe: KSafe,  // tokens, passwords — locked when device is locked
    private val prefsSafe: KSafe    // settings, cache — readable while the device is locked
) : ViewModel() {
    var authToken by secureSafe("")
    var lastSyncTime by prefsSafe(0L)
}
```

This pattern is especially useful for apps that perform background work (push notifications, sync) while the device is locked — the background-safe instance can still access its data, while the secure instance protects sensitive values.

***
