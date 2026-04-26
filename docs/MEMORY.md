# Memory Security Policy

Control the trade-off between performance and security for data in RAM:

```Kotlin
val ksafe = KSafe(
    fileName = "secrets",
    memoryPolicy = KSafeMemoryPolicy.ENCRYPTED // Default
)
```

| Policy | Best For | RAM Contents | Read Cost | Security |
|--------|----------|-------------|-----------|----------|
| `PLAIN_TEXT` | User settings, themes | Plaintext (forever) | O(1) lookup | Low — all data exposed in memory |
| `ENCRYPTED` (Default) | Tokens, passwords | Ciphertext only | AES-GCM decrypt every read | High — nothing plaintext in RAM |
| `ENCRYPTED_WITH_TIMED_CACHE` | Compose/SwiftUI screens | Ciphertext + short-lived plaintext | First read decrypts, then O(1) for TTL | Medium — plaintext only for recently-accessed keys, only for seconds |

All three policies encrypt data on disk. The difference is how data is handled in memory:
- **PLAIN_TEXT:** Maximum performance — decrypts once on load, stores plain values forever
- **ENCRYPTED:** Maximum security — stores ciphertext in RAM, decrypts on-demand every read
- **ENCRYPTED_WITH_TIMED_CACHE:** Best balance — stores ciphertext in RAM, but caches decrypted values for a configurable TTL

### ENCRYPTED_WITH_TIMED_CACHE — The Balanced Policy

Under `ENCRYPTED` policy, every read triggers AES-GCM decryption. In UI frameworks like Jetpack Compose or SwiftUI, the same encrypted property may be read multiple times during a single recomposition/re-render. `ENCRYPTED_WITH_TIMED_CACHE` eliminates redundant crypto: only the first read decrypts; subsequent reads within the TTL window are pure memory lookups.

```kotlin
val ksafe = KSafe(
    context = context,
    memoryPolicy = KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE,
    plaintextCacheTtl = 5.seconds  // default; how long plaintext stays cached
)
```

**How it works internally:**
```
Read 1: decrypt → cache plaintext (TTL=5s) → return       ← one crypto operation
Read 2 (50ms later):  cache hit → return                   ← no decryption
Read 3 (100ms later): cache hit → return                   ← no decryption
...TTL expires...
Read 4: decrypt → cache plaintext (TTL=5s) → return        ← one crypto operation
```

**Thread safety:** Reads capture a local reference to the cached entry atomically. No background sweeper — expired entries are simply ignored on the next access. No race conditions possible.

### Lazy Loading

```Kotlin
val archive = KSafe(
    fileName = "archive",
    lazyLoad = true  // Skip preload, load on first request
)
```

### Constructor Parameters

```Kotlin
// Android
KSafe(
    context: Context,
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,  // only used with ENCRYPTED_WITH_TIMED_CACHE
    useStrongBox: Boolean = false,            // deprecated — use KSafeProtection.HARDWARE_ISOLATED per-property
    baseDir: File? = null                     // override the default DataStore directory (see docs/SETUP.md)
)

// JVM
KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    baseDir: File? = null                     // override the default DataStore directory (default: ~/.eu_anifantakis_ksafe)
)

// iOS
KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    useSecureEnclave: Boolean = false,        // deprecated — use KSafeProtection.HARDWARE_ISOLATED per-property
    directory: String? = null                 // override the default DataStore directory (default: NSApplicationSupportDirectory)
)

// Web (Kotlin/WASM + Kotlin/JS)
KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,  // accepted for API parity; ignored — always PLAIN_TEXT internally
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds
    // No baseDir / directory: localStorage has no directory concept — instances are isolated
    // by the `ksafe_<fileName>_` storage-key prefix.
)
```

### Encryption Configuration

```Kotlin
val ksafe = KSafe(
    context = context,
    config = KSafeConfig(
        keySize = 256,                       // AES key size: 128 or 256 bits
        androidAuthValiditySeconds = 30,     // reserved for future use (currently unused; default 30, must be > 0)
        requireUnlockedDevice = false,       // Default for protection-based encrypted writes
        json = KSafeDefaults.json            // Custom kotlinx.serialization Json — see docs/SERIALIZATION.md
    )
)
```

**Note:** The encryption algorithm (AES-GCM) is intentionally NOT configurable to prevent insecure configurations.

### Device Lock-State Policy

Control whether encrypted data is only accessible when the device is unlocked.

You now have two options:
1. **Per-entry (recommended):** Use `KSafeWriteMode.Encrypted(requireUnlockedDevice = ...)`
2. **Default fallback:** Use `KSafeConfig(requireUnlockedDevice = ...)` for no-mode encrypted writes (`put`/`putDirect` without `mode`)

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

// Fallback default for no-mode encrypted writes
val ksafe = KSafe(
    context = context,
    config = KSafeConfig(requireUnlockedDevice = true)
)

```

| Platform | `false` (default) | `true` |
|----------|-------------------|--------|
| **Android** | Keys accessible at any time | `setUnlockedDeviceRequired(true)` (API 28+) |
| **iOS** | `AfterFirstUnlockThisDeviceOnly` | `WhenUnlockedThisDeviceOnly` |
| **JVM** | No effect (software keys) | No effect (software keys) |
| **Kotlin/WASM** | No effect (browser has no lock concept) | No effect |
| **Kotlin/JS** | No effect (browser has no lock concept) | No effect |

**Important:** `requireUnlockedDevice` applies only to encrypted writes.
`KSafeWriteMode.Plain` intentionally does not use unlock policy.

**Metadata shape:** unlock policy is recorded per key in `__ksafe_meta_{key}__` JSON (`"u":"unlocked"` only when enabled). There is no global per-instance access-policy marker.

**Error behavior when locked:** When `requireUnlockedDevice = true` and the device is locked, encrypted **reads** (`getDirect`, `get`, `getFlow`) throw `IllegalStateException`. The suspend `put()` also throws for encrypted data. However, `putDirect` does **not** throw to the caller — it queues the write to a background consumer that logs the error and drops the batch (the consumer stays alive for future writes after the device is unlocked). Your app can catch read-side exceptions to show a "device is locked" message instead of silently receiving default values.

#### Multiple Safes with Different Lock Policies

You can still use multiple instances for hard separation (for example, `secure` and `prefs`), but it is no longer required for lock-policy control because policy can be set per write entry.

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

    // General preferences: accessible even when locked (e.g., for background sync)
    single(named("prefs")) {
        KSafe(
            context = androidApplication(),
            fileName = "prefs",
            config = KSafeConfig(requireUnlockedDevice = false)
        )
    }
}

// Usage in ViewModel
class MyViewModel(
    private val secureSafe: KSafe,  // tokens, passwords — locked when device is locked
    private val prefsSafe: KSafe    // settings, cache — always accessible
) : ViewModel() {
    var authToken by secureSafe("")
    var lastSyncTime by prefsSafe(0L)
}
```

This pattern is especially useful for apps that perform background work (push notifications, sync) while the device is locked — the background-safe instance can still access its data, while the secure instance protects sensitive values.

***
