# Alternatives & Comparison

| Feature | KSafe | EncryptedSharedPrefs | KVault | Multiplatform Settings | SQLCipher |
|---------|-------|---------------------|--------|------------------------|-----------|
| **KMP Support** | ✅ Android, iOS, macOS, JVM Desktop, WASM, JS | ❌ Android only | ✅ Android, iOS | ✅ Multi-platform | ⚠️ Limited |
| **Hardware-backed Keys** | ✅ Keystore/Keychain | ✅ Keystore | ✅ Keystore/Keychain | ❌ No encryption | ❌ Software |
| **Zero Boilerplate** | ✅ `by ksafe(0)` | ❌ Verbose API | ⚠️ Moderate | ⚠️ Moderate | ❌ SQL required |
| **Key Rotation** | ✅ `rotateKeys()` + `MaxAge` policy + authenticated v3 envelope | ❌ Manual | ❌ Manual | ❌ Manual | ⚠️ Manual re-key |
| **Biometric Helper** | ✅ Real OS prompts on Android, iOS/macOS, JVM Desktop (Touch ID / Windows Hello) & web (WebAuthn) via `:ksafe-biometrics` | ❌ Manual | ❌ Manual | ❌ Manual | ❌ Manual |
| **Compose State** | ✅ `mutableStateOf` | ❌ Manual | ❌ Manual | ❌ Manual | ❌ Manual |
| **Type Safety** | ✅ Reified generics | ⚠️ Limited | ✅ Good | ✅ Good | ❌ SQL strings |
| **Auth Caching** | ✅ Scoped sessions | ❌ No | ❌ No | ❌ No | ❌ No |
| **Operational Preflight** | ✅ `isEncryptionOperational` — will an encrypted write actually succeed? | ❌ No | ❌ No | ❌ No | ❌ No |

**When to choose KSafe:**
- You want one single dependency that handles both blazing-fast plain-text preferences AND hardware-isolated secrets
- You need encrypted persistence across Android, iOS, Desktop, and Web
- You want property delegation (`by ksafe(x)`) for minimal boilerplate
- You need integrated biometric authentication with smart caching
- You're using Jetpack Compose and want reactive encrypted state
- You need periodic key rotation for compliance hygiene — `rotateKeys()` plus a `MaxAge` policy re-encrypts the whole store under a fresh key generation in the background, without ever blocking startup or reads
- You want tamper-evident storage — once rotated, encrypted entries carry an authenticated envelope so they can't be copied, swapped, or relocated between keys; tampering that moves, swaps, or re-tiers an *encrypted* entry breaks the GCM tag, so the read fails closed to the caller's default instead of decrypting in the wrong context (rewriting an entry's metadata to plaintext instead reclassifies it as plaintext, so the read returns the stored bytes verbatim — undecipherable ciphertext, never the underlying secret)
- Performance is critical — KSafe encrypted reads and writes are dramatically faster than KVault (see [BENCHMARKS.md](BENCHMARKS.md); figures measured on the 2.1.2 run and current for 3.0.0)

**Browser support, specifically:** KSafe ships two independent web artifacts — a Kotlin/WASM build (WasmGC) and a Kotlin/JS build for older browsers — sharing one `localStorage` layout and AES-256-GCM via WebCrypto, so you can switch targets without losing data; call `awaitCacheReady()` once at startup before the first encrypted read. See [SETUP.md](SETUP.md) and [ARCHITECTURE.md](ARCHITECTURE.md) for details.

**When to consider alternatives:**
- You need complex queries → Consider SQLCipher or Room with encryption
- Android-only app with simple needs → EncryptedSharedPreferences works
- No encryption needed → Multiplatform Settings is lighter
- Simple KMP encryption needs → KVault is a good alternative (but slower)
