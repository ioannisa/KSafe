# Alternatives & Comparison

| Feature | KSafe | EncryptedSharedPrefs | KVault | Multiplatform Settings | SQLCipher |
|---------|-------|---------------------|--------|------------------------|-----------|
| **KMP Support** | ✅ Android, iOS, JVM, WASM | ❌ Android only | ✅ Android, iOS | ✅ Multi-platform | ⚠️ Limited |
| **Hardware-backed Keys** | ✅ Keystore/Keychain | ✅ Keystore | ✅ Keystore/Keychain | ❌ No encryption | ❌ Software |
| **Zero Boilerplate** | ✅ `by ksafe(0)` | ❌ Verbose API | ⚠️ Moderate | ⚠️ Moderate | ❌ SQL required |
| **Biometric Helper** | ✅ Built-in | ❌ Manual | ❌ Manual | ❌ Manual | ❌ Manual |
| **Compose State** | ✅ `mutableStateOf` | ❌ Manual | ❌ Manual | ❌ Manual | ❌ Manual |
| **Type Safety** | ✅ Reified generics | ⚠️ Limited | ✅ Good | ✅ Good | ❌ SQL strings |
| **Auth Caching** | ✅ Scoped sessions | ❌ No | ❌ No | ❌ No | ❌ No |

**When to choose KSafe:**
- You want one single dependency that handles both blazing-fast plain-text preferences AND hardware-isolated secrets
- You need encrypted persistence across Android, iOS, Desktop, and Web
- You want property delegation (`by ksafe(x)`) for minimal boilerplate
- You need integrated biometric authentication with smart caching
- You're using Jetpack Compose and want reactive encrypted state
- Performance is critical — KSafe is **14x faster** than KVault for encrypted reads, **34x faster** for writes

**When to consider alternatives:**
- You need complex queries → Consider SQLCipher or Room with encryption
- Android-only app with simple needs → EncryptedSharedPreferences works
- No encryption needed → Multiplatform Settings is lighter
- Simple KMP encryption needs → KVault is a good alternative (but slower)
