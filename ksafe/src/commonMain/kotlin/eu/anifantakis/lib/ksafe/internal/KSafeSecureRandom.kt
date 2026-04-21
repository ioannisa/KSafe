package eu.anifantakis.lib.ksafe.internal

/**
 * Generates a [ByteArray] of cryptographically secure random bytes.
 *
 * This function delegates to the platform's strongest available CSPRNG:
 *
 * | Platform | Source |
 * |----------|--------|
 * | Android  | `java.security.SecureRandom` |
 * | JVM      | `java.security.SecureRandom` |
 * | iOS      | `SecRandomCopyBytes` (Security framework) |
 * | WASM     | `crypto.getRandomValues()` (WebCrypto API) |
 *
 * ## Example
 * ```kotlin
 * val nonce = secureRandomBytes(16)
 * val aesKey = secureRandomBytes(32)  // 256-bit key
 * ```
 *
 * @param size Number of random bytes to generate. Must be positive.
 * @return A new [ByteArray] filled with cryptographically secure random bytes.
 * @throws IllegalArgumentException if [size] is not positive.
 */
expect fun secureRandomBytes(size: Int): ByteArray
