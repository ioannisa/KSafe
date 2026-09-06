package eu.anifantakis.lib.ksafe.internal

/** Returns [size] cryptographically secure random bytes from the platform CSPRNG.
 *  @throws IllegalArgumentException if [size] is not positive. */
expect fun secureRandomBytes(size: Int): ByteArray
