package eu.anifantakis.lib.ksafe

/**
 * JVM/Desktop stub for IntegrityChecker.
 *
 * Device integrity verification is not available on JVM/Desktop platforms.
 * All methods return [IntegrityResult.NotSupported].
 *
 * For server-side applications, consider using other verification methods
 * such as client certificates or hardware security keys.
 */
actual class IntegrityChecker {

    /**
     * Always returns false on JVM - integrity checking is not supported.
     */
    actual fun isAvailable(): Boolean = false

    /**
     * Always returns [IntegrityResult.NotSupported] on JVM.
     */
    actual suspend fun requestIntegrityToken(nonce: String): IntegrityResult {
        return IntegrityResult.NotSupported
    }
}
