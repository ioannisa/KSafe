package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.DeviceCheck.DCDevice
import platform.Foundation.NSData
import platform.Foundation.NSError
import platform.Foundation.base64EncodedStringWithOptions
import kotlin.coroutines.resume

/**
 * iOS implementation using DeviceCheck framework.
 *
 * ## How DeviceCheck Works
 * DeviceCheck generates a token that uniquely identifies the device (not the user).
 * The token can be verified server-side with Apple's DeviceCheck API.
 *
 * ## Server-Side Verification
 * The token must be sent to your server, which calls Apple's API:
 * `POST https://api.devicecheck.apple.com/v1/validate_device_token`
 *
 * Your server needs:
 * - Apple Developer account
 * - DeviceCheck private key (.p8 file)
 * - Key ID and Team ID
 *
 * ## Limitations
 * - DeviceCheck is available on iOS 11+
 * - Tokens are device-specific, not install-specific
 * - Apple rate limits: 3 updates per device per week
 *
 * @see <a href="https://developer.apple.com/documentation/devicecheck">DeviceCheck Documentation</a>
 */
actual class IntegrityChecker {

    /**
     * Check if DeviceCheck is available on this device.
     * Returns false on simulator or iOS < 11.
     */
    actual fun isAvailable(): Boolean {
        return DCDevice.currentDevice.isSupported()
    }

    /**
     * Request a DeviceCheck token.
     *
     * @param nonce Server-generated nonce (included in your server request, not in token)
     *              DeviceCheck tokens don't include the nonce directly - you should
     *              send both the token AND nonce to your server for verification.
     * @return IntegrityResult with token or error
     */
    @OptIn(ExperimentalForeignApi::class)
    actual suspend fun requestIntegrityToken(nonce: String): IntegrityResult {
        if (!isAvailable()) {
            return IntegrityResult.NotSupported
        }

        return suspendCancellableCoroutine { continuation ->
            DCDevice.currentDevice.generateTokenWithCompletionHandler { tokenData: NSData?, error: NSError? ->
                when {
                    error != null -> {
                        if (continuation.isActive) {
                            continuation.resume(
                                IntegrityResult.Error(
                                    message = error.localizedDescription,
                                    code = error.code.toInt()
                                )
                            )
                        }
                    }
                    tokenData != null -> {
                        if (continuation.isActive) {
                            val tokenString = tokenData.base64EncodedStringWithOptions(0u)
                            continuation.resume(
                                IntegrityResult.Success(
                                    token = tokenString,
                                    platform = "ios"
                                )
                            )
                        }
                    }
                    else -> {
                        if (continuation.isActive) {
                            continuation.resume(
                                IntegrityResult.Error(
                                    message = "DeviceCheck returned no token and no error"
                                )
                            )
                        }
                    }
                }
            }
        }
    }
}
