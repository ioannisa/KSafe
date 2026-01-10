package eu.anifantakis.lib.ksafe

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.google.android.play.core.integrity.IntegrityServiceException
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.MessageDigest
import kotlin.coroutines.resume

/**
 * Android implementation using Google Play Integrity API.
 *
 * ## Setup Requirements
 * 1. Enable Play Integrity API in Google Cloud Console
 * 2. Link your app in Google Play Console
 * 3. Get your Cloud Project Number from Google Cloud Console
 *
 * ## Server-Side Verification
 * The token returned must be sent to your server, which then calls:
 * `POST https://playintegrity.googleapis.com/v1/{packageName}:decodeIntegrityToken`
 *
 * @param context Android context
 * @param cloudProjectNumber Your Google Cloud project number (not project ID)
 *
 * @see <a href="https://developer.android.com/google/play/integrity">Play Integrity Documentation</a>
 */
actual class IntegrityChecker(
    private val context: Context,
    private val cloudProjectNumber: Long
) {
    private val integrityManager = IntegrityManagerFactory.create(context)

    /**
     * Check if Play Integrity is available.
     * Returns true if Google Play Services is available.
     */
    actual fun isAvailable(): Boolean {
        return try {
            // Check if Google Play Services is available
            val googleApiAvailability = com.google.android.gms.common.GoogleApiAvailability.getInstance()
            val resultCode = googleApiAvailability.isGooglePlayServicesAvailable(context)
            resultCode == com.google.android.gms.common.ConnectionResult.SUCCESS
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Request a Play Integrity token.
     *
     * @param nonce Server-generated nonce (will be SHA-256 hashed for the request)
     * @return IntegrityResult with token or error
     */
    actual suspend fun requestIntegrityToken(nonce: String): IntegrityResult {
        if (!isAvailable()) {
            return IntegrityResult.NotSupported
        }

        return suspendCancellableCoroutine { continuation ->
            try {
                // Hash the nonce to create request hash (Play Integrity expects base64-encoded hash)
                val requestHash = hashNonce(nonce)

                val request = IntegrityTokenRequest.builder()
                    .setCloudProjectNumber(cloudProjectNumber)
                    .setNonce(requestHash)
                    .build()

                integrityManager.requestIntegrityToken(request)
                    .addOnSuccessListener { response ->
                        if (continuation.isActive) {
                            continuation.resume(
                                IntegrityResult.Success(
                                    token = response.token(),
                                    platform = "android"
                                )
                            )
                        }
                    }
                    .addOnFailureListener { exception ->
                        if (continuation.isActive) {
                            val errorCode = (exception as? IntegrityServiceException)?.errorCode
                            continuation.resume(
                                IntegrityResult.Error(
                                    message = exception.message ?: "Unknown Play Integrity error",
                                    code = errorCode
                                )
                            )
                        }
                    }
            } catch (e: Exception) {
                if (continuation.isActive) {
                    continuation.resume(
                        IntegrityResult.Error(
                            message = e.message ?: "Failed to request integrity token"
                        )
                    )
                }
            }
        }
    }

    /**
     * Hash the nonce using SHA-256 and encode as Base64.
     * Play Integrity expects a Base64-encoded hash as the nonce.
     */
    private fun hashNonce(nonce: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(nonce.toByteArray(Charsets.UTF_8))
        return android.util.Base64.encodeToString(hash, android.util.Base64.NO_WRAP)
    }
}
