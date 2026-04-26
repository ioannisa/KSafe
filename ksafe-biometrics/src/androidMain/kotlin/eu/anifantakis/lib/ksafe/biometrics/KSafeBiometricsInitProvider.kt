package eu.anifantakis.lib.ksafe.biometrics

import android.app.Application
import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri

/**
 * Auto-initializer for [KSafeBiometrics] on Android.
 *
 * Declared in the library's `AndroidManifest.xml`; the consumer's manifest
 * merger picks it up automatically. Android instantiates the provider during
 * application startup with the application Context, which we use to
 * bootstrap [BiometricHelper] for activity-lifecycle tracking.
 *
 * This is the same pattern used by WorkManager, Firebase, AppCompat, and
 * other libraries that need a Context once at startup. The consumer doesn't
 * need to touch their `Application` class — the library is zero-config.
 *
 * If the consumer specifically wants to disable this auto-init (rare), they
 * can override the provider in their app's manifest with
 * `tools:node="remove"` on the matching `<provider>` entry.
 */
internal class KSafeBiometricsInitProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        val app = context?.applicationContext as? Application ?: return false
        BiometricHelper.init(app)
        return true
    }

    // Required ContentProvider methods — no-ops since we never serve data.
    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0
}
