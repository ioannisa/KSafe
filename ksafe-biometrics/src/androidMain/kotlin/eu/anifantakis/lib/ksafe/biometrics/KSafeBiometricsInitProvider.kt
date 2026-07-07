package eu.anifantakis.lib.ksafe.biometrics

import android.app.Application
import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri

/**
 * Zero-config auto-initializer for [KSafeBiometrics]. Declared in the library manifest and
 * merged into the consumer's; Android instantiates it at startup with the application Context,
 * which bootstraps [BiometricHelper]'s activity-lifecycle tracking (the WorkManager/Firebase
 * pattern). To disable, remove the `<provider>` via `tools:node="remove"`.
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
