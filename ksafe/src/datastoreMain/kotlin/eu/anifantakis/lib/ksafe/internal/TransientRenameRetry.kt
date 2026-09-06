package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay

// DataStore rewrites the store by renaming a scratch file over it, and that rename loses to any
// other program holding either file open — on Windows an antivirus, the search indexer or a backup
// agent do it routinely. DataStore blames multiple instances; the condition clears in milliseconds.
internal const val TRANSIENT_RENAME_MARKER: String = "Unable to rename"

internal const val TRANSIENT_RENAME_RETRIES: Int = 5

internal fun isTransientRenameFailure(error: Throwable): Boolean {
    var cause: Throwable? = error
    var depth = 0
    while (cause != null && depth++ < 5) {
        if (cause.message?.contains(TRANSIENT_RENAME_MARKER) == true) return true
        cause = cause.cause
    }
    return false
}

/**
 * Repeats [commit] while the store rewrite keeps losing its rename to another program's file
 * handle, then rethrows. Safe to repeat: a lost rename leaves the file unchanged and every
 * attempt recomputes the transform from the file.
 */
internal suspend inline fun <T> retryingTransientRename(commit: () -> T): T {
    var attempt = 0
    while (true) {
        try {
            val committed = commit()
            if (attempt > 0) {
                ksafeLogWarning(
                    "KSafe: the store rewrite lost its rename to another program holding the file " +
                        "open (antivirus, indexer or backup); it succeeded on attempt ${attempt + 1}.",
                )
            }
            return committed
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if (attempt == TRANSIENT_RENAME_RETRIES || !isTransientRenameFailure(e)) throw e
            delay(20L shl attempt++) // 20ms doubling to 320ms
        }
    }
}
