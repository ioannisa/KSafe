package eu.anifantakis.lib.ksafe.internal

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import kotlinx.coroutines.runBlocking
import java.util.concurrent.ConcurrentHashMap

/** On API 28..34 keystore2 cannot mint a `setUnlockedDeviceRequired` key while no secure lock
 *  screen exists, and there is nothing to lock against there anyway; API 35+ copes on its own. */
internal fun relaxesUnlockedDeviceRequirement(sdkInt: Int, deviceSecure: Boolean): Boolean =
    sdkInt in 28..34 && !deviceSecure

internal object AndroidLockScreen {

    /** Test seams: each replaces one INPUT of [relaxesUnlockedDeviceRequirement], never its verdict,
     *  so the API band is decided by the same code in a test as in production. */
    @Volatile internal var deviceSecureForTest: Boolean? = null

    @Volatile internal var sdkIntForTest: Int? = null

    private val relaxedMintWarning = OneShotWarning()

    /** The live decision for this device, now. Without a context (an engine built outside the
     *  factory) the flag is kept. */
    fun relaxUnlockedDeviceRequirement(context: Context? = SecurityChecker.applicationContext): Boolean {
        val deviceSecure = deviceSecureForTest
            ?: context?.getSystemService(KeyguardManager::class.java)?.isDeviceSecure
            ?: return false
        return relaxesUnlockedDeviceRequirement(sdkIntForTest ?: Build.VERSION.SDK_INT, deviceSecure)
    }

    fun warnRelaxedMint() = relaxedMintWarning.warn {
        "KSafe: no secure lock screen on API ${Build.VERSION.SDK_INT}; requireUnlockedDevice keys are " +
            "minted without setUnlockedDeviceRequired until the next key generation " +
            "(protectionInfo.notes: ${KSafeProtectionNotes.ANDROID_LOCK_SCREEN_ABSENT})."
    }
}

/** Which Keystore aliases were minted without `setUnlockedDeviceRequired`: a device that grows a
 *  lock screen does not re-bind them, so the disclosure must outlive the condition. Records sit in
 *  the reserved `__ksafe_` space beside the wrapped DEKs, wiped by `clearAll()`, gone with `deleteKey`. */
internal class RelaxedMintMarkerStore(private val storage: KSafePlatformStorage) {

    // The engine owns every write to these records, so one read stays authoritative until a wipe.
    @Volatile private var marked: MutableSet<String>? = null

    fun isMarked(alias: String): Boolean = loaded()?.contains(alias) == true

    /** Whether any key of this store was minted relaxed — per-entry aliases included, which a
     *  probe of the two master spellings never sees. */
    fun hasAny(): Boolean = loaded()?.isNotEmpty() == true

    fun mark(alias: String) {
        if (loaded()?.add(alias) == false) return
        write(StorageOp.Put(recordKey(alias), StoredValue.BoolVal(true)))
    }

    fun unmark(alias: String) {
        if (loaded()?.remove(alias) == false) return
        write(StorageOp.Delete(recordKey(alias)))
    }

    /** The wipe took the records with the rest of the store — but a mint racing it can land its
     *  own after, so drop to "unknown" and re-read rather than assume nothing survived. */
    fun onStoreCleared() {
        marked = null
    }

    /** Null when the store could not be read: unknown, so the next call retries instead of
     *  caching "nothing is marked" and hiding a degrade for the life of the process. */
    private fun loaded(): MutableSet<String>? {
        marked?.let { return it }
        synchronized(this) {
            marked?.let { return it }
            val snapshot = runCatching { runBlocking { storage.snapshot() } }.getOrElse { return null }
            val set = ConcurrentHashMap.newKeySet<String>()
            for (key in snapshot.keys) {
                if (key.startsWith(RECORD_PREFIX)) set.add(key.removePrefix(RECORD_PREFIX))
            }
            marked = set
            return set
        }
    }

    private fun write(op: StorageOp) {
        // Diagnostic state: an unwritable record must not fail the key operation that produced it.
        runCatching { runBlocking { storage.applyBatch(listOf(op)) } }
    }

    companion object {
        /** Reserved `__ksafe_` namespace, one record per alias: not a user value, skipped by the
         *  orphan sweep, wiped by clearAll(). */
        const val RECORD_PREFIX: String = "__ksafe____NOUNLOCKBIND____@"

        fun recordKey(alias: String): String = RECORD_PREFIX + alias
    }
}
