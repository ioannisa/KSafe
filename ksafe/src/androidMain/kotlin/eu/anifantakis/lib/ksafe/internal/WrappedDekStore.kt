package eu.anifantakis.lib.ksafe.internal

import android.util.Base64
import kotlinx.coroutines.runBlocking

/**
 * Engine-private persistence for the single KEK-wrapped DEK of one KSafe instance.
 *
 * The wrapped DEK lives as a reserved entry in the **same DataStore** the safe already
 * uses for its values — never in `SharedPreferences`. Because there is exactly one
 * relaxed master KEK per safe, a single fixed reserved key holds that safe's DEK.
 */
internal interface WrappedDekStore {
    /** The KEK-wrapped DEK bytes, or `null` if none has been persisted yet. */
    fun load(): ByteArray?

    /** Persists [wrapped] durably, replacing any previous DEK. */
    fun save(wrapped: ByteArray)

    /** Removes the wrapped DEK (used when the KEK is permanently invalidated). */
    fun delete()
}

/**
 * [WrappedDekStore] backed by the safe's own [KSafePlatformStorage] (its DataStore).
 *
 * Stores the wrapped DEK as Base64 [StoredValue.Text] under the fixed reserved key
 * [DEK_KEY]. The engine's encrypt/decrypt entry points are synchronous, so the suspend
 * storage API is bridged with a one-time [runBlocking] — the unwrapped DEK is then cached
 * in the engine, so this blocks at most once per process (the same "block once on first
 * use" pattern as [KSafeCore]'s cold-start preload). The DataStore reads/edits here run on
 * the store's own scope, so blocking the calling thread cannot deadlock the actor.
 */
internal class DataStoreDekStore(
    private val storage: KSafePlatformStorage,
) : WrappedDekStore {

    override fun load(): ByteArray? {
        val b64 = runBlocking { (storage.snapshot()[DEK_KEY] as? StoredValue.Text)?.value }
            ?: return null
        return Base64.decode(b64, Base64.NO_WRAP)
    }

    override fun save(wrapped: ByteArray) {
        val b64 = Base64.encodeToString(wrapped, Base64.NO_WRAP)
        runBlocking { storage.applyBatch(listOf(StorageOp.Put(DEK_KEY, StoredValue.Text(b64)))) }
    }

    override fun delete() {
        runBlocking { storage.applyBatch(listOf(StorageOp.Delete(DEK_KEY))) }
    }

    companion object {
        /**
         * Fixed reserved key for the wrapped DEK. It lives in KSafe's internal `__ksafe_`
         * namespace, so [KSafeCore]'s `isInternalStorageKey` filter never surfaces it as a
         * user value, the orphan sweep (which only probes `__ksafe_value_`) never touches
         * it, and `clearAll()` (`storage.clear()`) still wipes it. One per DataStore = one
         * DEK per safe.
         */
        const val DEK_KEY: String = "__ksafe____DEK____"
    }
}
