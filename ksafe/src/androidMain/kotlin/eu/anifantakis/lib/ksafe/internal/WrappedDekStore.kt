package eu.anifantakis.lib.ksafe.internal

import android.util.Base64
import kotlinx.coroutines.runBlocking

/**
 * Persistence for one KSafe instance's single KEK-wrapped DEK. It lives as a reserved entry
 * in the safe's own DataStore (never SharedPreferences); one relaxed master KEK per safe means
 * one fixed reserved key holds the DEK.
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
 * [WrappedDekStore] backed by the safe's own DataStore, storing the wrapped DEK as Base64
 * [StoredValue.Text] under [DEK_KEY]. The engine's encrypt/decrypt are synchronous, so the
 * suspend storage API is bridged with [runBlocking]; the engine then caches the unwrapped DEK,
 * so this blocks at most once per process. DataStore runs on its own scope, so blocking the
 * calling thread cannot deadlock the actor.
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
        // Reserved key for the wrapped DEK, in the internal `__ksafe_` namespace so it's never
        // surfaced as a user value nor touched by the orphan sweep, yet `clearAll()` still wipes it.
        const val DEK_KEY: String = "__ksafe____DEK____"
    }
}
