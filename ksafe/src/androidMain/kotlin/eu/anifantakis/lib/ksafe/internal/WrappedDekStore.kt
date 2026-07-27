package eu.anifantakis.lib.ksafe.internal

import android.util.Base64
import kotlinx.coroutines.runBlocking

/**
 * Persistence for a KSafe instance's KEK-wrapped DEKs, one record per master-KEK alias.
 * Records live as reserved entries in the safe's own DataStore (never SharedPreferences).
 *
 * Generation-aware since 3.0.0: key rotation encrypts under generation-suffixed master
 * aliases (`master.gN`), each wrapping its own DEK. A single fixed slot would make the first
 * `.g2` encrypt destroy the gen-1 DEK (its KEK can't unwrap the old record, and the recovery
 * path deleted the only persisted copy) — bricking every not-yet-rotated entry after a
 * restart. Per-alias records keep every generation's DEK independently durable until
 * [KSafeEncryption.deleteKey] reclaims it with its KEK.
 */
internal interface WrappedDekStore {
    /** The KEK-wrapped DEK bytes for [alias], or `null` if none has been persisted. */
    fun load(alias: String): ByteArray?

    /** Persists [wrapped] durably for [alias], replacing any previous DEK for that alias. */
    fun save(alias: String, wrapped: ByteArray)

    /** Removes the wrapped DEK for [alias] (KEK invalidation, or generation reclamation). */
    fun delete(alias: String)

    /**
     * True when each alias maps to its OWN record (generation-aware mode). In the legacy
     * single-slot mode (no base alias) every alias collides on one record, so a per-entry
     * [KSafeEncryption.deleteKey] must NOT delete it (it would brick every DEFAULT value) —
     * the DEK is removed only by `discardDek`/`clearAll`, matching pre-3.0.0 behaviour.
     */
    val isGenerationAware: Boolean
}

/**
 * [WrappedDekStore] backed by the safe's own DataStore, storing each wrapped DEK as Base64
 * [StoredValue.Text]. The engine's encrypt/decrypt are synchronous, so the suspend storage API
 * is bridged with [runBlocking]; the engine then caches the unwrapped DEK, so this blocks at
 * most once per process per alias. DataStore runs on its own scope, so blocking the calling
 * thread cannot deadlock the actor.
 *
 * [baseAlias] (the un-suffixed relaxed master — the only alias that ever used the DEK before
 * rotation existed) maps to the historical fixed [DEK_KEY], so existing installs upgrade with
 * zero migration; every other alias gets its own derived record.
 */
internal class DataStoreDekStore(
    private val storage: KSafePlatformStorage,
    private val baseAlias: String? = null,
) : WrappedDekStore {

    override val isGenerationAware: Boolean = baseAlias != null

    private fun recordKey(alias: String): String = recordKeyFor(baseAlias, alias)

    override fun load(alias: String): ByteArray? {
        val key = recordKey(alias)
        val b64 = runBlocking { (storage.snapshot()[key] as? StoredValue.Text)?.value }
            ?: return null
        return Base64.decode(b64, Base64.NO_WRAP)
    }

    override fun save(alias: String, wrapped: ByteArray) {
        val b64 = Base64.encodeToString(wrapped, Base64.NO_WRAP)
        runBlocking { storage.applyBatch(listOf(StorageOp.Put(recordKey(alias), StoredValue.Text(b64)))) }
    }

    override fun delete(alias: String) {
        runBlocking { storage.applyBatch(listOf(StorageOp.Delete(recordKey(alias)))) }
    }

    companion object {
        // Reserved key for the base (pre-rotation) wrapped DEK, in the internal `__ksafe_`
        // namespace so it's never surfaced as a user value nor touched by the orphan sweep,
        // yet `clearAll()` still wipes it.
        const val DEK_KEY: String = "__ksafe____DEK____"

        /**
         * Record key for one alias's wrapped DEK. The base alias keeps the exact historical
         * [DEK_KEY] (zero-migration invariant); any other alias appends itself after an `@`
         * (outside the alias charset of dots and identifier characters), staying inside the
         * reserved `__ksafe_` namespace. Null [baseAlias] preserves the legacy single-slot
         * behaviour for any test construction that predates generation awareness.
         */
        fun recordKeyFor(baseAlias: String?, alias: String): String =
            if (baseAlias == null || alias == baseAlias) DEK_KEY else "$DEK_KEY@$alias"
    }
}
