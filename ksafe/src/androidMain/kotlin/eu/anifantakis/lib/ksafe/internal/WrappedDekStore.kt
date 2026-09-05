package eu.anifantakis.lib.ksafe.internal

import android.util.Base64
import kotlinx.coroutines.runBlocking

/**
 * Persistence for a KSafe instance's KEK-wrapped DEKs, one record per master-KEK alias. One shared
 * slot would let the first `.g2` encrypt destroy the gen-1 DEK, bricking un-rotated entries.
 */
internal interface WrappedDekStore {
    fun load(alias: String): ByteArray?

    fun save(alias: String, wrapped: ByteArray)

    fun delete(alias: String)

    /**
     * True when each alias maps to its own record. In the legacy single-slot mode all aliases
     * share one record, so a per-entry [KSafeEncryption.deleteKey] must not delete it.
     */
    val isGenerationAware: Boolean
}

/**
 * [WrappedDekStore] over the safe's own DataStore. The engine's crypto is synchronous, so
 * [runBlocking] bridges the suspend storage API; DataStore's own scope keeps that deadlock-free.
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
        // Reserved `__ksafe_` namespace: not a user value, skipped by the orphan sweep, wiped by clearAll().
        const val DEK_KEY: String = "__ksafe____DEK____"

        /**
         * The base alias keeps the historical [DEK_KEY] so installs need no migration; any other
         * alias appends `@alias`, outside the alias charset.
         */
        fun recordKeyFor(baseAlias: String?, alias: String): String =
            if (baseAlias == null || alias == baseAlias) DEK_KEY else "$DEK_KEY@$alias"
    }
}
