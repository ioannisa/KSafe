package eu.anifantakis.lib.ksafe.internal

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.doublePreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.floatPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

/**
 * [KSafePlatformStorage] backed by a Jetpack `DataStore<Preferences>`.
 *
 * This adapter is the only place in the library that knows about DataStore's
 * typed [Preferences.Key] machinery. It translates between [StoredValue] and
 * the matching typed key on write, and does the reverse on read so the core
 * orchestrator can work entirely in terms of the sealed [StoredValue] type.
 *
 * DataStore already gives us atomic `edit {}` blocks and a change-notifying
 * `data: Flow<Preferences>`, so both batching and observation map directly.
 */
@PublishedApi
internal class DataStoreStorage(
    @PublishedApi internal val dataStore: DataStore<Preferences>,
) : KSafePlatformStorage {

    override suspend fun snapshot(): Map<String, StoredValue> =
        toStoredMap(dataStore.data.first())

    override fun snapshotFlow(): Flow<Map<String, StoredValue>> =
        dataStore.data.map(::toStoredMap)

    override suspend fun applyBatch(ops: List<StorageOp>) {
        if (ops.isEmpty()) return
        dataStore.edit { prefs ->
            for (op in ops) when (op) {
                is StorageOp.Put -> writeOne(prefs, op.rawKey, op.value)
                is StorageOp.Delete -> removeByName(prefs, op.rawKey)
            }
        }
    }

    override suspend fun clear() {
        dataStore.edit { it.clear() }
    }

    private fun writeOne(prefs: MutablePreferences, rawKey: String, value: StoredValue) {
        when (value) {
            is StoredValue.BoolVal -> prefs[booleanPreferencesKey(rawKey)] = value.value
            is StoredValue.IntVal -> prefs[intPreferencesKey(rawKey)] = value.value
            is StoredValue.LongVal -> prefs[longPreferencesKey(rawKey)] = value.value
            is StoredValue.FloatVal -> prefs[floatPreferencesKey(rawKey)] = value.value
            is StoredValue.DoubleVal -> prefs[doublePreferencesKey(rawKey)] = value.value
            is StoredValue.Text -> prefs[stringPreferencesKey(rawKey)] = value.value
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun removeByName(prefs: MutablePreferences, rawKey: String) {
        prefs.asMap().keys.firstOrNull { it.name == rawKey }?.let {
            prefs.remove(it as Preferences.Key<Any?>)
        }
    }

    private fun toStoredMap(prefs: Preferences): Map<String, StoredValue> {
        val raw = prefs.asMap()
        val out = HashMap<String, StoredValue>(raw.size)
        for ((k, v) in raw) {
            val sv: StoredValue = when (v) {
                is Boolean -> StoredValue.BoolVal(v)
                is Int -> StoredValue.IntVal(v)
                is Long -> StoredValue.LongVal(v)
                is Float -> StoredValue.FloatVal(v)
                is Double -> StoredValue.DoubleVal(v)
                is String -> StoredValue.Text(v)
                else -> continue   // Set<String> or any other type KSafe doesn't emit
            }
            out[k.name] = sv
        }
        return out
    }
}
