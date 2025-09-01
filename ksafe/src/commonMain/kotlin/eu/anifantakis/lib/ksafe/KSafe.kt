package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.flow.Flow

/**
 * An API for secure key–value storage.
 *
 * The default behavior is to encrypt data.
 */
@Suppress("unused")
expect class KSafe {
    inline fun <reified T> getDirect(key: String, defaultValue: T, encrypted: Boolean = true): T
    inline fun <reified T> putDirect(key: String, value: T, encrypted: Boolean = true)

    suspend inline fun <reified T> get(key: String, defaultValue: T, encrypted: Boolean = true): T
    inline fun <reified T> getFlow(key: String, defaultValue: T, encrypted: Boolean = true): Flow<T>
    suspend inline fun <reified T> put(key: String, value: T, encrypted: Boolean = true)

    suspend fun delete(key: String)
    fun deleteDirect(key: String)
}
