package eu.anifantakis.ksafe.compose

import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.KSafeWriteMode
import eu.anifantakis.lib.ksafe.awaitCacheReady
import eu.anifantakis.lib.ksafe.compose.mutableStateOf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield

/**
 * Locks in: the web (wasmJs + js) cold-start contract behind [KSafe.mutableStateOf]'s self-heal —
 * synchronous `getDirect` returns the default until the async cache warms, while `getFlow().first()`
 * already carries the persisted (and, for encrypted entries, decrypted) value because
 * `LocalStorageStorage` seeds its flow from `localStorage` synchronously.
 */
class WebKSafeMutableStateOfTest {

    @Test
    fun coldStart_plain_getFlowFirstEmissionContainsPersistedValue() = runTest {
        val fileName = uniqueFileName()
        val key = "plain_value"
        val stored = "persisted-plain"
        val default = "default-plain"

        val writer = KSafe(fileName = fileName)
        writer.awaitCacheReady()
        // Suspending put flushes before returning; putDirect's 16ms real-time batch window
        // would not advance under runTest's virtual clock.
        writer.put(key, stored, KSafeWriteMode.Plain)

        // Fresh instance (same fileName) simulates a page reload: the cache is empty until warmed.
        val reader = KSafe(fileName = fileName)

        // Cold start: synchronous reads return the default until the cache warms — this is what
        // makes mutableStateOf boot with the default and trigger self-heal.
        assertEquals(default, reader.getDirect(key, default))

        // Self-heal relies on getFlow's first emission already carrying the persisted value, even
        // with a cold cache, because LocalStorageStorage seeds its flow from localStorage on construction.
        val flowed = reader.getFlow(key, default).first()
        assertEquals(stored, flowed)

        // End-to-end self-heal: the delegate boots with the default, then a coroutine on
        // Dispatchers.Default updates it via getFlow().first(). Repeated yield() lets the browser
        // event loop run those microtasks without real wall-clock time (which runTest virtualises away).
        var value by reader.mutableStateOf(
            defaultValue = default,
            key = key,
            mode = KSafeWriteMode.Plain,
        )
        assertEquals(default, value, "cold-start initial read returns default")
        repeat(50) { yield() }
        assertEquals(stored, value, "self-heal must update Compose state to the persisted value")

        reader.clearAll()
    }

    @Test
    fun coldStart_encrypted_getFlowFirstEmissionContainsDecryptedValue() = runTest {
        val fileName = uniqueFileName()
        val key = "encrypted_value"
        val stored = "persisted-encrypted"
        val default = "default-encrypted"

        val writer = KSafe(fileName = fileName)
        writer.awaitCacheReady()
        // Suspending put awaits the WebCrypto encrypt + localStorage write, so data is durably visible.
        writer.put(key, stored) // default mode = encrypted

        val reader = KSafe(fileName = fileName)

        assertEquals(default, reader.getDirect(key, default))

        // getFlow decrypts inline per emission, so the first emission already carries the plaintext.
        val flowed = reader.getFlow(key, default).first()
        assertEquals(stored, flowed)

        var value by reader.mutableStateOf(
            defaultValue = default,
            key = key,
            mode = KSafeWriteMode.Encrypted(),
        )
        assertEquals(default, value, "cold-start initial read returns default")
        repeat(50) { yield() }
        assertEquals(stored, value, "self-heal must update Compose state to the persisted value")

        reader.clearAll()
    }

    companion object {
        private var counter = 0

        // localStorage is shared across tests; each needs its own namespace. KSafe enforces lowercase-letter fileNames.
        private fun uniqueFileName(): String {
            counter++
            val sb = StringBuilder("composeselfheal")
            var x = counter
            while (x > 0) {
                x--
                sb.append('a' + (x % 26))
                x /= 26
            }
            return sb.toString()
        }
    }
}
