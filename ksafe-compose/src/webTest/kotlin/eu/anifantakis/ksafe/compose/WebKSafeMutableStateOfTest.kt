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
 * Pins the web (wasmJs + js) cold-start contract that [KSafe.mutableStateOf]'s
 * self-heal depends on: web's `getDirect` cannot block on the async cache
 * preload, so a fresh instance returns the default until the cache warms, while
 * `getFlow(...).first()` must already carry the persisted (and, for encrypted
 * entries, decrypted) value because `LocalStorageStorage` seeds its flow from
 * `localStorage` synchronously. Plain [String] values keep this file free of
 * the kotlinx-serialization compiler plugin.
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
        // Suspending put — actually flushes to localStorage before returning,
        // unlike fire-and-forget putDirect (whose 16ms batch window is on
        // real time and would not advance under runTest's virtual clock).
        writer.put(key, stored, KSafeWriteMode.Plain)

        // Fresh instance with the same fileName simulates a page reload —
        // the in-memory cache is empty until something warms it.
        val reader = KSafe(fileName = fileName)

        // Cold-start contract: synchronous reads return the default until
        // the cache warms, which is exactly why mutableStateOf ends up with
        // initialValue == defaultValue and triggers self-heal.
        assertEquals(default, reader.getDirect(key, default))

        // Self-heal relies on this: getFlow's first emission must already
        // carry the persisted value, even with a cold KSafeCore cache,
        // because LocalStorageStorage seeds its MutableStateFlow from
        // localStorage on construction.
        val flowed = reader.getFlow(key, default).first()
        assertEquals(stored, flowed)

        // End-to-end self-heal check. The delegate boots with the default;
        // the self-heal coroutine launches on Dispatchers.Default and is
        // expected to update the state via getFlow().first(). Repeatedly
        // yielding gives the browser event loop a chance to run pending
        // microtasks (the self-heal launch + its single getFlow emission)
        // without relying on real wall-clock time, which runTest's
        // TestDispatcher virtualises away.
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
        // Suspending put — actually awaits the WebCrypto encrypt + the
        // localStorage write, so the data is durably visible to the reader.
        writer.put(key, stored) // default mode = encrypted

        val reader = KSafe(fileName = fileName)

        assertEquals(default, reader.getDirect(key, default))

        // getFlow decrypts inline on each snapshot emission — the first
        // emission must therefore already carry the decrypted plaintext.
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

        // localStorage is shared across tests in the same browser instance, so
        // each test needs its own namespace. KSafe enforces lowercase-letter
        // file names.
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
