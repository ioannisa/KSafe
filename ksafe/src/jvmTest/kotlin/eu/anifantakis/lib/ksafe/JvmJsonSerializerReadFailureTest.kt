package eu.anifantakis.lib.ksafe

import androidx.datastore.core.CorruptionException
import eu.anifantakis.lib.ksafe.internal.DataStoreJsonStorage
import kotlinx.coroutines.runBlocking
import java.io.IOException
import java.io.InputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Regression test for deep-review #33: a transient read failure on an existing JSON-fallback
 * file must **propagate** out of the serializer, not be swallowed as an empty store. If it
 * returned `emptyMap()`, datastore-core would cache that as the current state and the next
 * write would atomically overwrite the real file with empty — silently wiping every entry.
 * Letting it propagate leaves the file untouched (DataStore never writes on a failed read).
 */
class JvmJsonSerializerReadFailureTest {

    private val serializer = DataStoreJsonStorage.JsonMapSerializer

    /** An InputStream whose read fails partway, like a disk/network-FS error mid-read. */
    private class FailingInputStream : InputStream() {
        override fun read(): Int = throw IOException("simulated transient read failure")
        override fun read(b: ByteArray, off: Int, len: Int): Int =
            throw IOException("simulated transient read failure")
    }

    @Test
    fun transientReadFailure_propagates_insteadOfReturningEmptyStore() {
        // Pre-fix: readFrom caught IOException and returned emptyMap() → data wipe on next write.
        assertFailsWith<IOException> {
            runBlocking { serializer.readFrom(FailingInputStream()) }
        }
    }

    @Test
    fun validJson_roundTrips() {
        val bytes = """{"a":"1","b":"two"}""".encodeToByteArray()
        val out = runBlocking { serializer.readFrom(bytes.inputStream()) }
        assertEquals(mapOf("a" to "1", "b" to "two"), out)
    }

    @Test
    fun blankFile_isFreshStore() {
        val out = runBlocking { serializer.readFrom(ByteArray(0).inputStream()) }
        assertEquals(emptyMap(), out)
    }

    @Test
    fun unparseableContent_signalsCorruption_notEmpty() {
        // Genuine corruption (non-blank, unparseable) must route to the corruption
        // handler via CorruptionException — never be discarded as empty.
        assertFailsWith<CorruptionException> {
            runBlocking { serializer.readFrom("}{ not json".encodeToByteArray().inputStream()) }
        }
    }
}
