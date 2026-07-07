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
 * Locks in: a transient read failure on the JSON-fallback file propagates out of the serializer instead of reading as an empty store, which would wipe every entry on the next write.
 */
class JvmJsonSerializerReadFailureTest {

    private val serializer = DataStoreJsonStorage.JsonMapSerializer

    /** An InputStream whose read fails partway, like a disk error mid-read. */
    private class FailingInputStream : InputStream() {
        override fun read(): Int = throw IOException("simulated transient read failure")
        override fun read(b: ByteArray, off: Int, len: Int): Int =
            throw IOException("simulated transient read failure")
    }

    @Test
    fun transientReadFailure_propagates_insteadOfReturningEmptyStore() {
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
        // Non-blank unparseable content must route to the corruption handler, not read as empty.
        assertFailsWith<CorruptionException> {
            runBlocking { serializer.readFrom("}{ not json".encodeToByteArray().inputStream()) }
        }
    }
}
