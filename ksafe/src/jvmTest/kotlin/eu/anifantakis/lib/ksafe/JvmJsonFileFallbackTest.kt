package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.JsonFileStorage
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.keyvault.FileKeyVault
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit coverage for the JVM no-`Unsafe` fallback backends:
 * [JsonFileStorage] (the [eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage]
 * impl) and [FileKeyVault] (the software [eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVault]).
 * These are what KSafe selects when `sun.misc.Unsafe` (module `jdk.unsupported`)
 * is absent, so DataStore's protobuf can't run — neither class touches protobuf
 * or `Unsafe`. The end-to-end "runs under a trimmed jlink runtime" gate is
 * covered separately (see JSONFILE_FALLBACK_PLAN.md).
 */
class JvmJsonFileFallbackTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_jsonfb_${System.nanoTime()}")
        .apply { mkdirs() }

    @AfterTest
    fun tearDown() {
        tmp.deleteRecursively()
    }

    // ── JsonFileStorage ──────────────────────────────────────────────────────

    @Test
    fun jsonStorage_putGetDelete_roundTrips() = runTest {
        val store = JsonFileStorage(File(tmp, "a.json"))
        store.applyBatch(listOf(StorageOp.Put("__ksafe_value_token", StoredValue.Text("abc"))))
        assertEquals(StoredValue.Text("abc"), store.snapshot()["__ksafe_value_token"])

        store.applyBatch(listOf(StorageOp.Delete("__ksafe_value_token")))
        assertNull(store.snapshot()["__ksafe_value_token"])
    }

    @Test
    fun jsonStorage_flattensAllTypesToText() = runTest {
        // Mirrors LocalStorageStorage: everything is stored/returned as Text;
        // KSafeCore re-types primitives via the request serializer on read.
        val store = JsonFileStorage(File(tmp, "types.json"))
        store.applyBatch(
            listOf(
                StorageOp.Put("i", StoredValue.IntVal(42)),
                StorageOp.Put("l", StoredValue.LongVal(7L)),
                StorageOp.Put("b", StoredValue.BoolVal(true)),
                StorageOp.Put("d", StoredValue.DoubleVal(1.5)),
                StorageOp.Put("s", StoredValue.Text("hi")),
            )
        )
        val snap = store.snapshot()
        assertEquals(StoredValue.Text("42"), snap["i"])
        assertEquals(StoredValue.Text("7"), snap["l"])
        assertEquals(StoredValue.Text("true"), snap["b"])
        assertEquals(StoredValue.Text("1.5"), snap["d"])
        assertEquals(StoredValue.Text("hi"), snap["s"])
    }

    @Test
    fun jsonStorage_persistsAcrossInstances() = runTest {
        val file = File(tmp, "persist.json")
        JsonFileStorage(file).applyBatch(listOf(StorageOp.Put("k", StoredValue.Text("v"))))
        // A fresh instance on the same file must read the prior write.
        assertEquals(StoredValue.Text("v"), JsonFileStorage(file).snapshot()["k"])
        assertTrue(file.exists())
    }

    @Test
    fun jsonStorage_snapshotFlowEmitsLatest() = runTest {
        val store = JsonFileStorage(File(tmp, "flow.json"))
        store.applyBatch(listOf(StorageOp.Put("k", StoredValue.Text("v1"))))
        assertEquals(StoredValue.Text("v1"), store.snapshotFlow().first()["k"])
    }

    @Test
    fun jsonStorage_clearEmptiesStore() = runTest {
        val file = File(tmp, "clear.json")
        val store = JsonFileStorage(file)
        store.applyBatch(listOf(StorageOp.Put("k", StoredValue.Text("v"))))
        store.clear()
        assertTrue(store.snapshot().isEmpty())
        // A fresh instance also sees nothing.
        assertTrue(JsonFileStorage(file).snapshot().isEmpty())
    }

    @Test
    fun jsonStorage_corruptFileReadsAsEmpty() = runTest {
        val file = File(tmp, "corrupt.json").apply { writeText("{ not valid json") }
        // Must not throw — behaves like a fresh store.
        assertTrue(JsonFileStorage(file).snapshot().isEmpty())
    }

    // ── FileKeyVault ─────────────────────────────────────────────────────────

    @Test
    fun fileKeyVault_putGetDelete_roundTrips() {
        val vault = FileKeyVault(File(tmp, "keys.json"))
        val key = ByteArray(32) { it.toByte() }
        vault.put("alias", key)
        assertContentEquals(key, vault.get("alias"))
        vault.delete("alias")
        assertNull(vault.get("alias"))
    }

    @Test
    fun fileKeyVault_persistsAcrossInstances_andIsNotOsBacked() {
        val file = File(tmp, "keys2.json")
        val key = ByteArray(16) { (it * 3).toByte() }
        FileKeyVault(file).put("a", key)
        val reopened = FileKeyVault(file)
        assertContentEquals(key, reopened.get("a"))
        assertFalse(reopened.isOsBacked)
        assertNull(reopened.get("missing"))
    }
}
