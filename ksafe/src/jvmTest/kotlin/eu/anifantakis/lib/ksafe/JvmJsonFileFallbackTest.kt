package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.DataStoreJsonStorage
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.keyvault.FileKeyVault
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Locks in: the JVM no-`Unsafe` fallback backends ([DataStoreJsonStorage] and [FileKeyVault]) round-trip, persist across instances, and surface corruption instead of silently discarding data.
 */
class JvmJsonFileFallbackTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_jsonfb_${System.nanoTime()}")
        .apply { mkdirs() }

    /** DataStore allows ONE active instance per file per process — track scopes and release them. */
    private val scopes = mutableListOf<CoroutineScope>()

    private fun storage(file: File): DataStoreJsonStorage {
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        scopes += scope
        return DataStoreJsonStorage(file, scope)
    }

    @AfterTest
    fun tearDown() {
        runBlocking { scopes.forEach { it.coroutineContext[Job]?.cancelAndJoin() } }
        tmp.deleteRecursively()
    }

    // ── DataStoreJsonStorage ─────────────────────────────────────────────────

    @Test
    fun jsonStorage_putGetDelete_roundTrips() = runTest {
        val store = storage(File(tmp, "a.json"))
        store.applyBatch(listOf(StorageOp.Put("__ksafe_value_token", StoredValue.Text("abc"))))
        assertEquals(StoredValue.Text("abc"), store.snapshot()["__ksafe_value_token"])

        store.applyBatch(listOf(StorageOp.Delete("__ksafe_value_token")))
        assertNull(store.snapshot()["__ksafe_value_token"])
    }

    @Test
    fun jsonStorage_flattensAllTypesToText() = runTest {
        // Everything is stored/returned as Text; KSafeCore re-types primitives on read.
        val store = storage(File(tmp, "types.json"))
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
        // Cancel + join the first scope so DataStore releases the file for a second instance.
        val scope1 = CoroutineScope(Dispatchers.IO + SupervisorJob())
        DataStoreJsonStorage(file, scope1)
            .applyBatch(listOf(StorageOp.Put("k", StoredValue.Text("v"))))
        scope1.coroutineContext[Job]!!.cancelAndJoin()

        assertEquals(StoredValue.Text("v"), storage(file).snapshot()["k"])
        assertTrue(file.exists())
    }

    @Test
    fun jsonStorage_snapshotFlowEmitsLatest() = runTest {
        val store = storage(File(tmp, "flow.json"))
        store.applyBatch(listOf(StorageOp.Put("k", StoredValue.Text("v1"))))
        assertEquals(StoredValue.Text("v1"), store.snapshotFlow().first()["k"])
    }

    @Test
    fun jsonStorage_clearEmptiesStore() = runTest {
        val store = storage(File(tmp, "clear.json"))
        store.applyBatch(listOf(StorageOp.Put("k", StoredValue.Text("v"))))
        store.clear()
        assertTrue(store.snapshot().isEmpty())
    }

    @Test
    fun jsonStorage_corruptFile_isQuarantinedNotSilentlyDiscarded() = runTest {
        // Unparseable content must be quarantined to a .corrupt-* sibling, not read back
        // as empty — an empty read would let the next write overwrite recoverable bytes.
        val file = File(tmp, "corrupt.json")
        file.writeText("{ this is not valid json")
        assertTrue(storage(file).snapshot().isEmpty())
        val quarantined = tmp.listFiles().orEmpty()
            .filter { it.name.startsWith("corrupt.json.corrupt-") }
        assertTrue(quarantined.isNotEmpty(), "corrupt file must be quarantined, not discarded")
        assertEquals("{ this is not valid json", quarantined.first().readText())
    }

    @Test
    fun jsonStorage_blankFile_isFreshStore_notQuarantined() = runTest {
        // A blank file is "no data yet" — empty, not corruption.
        val file = File(tmp, "blank.json")
        file.writeText("   ")
        assertTrue(storage(file).snapshot().isEmpty())
        assertTrue(tmp.listFiles().orEmpty().none { it.name.contains(".corrupt-") })
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

    @Test
    fun fileKeyVault_unreadableFile_throwsRatherThanReportingEmpty() {
        // An unparseable keys file must not read back as "no keys" — that would let the
        // orphan sweep delete recoverable ciphertext.
        val file = File(tmp, "corruptkeys.json")
        file.writeText("{ not valid json")
        assertFailsWith<IllegalStateException> { FileKeyVault(file).get("anything") }
    }

    @Test
    fun fileKeyVault_absentFile_isEmptyNotError() {
        assertNull(FileKeyVault(File(tmp, "nope.json")).get("anything"))
    }

    @Test
    fun fileKeyVault_keyFileIsOwnerOnly_onPosix() {
        // The key file must be created owner-only (rw-------); skipped on non-POSIX filesystems.
        val file = File(tmp, "perms.ksafe-keys.json")
        FileKeyVault(file).put("alias", ByteArray(32) { it.toByte() })
        val view = java.nio.file.Files.getFileAttributeView(
            file.toPath(),
            java.nio.file.attribute.PosixFileAttributeView::class.java,
        ) ?: return // non-POSIX: nothing to assert
        val perms = view.readAttributes().permissions()
        assertEquals(
            setOf(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
            ),
            perms,
            "key file must be owner read/write only; was $perms",
        )
    }
}
