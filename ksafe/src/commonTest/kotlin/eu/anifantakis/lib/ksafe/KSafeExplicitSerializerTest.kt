package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.nullable
import kotlinx.serialization.builtins.serializer
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Locks in the explicit-serializer overloads: a generic layer whose `T` is not reified can sit
 * on top of KSafe (issue #37), and its entries are interchangeable with the reified API's.
 */
abstract class KSafeExplicitSerializerTest {

    private val tracked = mutableListOf<KSafe>()

    protected abstract fun newKSafe(fileName: String? = null): KSafe

    private fun createKSafe(): KSafe = newKSafe().also { tracked += it }

    @AfterTest
    fun tearDown() {
        tracked.forEach { runCatching { it.close() } }
        tracked.clear()
    }

    // The app-level abstraction from the issue: nothing here is reified.
    private interface SecureStore {
        suspend fun <T> get(key: String, defaultValue: T, serializer: KSerializer<T>): T
        suspend fun <T> put(key: String, value: T, serializer: KSerializer<T>)
    }

    private class KSafeSecureStore(private val safe: KSafe) : SecureStore {
        override suspend fun <T> get(key: String, defaultValue: T, serializer: KSerializer<T>): T =
            safe.get(key, defaultValue, serializer)

        override suspend fun <T> put(key: String, value: T, serializer: KSerializer<T>) =
            safe.put(key, value, serializer)
    }

    private val alice = TestData(1, "alice", true, listOf(1.5), mapOf("role" to "admin"))
    private val nobody = TestData(0, "", false, emptyList(), emptyMap())

    @Test
    fun aNonReifiedWrapperRoundTripsPrimitivesClassesAndGenerics() = runTest {
        val store: SecureStore = KSafeSecureStore(createKSafe())

        store.put("token", "abc", String.serializer())
        store.put("age", 42, Int.serializer())
        store.put("user", alice, TestData.serializer())
        store.put("users", listOf(alice), ListSerializer(TestData.serializer()))

        assertEquals("abc", store.get("token", "", String.serializer()))
        assertEquals(42, store.get("age", 0, Int.serializer()))
        assertEquals(alice, store.get("user", nobody, TestData.serializer()))
        assertEquals(listOf(alice), store.get("users", emptyList(), ListSerializer(TestData.serializer())))
        assertEquals("fallback", store.get("absent", "fallback", String.serializer()))
    }

    @Test
    fun explicitAndReifiedCallsReadEachOthersEntries() = runTest {
        val ksafe = createKSafe()

        ksafe.put("written_reified", 7)
        ksafe.put("written_explicit", 9, Int.serializer())

        assertEquals(7, ksafe.get("written_reified", 0, Int.serializer()))
        assertEquals(9, ksafe.get("written_explicit", 0))
    }

    @Test
    fun explicitWritesHonourTheirMode() = runTest {
        val ksafe = createKSafe()

        ksafe.put("put_default", "a", String.serializer())
        ksafe.put("put_plain", "b", String.serializer(), KSafeWriteMode.Plain)
        ksafe.putDirect("direct_default", "c", String.serializer())
        ksafe.putDirect("direct_plain", "d", String.serializer(), KSafeWriteMode.Plain)
        // FIFO flush: once this returns, the fire-and-forget writes above are committed.
        ksafe.put("__flush__", "x", KSafeWriteMode.Plain)

        assertEquals(KSafeProtection.DEFAULT, assertNotNull(ksafe.getKeyInfo("put_default")).protection)
        assertNull(assertNotNull(ksafe.getKeyInfo("put_plain")).protection)
        assertEquals(KSafeProtection.DEFAULT, assertNotNull(ksafe.getKeyInfo("direct_default")).protection)
        assertNull(assertNotNull(ksafe.getKeyInfo("direct_plain")).protection)
        assertEquals("c", ksafe.get("direct_default", "", String.serializer()))
        assertEquals("d", ksafe.get("direct_plain", "", String.serializer()))
    }

    @Test
    fun theSerializerPassedDecidesWhetherAStoredNullReadsAsNull() = runTest {
        val ksafe = createKSafe()
        val nullableString = String.serializer().nullable

        ksafe.put("cleared", null, nullableString)

        assertNull(ksafe.get("cleared", "fallback", nullableString))
        assertEquals("fallback", ksafe.get("cleared", "fallback", String.serializer()))
        assertEquals("fallback", ksafe.get("absent", "fallback", nullableString))
    }

    @Test
    fun explicitGetDirectReadsTheCache() = runTest {
        val ksafe = createKSafe()

        ksafe.put("count", 5, Int.serializer())

        assertEquals(5, ksafe.getDirect("count", 0, Int.serializer()))
        assertEquals(-1, ksafe.getDirect("missing", -1, Int.serializer()))
    }

    @Test
    fun explicitFlowsStartFromTheStoredValue() = runTest {
        val ksafe = createKSafe()

        ksafe.put("observed", "v1", String.serializer())

        assertEquals("v1", ksafe.getFlow("observed", "", String.serializer()).first())
        assertEquals("v1", ksafe.getStateFlow("observed", "", String.serializer(), backgroundScope).value)
    }
}
