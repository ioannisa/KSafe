package eu.anifantakis.lib.ksafe

import androidx.datastore.preferences.core.Preferences
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * CHARACTERIZATION suite for numeric primitive types: what a value is actually
 * persisted as, and what happens when a key is written with one numeric type and
 * later read as another (the "I shipped `ksafe(0)` and now want `ksafe(0L)`"
 * migration). Probes plain vs encrypted, Int<->Long, Float<->Double, including
 * out-of-range and the "encrypted 0, later store a Long" case.
 *
 * Reads exercise `KSafeCore.convertStoredValue` (plain path — a typed coercion
 * table) and `jsonDecode` (encrypted path — type-tagless JSON). These tests assert
 * the DESIRED behaviour (cross-type reads return the coerced value), so any case
 * the current code can't coerce will FAIL and pinpoint the gap.
 *
 * Uses FakeEncryption (reversible XOR) so the encrypted path is exercised
 * deterministically without touching a real OS key store.
 */
class JvmNumericTypeMigrationTest {

    private val tracked = mutableListOf<KSafe>()
    private var counter = 0

    private fun uniqueName(): String {
        counter++
        val sb = StringBuilder("numtype")
        var n = System.nanoTime() xor counter.toLong()
        if (n < 0) n = -n
        while (n > 0) { sb.append('a' + (n % 26).toInt()); n /= 26 }
        return sb.toString()
    }

    private fun newKSafe(memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT): KSafe =
        KSafe(fileName = uniqueName(), memoryPolicy = memoryPolicy, testEngine = FakeEncryption())
            .also { tracked += it }

    @AfterTest
    fun tearDown() {
        tracked.forEach { runCatching { it.close() } }
        tracked.clear()
    }

    /** All numeric (Int/Long/Float/Double) values currently persisted, regardless of key name. */
    private suspend fun numericValues(ksafe: KSafe): List<Any> =
        ksafe.dataStore.data.first().asMap().values
            .filter { it is Int || it is Long || it is Float || it is Double }

    // ======================================================================
    // GROUP A — what does an unencrypted primitive actually persist AS?
    // ======================================================================

    @Test
    fun plain_int_persistsAsInt_notLong() = runTest {
        val ksafe = newKSafe()
        ksafe.put("k", 42, KSafeWriteMode.Plain)
        val nums = numericValues(ksafe)
        assertEquals(1, nums.size, "exactly one numeric value entry expected, got: $nums")
        assertTrue(nums.single() is Int, "plain Int 42 persists as: ${nums.single()::class.simpleName} (value=$nums)")
    }

    @Test
    fun plain_long_persistsAsLong() = runTest {
        val ksafe = newKSafe()
        ksafe.put("k", 42L, KSafeWriteMode.Plain)
        val nums = numericValues(ksafe)
        assertEquals(1, nums.size, "exactly one numeric value entry expected, got: $nums")
        assertTrue(nums.single() is Long, "plain Long 42 persists as: ${nums.single()::class.simpleName}")
    }

    @Test
    fun plain_float_persistsAsFloat() = runTest {
        val ksafe = newKSafe()
        ksafe.put("k", 1.5f, KSafeWriteMode.Plain)
        val nums = numericValues(ksafe)
        assertEquals(1, nums.size, "exactly one numeric value entry expected, got: $nums")
        assertTrue(nums.single() is Float, "plain Float persists as: ${nums.single()::class.simpleName}")
    }

    @Test
    fun plain_double_persistsAsDouble() = runTest {
        val ksafe = newKSafe()
        ksafe.put("k", 1.5, KSafeWriteMode.Plain)
        val nums = numericValues(ksafe)
        assertEquals(1, nums.size, "exactly one numeric value entry expected, got: $nums")
        assertTrue(nums.single() is Double, "plain Double persists as: ${nums.single()::class.simpleName}")
    }

    // ======================================================================
    // GROUP B — Int <-> Long migration
    // ======================================================================

    @Test
    fun plain_intWritten_readAsLong_coerces() = runTest {
        val ksafe = newKSafe()
        ksafe.put("k", 7, KSafeWriteMode.Plain)        // T = Int
        assertEquals(7L, ksafe.get("k", 0L))           // read T = Long
    }

    @Test
    fun encrypted_intWritten_readAsLong_coerces() = runTest {
        val ksafe = newKSafe(KSafeMemoryPolicy.ENCRYPTED)
        ksafe.put("k", 7)                              // encrypted, T = Int
        assertEquals(7L, ksafe.get("k", 0L))           // read T = Long
    }

    @Test
    fun plain_longWritten_readAsInt_inRange_coerces() = runTest {
        val ksafe = newKSafe()
        ksafe.put("k", 7L, KSafeWriteMode.Plain)
        assertEquals(7, ksafe.get("k", -1))
    }

    @Test
    fun encrypted_longWritten_readAsInt_inRange_coerces() = runTest {
        val ksafe = newKSafe(KSafeMemoryPolicy.ENCRYPTED)
        ksafe.put("k", 7L)
        assertEquals(7, ksafe.get("k", -1))
    }

    /** Documents the lossy boundary: a Long that can't fit in Int falls back to the default. */
    @Test
    fun plain_longWritten_readAsInt_outOfRange_fallsBackToDefault() = runTest {
        val ksafe = newKSafe()
        ksafe.put("k", 5_000_000_000L, KSafeWriteMode.Plain)
        assertEquals(-1, ksafe.get("k", -1), "out-of-Int-range Long should fall back to default")
    }

    @Test
    fun encrypted_longWritten_readAsInt_outOfRange_fallsBackToDefault() = runTest {
        val ksafe = newKSafe(KSafeMemoryPolicy.ENCRYPTED)
        ksafe.put("k", 5_000_000_000L)
        assertEquals(-1, ksafe.get("k", -1), "out-of-Int-range Long should fall back to default")
    }

    // ======================================================================
    // GROUP C — Float <-> Double migration
    // ======================================================================

    @Test
    fun plain_floatWritten_readAsDouble_coerces() = runTest {
        val ksafe = newKSafe()
        ksafe.put("k", 1.5f, KSafeWriteMode.Plain)     // T = Float
        assertEquals(1.5, ksafe.get("k", 0.0), 1e-6)   // read T = Double — should coerce, not return default
    }

    @Test
    fun plain_doubleWritten_readAsFloat_coerces() = runTest {
        val ksafe = newKSafe()
        ksafe.put("k", 1.5, KSafeWriteMode.Plain)      // T = Double
        assertEquals(1.5f, ksafe.get("k", 0.0f), 1e-6f) // read T = Float — should coerce, not return default
    }

    @Test
    fun encrypted_floatWritten_readAsDouble_coerces() = runTest {
        val ksafe = newKSafe(KSafeMemoryPolicy.ENCRYPTED)
        ksafe.put("k", 1.5f)
        assertEquals(1.5, ksafe.get("k", 0.0), 1e-6)
    }

    @Test
    fun encrypted_doubleWritten_readAsFloat_coerces() = runTest {
        val ksafe = newKSafe(KSafeMemoryPolicy.ENCRYPTED)
        ksafe.put("k", 1.5)
        assertEquals(1.5f, ksafe.get("k", 0.0f), 1e-6f)
    }

    // ======================================================================
    // GROUP D — the specific "encrypted 0, later store a Long" question
    // ======================================================================

    @Test
    fun encrypted_zeroAsInt_thenOverwrittenWithLong_readsBackCorrectly() = runTest {
        val ksafe = newKSafe(KSafeMemoryPolicy.ENCRYPTED)
        ksafe.put("k", 0)                               // encrypted Int 0
        assertEquals(0L, ksafe.get("k", 0L), "encrypted Int 0 read as Long")

        ksafe.put("k", 5_000_000_000L)                  // later: a real Long, same key
        assertEquals(5_000_000_000L, ksafe.get("k", 0L), "later Long value reads back intact")
    }

    // ======================================================================
    // GROUP E — overwriting a key with a DIFFERENT numeric type
    //   On typed-DataStore platforms a key is identified by (name, type), so an
    //   Int `k` and a Long `k` are different on-disk keys. writeOne must purge the
    //   stale entry so no duplicate lingers and reads stay deterministic.
    // ======================================================================

    @Test
    fun plain_intStored_thenOverwrittenWithLong_readsBackAsLong_andLeavesNoDuplicate() = runTest {
        val ksafe = newKSafe()
        ksafe.put("k", 0, KSafeWriteMode.Plain)                 // stored as Int
        ksafe.put("k", 5_000_000_000L, KSafeWriteMode.Plain)    // overwrite with a Long

        assertEquals(5_000_000_000L, ksafe.get("k", 0L), "the later Long must win")
        val nums = numericValues(ksafe)
        assertEquals(1, nums.size, "stale Int entry must be purged — exactly one numeric entry, got: $nums")
        assertTrue(nums.single() is Long, "the surviving on-disk entry must be the Long")
    }

    @Test
    fun plain_longStored_thenOverwrittenWithInt_readsBackAsInt_andLeavesNoDuplicate() = runTest {
        val ksafe = newKSafe()
        ksafe.put("k", 5_000_000_000L, KSafeWriteMode.Plain)    // stored as Long
        ksafe.put("k", 42, KSafeWriteMode.Plain)                // overwrite with an Int

        assertEquals(42, ksafe.get("k", -1), "the later Int must win")
        val nums = numericValues(ksafe)
        assertEquals(1, nums.size, "stale Long entry must be purged — exactly one numeric entry, got: $nums")
        assertTrue(nums.single() is Int, "the surviving on-disk entry must be the Int")
    }

    // ======================================================================
    // GROUP F — full integer <-> decimal matrix (plain path)
    //   Widening (Int/Long -> Float/Double) is exact or loses only precision.
    //   Decimal -> integer coerces ONLY when the value is whole and in range;
    //   a fractional or out-of-range decimal falls back to the default rather
    //   than silently truncating or wrapping.
    // ======================================================================

    @Test fun plain_intReadAsDouble_widens() = runTest {
        val ksafe = newKSafe(); ksafe.put("k", 5, KSafeWriteMode.Plain)
        assertEquals(5.0, ksafe.get("k", 0.0), 1e-9)
    }

    @Test fun plain_intReadAsFloat_widens() = runTest {
        val ksafe = newKSafe(); ksafe.put("k", 5, KSafeWriteMode.Plain)
        assertEquals(5.0f, ksafe.get("k", 0.0f), 1e-9f)
    }

    @Test fun plain_longReadAsDouble_widens() = runTest {
        val ksafe = newKSafe(); ksafe.put("k", 5L, KSafeWriteMode.Plain)
        assertEquals(5.0, ksafe.get("k", 0.0), 1e-9)
    }

    @Test fun plain_longReadAsFloat_widens() = runTest {
        val ksafe = newKSafe(); ksafe.put("k", 5L, KSafeWriteMode.Plain)
        assertEquals(5.0f, ksafe.get("k", 0.0f), 1e-9f)
    }

    @Test fun plain_wholeDoubleReadAsInt_coerces() = runTest {
        val ksafe = newKSafe(); ksafe.put("k", 5.0, KSafeWriteMode.Plain)
        assertEquals(5, ksafe.get("k", -1))
    }

    @Test fun plain_fractionalDoubleReadAsInt_fallsBackToDefault() = runTest {
        val ksafe = newKSafe(); ksafe.put("k", 5.7, KSafeWriteMode.Plain)
        assertEquals(-1, ksafe.get("k", -1), "a fractional Double must NOT silently truncate to Int")
    }

    @Test fun plain_outOfRangeWholeDoubleReadAsInt_fallsBackToDefault() = runTest {
        val ksafe = newKSafe(); ksafe.put("k", 5e18, KSafeWriteMode.Plain) // whole, but > Int range
        assertEquals(-1, ksafe.get("k", -1), "an out-of-Int-range Double must fall back to default")
    }

    @Test fun plain_wholeDoubleReadAsLong_coerces() = runTest {
        val ksafe = newKSafe(); ksafe.put("k", 5.0, KSafeWriteMode.Plain)
        assertEquals(5L, ksafe.get("k", -1L))
    }

    @Test fun plain_wholeFloatReadAsInt_coerces() = runTest {
        val ksafe = newKSafe(); ksafe.put("k", 5.0f, KSafeWriteMode.Plain)
        assertEquals(5, ksafe.get("k", -1))
    }

    @Test fun plain_wholeFloatReadAsLong_coerces() = runTest {
        val ksafe = newKSafe(); ksafe.put("k", 5.0f, KSafeWriteMode.Plain)
        assertEquals(5L, ksafe.get("k", -1L))
    }
}
