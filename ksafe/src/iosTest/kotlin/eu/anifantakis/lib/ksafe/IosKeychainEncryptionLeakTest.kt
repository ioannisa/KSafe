package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import platform.posix.RUSAGE_SELF
import platform.posix.getrusage
import platform.posix.rusage
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Locks in: keychain calls on background threads leak no NSString bridging allocations. Native
 * coroutine workers have no ambient ObjC autorelease pool, so `CFBridgingRetain(keyId)` there
 * strands allocations unless the operation runs inside an explicit `autoreleasepool { }` — remove
 * those wrappers in AppleKeychainEncryption.kt and peak RSS here grows by several megabytes.
 */
class IosKeychainEncryptionLeakTest {

    @OptIn(ExperimentalUuidApi::class)
    private fun uniqueKeyId(): String = "leak_${Uuid.random().toString().take(8)}"

    @Test
    fun testNoLeakOnBackgroundThread_decrypt() = runBlocking {
        val encryption = AppleKeychainEncryption()
        val keyId = uniqueKeyId()
        val fakeCiphertext = ByteArray(48) { it.toByte() }

        // Warm up on the worker so lazy class init and allocator slack are paid before the baseline.
        withContext(Dispatchers.Default) {
            repeat(WARMUP_ITERATIONS) {
                try {
                    encryption.decrypt(keyId, fakeCiphertext)
                } catch (_: Exception) {
                    // Expected — no entitlements here; the bridging under test happens first.
                }
            }
        }
        val baselinePeakBytes = peakResidentMemoryBytes()

        withContext(Dispatchers.Default) {
            repeat(LEAK_TEST_ITERATIONS) {
                try {
                    encryption.decrypt(keyId, fakeCiphertext)
                } catch (_: Exception) {
                }
            }
        }
        val finalPeakBytes = peakResidentMemoryBytes()

        // Every iteration throws here (no keychain entitlements in the test runner) and the stack
        // traces inflate peak RSS by 5-10 MB unrelated to the bridging leak, so this is a loose
        // secondary check; the strict guard is testNoLeakOnBackgroundThread_deleteKey, which cannot throw.
        assertBoundedGrowth(baselinePeakBytes, finalPeakBytes, "decrypt", LEAK_GROWTH_THRESHOLD_LOOSE_BYTES)
    }

    @Test
    fun testNoLeakOnBackgroundThread_deleteKey() = runBlocking {
        val encryption = AppleKeychainEncryption()

        withContext(Dispatchers.Default) {
            repeat(WARMUP_ITERATIONS) { encryption.deleteKey(uniqueKeyId()) }
        }
        val baselinePeakBytes = peakResidentMemoryBytes()

        withContext(Dispatchers.Default) {
            repeat(LEAK_TEST_ITERATIONS) { encryption.deleteKey(uniqueKeyId()) }
        }
        val finalPeakBytes = peakResidentMemoryBytes()

        // deleteKey never throws, so peak RSS reflects only the CFBridgingRetain/autorelease balance
        // under test — the strict threshold makes a real leak (≥5 MB over 5k iters) fail the build.
        assertBoundedGrowth(baselinePeakBytes, finalPeakBytes, "deleteKey", LEAK_GROWTH_THRESHOLD_STRICT_BYTES)
    }

    private fun assertBoundedGrowth(baseline: Long, final: Long, opName: String, thresholdBytes: Long) {
        val growthBytes = final - baseline
        val growthMb = growthBytes / 1_048_576
        assertTrue(
            growthBytes < thresholdBytes,
            "Peak RSS grew by $growthMb MB after $LEAK_TEST_ITERATIONS background-thread $opName calls " +
                "(threshold: ${thresholdBytes / 1_048_576} MB). " +
                "Indicates Kotlin→NSString bridging allocations are leaking — missing autoreleasepool in AppleKeychainEncryption?"
        )
    }

    @OptIn(ExperimentalForeignApi::class, kotlin.native.runtime.NativeRuntimeApi::class)
    private fun peakResidentMemoryBytes(): Long = memScoped {
        kotlin.native.runtime.GC.collect()
        val usage = alloc<rusage>()
        getrusage(RUSAGE_SELF, usage.ptr)
        // ru_maxrss is bytes on Darwin (kilobytes on Linux), and peak is monotonically
        // non-decreasing, so growth after warmup signals new high-water allocations.
        usage.ru_maxrss
    }

    companion object {
        private const val WARMUP_ITERATIONS = 200
        private const val LEAK_TEST_ITERATIONS = 5_000

        // A leaking implementation costs ≥1KB per iteration (measured with Instruments), so 5k
        // iterations push peak RSS up by ≥5 MB; with the pools in place growth stays under 2 MB.
        private const val LEAK_GROWTH_THRESHOLD_STRICT_BYTES: Long = 2L * 1024 * 1024

        // For the throwing decrypt path only, where stack traces add 5-10 MB of transient allocations.
        private const val LEAK_GROWTH_THRESHOLD_LOOSE_BYTES: Long = 12L * 1024 * 1024
    }
}
