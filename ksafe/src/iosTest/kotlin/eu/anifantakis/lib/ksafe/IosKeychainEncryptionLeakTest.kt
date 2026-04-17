package eu.anifantakis.lib.ksafe

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
 * Regression tests for issue #22: NSString leak on background threads.
 *
 * Kotlin coroutine worker threads (Dispatchers.Default on Native) do not have
 * an ambient ObjC autorelease pool. Any Kotlin→NSString bridging performed on
 * those threads — e.g. `CFBridgingRetain(keyId)` where `keyId` is a Kotlin
 * String — produces autoreleased NSString allocations that are never drained.
 *
 * Each test runs many keychain operations on Dispatchers.Default and asserts
 * that peak resident memory does not grow unboundedly. Each iteration fails
 * with errSecMissingEntitlement in the test runner — that is expected and
 * does not prevent the leak: the NSString bridging happens before the
 * keychain call errors out.
 *
 * Reproduction instructions: remove the `autoreleasepool { }` wrappers added
 * to IosKeychainEncryption.kt and these tests fail with peak RSS growing by
 * several megabytes beyond baseline.
 */
class IosKeychainEncryptionLeakTest {

    @OptIn(ExperimentalUuidApi::class)
    private fun uniqueKeyId(): String = "leak_${Uuid.random().toString().take(8)}"

    @Test
    fun testNoLeakOnBackgroundThread_decrypt() = runBlocking {
        val encryption = IosKeychainEncryption()
        val keyId = uniqueKeyId()
        val fakeCiphertext = ByteArray(48) { it.toByte() }

        // Warm up on the worker so lazy class init / allocator slack is paid
        // before we sample the baseline peak.
        withContext(Dispatchers.Default) {
            repeat(WARMUP_ITERATIONS) {
                try {
                    encryption.decrypt(keyId, fakeCiphertext)
                } catch (_: IllegalStateException) {
                    // Expected — test runner has no keychain entitlements.
                }
            }
        }
        val baselinePeakBytes = peakResidentMemoryBytes()

        withContext(Dispatchers.Default) {
            repeat(LEAK_TEST_ITERATIONS) {
                try {
                    encryption.decrypt(keyId, fakeCiphertext)
                } catch (_: IllegalStateException) {
                }
            }
        }
        val finalPeakBytes = peakResidentMemoryBytes()

        assertBoundedGrowth(baselinePeakBytes, finalPeakBytes, "decrypt")
    }

    @Test
    fun testNoLeakOnBackgroundThread_deleteKey() = runBlocking {
        val encryption = IosKeychainEncryption()

        withContext(Dispatchers.Default) {
            repeat(WARMUP_ITERATIONS) { encryption.deleteKey(uniqueKeyId()) }
        }
        val baselinePeakBytes = peakResidentMemoryBytes()

        withContext(Dispatchers.Default) {
            repeat(LEAK_TEST_ITERATIONS) { encryption.deleteKey(uniqueKeyId()) }
        }
        val finalPeakBytes = peakResidentMemoryBytes()

        assertBoundedGrowth(baselinePeakBytes, finalPeakBytes, "deleteKey")
    }

    private fun assertBoundedGrowth(baseline: Long, final: Long, opName: String) {
        val growthBytes = final - baseline
        val growthMb = growthBytes / 1_048_576
        assertTrue(
            growthBytes < LEAK_GROWTH_THRESHOLD_BYTES,
            "Peak RSS grew by $growthMb MB after $LEAK_TEST_ITERATIONS background-thread $opName calls " +
                "(threshold: ${LEAK_GROWTH_THRESHOLD_BYTES / 1_048_576} MB). " +
                "Indicates Kotlin→NSString bridging allocations are leaking — missing autoreleasepool in IosKeychainEncryption?"
        )
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun peakResidentMemoryBytes(): Long = memScoped {
        val usage = alloc<rusage>()
        getrusage(RUSAGE_SELF, usage.ptr)
        // ru_maxrss is bytes on Darwin (kilobytes on Linux). Peak is
        // monotonically non-decreasing — growth after warmup reliably signals
        // new high-water allocations.
        usage.ru_maxrss
    }

    companion object {
        private const val WARMUP_ITERATIONS = 200
        private const val LEAK_TEST_ITERATIONS = 5_000

        // Pre-fix: each iteration leaks ≥1KB of NSString/Malloc allocations
        // (per Instruments in issue #22), so 5k iterations push peak RSS up
        // by multiple MB. Post-fix: growth is dominated by allocator slack and
        // stays under 2 MB.
        private const val LEAK_GROWTH_THRESHOLD_BYTES: Long = 2L * 1024 * 1024
    }
}
