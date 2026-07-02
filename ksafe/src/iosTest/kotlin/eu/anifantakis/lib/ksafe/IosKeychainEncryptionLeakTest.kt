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
 * Keychain operations on background threads must not leak NSString bridging
 * allocations.
 *
 * Kotlin coroutine worker threads (Dispatchers.Default on Native) do not have
 * an ambient ObjC autorelease pool. Any Kotlin→NSString bridging performed on
 * those threads — e.g. `CFBridgingRetain(keyId)` where `keyId` is a Kotlin
 * String — produces autoreleased NSString allocations that are never drained
 * unless the operation runs inside an explicit `autoreleasepool { }`.
 *
 * Each test runs many keychain operations on Dispatchers.Default and asserts
 * that peak resident memory does not grow unboundedly. Each iteration fails
 * with errSecMissingEntitlement in the test runner — that is expected and
 * does not prevent the leak: the NSString bridging happens before the
 * keychain call errors out.
 *
 * Reproduction: remove the `autoreleasepool { }` wrappers in
 * AppleKeychainEncryption.kt and these tests fail with peak RSS growing by
 * several megabytes beyond baseline.
 */
class IosKeychainEncryptionLeakTest {

    @OptIn(ExperimentalUuidApi::class)
    private fun uniqueKeyId(): String = "leak_${Uuid.random().toString().take(8)}"

    @Test
    fun testNoLeakOnBackgroundThread_decrypt() = runBlocking {
        val encryption = AppleKeychainEncryption()
        val keyId = uniqueKeyId()
        val fakeCiphertext = ByteArray(48) { it.toByte() }

        // Warm up on the worker so lazy class init / allocator slack is paid
        // before we sample the baseline peak.
        withContext(Dispatchers.Default) {
            repeat(WARMUP_ITERATIONS) {
                try {
                    encryption.decrypt(keyId, fakeCiphertext)
                } catch (_: Exception) {
                    // Expected — test runner has no keychain entitlements.
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

        // The decrypt path throws every iteration here (no keychain entitlements in the
        // test runner), and Kotlin/Native 2.3+ captures a stack trace per exception, which
        // inflates peak RSS by 5-10 MB of transient allocations unrelated to the bridging
        // leak. This test therefore uses the loose threshold and is only a secondary check;
        // testNoLeakOnBackgroundThread_deleteKey (which never throws) is the STRICT guard
        // that can actually fail on the ~5 MB bridging-leak signature (deep-review L1).
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

        // deleteKey never throws, so peak RSS reflects only the CFBridgingRetain/autorelease
        // balance under test — use the STRICT threshold so a real leak (≥5 MB over 5k iters)
        // actually fails the build (deep-review L1).
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
        // ru_maxrss is bytes on Darwin (kilobytes on Linux). Peak is
        // monotonically non-decreasing — growth after warmup reliably signals
        // new high-water allocations.
        usage.ru_maxrss
    }

    companion object {
        private const val WARMUP_ITERATIONS = 200
        private const val LEAK_TEST_ITERATIONS = 5_000

        // A leaking implementation costs ≥1KB of NSString/Malloc allocations
        // per iteration (measured with Instruments), so 5k iterations push
        // peak RSS up by ≥5 MB. With autorelease pools in place, growth is
        // dominated by allocator slack and stays under 2 MB.
        //
        // STRICT: for non-throwing ops (deleteKey) whose peak RSS reflects only the
        // bridging balance — kept BELOW the ~5 MB leak signature so a regression fails.
        private const val LEAK_GROWTH_THRESHOLD_STRICT_BYTES: Long = 2L * 1024 * 1024

        // LOOSE: only for the throwing decrypt path, where Kotlin/Native 2.3+ exception
        // stack traces add 5-10 MB of transient allocations that inflate peak RSS. This
        // path can't distinguish a leak from exception overhead, so it's a secondary
        // check; the strict deleteKey test is the real guard.
        private const val LEAK_GROWTH_THRESHOLD_LOOSE_BYTES: Long = 12L * 1024 * 1024
    }
}
