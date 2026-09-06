package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import platform.Foundation.NSProcessInfo
import kotlin.time.Duration.Companion.seconds

internal val APPLE_PROBE_TIMEOUT = 15.seconds

/** Same signal the Apple actual reads; the Simulator has no biometric hardware. */
@OptIn(ExperimentalForeignApi::class)
internal fun runningOnSimulator(): Boolean =
    NSProcessInfo.processInfo.environment["SIMULATOR_UDID"] != null

/**
 * Runs [block] with `Dispatchers.Main` replaced by an unconfined test dispatcher: the actuals
 * deliver results on Main, which nobody pumps while a test binary blocks in `runBlocking`.
 * Bounded, so a reply that never arrives fails the test instead of hanging the job.
 */
@OptIn(ExperimentalCoroutinesApi::class)
internal fun <T> withTestMain(block: suspend CoroutineScope.() -> T): T {
    Dispatchers.setMain(UnconfinedTestDispatcher())
    try {
        return runBlocking { withTimeout(APPLE_PROBE_TIMEOUT) { block() } }
    } finally {
        Dispatchers.resetMain()
    }
}
