package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: the Secure Enclave availability probe — which replaced an `!isSimulator()` heuristic
 * that over-reported SE on every Mac — runs without throwing and returns a stable, cached result.
 * The concrete true/false is host-dependent (Apple Silicon / T2 → true, pre-T2 Intel / VM → false),
 * so only the well-behavedness is asserted: stable per process, never crashing or flapping.
 */
class MacosSecureEnclaveProbeTest {

    @Test
    fun deviceHasSecureEnclave_isStableAndDoesNotThrow() {
        val first = AppleKeychainEncryption.deviceHasSecureEnclave()
        val second = AppleKeychainEncryption.deviceHasSecureEnclave()
        assertEquals(first, second, "the SE probe must be cached and return a stable value per process")
    }
}
