package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import eu.anifantakis.lib.ksafe.internal.AppleKeychainStore
import eu.anifantakis.lib.ksafe.internal.KSafeConcurrentMap
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Locks in: a strict (`requireUnlockedDevice`) access evicts any plaintext key bytes a previous
 * non-strict write left in the engine's in-process cache. Real Keychain round-trips can't run in
 * the Kotlin/Native test runner, so an in-memory [AppleKeychainStore] stands in.
 */
class MacosStrictKeyCacheEvictionTest {

    @Test
    fun strictRewrite_evictsLingeringNonStrictPlaintextKeyBytes() {
        val engine = AppleKeychainEncryption(keychainStore = FakeKeychainStore())
        val id = "alias1"

        engine.getOrCreateKeychainKey(id, hardwareIsolated = false, requireUnlockedDevice = false)
        assertNotNull(engine.cachedKeyBytesForTest(id), "precondition: a non-strict write caches the plaintext key")

        engine.getOrCreateKeychainKey(id, hardwareIsolated = false, requireUnlockedDevice = true)
        assertNull(
            engine.cachedKeyBytesForTest(id),
            "a strict rewrite must evict the lingering non-strict plaintext key bytes (low)",
        )
    }
}
