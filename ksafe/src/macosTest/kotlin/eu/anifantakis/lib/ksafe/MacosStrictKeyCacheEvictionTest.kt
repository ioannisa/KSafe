package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import eu.anifantakis.lib.ksafe.internal.AppleKeychainStore
import eu.anifantakis.lib.ksafe.internal.KSafeConcurrentMap
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * FEEDBACK_4 low: a strict (`requireUnlockedDevice`) key's plaintext must NEVER live in
 * the engine's in-process key-bytes cache. A NON-strict write caches the plaintext; if the
 * same key is later rewritten strict, the cached bytes used to linger — defeating the
 * unlock policy in memory. A strict access must evict any lingering entry.
 *
 * Real Keychain round-trips can't run in the Kotlin/Native test runner, so an in-memory
 * [AppleKeychainStore] stands in.
 */
class MacosStrictKeyCacheEvictionTest {

    private class FakeKeychainStore : AppleKeychainStore {
        val map = KSafeConcurrentMap<ByteArray>()
        override fun readBytes(account: String): ByteArray? = map[account]
        override fun store(account: String, bytes: ByteArray, requireUnlocked: Boolean) { map[account] = bytes }
        override fun delete(account: String) { map.remove(account) }
    }

    @Test
    fun strictRewrite_evictsLingeringNonStrictPlaintextKeyBytes() {
        val engine = AppleKeychainEncryption(keychainStore = FakeKeychainStore())
        val id = "alias1"

        // A non-strict write caches the plaintext key in-process.
        engine.getOrCreateKeychainKey(id, hardwareIsolated = false, requireUnlockedDevice = false)
        assertNotNull(engine.cachedKeyBytesForTest(id), "precondition: a non-strict write caches the plaintext key")

        // Rewriting the SAME key strict must evict the lingering plaintext bytes.
        engine.getOrCreateKeychainKey(id, hardwareIsolated = false, requireUnlockedDevice = true)
        assertNull(
            engine.cachedKeyBytesForTest(id),
            "a strict rewrite must evict the lingering non-strict plaintext key bytes (low)",
        )
    }
}
