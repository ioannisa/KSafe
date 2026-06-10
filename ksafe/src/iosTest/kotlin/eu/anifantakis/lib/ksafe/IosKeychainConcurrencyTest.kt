package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import eu.anifantakis.lib.ksafe.internal.AppleKeychainStore
import eu.anifantakis.lib.ksafe.internal.KSafeConcurrentMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Concurrency regression test for [AppleKeychainEncryption] key resolution (deep-review #8).
 *
 * Real Keychain round-trips can't run in the Kotlin/Native test runner (no entitlements →
 * `errSecMissingEntitlement`), so this injects an in-memory [AppleKeychainStore]. The fake is
 * thread-safe but **last-write-wins** on `store`, faithfully reproducing the production clobber:
 * two unsynchronized creators both read "absent", both generate a key, and the second store
 * overwrites the first.
 *
 * Without the engine's `keyResolutionLock`, concurrent first-creation of one alias returns
 * several different keys (each creator's own) — exactly the bug that loses data, since the
 * losing key's ciphertext becomes undecryptable. With the lock, all callers resolve to the one
 * surviving key.
 */
class IosKeychainConcurrencyTest {

    /** In-memory stand-in for the Keychain. Thread-safe (CAS) but last-write-wins, like the
     *  real delete-then-add `SecItemAdd` under a race. */
    private class FakeKeychainStore : AppleKeychainStore {
        val map = KSafeConcurrentMap<ByteArray>()
        override fun readBytes(account: String): ByteArray? = map[account]
        override fun store(account: String, bytes: ByteArray, requireUnlocked: Boolean) {
            map[account] = bytes
        }
        override fun delete(account: String) { map.remove(account) }
    }

    @Test
    fun concurrentMasterKeyCreation_resolvesToExactlyOneKey() {
        val store = FakeKeychainStore()
        val engine = AppleKeychainEncryption(keychainStore = store)
        val alias = "__ksafe_master__" // the shared DEFAULT master alias — the contended one

        val n = 16
        val results: List<ByteArray> = runBlocking(Dispatchers.Default) {
            (0 until n).map { async { engine.getOrCreateKeychainKey(alias) } }.awaitAll()
        }

        val distinct = results.map { it.toList() }.distinct()
        assertEquals(
            1, distinct.size,
            "concurrent first-creation of one alias must resolve to exactly ONE key — " +
                "got ${distinct.size} distinct keys (a clobber that loses data)",
        )
        assertContentEquals(
            store.map[alias], results.first(),
            "the single surviving key in the store must equal the resolved key",
        )
        assertTrue(results.first().isNotEmpty(), "resolved key must be non-empty")
    }
}
