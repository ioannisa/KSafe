package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainStore
import eu.anifantakis.lib.ksafe.internal.KSafeConcurrentMap

/**
 * In-memory [AppleKeychainStore] for the iOS and macOS suites: the real Keychain is not reachable
 * from a sandboxed test process, so every engine-level test injects this instead. Shared because
 * a copy whose `store`/`readBytes` pairing drifts would let one platform's suite pass against
 * semantics the other never sees.
 */
internal class FakeKeychainStore : AppleKeychainStore {
    val map = KSafeConcurrentMap<ByteArray>()
    override fun readBytes(account: String): ByteArray? = map[account]
    override fun store(account: String, bytes: ByteArray, requireUnlocked: Boolean) { map[account] = bytes }
    override fun delete(account: String) { map.remove(account) }
}
