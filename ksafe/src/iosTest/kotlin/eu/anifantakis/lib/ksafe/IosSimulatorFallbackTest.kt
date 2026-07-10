package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import eu.anifantakis.lib.ksafe.internal.AppleKeychainStore
import eu.anifantakis.lib.ksafe.internal.FileSimulatorFallbackKeyStore
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNull

/**
 * Locks in: the Simulator fallback's REAL sandbox file store on an actual iOS Simulator —
 * directory creation, atomic write, SHA-256 file naming, read-back across engine
 * instances, and deletion. The Keychain fake forces the -34018 path deterministically
 * regardless of the test runner's own entitlements.
 */
class IosSimulatorFallbackTest {

    /** Keychain rejecting every read/store with -34018, as an unentitled process sees it. */
    private class EntitlementBlockedKeychainStore : AppleKeychainStore {
        override fun readBytes(account: String): ByteArray? =
            throw IllegalStateException("KSafe: Keychain error -34018 for account $account")
        override fun store(account: String, bytes: ByteArray, requireUnlocked: Boolean) =
            throw IllegalStateException("KSafe: Failed to store key in Keychain, status: -34018")
        override fun delete(account: String) {}
    }

    @Test
    fun blockedKeychain_realFileStore_mintsPersistsAndDeletesOnTheSimulator() {
        // Test-scoped service name keeps these files out of the production fallback dir.
        val fallback = FileSimulatorFallbackKeyStore("eu.anifantakis.ksafe.test")
        val alias = "ios.simfallback.itest/weird key±chars" // exercises SHA-256 file naming
        fallback.delete(alias) // defensive: a stale key from a prior run must not mask the mint

        val payload = "simulator fallback payload".encodeToByteArray()
        val engine = AppleKeychainEncryption(
            keychainStore = EntitlementBlockedKeychainStore(),
            simulatorFallback = fallback,
        )
        val ct = engine.encrypt(alias, payload)
        assertContentEquals(payload, engine.decrypt(alias, ct))

        // A fresh engine (cold key cache) must read the key back from the real file.
        val reopened = AppleKeychainEncryption(
            keychainStore = EntitlementBlockedKeychainStore(),
            simulatorFallback = fallback,
        )
        assertContentEquals(payload, reopened.decrypt(alias, ct))

        reopened.deleteKey(alias)
        assertNull(fallback.read(alias), "deleteKey must remove the on-disk fallback key file")
    }
}
