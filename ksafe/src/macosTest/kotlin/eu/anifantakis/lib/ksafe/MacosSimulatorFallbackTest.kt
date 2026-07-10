package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import eu.anifantakis.lib.ksafe.internal.AppleKeychainStore
import eu.anifantakis.lib.ksafe.internal.KSafeConcurrentMap
import eu.anifantakis.lib.ksafe.internal.SimulatorFallbackKeyStore
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Locks in: the iOS-Simulator fallback for an entitlement-blocked Keychain
 * (`errSecMissingEntitlement`, -34018). With a fallback store injected, an unentitled
 * process mints/serves keys from the sandbox store and encrypted writes keep working;
 * without one (a real device), -34018 still fails loudly. Fakes stand in for both
 * stores — real Keychain round-trips can't run in the Kotlin/Native test runner.
 */
class MacosSimulatorFallbackTest {

    /** Keychain rejecting every read/store with -34018, as an unentitled process sees it. */
    private class EntitlementBlockedKeychainStore : AppleKeychainStore {
        var storeAttempts = 0
        override fun readBytes(account: String): ByteArray? =
            throw IllegalStateException("KSafe: Keychain error -34018 for account $account")
        override fun store(account: String, bytes: ByteArray, requireUnlocked: Boolean) {
            storeAttempts++
            throw IllegalStateException("KSafe: Failed to store key in Keychain, status: -34018")
        }
        override fun delete(account: String) {}
    }

    private class FakeKeychainStore : AppleKeychainStore {
        val map = KSafeConcurrentMap<ByteArray>()
        override fun readBytes(account: String): ByteArray? = map[account]
        override fun store(account: String, bytes: ByteArray, requireUnlocked: Boolean) { map[account] = bytes }
        override fun delete(account: String) { map.remove(account) }
    }

    private class InMemoryFallbackStore : SimulatorFallbackKeyStore {
        val map = KSafeConcurrentMap<ByteArray>()
        var writes = 0
        override fun read(account: String): ByteArray? = map[account]
        override fun write(account: String, bytes: ByteArray) { writes++; map[account] = bytes }
        override fun delete(account: String) { map.remove(account) }
    }

    private val payload = "sim-fallback secret".encodeToByteArray()

    @Test
    fun blockedKeychain_withFallback_encryptDecryptRoundTrips() {
        val fallback = InMemoryFallbackStore()
        val engine = AppleKeychainEncryption(
            keychainStore = EntitlementBlockedKeychainStore(),
            simulatorFallback = fallback,
        )
        assertFalse(engine.isSimulatorFallbackActive(), "fallback must report inactive before any op")

        val ct = engine.encrypt("alias.roundtrip", payload)
        assertContentEquals(payload, engine.decrypt("alias.roundtrip", ct))
        assertTrue(engine.isSimulatorFallbackActive(), "a fallback-minted key must set the active flag")
        assertEquals(1, fallback.writes, "exactly one key must be minted into the fallback store")
    }

    @Test
    fun blockedKeychain_withFallback_keySurvivesEngineRestart() {
        val fallback = InMemoryFallbackStore()
        val ct = AppleKeychainEncryption(
            keychainStore = EntitlementBlockedKeychainStore(),
            simulatorFallback = fallback,
        ).encrypt("alias.restart", payload)

        // A fresh engine (cold key cache) must decrypt via the persisted fallback key.
        val reopened = AppleKeychainEncryption(
            keychainStore = EntitlementBlockedKeychainStore(),
            simulatorFallback = fallback,
        )
        assertContentEquals(payload, reopened.decrypt("alias.restart", ct))
    }

    @Test
    fun blockedKeychain_withoutFallback_throwsWithActionableHint() {
        // Real devices construct no fallback store — -34018 must keep failing loudly.
        val engine = AppleKeychainEncryption(keychainStore = EntitlementBlockedKeychainStore())
        val e = assertFails { engine.encrypt("alias.device", payload) }
        assertTrue(
            e.message.orEmpty().contains("-34018"),
            "the device-path failure must surface the raw OSStatus; was: ${e.message}",
        )
    }

    @Test
    fun workingKeychain_fallbackStaysEmptyAndInactive() {
        val keychain = FakeKeychainStore()
        val fallback = InMemoryFallbackStore()
        val engine = AppleKeychainEncryption(keychainStore = keychain, simulatorFallback = fallback)

        val ct = engine.encrypt("alias.entitled", payload)
        assertContentEquals(payload, engine.decrypt("alias.entitled", ct))
        assertEquals(0, fallback.writes, "an entitled process must keep using the Keychain")
        assertFalse(engine.isSimulatorFallbackActive(), "fallback must stay inactive when the Keychain works")
    }

    @Test
    fun fallbackKey_winsOverKeychainKey_stickyPrecedence() {
        // A broken period minted a fallback key and encrypted data under it; entitlements
        // were then fixed. The fallback key must keep winning or that data goes unreadable.
        val fallback = InMemoryFallbackStore()
        val ct = AppleKeychainEncryption(
            keychainStore = EntitlementBlockedKeychainStore(),
            simulatorFallback = fallback,
        ).encrypt("alias.sticky", payload)

        val healedKeychain = FakeKeychainStore()
        val healed = AppleKeychainEncryption(keychainStore = healedKeychain, simulatorFallback = fallback)
        assertContentEquals(
            payload, healed.decrypt("alias.sticky", ct),
            "data written under the fallback key must stay readable after entitlements are fixed",
        )
        // And new writes keep converging on the same fallback key — never a divergent Keychain twin.
        val ct2 = healed.encrypt("alias.sticky", payload)
        assertContentEquals(payload, healed.decrypt("alias.sticky", ct2))
        assertNull(healedKeychain.map["alias.sticky"], "no divergent Keychain key may be minted for a fallback alias")
    }

    @Test
    fun blockedKeychain_hardwareIsolated_routesToFallbackAndRoundTrips() {
        // The SE path first reads the wrapped-key account, which throws -34018; that must
        // route to the plain path's fallback, not rethrow out of encrypt.
        val fallback = InMemoryFallbackStore()
        val engine = AppleKeychainEncryption(
            keychainStore = EntitlementBlockedKeychainStore(),
            simulatorFallback = fallback,
        )
        val ct = engine.encrypt("alias.hw", payload, hardwareIsolated = true)
        assertContentEquals(payload, engine.decrypt("alias.hw", ct))
        assertTrue(engine.isSimulatorFallbackActive())
    }

    @Test
    fun blockedKeychain_strictRequireUnlocked_roundTrips() {
        // requireUnlockedDevice can't be Keychain-enforced under the fallback (Simulator-only
        // dev convenience); the value must still round-trip rather than fail every write.
        val fallback = InMemoryFallbackStore()
        val engine = AppleKeychainEncryption(
            keychainStore = EntitlementBlockedKeychainStore(),
            simulatorFallback = fallback,
        )
        val ct = engine.encrypt("alias.strict", payload, requireUnlockedDevice = true)
        assertContentEquals(payload, engine.decrypt("alias.strict", ct, requireUnlockedDevice = true))
    }

    @Test
    fun deleteKey_removesTheFallbackKey() {
        val fallback = InMemoryFallbackStore()
        val engine = AppleKeychainEncryption(
            keychainStore = EntitlementBlockedKeychainStore(),
            simulatorFallback = fallback,
        )
        engine.encrypt("alias.delete", payload)
        engine.deleteKey("alias.delete")
        assertNull(fallback.read("alias.delete"), "deleteKey must remove the fallback key file")
    }

    @Test
    fun decrypt_neverMintsAFallbackKey() {
        // Decrypt has no create-on-miss: with no key anywhere it must throw, not mint a
        // fresh key that would poison the ciphertext as permanently undecryptable.
        val fallback = InMemoryFallbackStore()
        val engine = AppleKeychainEncryption(
            keychainStore = EntitlementBlockedKeychainStore(),
            simulatorFallback = fallback,
        )
        assertFails { engine.decrypt("alias.nokey", payload) }
        assertEquals(0, fallback.writes, "a failed decrypt must never mint a key")
    }

    @Test
    fun missingEntitlementFailure_matchesOnlyThatStatus() {
        assertTrue(AppleKeychainEncryption.isMissingEntitlementFailure("KSafe: Keychain error -34018 for account x"))
        assertTrue(AppleKeychainEncryption.isMissingEntitlementFailure("KSafe: Failed to store key in Keychain, status: -34018"))
        assertFalse(AppleKeychainEncryption.isMissingEntitlementFailure("KSafe: Keychain error -25300 for account x"))
        assertFalse(AppleKeychainEncryption.isMissingEntitlementFailure("KSafe: Cannot access Keychain - device is locked."))
        assertFalse(AppleKeychainEncryption.isMissingEntitlementFailure(null))
    }
}
