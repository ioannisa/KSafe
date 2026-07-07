package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.cleanupOrphanedKeychainEntries
import eu.anifantakis.lib.ksafe.internal.keychainOrphanSweepEnabled
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.OsFamily
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: the Keychain orphan sweep is a no-op on macOS, whose shared per-user login
 * keychain (no app-identity scoping) would otherwise let one app's sweep delete another
 * app's keys.
 */
class MacosKeychainSweepTest {

    /** Records whether the sweep read storage, i.e. did NOT short-circuit. */
    private class SpyStorage : KSafePlatformStorage {
        var snapshotCalled = false
        override suspend fun snapshot(): Map<String, StoredValue> {
            snapshotCalled = true
            return emptyMap()
        }
        override fun snapshotFlow(): Flow<Map<String, StoredValue>> = flowOf(emptyMap())
        override suspend fun applyBatch(ops: List<StorageOp>) {}
        override suspend fun clear() {}
    }

    @Test
    fun sweepIsNoOpOnMacOs_neverTouchesStorageOrKeychain() = runBlocking {
        val spy = SpyStorage()
        cleanupOrphanedKeychainEntries(
            storage = spy,
            engine = FakeEncryption(),
            serviceName = "eu.anifantakis.ksafe",
            keyPrefix = "eu.anifantakis.ksafe",
            fileName = null,
            legacyEncryptedPrefix = "__ksafe_encrypted_",
            seKeyTagPrefix = "se.",
            reservedKeyIds = emptySet(),
        )
        assertFalse(
            spy.snapshotCalled,
            "the Keychain orphan sweep must be a no-op on macOS (shared login keychain)",
        )
    }

    @OptIn(ExperimentalNativeApi::class)
    @Test
    fun sweepEnabledDecision_disablesMacOsOnly() {
        assertFalse(keychainOrphanSweepEnabled(OsFamily.MACOSX), "must be disabled on macOS")
        assertTrue(keychainOrphanSweepEnabled(OsFamily.IOS), "must stay enabled on iOS (app-private keychain)")
        assertTrue(keychainOrphanSweepEnabled(OsFamily.TVOS))
        assertTrue(keychainOrphanSweepEnabled(OsFamily.WATCHOS))
    }
}
