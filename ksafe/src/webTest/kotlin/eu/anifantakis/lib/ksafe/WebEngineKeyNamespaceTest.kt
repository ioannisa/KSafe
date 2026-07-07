package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/** Locks in: per-`appNamespace` isolation of the AES-GCM CryptoKey records (real WebCrypto engine), so one app's `clearAll()` cannot make a same-`fileName` sibling undecryptable. */
class WebEngineKeyNamespaceTest {

    @Test
    fun sameFileNameDifferentAppNamespace_keysAreIsolated_soClearAllDoesNotBreakSibling() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()

        // REAL engine (no testEngine) → real AES-GCM CryptoKey in IndexedDB.
        val appA = KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.a"))
        val appB = KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.b"))
        appA.awaitCacheReady(); appB.awaitCacheReady()

        appA.put("token", "secret-A", KSafeWriteMode.Encrypted())
        appB.put("token", "secret-B", KSafeWriteMode.Encrypted())

        // A's clearAll deletes A's keys; shared keys would also destroy B's and make B undecryptable.
        appA.clearAll()

        val appBReopened = KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.b"))
        appBReopened.awaitCacheReady()
        assertEquals(
            "secret-B", appBReopened.get("token", "GONE"),
            "app B's encryption key must survive app A's clearAll — keys must be isolated per appNamespace",
        )

        appBReopened.clearAll()
    }

    /**
     * A namespaced instance's clearAll must NOT delete the un-namespaced IndexedDB key record:
     * `unNamespacedIdbName(alias)` is byte-identical to the `idbName` a co-existing no-appNamespace
     * KSafe on the same fileName uses, so deleting it would destroy that sibling's LIVE key. The
     * orphaned pre-namespace record (a non-extractable key, no plaintext) is the accepted cost.
     */
    @Test
    fun namespacedClearAll_doesNotDeleteCoexistingNoNamespaceSiblingsKey() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()

        // No-namespace store: its key lives at the un-namespaced IndexedDB record (real WebCrypto).
        val noNs = KSafe(fileName = file)
        noNs.awaitCacheReady()
        noNs.put("token", "sibling-secret", KSafeWriteMode.Encrypted())

        // Co-existing namespaced store; reading migrates the key forward (un-namespaced → namespaced), so both records exist.
        val nsApp = KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.a"))
        nsApp.awaitCacheReady()
        assertEquals("sibling-secret", nsApp.get("token", "GONE"), "precondition: namespaced store migrated + reads the value")

        // Namespaced clearAll must not delete the un-namespaced record (the sibling's live key).
        nsApp.clearAll()

        val noNsReopened = KSafe(fileName = file)
        noNsReopened.awaitCacheReady()
        assertEquals(
            "sibling-secret", noNsReopened.get("token", "GONE"),
            "a namespaced instance's clearAll must not delete a co-existing no-namespace sibling's live key",
        )
        noNsReopened.clearAll()
    }
}
