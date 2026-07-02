package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * FEEDBACK_4 low (web): the AES-GCM CryptoKey records must be isolated per
 * `appNamespace`, not shared across appNamespaces for one `fileName` — otherwise one
 * app's `clearAll()` (which deletes its keys) would make a co-existing same-`fileName`
 * app's data undecryptable. Verified against the REAL WebCrypto engine (no test engine):
 * the engine's IndexedDB record name includes the appNamespace prefix, so this locks in
 * the isolation.
 */
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

        // App A wipes itself — this deletes A's encryption keys. If the keys were shared
        // across appNamespaces, this would also destroy B's key and make B undecryptable.
        appA.clearAll()

        // B re-opened must still decrypt its own value with its own (surviving) namespaced key.
        val appBReopened = KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.b"))
        appBReopened.awaitCacheReady()
        assertEquals(
            "secret-B", appBReopened.get("token", "GONE"),
            "app B's encryption key must survive app A's clearAll — keys must be isolated per appNamespace (low)",
        )

        appBReopened.clearAll()
    }

    /**
     * FEEDBACK_4 L9: the audit proposed that a namespaced instance's delete/clearAll also delete
     * the un-namespaced IndexedDB key record left behind by the FB3-H1 copy-forward migration.
     * That is UNSAFE — `unNamespacedIdbName(alias)` is byte-identical to the `idbName` a co-existing
     * no-appNamespace KSafe on the same fileName uses, so deleting it would destroy that sibling's
     * LIVE key (an H2-class cross-instance data loss). This locks in the safe behaviour: a namespaced
     * instance's clearAll must NEVER break a co-existing no-namespace sibling's key. The orphaned
     * pre-namespace record (a non-extractable key, no plaintext) is the accepted cost instead.
     */
    @Test
    fun namespacedClearAll_doesNotDeleteCoexistingNoNamespaceSiblingsKey() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()

        // No-appNamespace store writes an encrypted value → its key lives at the un-namespaced
        // IndexedDB record (REAL engine, real WebCrypto key).
        val noNs = KSafe(fileName = file)
        noNs.awaitCacheReady()
        noNs.put("token", "sibling-secret", KSafeWriteMode.Encrypted())

        // A co-existing same-fileName namespaced store. Touching the key runs the FB3-H1
        // copy-forward (unNamespacedIdbName → its own namespaced idbName), so both records exist.
        val nsApp = KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.a"))
        nsApp.awaitCacheReady()
        assertEquals("sibling-secret", nsApp.get("token", "GONE"), "precondition: namespaced store migrated + reads the value")

        // The namespaced instance wipes itself. It must NOT delete the un-namespaced record —
        // that is the no-namespace sibling's live key.
        nsApp.clearAll()

        // The no-namespace sibling, re-opened from disk, must still decrypt its own value.
        val noNsReopened = KSafe(fileName = file)
        noNsReopened.awaitCacheReady()
        assertEquals(
            "sibling-secret", noNsReopened.get("token", "GONE"),
            "a namespaced instance's clearAll must not delete a co-existing no-namespace sibling's live key (L9 must not be 'fixed' by deleting unNamespacedIdbName)",
        )
        noNsReopened.clearAll()
    }
}
