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
}
