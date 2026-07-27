package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.WebSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.localStorageSet
import eu.anifantakis.lib.ksafe.internal.webKeyMigrationSealMarker
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull

/**
 * `KSafe()` and `KSafe("default")` are separate stores that share the `ksafe_default_` legacy
 * prefix. Their key records stay apart because the alias carries the fileName, but everything
 * derived from the prefix ALONE lands on both — locks in that neither store's wipe can reach
 * into the other through one of those.
 */
class WebDefaultStoreSealScopeTest {

    private val config = KSafeConfig(appNamespace = "com.example.defaultseal")

    @Test
    fun theTwoDefaultSpellingsGetDistinctSeals() {
        val unnamed = assertNotNull(webKeyMigrationSealMarker(config.appNamespace, "ksafe_default_", null))
        val named = assertNotNull(webKeyMigrationSealMarker(config.appNamespace, "ksafe_default_", "default"))
        assertNotEquals(
            unnamed, named,
            "the seal is derived from the shared prefix; one marker for both would let either " +
                "store's wipe permanently close the other's key migrate-forward",
        )
    }

    /**
     * The wipe writes a permanent marker, so a seal that reached the sibling would strand its
     * pre-namespace ciphertext undecryptable for good.
     */
    @Test
    fun oneSpellingsWipe_doesNotSealTheOthersKeyMigration() = runTest {
        // A unique prefix standing in for the shared `ksafe_default_`, so the two engines below
        // have identical key custody without touching the real default store's records.
        val prefix = "ksafe_${WebKSafeTest.generateUniqueFileName()}_"
        val payload = "pre-namespace-secret".encodeToByteArray()

        val preNamespace = WebSoftwareEncryption(KSafeConfig(), prefix)
        val ct = preNamespace.encryptSuspend("token", payload)

        // KSafe("default") under the namespace wipes: only ITS seal may be written.
        localStorageSet(
            assertNotNull(webKeyMigrationSealMarker(config.appNamespace, prefix, "default")), "1",
        )

        val unnamed = WebSoftwareEncryption(config, prefix, fileName = null)
        assertContentEquals(
            payload, unnamed.decryptSuspend("token", ct),
            "the sibling store's wipe must not close KSafe()'s migrate-forward",
        )
    }

    /**
     * End to end, through the two spellings themselves: the alias carries the fileName, so their
     * key records never coincide and a wipe of one leaves the other whole.
     */
    @Test
    fun oneSpellingsWipe_leavesTheOthersEncryptedDataReadable() = runTest {
        // A unique appNamespace isolates both stores from the rest of the suite while keeping the
        // two spellings on the one legacy prefix they really share.
        val isolated = KSafeConfig(appNamespace = "shared-${WebKSafeTest.generateUniqueFileName()}")

        val unnamed = KSafe(config = isolated)
        val named = KSafe(fileName = "default", config = isolated)
        unnamed.awaitCacheReady(); named.awaitCacheReady()

        unnamed.put("token", "sibling-secret", KSafeWriteMode.Encrypted())
        named.put("token", "its-own-secret", KSafeWriteMode.Encrypted())

        named.clearAll()

        val reopened = KSafe(config = isolated)
        reopened.awaitCacheReady()
        assertEquals(
            "sibling-secret", reopened.get("token", "GONE"),
            "KSafe(\"default\").clearAll() must not reach KSafe()'s key or data",
        )

        reopened.clearAll()
    }
}
