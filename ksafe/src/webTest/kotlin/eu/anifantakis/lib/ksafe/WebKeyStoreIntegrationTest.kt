package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.WebSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.localStorageGet
import eu.anifantakis.lib.ksafe.internal.localStorageRemove
import eu.anifantakis.lib.ksafe.internal.localStorageSet
import kotlinx.coroutines.test.runTest
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Integration test for the real web key path — non-extractable WebCrypto
 * `CryptoKey` persisted in IndexedDB, and the legacy-`localStorage` migration.
 *
 * Lives in `webTest`, so it runs under both `jsBrowserTest` and
 * `wasmJsBrowserTest` (real browser → real WebCrypto + IndexedDB). It uses the
 * real [WebSoftwareEncryption] (not `FakeEncryption`).
 */
@OptIn(ExperimentalEncodingApi::class)
class WebKeyStoreIntegrationTest {

    private fun uniquePrefix() = "ksafe_it_${Random.nextLong().toString().trimStart('-')}_"
    private fun legacyLsKey(prefix: String, alias: String) = "${prefix}ksafe_key_$alias"

    @Test
    fun freshKey_roundTrips_crossInstance_andNeverInLocalStorage() = runTest {
        val prefix = uniquePrefix()
        val alias = "tok"
        val plaintext = "web-fresh-secret"

        val engineA = WebSoftwareEncryption(storagePrefix = prefix)
        val ct = engineA.encryptSuspend(alias, plaintext.encodeToByteArray())
        assertEquals(plaintext, engineA.decryptSuspend(alias, ct).decodeToString())

        // The raw key must never appear in localStorage — it lives only as a
        // non-extractable CryptoKey in IndexedDB.
        assertNull(
            localStorageGet(legacyLsKey(prefix, alias)),
            "raw key must not be written to localStorage",
        )

        // A fresh engine (new process simulation) must decrypt by reloading the
        // non-extractable key from IndexedDB.
        val engineB = WebSoftwareEncryption(storagePrefix = prefix)
        assertEquals(
            plaintext,
            engineB.decryptSuspend(alias, ct).decodeToString(),
            "second instance must reload the key from IndexedDB",
        )

        engineB.deleteKeySuspend(alias)
    }

    @Test
    fun legacyLocalStorageKey_isMigrated_thenScrubbed() = runTest {
        val prefix = uniquePrefix()
        val alias = "legacy"
        val plaintext = "migrate-me-web"

        // Simulate a key written by KSafe <= 2.0: raw AES-256 bytes, Base64,
        // in localStorage under the historical key name.
        val legacyRaw = ByteArray(32) { (it * 5 + 1).toByte() }
        localStorageSet(legacyLsKey(prefix, alias), Base64.encode(legacyRaw))

        val engineA = WebSoftwareEncryption(storagePrefix = prefix)
        val ct = engineA.encryptSuspend(alias, plaintext.encodeToByteArray())
        assertEquals(plaintext, engineA.decryptSuspend(alias, ct).decodeToString())

        // Legacy raw key must be scrubbed from localStorage post-migration.
        assertNull(
            localStorageGet(legacyLsKey(prefix, alias)),
            "legacy localStorage raw key must be deleted after migration",
        )

        // The migrated (now non-extractable) key persisted in IndexedDB must
        // still decrypt from a fresh instance.
        val engineB = WebSoftwareEncryption(storagePrefix = prefix)
        assertEquals(
            plaintext,
            engineB.decryptSuspend(alias, ct).decodeToString(),
            "migrated key must round-trip from IndexedDB",
        )

        engineB.deleteKeySuspend(alias)
        localStorageRemove(legacyLsKey(prefix, alias))
    }

    @Test
    fun eagerSweep_importsEveryLegacyLocalStorageKey_andScrubs() = runTest {
        val prefix = uniquePrefix()
        val payloads = mapOf(
            "tokA" to "secret-A",
            "tokB" to "secret-B",
            "cfgC" to "secret-C",
        )

        // Seed several KSafe <= 2.0 raw localStorage keys (extractable Base64).
        payloads.keys.forEachIndexed { i, alias ->
            localStorageSet(legacyLsKey(prefix, alias), Base64.encode(ByteArray(32) { (it + i).toByte() }))
        }

        val engineA = WebSoftwareEncryption(storagePrefix = prefix)
        // Eager sweep — WITHOUT touching any individual key first.
        engineA.migrateLegacyKeysSuspend()

        // Every legacy raw key must be gone from localStorage…
        payloads.keys.forEach { alias ->
            assertNull(
                localStorageGet(legacyLsKey(prefix, alias)),
                "$alias raw key must be scrubbed from localStorage by the eager sweep",
            )
        }

        // …and each key now usable from a FRESH instance (i.e. it was imported
        // as a non-extractable CryptoKey into IndexedDB), round-tripping data.
        val engineB = WebSoftwareEncryption(storagePrefix = prefix)
        payloads.forEach { (alias, msg) ->
            val ct = engineB.encryptSuspend(alias, msg.encodeToByteArray())
            assertEquals(msg, engineB.decryptSuspend(alias, ct).decodeToString())
        }

        // Idempotent.
        engineB.migrateLegacyKeysSuspend()

        payloads.keys.forEach { alias ->
            engineB.deleteKeySuspend(alias)
            localStorageRemove(legacyLsKey(prefix, alias))
        }
    }
}
