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

    /**
     * The 2.0.0 → 2.1.0 upgrade, web edition, with the realistic
     * **dirty** precondition: IndexedDB already holds a STALE non-extractable
     * key under this name (from a prior KSafe lifecycle in this origin) while
     * the genuine legacy raw key is still in localStorage. The legacy key
     * provably encrypted the ciphertext and must win; the stale IDB key must
     * be overwritten and the legacy key must NOT be destroyed.
     *
     * Every other web keyvault test uses a unique prefix ⇒ pristine IndexedDB
     * ⇒ the stale-shadow branch is unreachable; the dirty seed here is what
     * makes this test discriminate.
     */
    @Test
    fun legacyKey_survivesUpgrade_evenWhenIndexedDbHoldsAStaleKey() = runTest {
        val prefix = uniquePrefix()
        val alias = "tok"
        val payload = "web-stale-precondition-secret"
        val realKey = ByteArray(32) { (it * 5 + 1).toByte() }

        // (1) Ciphertext genuinely encrypted with the REAL legacy key (throw-
        //     away prefix, pristine IDB ⇒ it imports realKey and encrypts).
        val ctPrefix = uniquePrefix()
        localStorageSet(legacyLsKey(ctPrefix, alias), Base64.encode(realKey))
        val ctMaker = WebSoftwareEncryption(storagePrefix = ctPrefix)
        val ct = ctMaker.encryptSuspend(alias, payload.encodeToByteArray())
        ctMaker.deleteKeySuspend(alias)

        // (2) Pollute the TARGET prefix's IndexedDB with a STALE key under the
        //     same record name (import a different "legacy" then scrub LS).
        localStorageSet(legacyLsKey(prefix, alias), Base64.encode(ByteArray(32) { 0x5A }))
        WebSoftwareEncryption(storagePrefix = prefix)
            .encryptSuspend(alias, "x".encodeToByteArray()) // IDB[name] = STALE

        // (3) Recreate the genuine 2.0.0 state: real legacy key in localStorage
        //     alongside the now-stale IndexedDB key.
        localStorageSet(legacyLsKey(prefix, alias), Base64.encode(realKey))

        // (4) Fresh engine must decrypt the 2.0.0 ciphertext: legacy is
        //     authoritative and overwrites the stale IDB key.
        val engine = WebSoftwareEncryption(storagePrefix = prefix)
        assertEquals(
            payload,
            engine.decryptSuspend(alias, ct).decodeToString(),
            "legacy localStorage key must override a stale IndexedDB key",
        )

        // Legacy scrubbed only AFTER the real key was persisted to IDB; and a
        // brand-new instance still decrypts (real key truly in IndexedDB now).
        assertNull(
            localStorageGet(legacyLsKey(prefix, alias)),
            "legacy raw key scrubbed after authoritative migration",
        )
        val fresh = WebSoftwareEncryption(storagePrefix = prefix)
        assertEquals(payload, fresh.decryptSuspend(alias, ct).decodeToString())
        fresh.deleteKeySuspend(alias)
    }

    /**
     * FEEDBACK_4 H-A: a **decrypt** must NEVER mint a fresh key when the IndexedDB
     * key is absent. Web stores ciphertext (localStorage) and the key (IndexedDB)
     * in separate backends with independent eviction; if the IDB key goes missing
     * while the ciphertext survives, minting a fresh key on decrypt makes the old
     * ciphertext permanently undecryptable AND poisons it (a fresh key persisted).
     * Absence must instead surface recoverably as "web key missing" so the data
     * stays decryptable once the key backend is restored (matching Android/Apple/JVM,
     * which never create a key on the read path).
     */
    @Test
    fun decrypt_doesNotMintKey_whenIndexedDbKeyEvicted() = runTest {
        val prefix = uniquePrefix()
        val alias = "tok"
        val ct = WebSoftwareEncryption(storagePrefix = prefix)
            .encryptSuspend(alias, "recoverable-secret".encodeToByteArray())

        // Simulate the IndexedDB key backend being evicted (browser storage
        // pressure / "clear cached site data") while the localStorage ciphertext
        // (held in `ct`) survives.
        WebSoftwareEncryption(storagePrefix = prefix).deleteKeySuspend(alias)

        // A fresh engine (new session, empty in-memory `ensured`) decrypting the
        // surviving ciphertext must FAIL RECOVERABLY, not mint a poisoning key.
        val fresh = WebSoftwareEncryption(storagePrefix = prefix)
        val error = kotlin.test.assertFails("decrypt of an evicted-key entry must fail, not silently mint") {
            fresh.decryptSuspend(alias, ct)
        }
        // "web key missing" ⇔ keyOf returned null ⇔ decrypt did NOT mint a key.
        // (A minted key would instead produce a GCM OperationError.)
        kotlin.test.assertTrue(
            error.message?.contains("web key missing", ignoreCase = true) == true,
            "decrypt must surface recoverable 'web key missing' (no mint), got: ${error.message}",
        )
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
