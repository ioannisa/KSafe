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
 * Locks in: the real web key path — a non-extractable WebCrypto `CryptoKey` in
 * IndexedDB plus the legacy-`localStorage` key migration — under real
 * `jsBrowserTest`/`wasmJsBrowserTest`, using the real [WebSoftwareEncryption].
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

        // The raw key must never hit localStorage; it lives only as a non-extractable CryptoKey in IndexedDB.
        assertNull(
            localStorageGet(legacyLsKey(prefix, alias)),
            "raw key must not be written to localStorage",
        )

        // Fresh engine (new-process sim) must decrypt by reloading the key from IndexedDB.
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

        // Legacy on-disk format: raw AES-256 bytes, Base64, in localStorage under the historical key name.
        val legacyRaw = ByteArray(32) { (it * 5 + 1).toByte() }
        localStorageSet(legacyLsKey(prefix, alias), Base64.encode(legacyRaw))

        val engineA = WebSoftwareEncryption(storagePrefix = prefix)
        val ct = engineA.encryptSuspend(alias, plaintext.encodeToByteArray())
        assertEquals(plaintext, engineA.decryptSuspend(alias, ct).decodeToString())

        // Legacy raw key must be scrubbed from localStorage after migration.
        assertNull(
            localStorageGet(legacyLsKey(prefix, alias)),
            "legacy localStorage raw key must be deleted after migration",
        )

        // Migrated non-extractable key in IndexedDB must still decrypt from a fresh instance.
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
     * A legacy raw key in localStorage must win over a STALE same-named non-extractable key
     * already in IndexedDB: it provably encrypted the ciphertext, so it overwrites the stale
     * key and is not destroyed. The dirty IDB seed is what makes this branch reachable — every
     * other web keyvault test uses a unique prefix and hits pristine IndexedDB.
     */
    @Test
    fun legacyKey_survivesUpgrade_evenWhenIndexedDbHoldsAStaleKey() = runTest {
        val prefix = uniquePrefix()
        val alias = "tok"
        val payload = "web-stale-precondition-secret"
        val realKey = ByteArray(32) { (it * 5 + 1).toByte() }

        // (1) Ciphertext encrypted with the REAL legacy key (throwaway prefix, pristine IDB).
        val ctPrefix = uniquePrefix()
        localStorageSet(legacyLsKey(ctPrefix, alias), Base64.encode(realKey))
        val ctMaker = WebSoftwareEncryption(storagePrefix = ctPrefix)
        val ct = ctMaker.encryptSuspend(alias, payload.encodeToByteArray())
        ctMaker.deleteKeySuspend(alias)

        // (2) Pollute the target prefix's IndexedDB with a STALE key under the same record name.
        localStorageSet(legacyLsKey(prefix, alias), Base64.encode(ByteArray(32) { 0x5A }))
        WebSoftwareEncryption(storagePrefix = prefix)
            .encryptSuspend(alias, "x".encodeToByteArray()) // IDB[name] = STALE

        // (3) Recreate the legacy state: real legacy key in localStorage beside the stale IDB key.
        localStorageSet(legacyLsKey(prefix, alias), Base64.encode(realKey))

        // (4) Fresh engine must decrypt: the legacy key is authoritative and overwrites the stale IDB key.
        val engine = WebSoftwareEncryption(storagePrefix = prefix)
        assertEquals(
            payload,
            engine.decryptSuspend(alias, ct).decodeToString(),
            "legacy localStorage key must override a stale IndexedDB key",
        )

        // Legacy scrubbed only AFTER the real key persisted to IDB; a brand-new instance still decrypts.
        assertNull(
            localStorageGet(legacyLsKey(prefix, alias)),
            "legacy raw key scrubbed after authoritative migration",
        )
        val fresh = WebSoftwareEncryption(storagePrefix = prefix)
        assertEquals(payload, fresh.decryptSuspend(alias, ct).decodeToString())
        fresh.deleteKeySuspend(alias)
    }

    /**
     * A decrypt must NEVER mint a fresh key when the IndexedDB key is absent. Web keeps
     * ciphertext (localStorage) and key (IndexedDB) in separate backends with independent
     * eviction, so minting on decrypt would permanently poison surviving ciphertext. Absence
     * must instead surface recoverably as "web key missing" so the data stays decryptable once
     * the key backend is restored (matching Android/Apple/JVM, which never create a key on read).
     */
    @Test
    fun decrypt_doesNotMintKey_whenIndexedDbKeyEvicted() = runTest {
        val prefix = uniquePrefix()
        val alias = "tok"
        val ct = WebSoftwareEncryption(storagePrefix = prefix)
            .encryptSuspend(alias, "recoverable-secret".encodeToByteArray())

        // Evict the IndexedDB key (storage pressure / "clear site data") while the ciphertext survives.
        WebSoftwareEncryption(storagePrefix = prefix).deleteKeySuspend(alias)

        // Fresh engine decrypting the surviving ciphertext must fail recoverably, not mint a poisoning key.
        val fresh = WebSoftwareEncryption(storagePrefix = prefix)
        val error = kotlin.test.assertFails("decrypt of an evicted-key entry must fail, not silently mint") {
            fresh.decryptSuspend(alias, ct)
        }
        // "web key missing" ⇔ no key minted; a minted key would instead give a GCM OperationError.
        kotlin.test.assertTrue(
            error.message?.contains("web key missing", ignoreCase = true) == true,
            "decrypt must surface recoverable 'web key missing' (no mint), got: ${error.message}",
        )
    }

    /**
     * A value written with `requireUnlockedDevice = true` must be READABLE on web: a browser has
     * no device-lock to enforce the flag, so the web factory strips it. Uses the REAL web engine
     * (a synchronous test engine would hide the async-only WebCrypto decrypt path).
     */
    @Test
    fun strictEncryptedValue_isReadableOnWeb() = runTest {
        val ksafe = KSafe(fileName = WebKSafeTest.generateUniqueFileName())
        ksafe.awaitCacheReady()
        try {
            ksafe.put("tok", "strict-secret", KSafeWriteMode.Encrypted(requireUnlockedDevice = true))
            assertEquals("strict-secret", ksafe.get("tok", "DEFAULT"), "suspend get of a strict value must return it on web")
            assertEquals("strict-secret", ksafe.getDirect("tok", "DEFAULT"), "getDirect of a strict value must return it on web")
        } finally {
            ksafe.clearAll()
        }
    }

    /**
     * Adding `appNamespace` on upgrade must keep existing encrypted data readable. The data
     * migration moves the ciphertext to the namespaced prefix, but the CryptoKey's IndexedDB
     * record name is derived independently, so the engine migrates the pre-appNamespace key
     * forward on first access — otherwise it looks under the new name, finds nothing, and the
     * data is unreadable.
     */
    @Test
    fun addingAppNamespace_keepsExistingEncryptedDataReadable() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()

        // Session 1: no appNamespace — key at the un-namespaced IndexedDB record, ciphertext at ksafe.<file>:.
        val before = KSafe(fileName = file)
        before.awaitCacheReady()
        before.put("tok", "pre-namespace-secret", KSafeWriteMode.Encrypted())
        assertEquals("pre-namespace-secret", before.get("tok", "DEFAULT"))
        before.close()

        // Session 2: the developer adds an appNamespace. Construction migrates both the data and the key forward.
        val after = KSafe(fileName = file, config = KSafeConfig(appNamespace = "com.example.app"))
        after.awaitCacheReady()
        try {
            assertEquals(
                "pre-namespace-secret",
                after.get("tok", "LOST"),
                "existing encrypted value must survive adding appNamespace on upgrade",
            )
        } finally {
            after.clearAll()
        }
    }

    @Test
    fun eagerSweep_importsEveryLegacyLocalStorageKey_andScrubs() = runTest {
        val prefix = uniquePrefix()
        val payloads = mapOf(
            "tokA" to "secret-A",
            "tokB" to "secret-B",
            "cfgC" to "secret-C",
        )

        // Seed several legacy raw localStorage keys (extractable Base64).
        payloads.keys.forEachIndexed { i, alias ->
            localStorageSet(legacyLsKey(prefix, alias), Base64.encode(ByteArray(32) { (it + i).toByte() }))
        }

        val engineA = WebSoftwareEncryption(storagePrefix = prefix)
        // Eager sweep without touching any individual key first.
        engineA.migrateLegacyKeysSuspend()

        // Every legacy raw key must be gone from localStorage.
        payloads.keys.forEach { alias ->
            assertNull(
                localStorageGet(legacyLsKey(prefix, alias)),
                "$alias raw key must be scrubbed from localStorage by the eager sweep",
            )
        }

        // Each key now usable from a fresh instance (imported as a non-extractable CryptoKey), round-tripping data.
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
