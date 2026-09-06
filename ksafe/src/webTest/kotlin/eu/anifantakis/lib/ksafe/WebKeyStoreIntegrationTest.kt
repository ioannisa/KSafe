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

        assertNull(
            localStorageGet(legacyLsKey(prefix, alias)),
            "raw key must not be written to localStorage",
        )

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

        assertNull(
            localStorageGet(legacyLsKey(prefix, alias)),
            "legacy localStorage raw key must be deleted after migration",
        )

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
     * A legacy raw key in localStorage must win over a stale same-named key already in IndexedDB:
     * it provably encrypted the ciphertext. The dirty IDB seed is what makes this branch reachable
     * — every other web keyvault test uses a unique prefix and hits pristine IndexedDB.
     */
    @Test
    fun legacyKey_survivesUpgrade_evenWhenIndexedDbHoldsAStaleKey() = runTest {
        val prefix = uniquePrefix()
        val alias = "tok"
        val payload = "web-stale-precondition-secret"
        val realKey = ByteArray(32) { (it * 5 + 1).toByte() }

        // Ciphertext from the real legacy key, under a throwaway prefix so its IDB is pristine.
        val ctPrefix = uniquePrefix()
        localStorageSet(legacyLsKey(ctPrefix, alias), Base64.encode(realKey))
        val ctMaker = WebSoftwareEncryption(storagePrefix = ctPrefix)
        val ct = ctMaker.encryptSuspend(alias, payload.encodeToByteArray())
        ctMaker.deleteKeySuspend(alias)

        // Pollute the target prefix's IndexedDB with a stale key under the same record name.
        localStorageSet(legacyLsKey(prefix, alias), Base64.encode(ByteArray(32) { 0x5A }))
        WebSoftwareEncryption(storagePrefix = prefix)
            .encryptSuspend(alias, "x".encodeToByteArray()) // IDB[name] = stale

        // Recreate the legacy state: real legacy key in localStorage beside the stale IDB key.
        localStorageSet(legacyLsKey(prefix, alias), Base64.encode(realKey))

        val engine = WebSoftwareEncryption(storagePrefix = prefix)
        assertEquals(
            payload,
            engine.decryptSuspend(alias, ct).decodeToString(),
            "legacy localStorage key must override a stale IndexedDB key",
        )

        // The legacy copy is scrubbed only after the real key reached IDB, so a brand-new instance
        // still decrypts.
        assertNull(
            localStorageGet(legacyLsKey(prefix, alias)),
            "legacy raw key scrubbed after authoritative migration",
        )
        val fresh = WebSoftwareEncryption(storagePrefix = prefix)
        assertEquals(payload, fresh.decryptSuspend(alias, ct).decodeToString())
        fresh.deleteKeySuspend(alias)
    }

    /**
     * Web keeps ciphertext (localStorage) and key (IndexedDB) in separate backends with independent
     * eviction, so minting a key on decrypt would permanently poison surviving ciphertext. Absence
     * must surface recoverably as "web key missing" instead, matching Android/Apple/JVM.
     */
    @Test
    fun decrypt_doesNotMintKey_whenIndexedDbKeyEvicted() = runTest {
        val prefix = uniquePrefix()
        val alias = "tok"
        val ct = WebSoftwareEncryption(storagePrefix = prefix)
            .encryptSuspend(alias, "recoverable-secret".encodeToByteArray())

        // Evict the IndexedDB key (storage pressure / "clear site data") while the ciphertext survives.
        WebSoftwareEncryption(storagePrefix = prefix).deleteKeySuspend(alias)

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
     * A value written with `requireUnlockedDevice = true` stays readable on web: a browser has no
     * device-lock to enforce the flag, so the web factory strips it. Uses the real web engine — a
     * synchronous test engine would hide the async-only WebCrypto decrypt path.
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
     * The CryptoKey's IndexedDB record name is derived independently of the ciphertext prefix, so
     * adding an appNamespace has to carry the old key forward or the data reads back as missing.
     */
    @Test
    fun addingAppNamespace_keepsExistingEncryptedDataReadable() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()

        // Session 1, no appNamespace: key at the un-namespaced IndexedDB record.
        val before = KSafe(fileName = file)
        before.awaitCacheReady()
        before.put("tok", "pre-namespace-secret", KSafeWriteMode.Encrypted())
        assertEquals("pre-namespace-secret", before.get("tok", "DEFAULT"))
        before.close()

        // Session 2 adds an appNamespace; construction migrates both the data and the key forward.
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
        // Eager sweep, without touching any individual key first.
        engineA.migrateLegacyKeysSuspend()

        payloads.keys.forEach { alias ->
            assertNull(
                localStorageGet(legacyLsKey(prefix, alias)),
                "$alias raw key must be scrubbed from localStorage by the eager sweep",
            )
        }

        // A fresh instance proves the swept keys landed in IndexedDB, not in engineA's memory.
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

    /**
     * The legacy localStorage key is one shared source for every namespace and is scrubbed on first
     * import, so a namespaced consumer must also seed the shared un-namespaced IndexedDB record.
     */
    @Test
    fun legacyKeyConsumedByNamespacedInstanceFirst_staysAvailableToSiblings() = runTest {
        val prefix = uniquePrefix()
        val alias = "tok"
        localStorageSet(legacyLsKey(prefix, alias), Base64.encode(ByteArray(32) { (it * 7 + 3).toByte() }))

        // The namespaced instance touches first: imports the legacy key, scrubs the shared source.
        val nsA = WebSoftwareEncryption(KSafeConfig(appNamespace = "com.example.a"), prefix)
        val ct = nsA.encryptSuspend(alias, "shared-legacy-secret".encodeToByteArray())
        assertNull(
            localStorageGet(legacyLsKey(prefix, alias)),
            "legacy raw key must be scrubbed after the namespaced import",
        )

        val noNs = WebSoftwareEncryption(storagePrefix = prefix)
        assertEquals(
            "shared-legacy-secret",
            noNs.decryptSuspend(alias, ct).decodeToString(),
            "a no-namespace sibling must still get the legacy key after a namespaced instance consumed it first",
        )

        val nsB = WebSoftwareEncryption(KSafeConfig(appNamespace = "com.example.b"), prefix)
        assertEquals(
            "shared-legacy-secret",
            nsB.decryptSuspend(alias, ct).decodeToString(),
            "a second namespace must still get the legacy key after the first namespace consumed the localStorage source",
        )

        nsA.deleteKeySuspend(alias)
        nsB.deleteKeySuspend(alias)
        noNs.deleteKeySuspend(alias)
    }

    /**
     * A write racing a still-in-flight key delete must never commit ciphertext under the deleted
     * key: the encrypt path re-checks the key record afterwards and retries under a fresh key when
     * it lost. Single-context analogue of a cross-tab clearAll racing a sibling tab's write.
     */
    @Test
    fun writeRacingUnawaitedKeyDelete_neverCommitsUnderDeletedKey() = runTest {
        val prefix = uniquePrefix()
        val alias = "tok"
        val engine = WebSoftwareEncryption(storagePrefix = prefix)
        engine.encryptSuspend(alias, "seed".encodeToByteArray())

        // Fire-and-forget delete (IDB delete still in flight), then write immediately.
        engine.deleteKey(alias)
        val ct = engine.encryptSuspend(alias, "raced-write".encodeToByteArray())

        val fresh = WebSoftwareEncryption(storagePrefix = prefix)
        assertEquals(
            "raced-write",
            fresh.decryptSuspend(alias, ct).decodeToString(),
            "ciphertext returned by a write racing a key delete must be decryptable from a fresh instance",
        )
        fresh.deleteKeySuspend(alias)
    }
}
