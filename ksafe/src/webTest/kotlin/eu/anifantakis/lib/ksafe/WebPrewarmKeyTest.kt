package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeAliasFormat
import eu.anifantakis.lib.ksafe.internal.KSafeEngineMessage
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.WebSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.localStorageGet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Locks in: prewarming a web key must never MINT one.
 *
 * Ciphertext (localStorage) and key (IndexedDB) are independently clearable on the web, so
 * "key gone, data present" is the platform's characteristic failure and the startup orphan
 * sweep reclaims it by classifying the decrypt probe's "web key missing". A prewarm that
 * mints a master instead makes that probe fail as a GCM `OperationError`, which matches no
 * orphan pattern — the sweep is one-shot, so the ciphertext is stranded forever.
 */
class WebPrewarmKeyTest {

    private fun uniquePrefix() = "ksafe_pw_${Random.nextLong().toString().trimStart('-')}_"

    @Test
    fun prewarm_doesNotMintKey_whenIndexedDbKeyIsAbsent() = runTest {
        val prefix = uniquePrefix()
        val alias = "tok"
        val ct = WebSoftwareEncryption(storagePrefix = prefix)
            .encryptSuspend(alias, "orphaned-secret".encodeToByteArray())

        // Key backend wiped while the ciphertext survives (IndexedDB-only eviction).
        WebSoftwareEncryption(storagePrefix = prefix).deleteKeySuspend(alias)

        val engine = WebSoftwareEncryption(storagePrefix = prefix)
        engine.prewarmKey(alias)

        val sameEngine = assertFails("prewarm must not make the surviving ciphertext decryptable-looking") {
            engine.decryptSuspend(alias, ct)
        }
        assertTrue(
            sameEngine.message?.contains(KSafeEngineMessage.WEB_KEY_MISSING, ignoreCase = true) == true,
            "after prewarm, decrypt must still surface '${KSafeEngineMessage.WEB_KEY_MISSING}' " +
                "(a minted key gives a GCM OperationError instead); was: ${sameEngine.message}",
        )

        // A fresh engine shares no in-process state, so this reads the STORE: still no key.
        val fresh = WebSoftwareEncryption(storagePrefix = prefix)
        val freshError = assertFails { fresh.decryptSuspend(alias, ct) }
        assertTrue(
            freshError.message?.contains(KSafeEngineMessage.WEB_KEY_MISSING, ignoreCase = true) == true,
            "prewarm must leave IndexedDB without a key for the alias; was: ${freshError.message}",
        )
    }

    @Test
    fun prewarm_warmsAnExistingKey_soTheRoundTripStillWorks() = runTest {
        val prefix = uniquePrefix()
        val alias = "tok"
        val payload = "warm-me".encodeToByteArray()
        val ct = WebSoftwareEncryption(storagePrefix = prefix).encryptSuspend(alias, payload)

        val warm = WebSoftwareEncryption(storagePrefix = prefix)
        warm.prewarmKey(alias)

        assertContentEquals(payload, warm.decryptSuspend(alias, ct), "prewarm must warm an existing key")
        assertContentEquals(payload, warm.decryptSuspend(alias, warm.encryptSuspend(alias, payload)))

        warm.deleteKeySuspend(alias)
    }

    @Test
    fun prewarmOfAnAbsentKey_stillLetsTheFirstEncryptMint() = runTest {
        val prefix = uniquePrefix()
        val alias = "tok"
        val payload = "mint-on-write".encodeToByteArray()

        val engine = WebSoftwareEncryption(storagePrefix = prefix)
        engine.prewarmKey(alias)

        val ct = engine.encryptSuspend(alias, payload)
        assertContentEquals(
            payload,
            WebSoftwareEncryption(storagePrefix = prefix).decryptSuspend(alias, ct),
            "the mint-free prewarm miss must not be cached as 'ensured': the first encrypt must " +
                "still durably create the key",
        )

        engine.deleteKeySuspend(alias)
    }

    /**
     * End-to-end: an IndexedDB-only loss (DevTools "clear IndexedDB", a corruption reset, storage
     * eviction) must leave the surviving ciphertext reclaimable by the startup orphan sweep. A
     * construction-time prewarm that minted the master would make every probe fail as a GCM error
     * instead, and the sweep is one-shot — the entry would occupy the localStorage quota for good.
     */
    @Test
    fun startupSweep_reclaimsCiphertextWhoseIndexedDbKeyWasEvicted() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()
        val rawValueKey = "ksafe.$file:${KeySafeMetadataManager.VALUE_PREFIX}tok"

        val first = KSafe(fileName = file)
        first.awaitCacheReady()
        first.put("tok", "evictable-secret", KSafeWriteMode.Encrypted())
        assertNotNull(localStorageGet(rawValueKey), "precondition: the ciphertext is persisted")
        first.close()

        // Only the key backend is wiped; localStorage (the ciphertext) is untouched.
        WebSoftwareEncryption(KSafeConfig(), "ksafe_${file}_", file)
            .deleteKeySuspend(KSafeAliasFormat.colonMaster(file))
        assertNotNull(localStorageGet(rawValueKey), "precondition: the ciphertext outlives the key")

        val reopened = KSafe(fileName = file)
        reopened.awaitCacheReady()
        val reclaimed = withContext(Dispatchers.Default) {
            withTimeoutOrNull(10_000) {
                while (localStorageGet(rawValueKey) != null) delay(10)
                true
            }
        } ?: false

        assertTrue(reclaimed, "the startup orphan sweep must reclaim ciphertext whose key is gone")
        assertEquals("DEFAULT", reopened.getDirect("tok", "DEFAULT"))

        reopened.clearAll()
    }
}
