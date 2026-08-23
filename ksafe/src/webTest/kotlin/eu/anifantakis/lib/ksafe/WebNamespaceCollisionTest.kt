package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.WebSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.localStorageSet
import eu.anifantakis.lib.ksafe.internal.webKeyEncrypt
import eu.anifantakis.lib.ksafe.internal.webKeyEnsure
import kotlinx.coroutines.test.runTest
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails

/**
 * Locks in: a lossy `appNamespace` sanitization can no longer collide two DIFFERENT
 * configured ids (`a/b` vs `a?b` both → `a_b`) onto one data prefix / key custody — while
 * data and keys written by ≤ 2.2.1 under the old lossy token still carry forward.
 */
@OptIn(ExperimentalEncodingApi::class)
class WebNamespaceCollisionTest {

    @Test
    fun lossyCollidingNamespaces_dataStaysIsolated() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()

        val slash = KSafe(fileName = file, config = KSafeConfig(appNamespace = "a/b"), testEngine = FakeEncryption())
        val question = KSafe(fileName = file, config = KSafeConfig(appNamespace = "a?b"), testEngine = FakeEncryption())
        slash.awaitCacheReady(); question.awaitCacheReady()

        slash.put("k", "from-slash", KSafeWriteMode.Plain)
        question.put("k", "from-question", KSafeWriteMode.Plain)

        // Each store must read ITS OWN value from disk — one shared lossy prefix would make
        // the second write clobber the first.
        val slashReopened = KSafe(fileName = file, config = KSafeConfig(appNamespace = "a/b"), testEngine = FakeEncryption())
        slashReopened.awaitCacheReady()
        assertEquals("from-slash", slashReopened.get("k", "GONE"), "'a/b' must keep its own data slot")

        // And one store's clearAll must not wipe the other.
        slashReopened.clearAll()
        val questionReopened = KSafe(fileName = file, config = KSafeConfig(appNamespace = "a?b"), testEngine = FakeEncryption())
        questionReopened.awaitCacheReady()
        assertEquals(
            "from-question", questionReopened.get("k", "GONE"),
            "'a/b'.clearAll() must not reach into 'a?b''s slots",
        )
        questionReopened.clearAll()
    }

    @Test
    fun preCanonicalLossyNamespacedData_carriesForward() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()

        // A ≤ 2.2.1 install with appNamespace "a/b" wrote under the lossy "a_b@" segment.
        val oldPrefix = "ksafe.a_b@$file:"
        localStorageSet(oldPrefix + KeySafeMetadataManager.valueRawKey("k"), "legacy-value")
        localStorageSet(
            oldPrefix + KeySafeMetadataManager.metadataRawKey("k"),
            KeySafeMetadataManager.buildMetadataJson(protection = null, accessPolicy = null),
        )

        val upgraded = KSafe(fileName = file, config = KSafeConfig(appNamespace = "a/b"), testEngine = FakeEncryption())
        upgraded.awaitCacheReady()
        assertEquals(
            "legacy-value", upgraded.get("k", "GONE"),
            "data written under the ≤ 2.2.1 lossy namespace segment must carry forward",
        )
        upgraded.clearAll()
    }

    @Test
    fun lossyCollidingNamespaces_doNotShareKeyCustody() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()
        val enginePrefix = "ksafe_${file}_"

        // REAL WebCrypto engines: one shared lossy token would resolve both to ONE IndexedDB
        // key record, silently sharing key custody across two logical apps.
        val slash = WebSoftwareEncryption(KSafeConfig(appNamespace = "a/b"), enginePrefix)
        val question = WebSoftwareEncryption(KSafeConfig(appNamespace = "a?b"), enginePrefix)

        val ct = slash.encryptSuspend("token", "secret-slash".encodeToByteArray())
        assertFails("'a?b' must not be able to decrypt with 'a/b''s key") {
            question.decryptSuspend("token", ct)
        }
    }

    @Test
    fun preCanonicalLossyNamespacedKey_migratesForwardToTheCanonicalRecord() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()
        val enginePrefix = "ksafe_${file}_"

        // Seed a key + ciphertext under the FROZEN ≤ 2.2.1 record name ("a_b:" + engine prefix).
        val oldIdbName = "a_b:${enginePrefix}ksafe_key_token"
        webKeyEnsure(
            oldIdbName,
            null,
            mintIfAbsent = true,
            keySizeBits = KSafeAesKeySize.BITS_256.bits,
        )
        val ctB64 = webKeyEncrypt(oldIdbName, Base64.encode("legacy-secret".encodeToByteArray()), null)

        // The upgraded canonical engine must find it via the lossy-legacy probe.
        val upgraded = WebSoftwareEncryption(KSafeConfig(appNamespace = "a/b"), enginePrefix)
        assertContentEquals(
            "legacy-secret".encodeToByteArray(),
            upgraded.decryptSuspend("token", Base64.decode(ctB64)),
            "a key written under the ≤ 2.2.1 lossy record name must migrate forward",
        )
    }
}
