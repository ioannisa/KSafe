package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.anifantakis.lib.ksafe.internal.AndroidKeystoreEncryption
import eu.anifantakis.lib.ksafe.internal.DataStoreDekStore
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.isDefinitivelyUnreadableKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.UnrecoverableKeyException
import javax.crypto.SecretKey
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Locks in: only a PROVEN-permanent Keystore fault may delete and re-mint a key. A transient
 * daemon fault (keystore2 restarting, busy, StrongBox HAL absent) also surfaces as an
 * UnrecoverableKeyException, and treating it as permanent would erase every encrypted value.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKeystoreUnreadableKeyTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private val scopes = mutableListOf<CoroutineScope>()
    private val files = mutableListOf<File>()

    @After
    fun tearDown() {
        scopes.forEach { runCatching { it.cancel() } }
        files.forEach { runCatching { it.delete() } }
    }

    private var counter = 0
    private fun uniqueAlias(): String { counter++; return "ksafe_unreadable_${System.nanoTime()}_$counter" }

    private fun newStorage(): DataStoreStorage {
        counter++
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob()); scopes += scope
        val file = File(context.cacheDir, "unreadable_${System.nanoTime()}_$counter.preferences_pb"); files += file
        return DataStoreStorage(PreferenceDataStoreFactory.create(scope = scope) { file })
    }

    private fun engine(storage: DataStoreStorage) =
        AndroidKeystoreEncryption(config = KSafeConfig(), dekStore = DataStoreDekStore(storage), useSoftwareDek = true)

    private fun engine(storage: DataStoreStorage, loadKey: (String) -> SecretKey?) =
        AndroidKeystoreEncryption(
            config = KSafeConfig(),
            dekStore = DataStoreDekStore(storage),
            useSoftwareDek = true,
            loadKey = loadKey,
        )

    private fun dekRecord(storage: DataStoreStorage): String? =
        runBlocking { (storage.snapshot()[DataStoreDekStore.DEK_KEY] as? StoredValue.Text)?.value }

    /** A daemon-level fault: keystore2 wraps it into an URE that carries a cause. */
    private fun transientUre(): UnrecoverableKeyException =
        UnrecoverableKeyException("Failed to obtain X.509 form of public key")
            .apply { initCause(java.io.IOException("keystore busy")) }

    /** AndroidKeyStoreSpi re-wraps a permanently invalidated key as a cause-less URE. */
    private fun definitiveUre(): UnrecoverableKeyException = UnrecoverableKeyException("Key permanently invalidated")

    // --- the pure decision ---

    @Test
    fun causeLessFailure_isDefinitive() {
        assertTrue(isDefinitivelyUnreadableKey(hasCause = false, keyStoreErrorCode = null, isSystemError = false))
    }

    @Test
    fun unknownCause_isNotDefinitive() {
        assertFalse(isDefinitivelyUnreadableKey(hasCause = true, keyStoreErrorCode = null, isSystemError = false))
    }

    @Test
    fun systemError_isNotDefinitive_evenWhenCodeSaysCorrupted() {
        assertFalse(isDefinitivelyUnreadableKey(hasCause = true, keyStoreErrorCode = 7, isSystemError = true))
    }

    @Test
    fun corruptedOrAbsentKey_isDefinitive() {
        assertTrue(isDefinitivelyUnreadableKey(hasCause = true, keyStoreErrorCode = 7, isSystemError = false))
        assertTrue(isDefinitivelyUnreadableKey(hasCause = true, keyStoreErrorCode = 6, isSystemError = false))
    }

    @Test
    fun everyOtherErrorCode_isNotDefinitive() {
        for (code in listOf(1, 2, 3, 4, 5, 11)) {
            assertFalse(
                isDefinitivelyUnreadableKey(hasCause = true, keyStoreErrorCode = code, isSystemError = false),
                "error code $code is not proof the key is permanently unreadable",
            )
        }
    }

    // --- the wiring ---

    @Test
    fun transientFailure_onWrite_throwsRetryable_andKeepsTheWrappedDek() {
        val storage = newStorage()
        val alias = uniqueAlias()
        val healthy = engine(storage)
        try {
            healthy.encrypt(alias, "secret".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            val before = dekRecord(storage)
            assertNotNull(before, "precondition: a wrapped DEK is persisted")

            val flaky = engine(storage) { throw transientUre() }
            val failure = assertFailsWith<IllegalStateException> {
                flaky.encrypt(alias, "again".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            }
            val message = failure.message.orEmpty()
            assertFalse(message.contains("No encryption key found"), "a transient fault must not report a missing key: $message")
            assertTrue(message.contains("Keystore"), "a transient fault must surface as a retryable Keystore error: $message")

            assertEquals(before, dekRecord(storage), "a transient Keystore fault must not destroy the wrapped DEK")
        } finally {
            healthy.deleteKey(alias)
        }
    }

    @Test
    fun transientFailure_onRead_surfacesAsRetryable() {
        val storage = newStorage()
        val alias = uniqueAlias()
        val healthy = engine(storage)
        try {
            val blob = healthy.encrypt(alias, "secret".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)

            val flaky = engine(storage) { throw transientUre() }
            val failure = assertFailsWith<IllegalStateException> { flaky.decrypt(alias, blob) }
            val message = failure.message.orEmpty()
            // The message IS the contract: isTransientDecryptFailure accepts it, so the orphan
            // sweep leaves the entry alone instead of reclaiming a still-good value.
            assertFalse(message.contains("No encryption key found"), "a transient fault must not report a missing key: $message")
            assertTrue(message.contains("Keystore"), "a transient fault must surface as a retryable Keystore error: $message")
        } finally {
            healthy.deleteKey(alias)
        }
    }

    @Test
    fun definitiveFailure_onWrite_stillSelfHeals() {
        val storage = newStorage()
        val alias = uniqueAlias()
        val healthy = engine(storage)
        try {
            healthy.encrypt(alias, "secret".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            val before = dekRecord(storage)
            assertNotNull(before, "precondition: a wrapped DEK is persisted")

            val broken = engine(storage) { throw definitiveUre() }
            broken.encrypt(alias, "again".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)

            val after = dekRecord(storage)
            assertNotNull(after, "the write must succeed on a freshly minted key")
            assertNotEquals(before, after, "a permanently unreadable key must still be re-minted")
        } finally {
            healthy.deleteKey(alias)
        }
    }
}
