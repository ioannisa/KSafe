package eu.anifantakis.lib.ksafe

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyInfo
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.preferencesDataStoreFile
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.anifantakis.lib.ksafe.internal.ANDROID_KEYSTORE_PROVIDER
import eu.anifantakis.lib.ksafe.internal.AndroidKeystoreEncryption
import eu.anifantakis.lib.ksafe.internal.AndroidLockScreen
import eu.anifantakis.lib.ksafe.internal.DataStoreDekStore
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.KSafeAliasFormat
import eu.anifantakis.lib.ksafe.internal.KSafeProtectionNotes
import eu.anifantakis.lib.ksafe.internal.RelaxedMintMarkerStore
import eu.anifantakis.lib.ksafe.internal.dataStoreBaseFileName
import eu.anifantakis.lib.ksafe.internal.relaxesUnlockedDeviceRequirement
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.lang.reflect.Method
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Locks in: on API 28..34 without a secure lock screen a strict key is minted without
 * `setUnlockedDeviceRequired`, stays on the per-call TEE path, and is reported in
 * `protectionInfo.notes` until a new key generation re-decides, even after a lock screen appears.
 * The seams replace the decision's inputs only, so the API band is decided by production code.
 */
@RunWith(AndroidJUnit4::class)
class AndroidLockScreenAbsentTest {

    private val note = KSafeProtectionNotes.ANDROID_LOCK_SCREEN_ABSENT

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    // "KSD1" — must match AndroidKeystoreEncryption.DEK_MAGIC.
    private val magic = byteArrayOf(0x4B, 0x53, 0x44, 0x31)

    private val scopes = mutableListOf<CoroutineScope>()
    private val files = mutableListOf<File>()
    private val safes = mutableListOf<KSafe>()

    @Before
    fun resetSeamsBefore() = resetSeams()

    @After
    fun tearDown() {
        resetSeams()
        safes.forEach { safe ->
            runCatching { runBlocking { safe.clearAll() } }
            runCatching { safe.close() }
        }
        safes.clear()
        scopes.forEach { runCatching { it.cancel() } }
        files.forEach { runCatching { it.delete() } }
    }

    private fun resetSeams() {
        AndroidLockScreen.deviceSecureForTest = null
        AndroidLockScreen.sdkIntForTest = null
    }

    /** An API 28..34 device with no secure lock screen: the band where the mint must relax. */
    private fun forceRelax() {
        AndroidLockScreen.sdkIntForTest = 30
        AndroidLockScreen.deviceSecureForTest = false
    }

    /** Same band, lock screen present: the mint must keep the flag. */
    private fun forceKeep() {
        AndroidLockScreen.sdkIntForTest = 30
        AndroidLockScreen.deviceSecureForTest = true
    }

    private var counter = 0
    private fun uniqueName(prefix: String): String {
        counter++
        return "${prefix}_${System.nanoTime()}_$counter"
    }

    private fun newStorage(): DataStoreStorage {
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        scopes += scope
        val file = File(context.cacheDir, "${uniqueName("lockscreen")}.preferences_pb")
        files += file
        return DataStoreStorage(PreferenceDataStoreFactory.create(scope = scope) { file })
    }

    private fun engine(storage: DataStoreStorage) =
        AndroidKeystoreEncryption(config = KSafeConfig(), dekStore = DataStoreDekStore(storage))

    /** As the factory builds it: with the marker store the production engine gets. */
    private fun markingEngine(storage: DataStoreStorage) =
        engine(storage).apply { relaxedMintMarkers = RelaxedMintMarkerStore(storage) }

    private fun newSafe(fileName: String): KSafe {
        files += context.preferencesDataStoreFile(dataStoreBaseFileName(fileName))
        return KSafe(context, fileName = fileName).also { safes += it }
    }

    private fun notes(safe: KSafe): List<String> = safe.protectionInfo.notes

    private fun dekPresent(storage: DataStoreStorage): Boolean =
        runBlocking { storage.snapshot().containsKey(DataStoreDekStore.DEK_KEY) }

    private fun markerRecordPresent(storage: DataStoreStorage, alias: String): Boolean =
        runBlocking { storage.snapshot().containsKey(RelaxedMintMarkerStore.recordKey(alias)) }

    private fun ByteArray.startsWithMagic(): Boolean =
        size >= magic.size && magic.indices.all { this[it] == magic[it] }

    /** What the device itself says, independent of anything KSafe computed. */
    private val deviceSecure: Boolean
        get() = context.getSystemService(KeyguardManager::class.java).isDeviceSecure

    private val thisDeviceRelaxes: Boolean
        get() = Build.VERSION.SDK_INT in 28..34 && !deviceSecure

    /** `KeyInfo.isUnlockedDeviceRequired` exists from API 37 only (compileSdk is older), hence reflection. */
    private val unlockProbe: Method? =
        runCatching { KeyInfo::class.java.getMethod("isUnlockedDeviceRequired") }.getOrNull()

    /** What the Keystore recorded on the key, independent of anything KSafe decided. */
    private fun unlockedDeviceRequiredOf(alias: String): Boolean {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
        val key = keyStore.getKey(alias, null) as SecretKey
        val info = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE_PROVIDER)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return checkNotNull(unlockProbe).invoke(info) as Boolean
    }

    @Test
    fun decision_relaxesOnlyOnApi28to34_withoutSecureLockScreen() {
        assertFalse(relaxesUnlockedDeviceRequirement(sdkInt = 27, deviceSecure = false), "API 27 has no flag to relax")
        assertTrue(relaxesUnlockedDeviceRequirement(sdkInt = 28, deviceSecure = false))
        assertTrue(relaxesUnlockedDeviceRequirement(sdkInt = 31, deviceSecure = false))
        assertTrue(relaxesUnlockedDeviceRequirement(sdkInt = 34, deviceSecure = false))
        assertFalse(relaxesUnlockedDeviceRequirement(sdkInt = 35, deviceSecure = false), "API 35+ copes without a lock screen")
        assertFalse(relaxesUnlockedDeviceRequirement(sdkInt = 37, deviceSecure = false))
        for (sdk in listOf(27, 28, 31, 34, 35, 37)) {
            assertFalse(relaxesUnlockedDeviceRequirement(sdkInt = sdk, deviceSecure = true), "API $sdk with a lock screen never relaxes")
        }
    }

    @Test
    fun liveDecision_matchesThisDevice_andKeepsTheFlagWithoutAContext() {
        assertEquals(
            thisDeviceRelaxes,
            AndroidLockScreen.relaxUnlockedDeviceRequirement(context),
            "api=${Build.VERSION.SDK_INT} deviceSecure=$deviceSecure",
        )
        assertFalse(AndroidLockScreen.relaxUnlockedDeviceRequirement(context = null), "no context: nothing to relax on")
    }

    @Test
    fun seams_replaceInputsOnly_soTheApiBandStillDecides() {
        AndroidLockScreen.deviceSecureForTest = false
        assertEquals(
            Build.VERSION.SDK_INT in 28..34,
            AndroidLockScreen.relaxUnlockedDeviceRequirement(context),
            "forcing the probe must not bypass the band guard on api=${Build.VERSION.SDK_INT}",
        )
        AndroidLockScreen.sdkIntForTest = 30
        assertTrue(AndroidLockScreen.relaxUnlockedDeviceRequirement(context))
        AndroidLockScreen.deviceSecureForTest = true
        assertFalse(AndroidLockScreen.relaxUnlockedDeviceRequirement(context))
    }

    @Test
    fun protectionInfoNote_present_iffThisDeviceRelaxes() {
        val notes = notes(newSafe(uniqueName("lsnote")))
        assertEquals(
            thisDeviceRelaxes,
            notes.contains(note),
            "api=${Build.VERSION.SDK_INT} deviceSecure=$deviceSecure notes=$notes",
        )
    }

    /** With no relaxed key on record the note is live: it follows the probe at call time. */
    @Test
    fun protectionInfoNote_followsTheDecisionAtCallTime() {
        forceKeep()
        val safe = newSafe(uniqueName("lslive"))
        // Mint both masters while the decision keeps the flag, so nothing can be marked and only
        // the probe moves the note.
        runBlocking { safe.put("pin", "1234", KSafeWriteMode.Encrypted(requireUnlockedDevice = true)) }
        forceRelax()
        assertTrue(notes(safe).contains(note))
        forceKeep()
        assertFalse(notes(safe).contains(note), "no key was minted relaxed, so nothing outlives the probe")
    }

    /** A strict write under a relaxed mint never leaves the TEE path: no DEK header, no DEK record. */
    @Test
    fun forcedRelax_strictWriteStaysOnTeePath_andDecrypts() {
        forceRelax()
        val storage = newStorage()
        val alias = uniqueName("ksafe_relaxed_tee")
        val e = engine(storage)
        try {
            val plain = "strict-without-a-lock-screen".encodeToByteArray()
            val blob = e.encrypt(alias, plain, hardwareIsolated = false, requireUnlockedDevice = true)
            assertFalse(blob.startsWithMagic(), "a strict write stays on the TEE path even when its key was minted relaxed")
            assertFalse(dekPresent(storage), "a strict write must not persist a DEK")
            assertContentEquals(plain, e.decrypt(alias, blob, requireUnlockedDevice = true))
        } finally {
            e.deleteKey(alias)
        }
    }

    /** The relaxed mint really drops the flag — asserted on the builder branch on every API level,
     *  and on the Keystore's own record of the key where the platform exposes it. */
    @Test
    fun forcedRelax_strictKeyMintsWithoutTheFlag() {
        forceRelax()
        val storage = newStorage()
        val alias = uniqueName("ksafe_relaxed_flag")
        val e = engine(storage)
        try {
            assertNull(e.lastMintUnlockedDeviceRequiredForTest, "nothing minted yet")
            e.encrypt(alias, "v".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = true)
            assertEquals(false, e.lastMintUnlockedDeviceRequiredForTest, "the mint must not have applied the flag")
            if (unlockProbe != null) {
                assertFalse(unlockedDeviceRequiredOf(alias), "a relaxed strict mint must not carry setUnlockedDeviceRequired")
            }
        } finally {
            e.deleteKey(alias)
        }
    }

    /** Control for the test above: with the decision forced off, the same mint carries the flag
     *  and records nothing. */
    @Test
    fun forcedKeep_strictKeyMintsWithTheFlag() {
        forceKeep()
        val storage = newStorage()
        val alias = uniqueName("ksafe_kept_flag")
        val e = markingEngine(storage)
        try {
            val plain = "strict-with-a-lock-screen".encodeToByteArray()
            val blob = e.encrypt(alias, plain, hardwareIsolated = false, requireUnlockedDevice = true)
            assertEquals(true, e.lastMintUnlockedDeviceRequiredForTest, "the mint must have applied the flag")
            assertFalse(e.mintedWithoutUnlockBinding(alias), "an un-relaxed mint records no marker")
            assertFalse(markerRecordPresent(storage, alias))
            if (unlockProbe != null) {
                assertTrue(unlockedDeviceRequiredOf(alias), "an un-relaxed strict mint must carry setUnlockedDeviceRequired")
            }
            assertFalse(blob.startsWithMagic())
            assertContentEquals(plain, e.decrypt(alias, blob, requireUnlockedDevice = true))
        } finally {
            e.deleteKey(alias)
        }
    }

    /** The marker is a reserved record beside the wrapped DEKs: written on a relaxed mint, read
     *  back after the device grows a lock screen, and deleted with the key it describes. */
    @Test
    fun relaxedMint_recordsAMarker_andDeleteKeyTakesItWithTheKey() {
        forceRelax()
        val storage = newStorage()
        val alias = uniqueName("ksafe_relaxed_marker")
        val e = markingEngine(storage)
        try {
            e.encrypt(alias, "v".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = true)
            assertTrue(e.mintedWithoutUnlockBinding(alias))
            assertTrue(markerRecordPresent(storage, alias), "the marker must be persisted, not just cached")
            AndroidLockScreen.deviceSecureForTest = true
            assertTrue(e.mintedWithoutUnlockBinding(alias), "a lock screen appearing does not re-bind the minted key")
        } finally {
            e.deleteKey(alias)
        }
        assertFalse(e.mintedWithoutUnlockBinding(alias))
        assertFalse(markerRecordPresent(storage, alias), "deleting the key must delete its marker")
    }

    @Test
    fun forcedRelax_strictPutRoundTrips_andReportsTheNote() {
        forceRelax()
        val fileName = uniqueName("lsput")
        val safe = newSafe(fileName)

        runBlocking { safe.put("pin", "1234", KSafeWriteMode.Encrypted(requireUnlockedDevice = true)) }
        assertEquals("1234", runBlocking { safe.get("pin", "") }, "a strict put must round-trip on a relaxing device")
        assertTrue(notes(safe).contains(note), "the degrade must be visible in protectionInfo; notes=${notes(safe)}")
        if (unlockProbe != null) {
            val strictMaster = KSafeAliasFormat.dottedMaster(fileName, requireUnlockedDevice = true)
            assertFalse(unlockedDeviceRequiredOf(strictMaster), "the strict master must have been minted relaxed")
        }
    }

    /** The disclosure outlives the condition: it is still reported once the probe is clean, and
     *  goes away only when a new key generation mints an unlock-bound master. */
    @Test
    fun note_survivesALockScreenAppearing_andClearsAtTheNextKeyGeneration() {
        forceRelax()
        val safe = newSafe(uniqueName("lsrotate"))
        runBlocking { safe.put("pin", "1234", KSafeWriteMode.Encrypted(requireUnlockedDevice = true)) }
        assertTrue(notes(safe).contains(note), "notes=${notes(safe)}")

        // The user sets a lock screen. The probe is clean, but the minted key is still unbound.
        AndroidLockScreen.deviceSecureForTest = true
        assertFalse(AndroidLockScreen.relaxUnlockedDeviceRequirement(context), "the probe must now be clean")
        assertTrue(notes(safe).contains(note), "the relaxed key is still in use; notes=${notes(safe)}")

        runBlocking { safe.rotateKeys() }
        assertFalse(notes(safe).contains(note), "a fresh generation re-decides; notes=${notes(safe)}")
    }

    /** The wipe and a relaxed mint are not ordered against each other: a marker that lands after
     *  `storage.clear()` must still be seen, not hidden behind a view assumed empty. */
    @Test
    fun markerLandingAfterAWipe_staysVisibleToTheView() {
        forceRelax()
        val storage = newStorage()
        val alias = uniqueName("ksafe_wipe_race")
        val e = markingEngine(storage)
        try {
            // clearAll's order: the store is wiped, the racing mint's marker lands, the engine is told.
            runBlocking { storage.clear() }
            e.encrypt(alias, "v".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = true)
            e.onStoreCleared()
            assertEquals(
                markerRecordPresent(storage, alias),
                e.mintedWithoutUnlockBinding(alias),
                "the in-RAM view must agree with the store about what survived the wipe",
            )
            assertTrue(e.mintedWithoutUnlockBinding(alias), "the marker outlived the wipe, so the key is still relaxed")
        } finally {
            e.deleteKey(alias)
        }
    }

    /** A strict HARDWARE_ISOLATED write mints a per-entry key, not a master, so the note must
     *  follow the markers rather than two derived master spellings. */
    @Test
    fun note_coversARelaxedPerEntryKey_notOnlyTheMasters() {
        forceKeep()
        val safe = newSafe(uniqueName("lsentry"))
        // Both masters are minted unlock-bound first, so only the per-entry key below can be marked.
        runBlocking { safe.put("bound", "v", KSafeWriteMode.Encrypted(requireUnlockedDevice = true)) }
        assertFalse(notes(safe).contains(note), "nothing was minted relaxed yet; notes=${notes(safe)}")

        forceRelax()
        runBlocking {
            safe.put(
                "pin",
                "1234",
                KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED, requireUnlockedDevice = true),
            )
        }
        AndroidLockScreen.deviceSecureForTest = true
        assertTrue(notes(safe).contains(note), "the relaxed per-entry key must be disclosed; notes=${notes(safe)}")

        runBlocking { safe.delete("pin") }
        assertFalse(notes(safe).contains(note), "the last relaxed key is gone; notes=${notes(safe)}")
    }

    /** The marker is a reserved store record, so the wipe takes it. */
    @Test
    fun clearAll_wipesTheMarker() {
        forceRelax()
        val safe = newSafe(uniqueName("lswipe"))
        runBlocking { safe.put("pin", "1234", KSafeWriteMode.Encrypted(requireUnlockedDevice = true)) }
        assertTrue(notes(safe).contains(note))

        runBlocking { safe.clearAll() }
        AndroidLockScreen.deviceSecureForTest = true
        assertFalse(notes(safe).contains(note), "clearAll must take the marker with the store; notes=${notes(safe)}")
    }
}
