package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.providers.cryptokit.CryptoKit
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.IosKeychainEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.cleanupOrphanedKeychainEntries
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.serialization.KSerializer
import okio.Path.Companion.toPath
import platform.CoreFoundation.CFAbsoluteTimeGetCurrent
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSProcessInfo
import platform.Foundation.NSURL
import platform.Foundation.NSUserDomainMask
import kotlin.concurrent.AtomicReference
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun encodeBase64(bytes: ByteArray): String = Base64.encode(bytes)

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun decodeBase64(encoded: String): ByteArray = Base64.decode(encoded)

/**
 * iOS implementation of KSafe.
 *
 * Thin shell over [KSafeCore]. iOS-specific responsibilities handled here:
 *
 * - **CryptoKit registration.** Kotlin/Native's dead-code elimination can
 *   strip `AES.GCM` if nothing references it statically, so the init block
 *   forces the symbol to be retained.
 * - **Secure Enclave detection.** Simulator = no hardware; real devices
 *   expose the Secure Enclave.
 * - **Legacy encrypted-key format.** Pre-1.8 iOS builds wrote encrypted
 *   entries under `"{fileName}_{key}"` rather than the common
 *   `"encrypted_{key}"`, so we override [KSafeCore]'s legacy key resolver.
 * - **Keychain orphan cleanup.** Runs once, inside the migration hook —
 *   removes Keychain entries whose DataStore counterpart no longer exists.
 * - **Biometric via LAContext.** Real Face ID / Touch ID integration with
 *   per-scope session caching.
 */
@Suppress("unused")
actual class KSafe(
    @PublishedApi internal val fileName: String? = null,
    lazyLoad: Boolean = false,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    private val config: KSafeConfig = KSafeConfig(),
    private val securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    @PublishedApi internal val plaintextCacheTtl: Duration = 5.seconds,
    @Deprecated("Use KSafeProtection.HARDWARE_ISOLATED per-property instead")
    private val useSecureEnclave: Boolean = false,
) {

    @PublishedApi
    internal constructor(
        fileName: String? = null,
        lazyLoad: Boolean = false,
        memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
        config: KSafeConfig = KSafeConfig(),
        securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
        plaintextCacheTtl: Duration = 5.seconds,
        useSecureEnclave: Boolean = false,
        testEngine: KSafeEncryption,
    ) : this(fileName, lazyLoad, memoryPolicy, config, securityPolicy, plaintextCacheTtl, useSecureEnclave) {
        _testEngine = testEngine
    }

    @PublishedApi internal var _testEngine: KSafeEncryption? = null

    companion object {
        private val fileNameRegex = Regex("[a-z][a-z0-9_]*")
        private const val SERVICE_NAME = "eu.anifantakis.ksafe"
        @PublishedApi internal const val KEY_PREFIX = "eu.anifantakis.ksafe"

        @OptIn(ExperimentalForeignApi::class)
        private fun isSimulator(): Boolean =
            NSProcessInfo.processInfo.environment["SIMULATOR_UDID"] != null
    }

    private val hasSecureEnclave: Boolean = !isSimulator()

    actual val deviceKeyStorages: Set<KSafeKeyStorage> = buildSet {
        add(KSafeKeyStorage.HARDWARE_BACKED)
        if (hasSecureEnclave) add(KSafeKeyStorage.HARDWARE_ISOLATED)
    }

    init {
        if (fileName != null && !fileName.matches(fileNameRegex)) {
            throw IllegalArgumentException("File name must start with a lowercase letter and contain only lowercase letters, digits, or underscores.")
        }
        validateSecurityPolicy(securityPolicy)

        // Force-register CryptoKit + retain AES.GCM so Kotlin/Native DCE can't
        // strip the providers out of the final binary.
        CryptographyProvider.CryptoKit
        @Suppress("UNUSED_VARIABLE") val retainAesGcm = AES.GCM
    }

    @OptIn(ExperimentalForeignApi::class)
    @PublishedApi
    internal val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.createWithPath(
        corruptionHandler = null,
        migrations = emptyList(),
        produceFile = {
            val docDir: NSURL? = NSFileManager.defaultManager.URLForDirectory(
                directory = NSDocumentDirectory,
                inDomain = NSUserDomainMask,
                appropriateForURL = null,
                create = true,
                error = null,
            )
            requireNotNull(docDir).path.plus(
                fileName?.let { "/eu_anifantakis_ksafe_datastore_$it.preferences_pb" }
                    ?: "/eu_anifantakis_ksafe_datastore.preferences_pb"
            ).toPath()
        },
    )

    @PublishedApi
    internal val engine: KSafeEncryption by lazy {
        _testEngine ?: IosKeychainEncryption(config = config, serviceName = SERVICE_NAME)
    }

    private fun iosKeyAlias(userKey: String): String =
        listOfNotNull(KEY_PREFIX, fileName, userKey).joinToString(".")

    private fun iosLegacyEncryptedKey(userKey: String): String =
        fileName?.let { "${it}_$userKey" } ?: KeySafeMetadataManager.legacyEncryptedRawKey(userKey)

    private fun iosLegacyEncryptedPrefix(): String =
        fileName?.let { "${it}_" } ?: KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX

    private fun resolveKeyStorageTier(userKey: String, protection: KSafeProtection?): KSafeKeyStorage {
        if (protection == null) return KSafeKeyStorage.SOFTWARE
        return if (protection == KSafeProtection.HARDWARE_ISOLATED && hasSecureEnclave)
            KSafeKeyStorage.HARDWARE_ISOLATED
        else KSafeKeyStorage.HARDWARE_BACKED
    }

    /**
     * Runs once per process — removes Keychain entries whose DataStore
     * counterpart is gone. Safe to call eagerly: failures are swallowed so a
     * locked device or transient Keychain error can't block startup.
     */
    private suspend fun cleanupOrphanedKeychainEntriesSafe() {
        runCatching {
            cleanupOrphanedKeychainEntries(
                storage = DataStoreStorage(dataStore),
                engine = engine,
                serviceName = SERVICE_NAME,
                keyPrefix = KEY_PREFIX,
                fileName = fileName,
                legacyEncryptedPrefix = iosLegacyEncryptedPrefix(),
                seKeyTagPrefix = IosKeychainEncryption.SE_KEY_TAG_PREFIX,
            )
        }.onFailure { t ->
            println("KSafe: Keychain orphan sweep failed (ignored): ${t.message}")
        }
    }

    @PublishedApi
    internal val core: KSafeCore = KSafeCore(
        storage = DataStoreStorage(dataStore),
        engineProvider = { engine },
        config = config,
        memoryPolicy = memoryPolicy,
        plaintextCacheTtl = plaintextCacheTtl,
        resolveKeyStorage = ::resolveKeyStorageTier,
        migrateAccessPolicy = { cleanupOrphanedKeychainEntriesSafe() },
        lazyLoad = lazyLoad,
        keyAlias = ::iosKeyAlias,
        legacyEncryptedPrefix = iosLegacyEncryptedPrefix(),
        legacyEncryptedKeyFor = ::iosLegacyEncryptedKey,
    )

    @PublishedApi
    internal actual fun defaultEncryptedMode(): KSafeWriteMode =
        KSafeWriteMode.Encrypted(requireUnlockedDevice = config.requireUnlockedDevice)

    @Suppress("DEPRECATION")
    @PublishedApi
    internal fun promoteMode(mode: KSafeWriteMode): KSafeWriteMode {
        if (!useSecureEnclave) return mode
        if (mode !is KSafeWriteMode.Encrypted) return mode
        if (mode.protection != KSafeEncryptedProtection.DEFAULT) return mode
        return KSafeWriteMode.Encrypted(
            protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
            requireUnlockedDevice = mode.requireUnlockedDevice,
        )
    }

    // ---------- Raw API (delegates to core; promoteMode handles useSecureEnclave) ----------

    @PublishedApi
    internal actual fun getDirectRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? =
        core.getDirectRaw(key, defaultValue, serializer)

    @PublishedApi
    internal actual fun putDirectRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) =
        core.putDirectRaw(key, value, promoteMode(mode), serializer)

    @PublishedApi
    internal actual suspend fun getRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? =
        core.getRaw(key, defaultValue, serializer)

    @PublishedApi
    internal actual fun getFlowRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Flow<Any?> =
        core.getFlowRaw(key, defaultValue, serializer)

    @PublishedApi
    internal actual suspend fun putRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) =
        core.putRaw(key, value, promoteMode(mode), serializer)

    actual fun deleteDirect(key: String) = core.deleteDirect(key)
    actual suspend fun delete(key: String) = core.delete(key)
    actual suspend fun clearAll() = core.clearAll()
    actual fun getKeyInfo(key: String): KSafeKeyInfo? = core.getKeyInfo(key)

    // ---------- Biometric API (LAContext) ----------

    private val biometricAuthSessions = AtomicReference<Map<String, Long>>(emptyMap())

    @OptIn(ExperimentalForeignApi::class)
    private fun currentTimeMillis(): Long =
        ((CFAbsoluteTimeGetCurrent() + 978307200.0) * 1000).toLong()

    private fun updateBiometricSession(scope: String, timestamp: Long) {
        while (true) {
            val current = biometricAuthSessions.value
            val updated = current + (scope to timestamp)
            if (biometricAuthSessions.compareAndSet(current, updated)) break
        }
    }

    actual suspend fun verifyBiometric(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?,
    ): Boolean {
        if (authorizationDuration != null && authorizationDuration.duration > 0) {
            val scope = authorizationDuration.scope ?: ""
            val lastAuth = biometricAuthSessions.value[scope] ?: 0L
            val now = currentTimeMillis()
            if (lastAuth > 0 && (now - lastAuth) < authorizationDuration.duration) {
                return true
            }
        }

        if (isSimulator()) {
            if (authorizationDuration != null) {
                updateBiometricSession(authorizationDuration.scope ?: "", currentTimeMillis())
            }
            return true
        }

        return suspendCancellableCoroutine { continuation ->
            runLAContextEvaluate(reason) { success ->
                if (success && authorizationDuration != null) {
                    updateBiometricSession(authorizationDuration.scope ?: "", currentTimeMillis())
                }
                continuation.resumeWith(Result.success(success))
            }
        }
    }

    actual fun verifyBiometricDirect(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?,
        onResult: (Boolean) -> Unit,
    ) {
        CoroutineScope(Dispatchers.Main).launch {
            if (authorizationDuration != null && authorizationDuration.duration > 0) {
                val scope = authorizationDuration.scope ?: ""
                val lastAuth = biometricAuthSessions.value[scope] ?: 0L
                val now = currentTimeMillis()
                if (lastAuth > 0 && (now - lastAuth) < authorizationDuration.duration) {
                    onResult(true)
                    return@launch
                }
            }
            if (isSimulator()) {
                if (authorizationDuration != null) {
                    updateBiometricSession(authorizationDuration.scope ?: "", currentTimeMillis())
                }
                onResult(true)
                return@launch
            }
            runLAContextEvaluate(reason) { success ->
                if (success && authorizationDuration != null) {
                    updateBiometricSession(authorizationDuration.scope ?: "", currentTimeMillis())
                }
                onResult(success)
            }
        }
    }

    actual fun clearBiometricAuth(scope: String?) {
        if (scope == null) {
            biometricAuthSessions.value = emptyMap()
            return
        }
        while (true) {
            val current = biometricAuthSessions.value
            val updated = current - scope
            if (biometricAuthSessions.compareAndSet(current, updated)) break
        }
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun runLAContextEvaluate(reason: String, onResult: (Boolean) -> Unit) {
        val context = platform.LocalAuthentication.LAContext()
        val policy = platform.LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics
        context.evaluatePolicy(policy, localizedReason = reason) { success, _ ->
            CoroutineScope(Dispatchers.Main).launch { onResult(success) }
        }
    }
}

// Non-inline helper retained from pre-refactor — external Swift callers may
// reference it for warm-up.
@Suppress("unused")
fun obtainAesGcm(): AES.GCM = CryptographyProvider.CryptoKit.get(AES.GCM)
