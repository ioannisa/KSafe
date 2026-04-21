package eu.anifantakis.lib.ksafe

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStoreFile
import eu.anifantakis.lib.ksafe.internal.AndroidKeystoreEncryption
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.SecurityChecker
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import kotlinx.serialization.KSerializer
import kotlinx.serialization.serializer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference
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
 * Android implementation of KSafe.
 *
 * Thin shell over [KSafeCore]. This file owns only the Android-specific
 * concerns: Context-backed DataStore creation (cached per filename so repeated
 * DI re-inits don't crash with "multiple active instances"), StrongBox
 * capability detection, the BiometricPrompt-backed biometric path, and the
 * per-key [KSafeKeyStorage] tier reported by [getKeyInfo].
 */
@Suppress("unused")
actual class KSafe(
    private val context: Context,
    @PublishedApi internal val fileName: String? = null,
    lazyLoad: Boolean = false,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    private val config: KSafeConfig = KSafeConfig(),
    private val securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    @PublishedApi internal val plaintextCacheTtl: Duration = 5.seconds,
    @Deprecated("Use KSafeProtection.HARDWARE_ISOLATED per-property instead")
    private val useStrongBox: Boolean = false,
) {

    @PublishedApi
    internal constructor(
        context: Context,
        fileName: String? = null,
        lazyLoad: Boolean = false,
        memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
        config: KSafeConfig = KSafeConfig(),
        securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
        plaintextCacheTtl: Duration = 5.seconds,
        useStrongBox: Boolean = false,
        testEngine: KSafeEncryption,
    ) : this(context, fileName, lazyLoad, memoryPolicy, config, securityPolicy, plaintextCacheTtl, useStrongBox) {
        _testEngine = testEngine
    }

    @PublishedApi internal var _testEngine: KSafeEncryption? = null

    companion object {
        private val fileNameRegex = Regex("[a-z][a-z0-9_]*")
        const val KEY_ALIAS_PREFIX = "eu.anifantakis.ksafe"
        private val dataStoreCache = ConcurrentHashMap<String, DataStore<Preferences>>()
    }

    private val hasStrongBox: Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    actual val deviceKeyStorages: Set<KSafeKeyStorage> = buildSet {
        add(KSafeKeyStorage.HARDWARE_BACKED)
        if (hasStrongBox) add(KSafeKeyStorage.HARDWARE_ISOLATED)
    }

    init {
        if (fileName != null && !fileName.matches(fileNameRegex)) {
            throw IllegalArgumentException("File name must start with a lowercase letter and contain only lowercase letters, digits, or underscores")
        }

        (context.applicationContext as? android.app.Application)?.let {
            BiometricHelper.init(it)
        }
        SecurityChecker.applicationContext = context.applicationContext

        validateSecurityPolicy(securityPolicy)
    }

    @PublishedApi
    internal val dataStore: DataStore<Preferences> = dataStoreCache.getOrPut(fileName ?: "default") {
        PreferenceDataStoreFactory.create(
            scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
            produceFile = {
                val file = fileName?.let { "eu_anifantakis_ksafe_datastore_$it" }
                    ?: "eu_anifantakis_ksafe_datastore"
                context.preferencesDataStoreFile(file)
            }
        )
    }

    @PublishedApi
    internal val engine: KSafeEncryption by lazy {
        _testEngine ?: AndroidKeystoreEncryption(config)
    }

    @PublishedApi
    internal val core: KSafeCore = KSafeCore(
        storage = DataStoreStorage(dataStore),
        engineProvider = { engine },
        config = config,
        memoryPolicy = memoryPolicy,
        plaintextCacheTtl = plaintextCacheTtl,
        resolveKeyStorage = ::resolveKeyStorageTier,
        lazyLoad = lazyLoad,
        keyAlias = { userKey ->
            listOfNotNull(KEY_ALIAS_PREFIX, fileName, userKey).joinToString(".")
        },
    )

    @PublishedApi
    internal actual fun defaultEncryptedMode(): KSafeWriteMode =
        KSafeWriteMode.Encrypted(requireUnlockedDevice = config.requireUnlockedDevice)

    /**
     * Honors the deprecated `useStrongBox` constructor flag by promoting every
     * default-protection encrypted write to [KSafeEncryptedProtection.HARDWARE_ISOLATED].
     * Writes that explicitly request a protection level pass through unchanged.
     */
    @Suppress("DEPRECATION")
    @PublishedApi
    internal fun promoteMode(mode: KSafeWriteMode): KSafeWriteMode {
        if (!useStrongBox) return mode
        if (mode !is KSafeWriteMode.Encrypted) return mode
        if (mode.protection != KSafeEncryptedProtection.DEFAULT) return mode
        return KSafeWriteMode.Encrypted(
            protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
            requireUnlockedDevice = mode.requireUnlockedDevice,
        )
    }

    private fun resolveKeyStorageTier(userKey: String, protection: KSafeProtection?): KSafeKeyStorage {
        if (protection == null) return KSafeKeyStorage.SOFTWARE
        return if (protection == KSafeProtection.HARDWARE_ISOLATED && hasStrongBox)
            KSafeKeyStorage.HARDWARE_ISOLATED
        else KSafeKeyStorage.HARDWARE_BACKED
    }

    // ---------- Raw API (delegates to core; promoteMode handles useStrongBox) ----------

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

    // ---------- Biometric API (BiometricPrompt) ----------

    /**
     * Per-scope last-success timestamp. Lets `verifyBiometric` skip the
     * platform prompt when a caller-supplied [BiometricAuthorizationDuration]
     * is still valid for the given scope.
     */
    private val biometricAuthSessions = AtomicReference<Map<String, Long>>(emptyMap())

    private fun updateBiometricSession(scope: String, timestamp: Long) {
        while (true) {
            val current = biometricAuthSessions.get()
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
            val lastAuth = biometricAuthSessions.get()[scope] ?: 0L
            val now = System.currentTimeMillis()
            if (lastAuth > 0 && (now - lastAuth) < authorizationDuration.duration) {
                return true
            }
        }

        return try {
            BiometricHelper.authenticate(reason)
            if (authorizationDuration != null) {
                updateBiometricSession(authorizationDuration.scope ?: "", System.currentTimeMillis())
            }
            true
        } catch (e: BiometricAuthException) {
            println("KSafe: Biometric authentication failed - ${e.message}")
            false
        } catch (e: BiometricActivityNotFoundException) {
            println("KSafe: Biometric Activity not found - ${e.message}")
            false
        } catch (e: Exception) {
            println("KSafe: Unexpected biometric error - ${e.message}")
            false
        }
    }

    actual fun verifyBiometricDirect(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?,
        onResult: (Boolean) -> Unit,
    ) {
        CoroutineScope(Dispatchers.Default + SupervisorJob()).launch {
            onResult(verifyBiometric(reason, authorizationDuration))
        }
    }

    actual fun clearBiometricAuth(scope: String?) {
        if (scope == null) {
            biometricAuthSessions.set(emptyMap())
            return
        }
        while (true) {
            val current = biometricAuthSessions.get()
            val updated = current - scope
            if (biometricAuthSessions.compareAndSet(current, updated)) break
        }
    }
}
