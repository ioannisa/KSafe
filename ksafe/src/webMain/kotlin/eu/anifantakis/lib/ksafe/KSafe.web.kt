package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.LocalStorageStorage
import eu.anifantakis.lib.ksafe.internal.WebSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlinx.coroutines.flow.Flow
import kotlinx.serialization.KSerializer
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun encodeBase64Web(bytes: ByteArray): String = Base64.encode(bytes)

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun decodeBase64Web(encoded: String): ByteArray = Base64.decode(encoded)

/**
 * Web (wasmJs + js) implementation of KSafe.
 *
 * Thin shell over [KSafeCore]. Web is the only target where:
 *
 * - **Encryption is async-only.** WebCrypto has no blocking path, so
 *   [WebSoftwareEncryption] overrides the suspend variants on
 *   [KSafeEncryption] and throws from the blocking ones. The core calls
 *   suspend crypto from every coroutine-context code path.
 * - **Memory policy is effectively PLAIN_TEXT.** There's no way to decrypt
 *   on-demand in the non-suspend [getDirect] path, so encrypted values are
 *   fully decrypted during the background preload and the cache holds
 *   plaintext. The `memoryPolicy` constructor parameter is accepted for
 *   API parity but ignored.
 * - **Cold-start sync reads don't block.** Browsers can't block the main
 *   thread, so a `getDirect` that races the async preload returns
 *   `defaultValue` until the cache finishes warming. Callers that need
 *   certainty should `awaitCacheReady()` first.
 * - **localStorage is string-only.** [LocalStorageStorage] flattens every
 *   [StoredValue] to a string on write, and [KSafeCore]'s
 *   `convertStoredValue` reconstitutes the typed primitive through the
 *   request's [KSerializer] on read.
 */
actual class KSafe(
    @PublishedApi internal val fileName: String? = null,
    lazyLoad: Boolean = false,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
    private val config: KSafeConfig = KSafeConfig(),
    private val securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    @PublishedApi internal val plaintextCacheTtl: Duration = 5.seconds,
) {

    @PublishedApi
    internal constructor(
        fileName: String? = null,
        lazyLoad: Boolean = false,
        memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
        config: KSafeConfig = KSafeConfig(),
        securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
        plaintextCacheTtl: Duration = 5.seconds,
        testEngine: KSafeEncryption,
    ) : this(fileName, lazyLoad, memoryPolicy, config, securityPolicy, plaintextCacheTtl) {
        _testEngine = testEngine
    }

    @PublishedApi internal var _testEngine: KSafeEncryption? = null

    companion object {
        private val fileNameRegex = Regex("[a-z][a-z0-9_]*")
    }

    actual val deviceKeyStorages: Set<KSafeKeyStorage> = setOf(KSafeKeyStorage.SOFTWARE)

    init {
        if (fileName != null && !fileName.matches(fileNameRegex)) {
            throw IllegalArgumentException("File name must start with a lowercase letter and contain only lowercase letters, digits, or underscores")
        }
        validateSecurityPolicy(securityPolicy)
    }

    @PublishedApi
    internal val storagePrefix: String = if (fileName != null) "ksafe_${fileName}_" else "ksafe_default_"

    @PublishedApi
    internal val engine: KSafeEncryption by lazy {
        _testEngine ?: WebSoftwareEncryption(config, storagePrefix)
    }

    @PublishedApi
    internal val core: KSafeCore = KSafeCore(
        storage = LocalStorageStorage(storagePrefix),
        engineProvider = { engine },
        config = config,
        // Forced PLAIN_TEXT — WebCrypto can't decrypt from the sync getDirect
        // path, so everything lives in the cache as plaintext after the
        // background preload completes. Any user-supplied value is ignored.
        memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
        plaintextCacheTtl = plaintextCacheTtl,
        resolveKeyStorage = { _, _ -> KSafeKeyStorage.SOFTWARE },
        lazyLoad = lazyLoad,
        keyAlias = { userKey -> fileName?.let { "$it:$userKey" } ?: userKey },
    )

    @PublishedApi
    internal actual fun defaultEncryptedMode(): KSafeWriteMode =
        KSafeWriteMode.Encrypted(requireUnlockedDevice = config.requireUnlockedDevice)

    /**
     * Suspends until the in-memory cache has been fully loaded from localStorage
     * — including async decryption of every encrypted value via WebCrypto.
     *
     * Web tests and apps that want a deterministic first read should call this
     * before [getDirect] / `mutableStateOf` / Compose delegates.
     */
    suspend fun awaitCacheReady() = core.ensureCacheReadySuspend()

    // ---------- Raw API (delegates to core) ----------

    @PublishedApi
    internal actual fun getDirectRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? =
        core.getDirectRaw(key, defaultValue, serializer)

    @PublishedApi
    internal actual fun putDirectRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) =
        core.putDirectRaw(key, value, mode, serializer)

    @PublishedApi
    internal actual suspend fun getRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? =
        core.getRaw(key, defaultValue, serializer)

    @PublishedApi
    internal actual fun getFlowRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Flow<Any?> =
        core.getFlowRaw(key, defaultValue, serializer)

    @PublishedApi
    internal actual suspend fun putRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) =
        core.putRaw(key, value, mode, serializer)

    actual fun deleteDirect(key: String) = core.deleteDirect(key)
    actual suspend fun delete(key: String) = core.delete(key)
    actual suspend fun clearAll() = core.clearAll()
    actual fun getKeyInfo(key: String): KSafeKeyInfo? = core.getKeyInfo(key)

    // ---------- Biometric API (browser: no hardware, no-op) ----------

    actual suspend fun verifyBiometric(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?,
    ): Boolean = true

    actual fun verifyBiometricDirect(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?,
        onResult: (Boolean) -> Unit,
    ) { onResult(true) }

    actual fun clearBiometricAuth(scope: String?) { /* no-op */ }
}
