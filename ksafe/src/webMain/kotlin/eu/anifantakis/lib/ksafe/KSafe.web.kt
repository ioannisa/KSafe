package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.LocalStorageStorage
import eu.anifantakis.lib.ksafe.internal.WebSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
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

private val fileNameRegex = Regex("[a-z][a-z0-9_]*")

/**
 * Web (wasmJs + js) factory for [KSafe]. Resolves to the same call syntax as
 * the pre-2.0 `KSafe(...)` constructor.
 *
 * Web is the only target where:
 * - **Encryption is async-only.** WebCrypto has no blocking path, so
 *   [WebSoftwareEncryption] overrides the suspend variants on
 *   [KSafeEncryption] and throws from the blocking ones. The core calls
 *   suspend crypto from every coroutine-context code path.
 * - **Memory policy is effectively PLAIN_TEXT.** There's no way to decrypt
 *   on-demand in the non-suspend [getDirect] path, so encrypted values are
 *   fully decrypted during the background preload and the cache holds
 *   plaintext. The `memoryPolicy` parameter is accepted for API parity but
 *   ignored.
 * - **Cold-start sync reads don't block.** Browsers can't block the main
 *   thread, so a `getDirect` that races the async preload returns
 *   `defaultValue` until the cache finishes warming. Callers that need
 *   certainty should `awaitCacheReady()` first.
 * - **localStorage is string-only.** [LocalStorageStorage] flattens every
 *   stored value to a string on write, and [KSafeCore]'s `convertStoredValue`
 *   reconstitutes the typed primitive through the request's serializer on read.
 */
@Suppress("UNUSED_PARAMETER")
fun KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
): KSafe = buildWebKSafe(
    fileName = fileName,
    lazyLoad = lazyLoad,
    config = config,
    securityPolicy = securityPolicy,
    plaintextCacheTtl = plaintextCacheTtl,
    testEngine = null,
)

@Suppress("UNUSED_PARAMETER")
@PublishedApi
internal fun KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    testEngine: KSafeEncryption,
): KSafe = buildWebKSafe(
    fileName = fileName,
    lazyLoad = lazyLoad,
    config = config,
    securityPolicy = securityPolicy,
    plaintextCacheTtl = plaintextCacheTtl,
    testEngine = testEngine,
)

private fun buildWebKSafe(
    fileName: String?,
    lazyLoad: Boolean,
    config: KSafeConfig,
    securityPolicy: KSafeSecurityPolicy,
    plaintextCacheTtl: Duration,
    testEngine: KSafeEncryption?,
): KSafe {
    if (fileName != null && !fileName.matches(fileNameRegex)) {
        throw IllegalArgumentException("File name must start with a lowercase letter and contain only lowercase letters, digits, or underscores")
    }
    validateSecurityPolicy(securityPolicy)

    val storagePrefix: String = if (fileName != null) "ksafe_${fileName}_" else "ksafe_default_"

    val engine: KSafeEncryption =
        testEngine ?: WebSoftwareEncryption(config, storagePrefix)

    val core = KSafeCore(
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

    return KSafe(
        core = core,
        deviceKeyStorages = setOf(KSafeKeyStorage.SOFTWARE),
    )
}

/**
 * Suspends until the in-memory cache has been fully loaded from localStorage
 * — including async decryption of every encrypted value via WebCrypto.
 *
 * Web tests and apps that want a deterministic first read should call this
 * before `getDirect` / `mutableStateOf` / Compose delegates. Defined as an
 * extension because `awaitCacheReady` is web-only — JVM/Android/iOS
 * preload synchronously and don't need it.
 */
suspend fun KSafe.awaitCacheReady() = core.ensureCacheReadySuspend()
