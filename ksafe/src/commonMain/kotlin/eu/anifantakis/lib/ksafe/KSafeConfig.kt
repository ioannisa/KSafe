package eu.anifantakis.lib.ksafe

import kotlinx.serialization.json.Json

/**
 * AES-GCM key strength used when KSafe creates a new key generation. Existing keys keep their
 * size until [KSafe.rotateKeys] re-encrypts the store.
 */
enum class KSafeAesKeySize(
    val bits: Int,
) {
    BITS_128(128),
    BITS_256(256),
    ;

    internal val bytes: Int get() = bits / Byte.SIZE_BITS
}

/**
 * Configuration for KSafe encryption. The algorithm (AES-GCM) is fixed, so no call site can
 * weaken it.
 *
 * @property aesKeySize Key size for newly created keys; existing keys keep theirs until rotation.
 * @property requireUnlockedDevice Default unlock policy for encrypted writes made without an
 *   explicit [KSafeWriteMode]; no effect on JVM or web. On Android before API 35, removing the
 *   lock screen can silently delete such keys (the values self-heal to their defaults).
 * @property json Serializer for user payloads; changing it can make stored non-primitive values
 *   unreadable.
 * @property appNamespace App-unique id (e.g. reverse-DNS) namespacing both data and keys on
 *   JVM and Web, where the OS store / origin storage is shared. No effect on Android/iOS.
 * @property keyRotationPolicy When to start a fresh key generation automatically; on-demand
 *   rotation is always available via [KSafe.rotateKeys].
 * @property keyRotationRetryAttempts Automatic next-instance retries after a completed rotation
 *   left retryable skipped entries. Each new instance consumes at most one; 0 disables them.
 * @throws IllegalArgumentException if [keyRotationRetryAttempts] is negative.
 */
data class KSafeConfig(
    val aesKeySize: KSafeAesKeySize = KSafeAesKeySize.BITS_256,
    val requireUnlockedDevice: Boolean = false,
    val json: Json = KSafeDefaults.json,
    val appNamespace: String? = null,
    val keyRotationPolicy: KSafeKeyRotationPolicy = KSafeKeyRotationPolicy.Never,
    val keyRotationRetryAttempts: Int = 3,
) {
    init {
        require(keyRotationRetryAttempts >= 0) {
            "keyRotationRetryAttempts must be non-negative. Got: $keyRotationRetryAttempts"
        }
    }

    /** The bit count behind [aesKeySize]. */
    @Deprecated(
        "Read aesKeySize instead — it is the typed source of truth. Removed in 4.0.0.",
        ReplaceWith("aesKeySize.bits"),
    )
    val keySize: Int get() = aesKeySize.bits

    /**
     * `Int`-typed constructor kept for compatibility; a [keySize] other than 128 or 256 throws
     * [IllegalArgumentException].
     */
    @Deprecated(
        "Use the aesKeySize parameter with KSafeAesKeySize. Removed in 4.0.0.",
        ReplaceWith(
            "KSafeConfig(KSafeAesKeySize.BITS_256, requireUnlockedDevice, json, appNamespace, " +
                "keyRotationPolicy)",
        ),
    )
    constructor(
        keySize: Int,
        requireUnlockedDevice: Boolean = false,
        json: Json = KSafeDefaults.json,
        appNamespace: String? = null,
        keyRotationPolicy: KSafeKeyRotationPolicy = KSafeKeyRotationPolicy.Never,
    ) : this(
        aesKeySize = keySize.toAesKeySize(),
        requireUnlockedDevice = requireUnlockedDevice,
        json = json,
        appNamespace = appNamespace,
        keyRotationPolicy = keyRotationPolicy,
    )

    /**
     * `Int`-typed `copy`; selected only when [keySize] is passed, so `copy()` reaches the
     * generated one.
     */
    @Deprecated(
        "Use copy(aesKeySize = …) with KSafeAesKeySize. Removed in 4.0.0.",
        ReplaceWith("copy(aesKeySize = KSafeAesKeySize.BITS_256)"),
    )
    fun copy(
        keySize: Int,
        requireUnlockedDevice: Boolean = this.requireUnlockedDevice,
        json: Json = this.json,
        appNamespace: String? = this.appNamespace,
        keyRotationPolicy: KSafeKeyRotationPolicy = this.keyRotationPolicy,
    ): KSafeConfig = copy(
        aesKeySize = keySize.toAesKeySize(),
        requireUnlockedDevice = requireUnlockedDevice,
        json = json,
        appNamespace = appNamespace,
        keyRotationPolicy = keyRotationPolicy,
        keyRotationRetryAttempts = this.keyRotationRetryAttempts,
    )
}

private fun Int.toAesKeySize(): KSafeAesKeySize = when (this) {
    128 -> KSafeAesKeySize.BITS_128
    256 -> KSafeAesKeySize.BITS_256
    else -> throw IllegalArgumentException("keySize must be 128 or 256 bits. Got: $this")
}

/** Shared defaults for KSafe configuration. */
object KSafeDefaults {
    /**
     * Default [Json] for user payloads. `allowSpecialFloatingPointValues` is on so `NaN` and
     * `±Infinity` round-trip through encrypted writes, as they already do under `PlainText`.
     */
    val json: Json = Json {
        ignoreUnknownKeys = true
        allowSpecialFloatingPointValues = true
    }
}
