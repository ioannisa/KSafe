package eu.anifantakis.lib.ksafe

import kotlinx.serialization.json.Json

/**
 * AES-GCM key strength used when KSafe creates a new key generation.
 *
 * Changing this setting does not mutate an existing key. Call [KSafe.rotateKeys] to re-encrypt an
 * existing store under a newly generated key of the selected size.
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
 * Configuration for KSafe encryption parameters. The algorithm (AES-GCM) is
 * intentionally not configurable to prevent insecure setups.
 *
 * @property aesKeySize AES-GCM key size used for newly created keys on every platform.
 *   Defaults to [KSafeAesKeySize.BITS_256]. Existing keys keep their original size until rotation.
 * @property requireUnlockedDevice Default unlock policy for encrypted writes
 *           made without an explicit [KSafeWriteMode]. When `true`, keys are
 *           only usable while the device is unlocked (Android API 28+ / iOS
 *           Keychain accessibility); no effect on JVM. For per-entry control,
 *           set `requireUnlockedDevice` on [KSafeWriteMode.Encrypted] instead.
 *           Android caveat: before Android 15 (API 35) the underlying
 *           `setUnlockedDeviceRequired(true)` had documented platform bugs on
 *           API 28-34 — removing the lock screen can silently delete such keys
 *           (the affected values then self-heal to their defaults via the
 *           missing-key sweep), and key generation/use can fail while no secure
 *           lock screen is configured. Weigh this before enabling it broadly on
 *           pre-35 fleets.
 * @property json The [Json] instance used for user-payload serialization.
 *           Override to register a custom SerializersModule or change JSON
 *           behaviour. Changing the format for an existing `fileName`
 *           namespace may make previously stored non-primitive values
 *           unreadable. Defaults to [KSafeDefaults.json].
 * @property appNamespace Optional app-unique identifier (e.g. reverse-DNS id)
 *           that namespaces the encryption-key destination on JVM/Desktop and
 *           Web, where the OS secret store / browser origin storage is shared
 *           and same-`fileName` apps would otherwise collide on the same key.
 *           No effect on Android/iOS (keystores are already per-app). If
 *           `null`, JVM uses a stable shared default namespace
 *           (override via `-Dksafe.appNamespace=` / env `KSAFE_APP_NAMESPACE`);
 *           Web falls back to origin isolation. Keys written by older releases
 *           under a launcher/main-class-derived namespace are still recovered
 *           on read, and legacy KSafe ≤ 2.0 keys migrate unchanged.
 * @property keyRotationPolicy When to start a fresh key generation automatically.
 *           Defaults to [KSafeKeyRotationPolicy.Never]; set
 *           [KSafeKeyRotationPolicy.MaxAge] to re-encrypt everything under a
 *           fresh key in the background once the current key exceeds that age.
 *           On-demand rotation is always available via [KSafe.rotateKeys].
 *           Since 3.1.0, passes carrying the explicit in-progress lifecycle
 *           state resume on the next instance under every policy. Marker-less
 *           3.0.0 records are conservatively adopted as completed. Normally
 *           completed passes with retryable skipped entries persist a marker
 *           for the next KSafe instance. That instance retries the same generation
 *           unless MaxAge is already due, in which case it starts the normal fresh one.
 * @property keyRotationRetryAttempts Maximum automatic next-instance retries after a
 *           normally completed rotation leaves retryable skipped entries. Defaults to 3.
 *           Each newly created KSafe instance consumes at most one persisted attempt; the
 *           current instance never loops. Set to 0 to disable these retries. Definitive
 *           failures do not consume or arm this budget.
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

    /**
     * The bit count behind [aesKeySize].
     *
     * Kept so `config.keySize` still reads on 3.x; [aesKeySize] is the configurable one, and an
     * `Int` cannot express that only two values are legal.
     */
    @Deprecated(
        "Read aesKeySize instead — it is the typed source of truth. Removed in 4.0.0.",
        ReplaceWith("aesKeySize.bits"),
    )
    val keySize: Int get() = aesKeySize.bits

    /**
     * Pre-3.1.0 constructor, kept so existing `KSafeConfig(keySize = 128)` call sites keep
     * compiling and linking. [keySize] must still be 128 or 256; anything else fails exactly as
     * it did before.
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
     * Pre-3.1.0 `copy(keySize = …)`. The generated `copy` takes [aesKeySize]; this overload keeps
     * the `Int` form resolving. Selected only when [keySize] is passed, so `copy()` and every
     * other named argument still reach the generated one.
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

/** Preserves the pre-3.1.0 rejection message for an unsupported bit count. */
private fun Int.toAesKeySize(): KSafeAesKeySize = when (this) {
    128 -> KSafeAesKeySize.BITS_128
    256 -> KSafeAesKeySize.BITS_256
    else -> throw IllegalArgumentException("keySize must be 128 or 256 bits. Got: $this")
}

/**
 * Shared defaults for KSafe configuration.
 */
object KSafeDefaults {
    /**
     * The default [Json] instance used for user-payload serialization.
     *
     * Uses `ignoreUnknownKeys = true` for forward/backward compatibility, and
     * `allowSpecialFloatingPointValues = true` so `Double`/`Float` `NaN` and `±Infinity`
     * round-trip through the default (Encrypted) write mode — the plain path already stores
     * these natively and the read path already decodes them, so without this a legitimate
     * special float would crash an encrypted `put()` while succeeding under `PlainText`.
     */
    val json: Json = Json {
        ignoreUnknownKeys = true
        allowSpecialFloatingPointValues = true
    }
}
