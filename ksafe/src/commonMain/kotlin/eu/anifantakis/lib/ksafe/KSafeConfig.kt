package eu.anifantakis.lib.ksafe

import kotlinx.serialization.json.Json

/**
 * Configuration for KSafe encryption parameters. The algorithm (AES-GCM) is
 * intentionally not configurable to prevent insecure setups.
 *
 * @property keySize AES key size in bits: 128 or 256 (default 256, recommended). Honored by the
 *   Android, JVM, and Apple engines; the web (JS/WasmJS) engine always uses AES-256-GCM regardless.
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
 * @property keyRotationPolicy When to rotate encryption keys automatically.
 *           Defaults to [KSafeKeyRotationPolicy.Never]; set
 *           [KSafeKeyRotationPolicy.MaxAge] to re-encrypt everything under a
 *           fresh key in the background once the current key exceeds that age.
 *           On-demand rotation is always available via [KSafe.rotateKeys].
 */
data class KSafeConfig(
    val keySize: Int = 256,
    val requireUnlockedDevice: Boolean = false,
    val json: Json = KSafeDefaults.json,
    val appNamespace: String? = null,
    val keyRotationPolicy: KSafeKeyRotationPolicy = KSafeKeyRotationPolicy.Never,
) {
    init {
        require(keySize == 128 || keySize == 256) {
            "keySize must be 128 or 256 bits. Got: $keySize"
        }
    }
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
