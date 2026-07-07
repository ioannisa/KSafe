package eu.anifantakis.lib.ksafe

import kotlinx.serialization.json.Json

/**
 * Configuration for KSafe encryption parameters. The algorithm (AES-GCM) is
 * intentionally not configurable to prevent insecure setups.
 *
 * @property keySize AES key size in bits: 128 or 256 (default 256, recommended).
 * @property androidAuthValiditySeconds Reserved for future use.
 * @property requireUnlockedDevice Default unlock policy for encrypted writes
 *           made without an explicit [KSafeWriteMode]. When `true`, keys are
 *           only usable while the device is unlocked (Android API 28+ / iOS
 *           Keychain accessibility); no effect on JVM. For per-entry control,
 *           set `requireUnlockedDevice` on [KSafeWriteMode.Encrypted] instead.
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
 *           `null`, JVM derives a best-effort id from the app's main class
 *           (override via `-Dksafe.appNamespace=` / env `KSAFE_APP_NAMESPACE`);
 *           Web falls back to origin isolation. Legacy KSafe ≤ 2.0 keys still
 *           migrate unchanged.
 */
data class KSafeConfig(
    val keySize: Int = 256,
    val androidAuthValiditySeconds: Int = 30,
    val requireUnlockedDevice: Boolean = false,
    val json: Json = KSafeDefaults.json,
    val appNamespace: String? = null
) {
    init {
        require(keySize == 128 || keySize == 256) {
            "keySize must be 128 or 256 bits. Got: $keySize"
        }
        require(androidAuthValiditySeconds > 0) {
            "androidAuthValiditySeconds must be positive. Got: $androidAuthValiditySeconds"
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
     * Uses `ignoreUnknownKeys = true` for forward/backward compatibility.
     */
    val json: Json = Json { ignoreUnknownKeys = true }
}
