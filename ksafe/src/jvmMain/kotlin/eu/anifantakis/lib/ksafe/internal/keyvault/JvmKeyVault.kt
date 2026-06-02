package eu.anifantakis.lib.ksafe.internal.keyvault

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Abstraction over *where the raw AES key bytes live* on the JVM.
 *
 * The JVM has no standard hardware keystore, so prior to this abstraction the
 * AES key was Base64-encoded straight into the DataStore preferences file next
 * to the ciphertext — recoverable by anyone who could read that file. A
 * [JvmKeyVault] moves the key into an OS-managed secret store instead:
 *
 * - Windows: DPAPI (key wrapped with the user's login credentials)
 * - macOS: Keychain (login/data-protection keychain, SE-gated on modern Macs)
 * - Linux: Secret Service / libsecret (login keyring)
 *
 * When no OS store is reachable (headless Linux with no keyring, JNA link
 * failure, locked keychain) selection falls back to [DataStoreKeyVault] — the
 * legacy plaintext-in-file behaviour — and emits a one-time warning. This keeps
 * existing deployments working unchanged ("fall back + warn").
 *
 * Implementations must be safe to call from multiple threads; callers
 * ([eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption]) additionally
 * serialise per-alias.
 */
internal interface JvmKeyVault {

    /** Human-readable identifier for diagnostics and the fallback warning. */
    val name: String

    /**
     * True when keys are protected by an OS secret store. False for the
     * plaintext [DataStoreKeyVault] fallback. Surfaced for tests/diagnostics;
     * not part of KSafe's public API.
     */
    val isOsBacked: Boolean

    /** Raw key bytes previously stored for [alias], or null if none. */
    fun get(alias: String): ByteArray?

    /** Stores (replacing any existing) the raw key bytes for [alias]. */
    fun put(alias: String, keyBytes: ByteArray)

    /** Removes the key for [alias]. No-op when absent. */
    fun delete(alias: String)
}

/**
 * Minimal string key/value store backed by DataStore Preferences.
 *
 * Used by [DataStoreKeyVault] (legacy raw-key persistence and migration source)
 * and by [WindowsDpapiKeyVault] (to persist the DPAPI-wrapped blob — which is
 * useless without the user's Windows login, so storing it in a file is safe).
 *
 * The blocking [runBlocking] bridges mirror the pre-existing engine code:
 * key access is rare (cached after first read) and never on a hot path.
 */
internal class DataStorePrefStore(
    private val dataStore: DataStore<Preferences>,
    private val prefix: String,
) {
    fun getString(alias: String): String? {
        val pref = stringPreferencesKey("$prefix$alias")
        return runBlocking { dataStore.data.first() }[pref]
    }

    fun putString(alias: String, value: String) {
        val pref = stringPreferencesKey("$prefix$alias")
        runBlocking { dataStore.edit { it[pref] = value } }
    }

    fun remove(alias: String) {
        val pref = stringPreferencesKey("$prefix$alias")
        runBlocking { dataStore.edit { it.remove(pref) } }
    }

    /** Every alias currently stored under [prefix] (for the eager sweep). */
    fun listAliases(): List<String> =
        runBlocking { dataStore.data.first() }.asMap().keys
            .asSequence()
            .map { it.name }
            .filter { it.startsWith(prefix) }
            .map { it.removePrefix(prefix) }
            .toList()
}

/**
 * Legacy / fallback vault: raw AES key Base64-encoded in DataStore under the
 * historical `ksafe_key_` prefix.
 *
 * This is intentionally identical to KSafe ≤ 2.0 on-disk format so it doubles
 * as the **migration source**: when an OS-backed vault is selected, an existing
 * key is read from here, copied into the OS store, then removed from here.
 *
 * Security: none beyond OS file permissions. Selected only when no OS secret
 * store is available.
 */
internal class DataStoreKeyVault(
    dataStore: DataStore<Preferences>,
) : JvmKeyVault {

    private val store = DataStorePrefStore(dataStore, KEY_PREFIX)

    override val name: String = "DataStore (software, plaintext — no OS protection)"
    override val isOsBacked: Boolean = false

    @OptIn(ExperimentalEncodingApi::class)
    override fun get(alias: String): ByteArray? =
        store.getString(alias)?.let { Base64.decode(it) }

    @OptIn(ExperimentalEncodingApi::class)
    override fun put(alias: String, keyBytes: ByteArray) {
        store.putString(alias, Base64.encode(keyBytes))
    }

    override fun delete(alias: String) = store.remove(alias)

    /** Aliases still stored under the legacy `ksafe_key_` prefix. */
    fun legacyAliases(): List<String> = store.listAliases()

    companion object {
        const val KEY_PREFIX = "ksafe_key_"
    }
}

/**
 * Resolves and holds the active [JvmKeyVault] plus the legacy
 * [DataStoreKeyVault] (always available for migration / fallback).
 *
 * Selection is performed once per engine instance. Each OS vault runs a
 * self-test (store → read-back → delete of a throwaway canary) before being
 * accepted, so a present-but-broken keyring degrades gracefully to the
 * fallback rather than failing every encrypt/decrypt.
 */
internal class JvmKeyVaultProvider(
    /**
     * DataStore backing the legacy [DataStoreKeyVault] and the OS-vault
     * detection ([pick]). Nullable for the no-DataStore JSON-file fallback
     * path (when `sun.misc.Unsafe` is unavailable): there a [legacyOverride]
     * ([FileKeyVault]) is supplied and no DataStore exists.
     */
    dataStore: DataStore<Preferences>? = null,
    /**
     * App-isolation namespace applied to the OS-vault **destination** only
     * (Keychain service / DPAPI blob prefix / Secret Service attribute) so
     * different desktop apps sharing the per-user secret store don't collide.
     * Blank = no namespace (legacy behaviour / tests). The legacy
     * [DataStoreKeyVault] is intentionally NOT namespaced — its `ksafe_key_`
     * layout is the frozen KSafe ≤ 2.0 on-disk format and the migration
     * source.
     */
    private val appNamespace: String = "",
    /** Test seam: force a specific vault and skip OS detection. */
    forced: JvmKeyVault? = null,
    /**
     * Replaces the default [DataStoreKeyVault] software vault. Used by the
     * JSON-file fallback to supply a [FileKeyVault] when there's no DataStore.
     */
    legacyOverride: JvmKeyVault? = null,
) {
    /** Legacy / software store — migration source and last-resort fallback. */
    val legacy: JvmKeyVault = legacyOverride ?: DataStoreKeyVault(
        requireNotNull(dataStore) {
            "JvmKeyVaultProvider requires a dataStore unless legacyOverride is provided"
        }
    )

    /**
     * Picked at construction (after OS detection + self-test). May still
     * fail at *runtime* — the canonical case is a Compose Desktop release
     * distributable whose `jlink`-built JRE is missing `jdk.unsupported`,
     * so JNA's first real call throws `NoClassDefFoundError: sun/misc/Unsafe`
     * even though the host clearly has Keychain/DPAPI/Secret-Service.
     * Runtime failures flip [degraded], after which [active] returns
     * [legacy] for the rest of this engine's life — losing OS-level key
     * protection but keeping data persistence working instead of silently
     * dropping every write.
     */
    private val picked: JvmKeyVault =
        forced ?: if (dataStore != null) pick(dataStore) else legacy
    private val degraded = AtomicBoolean(false)

    /** The vault the engine should use for new keys. */
    val active: JvmKeyVault
        get() = if (degraded.get()) legacy else picked

    /**
     * True once a runtime OS-vault failure has forced the software fallback
     * (see [degradeToLegacy]). When degraded, a null key lookup is ambiguous —
     * the key may live only in the now-unreachable OS vault — so callers must
     * report "vault unavailable" rather than "key absent", to keep the orphan
     * sweep from deleting still-recoverable ciphertext.
     */
    val hasDegraded: Boolean
        get() = degraded.get()

    /**
     * Flips the provider into degraded mode after a runtime JNA failure on
     * [picked]: subsequent reads of [active] return [legacy]. Emits a
     * one-time loud warning naming the cause so the operator can install
     * the missing JDK module (typically `jdk.unsupported`) rather than
     * silently running on the software fallback forever.
     *
     * Called by [eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption]
     * when a `LinkageError` (NoClassDefFoundError, UnsatisfiedLinkError, …)
     * or `ExceptionInInitializerError` escapes a `get`/`put`/`delete` on
     * the active vault.
     */
    internal fun degradeToLegacy(cause: Throwable) {
        if (degraded.compareAndSet(false, true)) {
            warnRuntimeDegrade(picked.name, cause)
        }
    }

    private fun pick(dataStore: DataStore<Preferences>): JvmKeyVault {
        // Explicit opt-out: forces the legacy software store without a warning.
        // Useful for CI/tests (no Keychain access prompt, no keyring pollution)
        // and for consumers who deliberately don't want OS-store integration.
        // System property takes precedence over the environment variable.
        val override = System.getProperty(PROP_KEY_VAULT)
            ?: System.getenv(ENV_KEY_VAULT)
        if (override != null && override.lowercase() in OPT_OUT_VALUES) {
            return legacy
        }

        val os = System.getProperty("os.name").orEmpty().lowercase()
        val candidate: JvmKeyVault? = try {
            when {
                os.contains("win") -> WindowsDpapiKeyVault(dataStore, appNamespace)
                os.contains("mac") || os.contains("darwin") -> MacosKeychainKeyVault(appNamespace)
                os.contains("nux") || os.contains("nix") || os.contains("aix") ->
                    LinuxSecretServiceKeyVault(appNamespace)
                else -> null
            }
        } catch (t: Throwable) {
            // JNA class-load / native-link failure, missing platform jar, etc.
            null
        }

        if (candidate != null && selfTest(candidate)) return candidate

        warnFallbackOnce(os)
        return legacy
    }

    /** Round-trips a canary value to confirm the native store actually works. */
    private fun selfTest(vault: JvmKeyVault): Boolean = try {
        val alias = "__ksafe_selftest__"
        val canary = byteArrayOf(0x4B, 0x53, 0x61, 0x66, 0x65) // "KSafe"
        vault.put(alias, canary)
        val read = vault.get(alias)
        vault.delete(alias)
        read != null && read.contentEquals(canary)
    } catch (t: Throwable) {
        false
    }

    private companion object {
        /** `-Dksafe.jvm.keyVault=software` (or env `KSAFE_JVM_KEY_VAULT`). */
        const val PROP_KEY_VAULT = "ksafe.jvm.keyVault"
        const val ENV_KEY_VAULT = "KSAFE_JVM_KEY_VAULT"
        val OPT_OUT_VALUES = setOf("software", "datastore", "off", "false", "none")

        val warned = AtomicBoolean(false)
        val runtimeDegradeWarned = AtomicBoolean(false)

        fun warnFallbackOnce(os: String) {
            if (warned.compareAndSet(false, true)) {
                System.err.println(
                    "KSafe SECURITY WARNING: no OS secret store is available on " +
                        "this JVM host (os=\"$os\"). Encryption keys will be stored " +
                        "Base64-encoded in the DataStore file, protected only by " +
                        "OS file permissions and recoverable by anyone who can read " +
                        "that file as this user. Install/enable a keyring " +
                        "(Linux: gnome-keyring/ksecretservice) or run on a host " +
                        "with DPAPI (Windows) / Keychain (macOS) for OS-backed " +
                        "key protection."
                )
            }
        }

        fun warnRuntimeDegrade(vaultName: String, cause: Throwable) {
            if (runtimeDegradeWarned.compareAndSet(false, true)) {
                val typed = "${cause::class.java.simpleName}: ${cause.message}"
                // NOTE: we deliberately do NOT promise "writes are not lost" here.
                // A runtime LinkageError almost always means a missing JDK module
                // (jdk.unsupported / sun.misc.Unsafe) in a jlink-trimmed runtime —
                // and Jetpack DataStore's protobuf layer ALSO requires
                // sun.misc.Unsafe, so it will crash independently of this key-vault
                // degrade. The key-vault fallback keeps key custody working; it
                // cannot rescue DataStore. The module is therefore required, not
                // optional, for KSafe on Compose Desktop release distributables.
                System.err.println(
                    "KSafe SECURITY WARNING: the OS keyvault ($vaultName) failed at " +
                        "runtime ($typed); key custody has degraded to the software " +
                        "vault. This usually means a jlink-trimmed runtime is missing " +
                        "`jdk.unsupported` (sun.misc.Unsafe). IMPORTANT: that same " +
                        "module is REQUIRED by Jetpack DataStore (KSafe's storage " +
                        "backend) — without it DataStore itself crashes and data will " +
                        "NOT persist; KSafe cannot work around that. Add " +
                        "`modules(\"jdk.unsupported\")` to your " +
                        "`compose.desktop.application.nativeDistributions` block " +
                        "(or run `./gradlew :<app>:suggestRuntimeModules`)."
                )
            }
        }
    }
}

/**
 * Resolves the effective app-isolation namespace for the JVM OS vaults.
 *
 * Priority: explicit [override] (`KSafeConfig.appNamespace`) →
 * `-Dksafe.appNamespace` → env `KSAFE_APP_NAMESPACE` → best-effort from the
 * app's launcher (`sun.java.command`) → `"shared"`. Sanitised to
 * `[A-Za-z0-9._-]` so it is safe as a Keychain service / DataStore key /
 * Secret Service attribute.
 *
 * Best-effort auto-derivation favours **stability** (the entry-point class /
 * jar name is stable across runs and install locations) over uniqueness;
 * production apps should set `KSafeConfig.appNamespace` explicitly. A blank
 * result is impossible (falls back to `"shared"`).
 */
internal fun resolveJvmAppNamespace(override: String?): String {
    fun String?.clean(): String? =
        this?.trim()?.takeIf { it.isNotEmpty() }
            ?.replace(Regex("[^A-Za-z0-9._-]"), "_")
            ?.take(120)
            ?.takeIf { it.isNotEmpty() }

    override.clean()?.let { return it }
    System.getProperty("ksafe.appNamespace").clean()?.let { return it }
    System.getenv("KSAFE_APP_NAMESPACE").clean()?.let { return it }

    // `sun.java.command` = "<mainClass-or-jar> <args...>"; keep only the
    // launcher token — the entry point is stable per app, args are not.
    val cmd = System.getProperty("sun.java.command").orEmpty().trim().substringBefore(' ')
    val launcher = when {
        cmd.isEmpty() -> null
        cmd.endsWith(".jar", ignoreCase = true) ->
            cmd.replace('\\', '/').substringAfterLast('/').removeSuffix(".jar")
        else -> cmd
    }
    launcher.clean()?.let { return it }
    return "shared"
}
