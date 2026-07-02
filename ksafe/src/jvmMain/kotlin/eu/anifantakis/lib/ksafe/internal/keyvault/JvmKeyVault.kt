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
 * Abstraction over *where the raw AES key bytes live* on the JVM (which has no
 * standard hardware keystore). Implementations put the key in an OS-managed
 * secret store:
 *
 * - Windows: DPAPI (key wrapped with the user's login credentials)
 * - macOS: Keychain (login/data-protection keychain, SE-gated on modern Macs)
 * - Linux: Secret Service / libsecret (login keyring)
 *
 * When no OS store is reachable (headless Linux with no keyring, JNA link
 * failure) selection falls back to [DataStoreKeyVault] — plaintext key in the
 * DataStore file — and emits a one-time warning.
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
 * Blocking [runBlocking] bridges are acceptable here: key access is rare
 * (cached after first read) and never on a hot path.
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
    /**
     * Test seam: candidate OS vault for [pick] to self-test, in place of the
     * real `os.name`-based detection. Lets tests drive both the self-test-pass
     * and (the data-loss-critical) self-test-fail paths deterministically
     * without touching a real Keychain / keyring. Unlike [forced], selection
     * still runs through [pick] (and therefore [selfTest]).
     */
    private val osCandidateForTest: JvmKeyVault? = null,
    /**
     * Test seam: stands in for the lazily-built legacy-derived-namespace twin
     * (see [legacyProbe]) so the 2.1.0/2.1.1 namespace-upgrade
     * recovery can be tested without a real OS secret store.
     */
    private val legacyNamespaceCandidateForTest: JvmKeyVault? = null,
    /**
     * Test seam: the namespace the injected [legacyNamespaceCandidateForTest]
     * stands for. `null` (the default) models a genuine 2.1.0/2.1.1 **derived**
     * legacy namespace — safe to delete after a verified migration. Set to
     * [DEFAULT_JVM_NAMESPACE] to model the stable-default `"shared"` source,
     * which must NEVER be deleted: a co-existing no-namespace instance may own
     * that key, and deleting it would orphan the sibling's ciphertext
     * (FEEDBACK_4 H2).
     */
    private val legacyNamespaceNameForTest: String? = null,
) {
    /**
     * Retained for [legacyProbe]: the Windows DPAPI twin needs the
     * same DataStore (it stores the wrapped blob there).
     */
    private val dataStoreForTwin: DataStore<Preferences>? = dataStore

    /**
     * True when a test injected the active vault or the OS candidate. Guards
     * [legacyProbe] from lazily constructing a REAL OS vault (and
     * probing the developer's actual Keychain/keyring) inside unit tests that
     * only stubbed the primary path.
     */
    private val usingTestSeams: Boolean = forced != null || osCandidateForTest != null
    /** Legacy / software store — migration source and last-resort fallback. */
    val legacy: JvmKeyVault = legacyOverride ?: DataStoreKeyVault(
        requireNotNull(dataStore) {
            "JvmKeyVaultProvider requires a dataStore unless legacyOverride is provided"
        }
    )

    /**
     * Set when the OS vault [picked] at construction (after OS detection +
     * self-test) later fails at *runtime* — the canonical case is a Compose
     * Desktop release distributable whose `jlink`-built JRE is missing
     * `jdk.unsupported`, so JNA's first real call throws
     * `NoClassDefFoundError: sun/misc/Unsafe` even though the host clearly has
     * Keychain/DPAPI/Secret-Service. Runtime failures flip this flag (see
     * [degradeToLegacy]), after which [active] returns [legacy] for the rest of
     * this engine's life — losing OS-level key protection but keeping data
     * persistence working instead of silently dropping every write. Unlike
     * [osVaultSelfTestFailed], the OS vault is dead *in-process* here, so there
     * is no reachable OS key to overwrite later and persisting into the
     * legacy/software store is safe.
     */
    private val degraded = AtomicBoolean(false)

    /**
     * Set when an OS vault *was constructible for this platform* but failed its
     * construction-time [selfTest] — a locked Keychain, a login keyring not yet
     * on D-Bus (headless / SSH / session autostart before unlock), etc. This is
     * fundamentally different from "no OS store exists here" (genuinely headless
     * Linux without a keyring, an unsupported OS, or the explicit
     * `-Dksafe.jvm.keyVault=software` opt-out): the real keys almost certainly
     * live in the OS store and it will be reachable again on a healthy launch.
     *
     * Silently treating the legacy software store as a healthy choice in this
     * state destroys data two ways, so we flag it instead:
     *  - a null key lookup becomes ambiguous, so reads must report
     *    "unavailable" not "absent" ([hasDegraded]) — otherwise KSafeCore's
     *    orphan sweep deletes still-recoverable OS-vault-only ciphertext;
     *  - key *creation* must not mint into the legacy DataStore migration
     *    source ([osVaultUnavailable]) — a junk key written there is trusted as
     *    authoritative by the next healthy launch's legacy-first migration and
     *    overwrites the real OS-vault key, destroying everything under it.
     */
    private val osVaultSelfTestFailed = AtomicBoolean(false)

    /**
     * Set when the explicit software opt-out (`-Dksafe.jvm.keyVault=software`) selected
     * the legacy store. Like [osVaultSelfTestFailed] it makes a null key lookup ambiguous
     * — a store that previously used the OS vault still has ciphertext whose key lives
     * only there — so reads must report "unavailable" (preserve) rather than "absent"
     * (which the orphan sweep would delete). Unlike [osVaultSelfTestFailed] it does NOT
     * refuse key creation: opting out deliberately mints new keys into the software store.
     *
     * TRADEOFF (round-3 audit R8, accepted): because we cannot tell — under opt-out,
     * without probing the very OS vault the user opted out of — whether a store was ever
     * OS-backed, we treat ALL opt-out stores as "possibly OS-migrated" and preserve. For a
     * genuinely software-only store this disables orphan-ciphertext reclamation (a key
     * that was deleted leaves its ciphertext on disk unread), which is harmless clutter,
     * not data loss or leakage. Erring toward preserve is the correct bias for a security
     * library: never risk deleting data that a re-enabled OS vault could still recover.
     */
    private val softwareOptOut = AtomicBoolean(false)

    /**
     * Picked at construction (after OS detection + self-test). Declared *after*
     * [degraded] / [osVaultSelfTestFailed] because [pick] writes the latter on a
     * self-test failure — initialising it earlier would dereference a not-yet-
     * constructed flag and NPE.
     */
    private val picked: JvmKeyVault =
        forced ?: if (dataStore != null) pick(dataStore) else legacy

    /** The vault the engine should use for new keys. */
    val active: JvmKeyVault
        get() = if (degraded.get()) legacy else picked

    /**
     * True when the OS vault is known/expected to exist but is currently
     * unreachable — either a runtime failure has forced the software fallback
     * ([degradeToLegacy]) or the construction-time [selfTest] failed
     * ([osVaultSelfTestFailed]). In both states a null key lookup is ambiguous
     * (the key may live only in the now-unreachable OS vault), so callers must
     * report "vault unavailable" rather than "key absent", to keep the orphan
     * sweep from deleting still-recoverable ciphertext.
     */
    val hasDegraded: Boolean
        get() = degraded.get() || osVaultSelfTestFailed.get() || softwareOptOut.get()

    /**
     * True when an OS vault exists for this platform but was unavailable at
     * construction (see [osVaultSelfTestFailed]). Callers must NOT mint new key
     * material into the legacy DataStore migration source while this holds:
     * doing so lets the next healthy launch's legacy-first migration overwrite
     * the real OS-vault key. Distinct from [hasDegraded] because the runtime
     * `LinkageError` degrade path (OS vault permanently dead in-process) *does*
     * legitimately persist into the legacy/software store.
     */
    val osVaultUnavailable: Boolean
        get() = osVaultSelfTestFailed.get()

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
            // Preserve, don't delete: a store that used the OS vault before the opt-out
            // still holds ciphertext whose key lives only there. Flag it so a missing
            // legacy key reads as "unavailable" (orphan sweep skips it) instead of
            // "absent" (which would permanently delete recoverable data). New keys still
            // mint into the software store — that's the point of the opt-out (deep-review
            // M3). A from-start opt-out store keeps its software keys in [legacy], so this
            // never fires for keys that are genuinely present.
            softwareOptOut.set(true)
            return legacy
        }

        val os = System.getProperty("os.name").orEmpty().lowercase()
        // A construction failure (JNA class-load / native-link failure, missing
        // platform jar, …) yields null: the OS vault never came up in-process
        // (like the runtime LinkageError case), so there is no reachable OS key
        // to overwrite later and the legacy/software store is a safe home.
        val candidate: JvmKeyVault? = osCandidateForTest ?: buildOsVault(os, appNamespace, dataStore)

        if (candidate != null) {
            if (selfTest(candidate)) return candidate
            // The OS vault exists but its self-test failed: present-but-
            // unreachable right now (locked Keychain, login keyring not yet
            // unlocked / no D-Bus session, SSH/headless launch). Do NOT silently
            // treat the legacy software store as healthy — that lets the orphan
            // sweep delete OS-vault-only ciphertext and mints junk keys into the
            // migration source that overwrite the real OS key on the next
            // healthy launch. Flag it so the engine fails safe (reads report
            // "unavailable"; key creation is refused) and the data survives
            // until the OS store is reachable again.
            osVaultSelfTestFailed.set(true)
            warnOsVaultUnavailableOnce(os)
            return legacy
        }

        // No OS vault for this platform at all — the legacy software store is the
        // legitimate, permanent home (no reachable OS key to protect).
        warnFallbackOnce(os)
        return legacy
    }

    /** OS-detected vault construction, shared by [pick] and [legacyProbe]. */
    private fun buildOsVault(
        os: String,
        namespace: String,
        dataStore: DataStore<Preferences>?,
    ): JvmKeyVault? = try {
        when {
            os.contains("win") -> dataStore?.let { WindowsDpapiKeyVault(it, namespace) }
            os.contains("mac") || os.contains("darwin") -> MacosKeychainKeyVault(namespace)
            os.contains("nux") || os.contains("nix") || os.contains("aix") ->
                LinuxSecretServiceKeyVault(namespace)
            else -> null
        }
    } catch (t: Throwable) {
        null
    }

    /**
     * The legacy-namespace read-fallback: the OS-vault twin used as a migration
     * source (see [recoverFromLegacyNamespace]), paired with the **namespace it
     * lives under**. Two upgrade paths feed it (see [legacyFallbackNamespace]):
     * the 2.1.0/2.1.1 launcher-**derived** namespace when on the stable default
     * (those releases derived it from `sun.java.command`; the default is now the
     * constant [DEFAULT_JVM_NAMESPACE]), OR the stable default `"shared"` itself
     * when an explicit `appNamespace` was newly set (FEEDBACK_4 H-D). Without
     * this probe pre-upgrade keys become invisible, every decrypt throws
     * "No encryption key found", and the startup orphan sweep permanently
     * deletes the user's ciphertext.
     *
     * The paired namespace gates destructive cleanup: a genuine derived legacy
     * namespace has no live owner and may be deleted after a verified migration,
     * but the stable default [DEFAULT_JVM_NAMESPACE] must NEVER be deleted — a
     * co-existing no-namespace KSafe instance may own that key, and deleting it
     * would orphan the sibling's ciphertext (FEEDBACK_4 H2).
     *
     * Built lazily and only when it can actually matter: production wiring
     * (no test seams), an OS-backed pick, and a fallback namespace that differs
     * from the active one.
     */
    private val legacyProbe: Pair<JvmKeyVault, String?>? by lazy {
        legacyNamespaceCandidateForTest?.let { return@lazy it to legacyNamespaceNameForTest }
        if (usingTestSeams) return@lazy null
        if (!picked.isOsBacked) return@lazy null
        // Probe the namespace that holds pre-upgrade keys: the 2.1.0/2.1.1 launcher-
        // derived namespace when on the stable default, OR the stable default itself
        // when an explicit appNamespace was newly set (FEEDBACK_4 H-D).
        val fallbackNs = legacyFallbackNamespace(appNamespace, legacyDerivedJvmNamespace())
            ?: return@lazy null
        val vault = buildOsVault(
            System.getProperty("os.name").orEmpty().lowercase(),
            fallbackNs,
            dataStoreForTwin,
        ) ?: return@lazy null
        vault to fallbackNs
    }

    /**
     * Read-fallback for a key that misses under the current namespace: probes
     * the legacy-namespace twin and, on a hit, migrates the key to the active
     * vault — write, read-back-verify, then delete the old entry ONLY when the
     * source is a genuine derived legacy namespace. On any migration hiccup the
     * bytes are still returned so this session decrypts normally and the
     * migration retries on a later launch; the old entry is never deleted
     * unverified — and never at all when the source is the stable default
     * `"shared"` (FEEDBACK_4 H2).
     *
     * Callers reach this only after a successful-but-null [active] lookup, so
     * the vault is healthy here — no degraded/self-test gating needed (those
     * states never route to the OS vault in the first place).
     */
    internal fun recoverFromLegacyNamespace(alias: String): ByteArray? {
        val (source, sourceNamespace) = legacyProbe ?: return null
        val bytes = try {
            source.get(alias)
        } catch (e: LinkageError) {
            throw e
        } catch (_: Throwable) {
            null
        } ?: return null
        try {
            picked.put(alias, bytes)
            // Reclaim the old entry only for a genuine derived legacy namespace
            // (no live owner). NEVER delete from the stable default "shared": a
            // co-existing no-namespace KSafe instance may be actively using that
            // key, and a MOVE would orphan the sibling's ciphertext (FEEDBACK_4
            // H2). Leaving it is harmless — the key now lives under the active
            // namespace, so active.get() hits next launch and this fallback
            // won't re-run.
            if (sourceNamespace != DEFAULT_JVM_NAMESPACE &&
                picked.get(alias)?.contentEquals(bytes) == true
            ) {
                runCatching { source.delete(alias) }
            }
        } catch (e: LinkageError) {
            throw e
        } catch (_: Throwable) {
            // Keep serving the recovered bytes; the un-deleted old entry makes
            // the migration retry next launch.
        }
        return bytes
    }

    /**
     * Best-effort delete from the legacy-namespace twin, so a delete-then-
     * recreate of the same alias cannot resurrect the pre-upgrade key via
     * [recoverFromLegacyNamespace] (the same guarantee deleteKey already
     * gives for the legacy DataStore vault). Skipped when the twin is the
     * stable default `"shared"`: a co-existing no-namespace instance may own
     * that key, so a namespaced instance must never scrub it (FEEDBACK_4 H2).
     */
    internal fun deleteFromLegacyNamespace(alias: String) {
        val (twin, twinNamespace) = legacyProbe ?: return
        if (twinNamespace == DEFAULT_JVM_NAMESPACE) return
        runCatching { twin.delete(alias) }
    }

    /**
     * Round-trips a canary value to confirm the native store actually works.
     *
     * The alias must be unique per attempt: the OS stores are per-user and
     * shared across every process and KSafe instance on the machine, so a
     * FIXED alias lets two concurrent self-tests interleave (A.put, B.put,
     * A.get, A.delete, B.get → null), flipping a healthy engine into
     * session-long fail-closed mode.
     */
    private fun selfTest(vault: JvmKeyVault): Boolean = try {
        val alias = "__ksafe_selftest__" + java.util.UUID.randomUUID()
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
        val osUnavailableWarned = AtomicBoolean(false)
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

        fun warnOsVaultUnavailableOnce(os: String) {
            if (osUnavailableWarned.compareAndSet(false, true)) {
                System.err.println(
                    "KSafe SECURITY WARNING: an OS secret store exists on this " +
                        "host (os=\"$os\") but is currently unreachable (locked " +
                        "Keychain, login keyring not yet unlocked / no D-Bus " +
                        "session, or an SSH/headless launch). KSafe will NOT fall " +
                        "back to plaintext key storage this session: doing so " +
                        "could permanently destroy keys already held in the OS " +
                        "store, taking all data encrypted under them with it. " +
                        "Encrypted reads return their defaults and encrypted " +
                        "writes fail until the OS store is reachable again (e.g. " +
                        "after interactive login). To deliberately use software " +
                        "key storage instead, set -Dksafe.jvm.keyVault=software " +
                        "(or env KSAFE_JVM_KEY_VAULT=software)."
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
 * `-Dksafe.appNamespace` → env `KSAFE_APP_NAMESPACE` → the stable constant
 * `"shared"`. Sanitised to `[A-Za-z0-9._-]` so it is safe as a Keychain
 * service / DataStore key / Secret Service attribute. A blank result is
 * impossible.
 *
 * **The default MUST be stable across launches.** A launcher-derived default
 * (jar name / main-class token) moves while the un-namespaced data file does
 * not, making every existing key invisible — and the startup orphan sweep
 * would then delete the user's encrypted data on upgrade.
 *
 * Apps that genuinely need per-app OS-vault isolation set
 * `KSafeConfig.appNamespace` explicitly — which also namespaces the data file,
 * so file and keys move together.
 */
/**
 * The stable default OS-vault namespace. Never derived from the launcher, so
 * it cannot silently move between runs/releases.
 */
internal const val DEFAULT_JVM_NAMESPACE = "shared"

/**
 * The OS-vault namespace to probe as a read-fallback migration source for a key that misses
 * under [currentNamespace], or `null` when there is nothing to probe. Two upgrade paths:
 *  - [currentNamespace] is the stable default (`"shared"`): probe the 2.1.0/2.1.1 launcher-
 *    **derived** namespace [derivedNamespace] (keys written before the default became stable).
 *  - [currentNamespace] is an **explicit** `appNamespace`: probe the stable default
 *    [DEFAULT_JVM_NAMESPACE] — an app that ran without a namespace and then set one holds its
 *    keys under `"shared"`, and adding `appNamespace` would otherwise orphan them (FEEDBACK_4 H-D).
 * Returns `null` when the fallback would equal [currentNamespace] (nothing to migrate).
 */
internal fun legacyFallbackNamespace(currentNamespace: String, derivedNamespace: String?): String? {
    val fallback = if (currentNamespace == DEFAULT_JVM_NAMESPACE) derivedNamespace else DEFAULT_JVM_NAMESPACE
    return fallback?.takeIf { it != currentNamespace }
}

private fun String?.cleanNamespaceToken(): String? =
    this?.trim()?.takeIf { it.isNotEmpty() }
        ?.replace(Regex("[^A-Za-z0-9._-]"), "_")
        ?.take(120)
        ?.takeIf { it.isNotEmpty() }

internal fun resolveJvmAppNamespace(override: String?): String {
    override.cleanNamespaceToken()?.let { return it }
    System.getProperty("ksafe.appNamespace").cleanNamespaceToken()?.let { return it }
    System.getenv("KSAFE_APP_NAMESPACE").cleanNamespaceToken()?.let { return it }

    // Deliberately NO `sun.java.command` derivation — it changes with the
    // launcher and would silently orphan the user's data on upgrade. Keys
    // written by released 2.1.0/2.1.1 under the old derived namespace are
    // recovered on read by [JvmKeyVaultProvider.recoverFromLegacyNamespace].
    return DEFAULT_JVM_NAMESPACE
}

/**
 * Reproduces — byte for byte — the default-namespace derivation that released
 * 2.1.0/2.1.1 used (`sun.java.command` first token; jar path → bare jar name;
 * same sanitization), so [JvmKeyVaultProvider.recoverFromLegacyNamespace] can
 * probe exactly where those releases stored a stable-launcher app's keys.
 * Returns null when no launcher token is available or when the derivation
 * lands on [DEFAULT_JVM_NAMESPACE] itself (nothing distinct to probe).
 */
internal fun legacyDerivedJvmNamespace(): String? {
    val cmd = System.getProperty("sun.java.command").orEmpty().trim().substringBefore(' ')
    val launcher = when {
        cmd.isEmpty() -> null
        cmd.endsWith(".jar", ignoreCase = true) ->
            cmd.replace('\\', '/').substringAfterLast('/').removeSuffix(".jar")
        else -> cmd
    }
    return launcher.cleanNamespaceToken()?.takeIf { it != DEFAULT_JVM_NAMESPACE }
}
