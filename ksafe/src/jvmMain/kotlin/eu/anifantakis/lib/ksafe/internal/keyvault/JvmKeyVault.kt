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
 * Abstraction over *where the raw AES key bytes live* on the JVM (no standard
 * hardware keystore). Implementations put the key in an OS secret store —
 * Windows DPAPI, macOS Keychain, Linux Secret Service — or, when none is
 * reachable, fall back to [DataStoreKeyVault] (plaintext in the DataStore file)
 * with a one-time warning.
 *
 * Implementations must be thread-safe; callers additionally serialise per-alias.
 */
internal interface JvmKeyVault {

    /** Human-readable identifier for diagnostics and the fallback warning. */
    val name: String

    /** True when keys are protected by an OS secret store; false for the plaintext fallback. */
    val isOsBacked: Boolean

    /** Raw key bytes previously stored for [alias], or null if none. */
    fun get(alias: String): ByteArray?

    /** Stores (replacing any existing) the raw key bytes for [alias]. */
    fun put(alias: String, keyBytes: ByteArray)

    /** Removes the key for [alias]. No-op when absent. */
    fun delete(alias: String)
}

/**
 * Minimal string key/value store over DataStore Preferences, used by
 * [DataStoreKeyVault] and [WindowsDpapiKeyVault]. The [runBlocking] bridges are
 * fine here: key access is rare (cached after first read), never on a hot path.
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
 * historical `ksafe_key_` prefix. Intentionally the frozen KSafe ≤ 2.0 on-disk
 * format, so it doubles as the migration source — when an OS vault is selected a
 * key here is copied into it, then removed. Security: none beyond OS file
 * permissions; selected only when no OS store is available.
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
 * Resolves and holds the active [JvmKeyVault] plus the legacy [DataStoreKeyVault]
 * (always available for migration / fallback). Selection runs once per engine
 * instance; each OS vault must pass a self-test (store → read-back → delete of a
 * canary) before being accepted, so a present-but-broken keyring degrades to the
 * fallback rather than failing every encrypt/decrypt.
 */
internal class JvmKeyVaultProvider(
    /**
     * DataStore backing the legacy [DataStoreKeyVault] and OS-vault detection.
     * Null on the JSON-file fallback path (no `sun.misc.Unsafe`), where a
     * [legacyOverride] [FileKeyVault] is supplied instead.
     */
    dataStore: DataStore<Preferences>? = null,
    /**
     * App-isolation namespace applied to the OS-vault **destination** only
     * (Keychain service / DPAPI prefix / Secret Service attribute) so apps
     * sharing the per-user store don't collide. Blank = no namespace. The legacy
     * [DataStoreKeyVault] is intentionally NOT namespaced — its `ksafe_key_`
     * layout is the frozen migration source.
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
     * Test seam: candidate OS vault for [pick] to self-test, replacing real
     * `os.name` detection. Unlike [forced], selection still runs through [pick]
     * (and [selfTest]), so tests can drive both the self-test-pass and the
     * data-loss-critical self-test-fail paths without a real keyring.
     */
    private val osCandidateForTest: JvmKeyVault? = null,
    /**
     * Test seam: stands in for the lazily-built legacy-namespace twin (see
     * [legacyProbes]) so namespace-upgrade recovery can be tested without a real
     * OS secret store.
     */
    private val legacyNamespaceCandidateForTest: JvmKeyVault? = null,
    /**
     * Test seam: the namespace [legacyNamespaceCandidateForTest] stands for.
     * `null` models a genuine derived legacy namespace (safe to delete after a
     * verified migration); [DEFAULT_JVM_NAMESPACE] models the stable-default
     * `"shared"` source, which must NEVER be deleted — a co-existing no-namespace
     * instance may own that key, and deleting it would orphan its ciphertext.
     */
    private val legacyNamespaceNameForTest: String? = null,
    /**
     * Test seam: multiple legacy-namespace twins, each paired with the namespace
     * it stands for, in probe order — models an explicit `appNamespace` probing
     * BOTH `"shared"` and the launcher-derived namespace. Takes precedence over
     * the single-candidate seams.
     */
    private val legacyNamespaceCandidatesForTest: List<Pair<JvmKeyVault, String?>>? = null,
) {
    /** Retained for [legacyProbes]: the Windows DPAPI twin needs the same DataStore. */
    private val dataStoreForTwin: DataStore<Preferences>? = dataStore

    /**
     * True when a test injected the active vault or OS candidate. Guards
     * [legacyProbes] from lazily building a REAL OS vault (probing the developer's
     * actual keyring) in tests that only stubbed the primary path.
     */
    private val usingTestSeams: Boolean = forced != null || osCandidateForTest != null
    /** Legacy / software store — migration source and last-resort fallback. */
    val legacy: JvmKeyVault = legacyOverride ?: DataStoreKeyVault(
        requireNotNull(dataStore) {
            "JvmKeyVaultProvider requires a dataStore unless legacyOverride is provided"
        }
    )

    /**
     * Set when the OS vault [picked] at construction later fails at *runtime* —
     * typically a jlink-trimmed JRE missing `jdk.unsupported`, so JNA's first call
     * throws `NoClassDefFoundError: sun/misc/Unsafe`. [degradeToLegacy] flips this,
     * after which [active] returns [legacy] for the engine's life. Unlike
     * [osVaultSelfTestFailed] the OS vault is dead *in-process*, so there is no
     * reachable OS key to overwrite and persisting to legacy is safe.
     */
    private val degraded = AtomicBoolean(false)

    /**
     * Set when an OS vault was constructible for this platform but failed its
     * construction-time [selfTest] — a locked Keychain, a login keyring not yet on
     * D-Bus, etc. Distinct from "no OS store exists here": the real keys almost
     * certainly live in the OS store and it'll be reachable on a healthy launch, so
     * treating the software store as healthy would destroy data two ways:
     *  - a null lookup is ambiguous, so reads must report "unavailable" not "absent"
     *    ([hasDegraded]), else the orphan sweep deletes recoverable OS-only ciphertext;
     *  - key creation must not mint into the legacy migration source
     *    ([osVaultUnavailable]) — the next healthy launch's legacy-first migration
     *    would trust that junk key and overwrite the real OS key.
     */
    private val osVaultSelfTestFailed = AtomicBoolean(false)

    /**
     * Set when the explicit software opt-out (`-Dksafe.jvm.keyVault=software`)
     * selected the legacy store. Like [osVaultSelfTestFailed] a null lookup is
     * ambiguous (a previously OS-backed store still holds OS-only ciphertext), so
     * reads report "unavailable" (preserve) not "absent"; unlike it, key creation
     * is allowed — opting out deliberately mints into the software store.
     *
     * Since we can't tell whether an opt-out store was ever OS-backed without
     * probing the vault the user opted out of, we preserve ALL of them. For a
     * genuinely software-only store this only forgoes orphan-ciphertext reclamation
     * (harmless clutter), which is the right bias for a security library.
     */
    private val softwareOptOut = AtomicBoolean(false)

    /**
     * Picked at construction. Declared *after* [degraded] / [osVaultSelfTestFailed]
     * because [pick] writes the latter on a self-test failure — ordering it earlier
     * would touch a not-yet-constructed flag and NPE.
     */
    private val picked: JvmKeyVault =
        forced ?: if (dataStore != null) pick(dataStore) else legacy

    /** The vault the engine should use for new keys. */
    val active: JvmKeyVault
        get() = if (degraded.get()) legacy else picked

    /**
     * True when the OS vault is expected to exist but is currently unreachable —
     * a runtime degrade ([degradeToLegacy]), a failed construction-time [selfTest]
     * ([osVaultSelfTestFailed]), or the software opt-out. A null lookup is then
     * ambiguous, so callers report "vault unavailable" not "key absent", keeping the
     * orphan sweep from deleting recoverable ciphertext.
     */
    val hasDegraded: Boolean
        get() = degraded.get() || osVaultSelfTestFailed.get() || softwareOptOut.get()

    /**
     * True when an OS vault exists but was unavailable at construction (see
     * [osVaultSelfTestFailed]). Callers must NOT mint new keys into the legacy
     * migration source while this holds — the next healthy launch's legacy-first
     * migration would overwrite the real OS key. Distinct from [hasDegraded]: the
     * runtime degrade path (OS vault dead in-process) *may* persist to legacy.
     */
    val osVaultUnavailable: Boolean
        get() = osVaultSelfTestFailed.get()

    /**
     * Flips the provider into degraded mode after a runtime JNA failure on [picked],
     * so [active] returns [legacy] thereafter. Emits a one-time warning naming the
     * cause (usually a missing `jdk.unsupported`). Called by JvmSoftwareEncryption
     * when a `LinkageError` / `ExceptionInInitializerError` escapes a get/put/delete
     * on the active vault.
     */
    internal fun degradeToLegacy(cause: Throwable) {
        if (degraded.compareAndSet(false, true)) {
            warnRuntimeDegrade(picked.name, cause)
        }
    }

    private fun pick(dataStore: DataStore<Preferences>): JvmKeyVault {
        // Explicit opt-out: force the legacy software store, no warning. The system
        // property beats the env var.
        val override = System.getProperty(PROP_KEY_VAULT)
            ?: System.getenv(ENV_KEY_VAULT)
        if (override != null && override.lowercase() in OPT_OUT_VALUES) {
            // Preserve, don't delete: a store that used the OS vault before the opt-out
            // still holds OS-only ciphertext, so flag it (a missing legacy key then reads
            // as "unavailable", not "absent"). New keys still mint into the software store
            // — the point of the opt-out.
            softwareOptOut.set(true)
            return legacy
        }

        val os = System.getProperty("os.name").orEmpty().lowercase()
        // A construction failure yields null: the OS vault never came up in-process, so
        // there is no reachable OS key to overwrite and the software store is a safe home.
        val candidate: JvmKeyVault? = osCandidateForTest ?: buildOsVault(os, appNamespace, dataStore)

        if (candidate != null) {
            if (selfTest(candidate)) return candidate
            // OS vault exists but self-test failed: present-but-unreachable (locked
            // Keychain, keyring not yet unlocked, headless launch). Flag it rather than
            // trusting the software store — otherwise the orphan sweep deletes OS-only
            // ciphertext and junk keys minted here overwrite the real OS key next launch.
            osVaultSelfTestFailed.set(true)
            warnOsVaultUnavailableOnce(os)
            return legacy
        }

        // No OS vault for this platform — the software store is the legitimate home.
        warnFallbackOnce(os)
        return legacy
    }

    /** OS-detected vault construction, shared by [pick] and [legacyProbes]. */
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
     * source (see [recoverFromLegacyNamespace]), paired with the namespace it lives
     * under. Feeds from [legacyFallbackNamespaces] — the launcher-derived namespace
     * and/or the stable default `"shared"`. Without this, pre-upgrade keys become
     * invisible, every decrypt fails, and the orphan sweep deletes the ciphertext.
     *
     * The paired namespace gates destructive cleanup: a derived legacy namespace has
     * no live owner and may be deleted after a verified migration, but
     * [DEFAULT_JVM_NAMESPACE] must NEVER be deleted — a co-existing no-namespace
     * instance may own that key, and deleting it would orphan its ciphertext.
     *
     * Built lazily and only when it can matter: production wiring, an OS-backed pick,
     * and a fallback namespace that differs from the active one.
     */
    private val legacyProbes: List<Pair<JvmKeyVault, String?>> by lazy {
        legacyNamespaceCandidatesForTest?.let { return@lazy it }
        legacyNamespaceCandidateForTest?.let { return@lazy listOf(it to legacyNamespaceNameForTest) }
        if (usingTestSeams) return@lazy emptyList()
        if (!picked.isOsBacked) return@lazy emptyList()
        // Probe every namespace that could hold pre-upgrade keys, in order: the
        // launcher-derived namespace and the stable default "shared", minus whichever
        // equals the active namespace.
        val os = System.getProperty("os.name").orEmpty().lowercase()
        legacyFallbackNamespaces(appNamespace, legacyDerivedJvmNamespace()).mapNotNull { ns ->
            buildOsVault(os, ns, dataStoreForTwin)?.let { it to ns }
        }
    }

    /**
     * Read-fallback for a key that misses under the current namespace: probes the
     * legacy-namespace twin and, on a hit, migrates it to the active vault — write,
     * read-back-verify, then delete the old entry ONLY when the source is a genuine
     * derived legacy namespace (never for the stable default `"shared"`). On any
     * hiccup the bytes are still returned so this session decrypts and the migration
     * retries later; the old entry is never deleted unverified.
     *
     * Reached only after a successful-but-null [active] lookup, so the vault is
     * healthy here — no degraded/self-test gating needed.
     */
    internal fun recoverFromLegacyNamespace(alias: String): ByteArray? {
        for ((source, sourceNamespace) in legacyProbes) {
            val bytes = try {
                source.get(alias)
            } catch (e: LinkageError) {
                throw e
            } catch (e: Throwable) {
                // OS vaults THROW "vault unavailable" (never null) when unreachable, so a
                // transient outage isn't misread as a miss. Propagate it — the caller then
                // reports "unavailable" (non-deletable to the orphan sweep) instead of
                // collapsing to null and letting the sweep delete recoverable ciphertext.
                // All probes read the same store, so one outage means all are unreachable.
                if (e.message?.contains("vault unavailable", ignoreCase = true) == true) throw e
                null
            } ?: continue // this namespace has no such key — try the next candidate
            try {
                picked.put(alias, bytes)
                // Reclaim the old entry only for a genuine derived legacy namespace (no
                // live owner). NEVER delete from the stable default "shared": a co-existing
                // no-namespace instance may still use that key, and a move would orphan its
                // ciphertext. Leaving it is harmless — the key now lives under the active
                // namespace, so this fallback won't re-run.
                if (sourceNamespace != DEFAULT_JVM_NAMESPACE &&
                    picked.get(alias)?.contentEquals(bytes) == true
                ) {
                    runCatching { source.delete(alias) }
                }
            } catch (e: LinkageError) {
                throw e
            } catch (_: Throwable) {
                // Keep serving the recovered bytes; the un-deleted entry retries the migration.
            }
            return bytes
        }
        return null
    }

    /**
     * Best-effort delete from the legacy-namespace twin, so a delete-then-recreate of
     * the same alias can't resurrect the pre-upgrade key via
     * [recoverFromLegacyNamespace]. Skipped for the stable default `"shared"`: a
     * co-existing no-namespace instance may own that key, so a namespaced instance
     * must never scrub it.
     */
    internal fun deleteFromLegacyNamespace(alias: String) {
        for ((twin, twinNamespace) in legacyProbes) {
            // Never scrub the stable default "shared" — a co-existing no-namespace instance
            // may own that key. Genuine derived legacy namespaces are scrubbed.
            if (twinNamespace == DEFAULT_JVM_NAMESPACE) continue
            runCatching { twin.delete(alias) }
        }
    }

    /**
     * Round-trips a canary to confirm the native store works. The alias must be
     * unique per attempt: the OS stores are shared across every process/instance on
     * the machine, so a FIXED alias lets two concurrent self-tests interleave (A.put,
     * B.put, A.get, A.delete, B.get → null) and flip a healthy engine into fail-closed.
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
                // Deliberately no "writes are not lost" promise: a LinkageError here means a
                // missing jdk.unsupported / sun.misc.Unsafe, which DataStore's protobuf ALSO
                // needs, so DataStore crashes independently. The fallback keeps key custody;
                // it can't rescue DataStore. The module is required, not optional.
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
 * The stable default OS-vault namespace. Never derived from the launcher, so it
 * cannot silently move between runs/releases — a moving default would leave the
 * un-namespaced data file behind, hide every key, and let the orphan sweep delete
 * the user's data on upgrade.
 */
internal const val DEFAULT_JVM_NAMESPACE = "shared"

/**
 * The OS-vault namespaces to probe, in order, as migration sources for a key that misses
 * under [currentNamespace]: the launcher-**derived** namespace [derivedNamespace] and the
 * stable default [DEFAULT_JVM_NAMESPACE], minus whichever equals [currentNamespace]. Empty
 * when neither differs.
 *  - [currentNamespace] is the default `"shared"`: probe just [derivedNamespace].
 *  - [currentNamespace] is an explicit `appNamespace`: probe `[derived, "shared"]`, since an
 *    app that ran un-namespaced holds keys under `"shared"` while a stable-launcher app that
 *    later set a namespace holds them under the derived one — either is possible.
 */
internal fun legacyFallbackNamespaces(currentNamespace: String, derivedNamespace: String?): List<String> =
    listOfNotNull(derivedNamespace, DEFAULT_JVM_NAMESPACE)
        .filter { it != currentNamespace }
        .distinct()

private fun String?.cleanNamespaceToken(): String? =
    this?.trim()?.takeIf { it.isNotEmpty() }
        ?.replace(Regex("[^A-Za-z0-9._-]"), "_")
        ?.take(120)
        ?.takeIf { it.isNotEmpty() }

internal fun resolveJvmAppNamespace(override: String?): String {
    override.cleanNamespaceToken()?.let { return it }
    System.getProperty("ksafe.appNamespace").cleanNamespaceToken()?.let { return it }
    System.getenv("KSAFE_APP_NAMESPACE").cleanNamespaceToken()?.let { return it }

    // Deliberately NO `sun.java.command` derivation — it changes with the launcher and
    // would silently orphan data on upgrade. Keys written under an old derived namespace
    // are recovered on read by [JvmKeyVaultProvider.recoverFromLegacyNamespace].
    return DEFAULT_JVM_NAMESPACE
}

/**
 * Reproduces — byte for byte — the legacy default-namespace derivation
 * (`sun.java.command` first token; jar path → bare jar name; same sanitization),
 * so [JvmKeyVaultProvider.recoverFromLegacyNamespace] can probe where an older
 * release stored a stable-launcher app's keys. Null when no launcher token exists
 * or the derivation lands on [DEFAULT_JVM_NAMESPACE] (nothing distinct to probe).
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
