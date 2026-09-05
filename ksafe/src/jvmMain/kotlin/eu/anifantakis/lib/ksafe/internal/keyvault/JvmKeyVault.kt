package eu.anifantakis.lib.ksafe.internal.keyvault

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import eu.anifantakis.lib.ksafe.decodeBase64
import eu.anifantakis.lib.ksafe.encodeBase64
import eu.anifantakis.lib.ksafe.internal.KSAFE_LEGACY_KEY_RECORD_PREFIX
import eu.anifantakis.lib.ksafe.internal.KSafeEngineMessage
import eu.anifantakis.lib.ksafe.internal.KSafeReservedKeys
import eu.anifantakis.lib.ksafe.internal.OneShotWarning
import eu.anifantakis.lib.ksafe.internal.canonicalNamespaceToken
import eu.anifantakis.lib.ksafe.internal.legacyLossyNamespaceToken
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicBoolean

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

    val name: String

    /** True when keys are protected by an OS secret store; false for the plaintext fallback. */
    val isOsBacked: Boolean

    fun get(alias: String): ByteArray?

    fun put(alias: String, keyBytes: ByteArray)

    fun delete(alias: String)

    /**
     * Wipes ALL key material this vault owns for the current store (orphans,
     * `getOrCreateSecret` slots the per-alias deletes miss). Default NO-OP: an OS-backed
     * vault is a shared global store and must never be wiped wholesale, and the DataStore
     * software vault lives inside the store `storage.clear()` already emptied. Only the
     * standalone [FileKeyVault] overrides this. Invoked on the write consumer via
     * [KSafeEncryption.onStoreCleared], so it never races a concurrent write.
     */
    fun clearAll() { }
}

/**
 * Minimal string key/value store over DataStore Preferences. [runBlocking] is safe
 * here: key access is rare (cached after first read), never on a hot path.
 */
internal class DataStorePrefStore(
    private val dataStore: DataStore<Preferences>,
    private val prefix: String,
) {
    /** The store key one alias occupies; one producer, so a written key stays readable and deletable. */
    private fun prefKey(alias: String) = stringPreferencesKey("$prefix$alias")

    fun getString(alias: String): String? =
        runBlocking { dataStore.data.first() }[prefKey(alias)]

    fun putString(alias: String, value: String) {
        val pref = prefKey(alias)
        runBlocking { dataStore.edit { it[pref] = value } }
    }

    fun remove(alias: String) {
        val pref = prefKey(alias)
        runBlocking { dataStore.edit { it.remove(pref) } }
    }

    fun listAliases(): List<String> =
        runBlocking { dataStore.data.first() }.asMap().keys
            .asSequence()
            .map { it.name }
            .filter { it.startsWith(prefix) }
            .map { it.removePrefix(prefix) }
            .toList()
}

/**
 * Legacy / fallback vault: raw AES key Base64-encoded in DataStore under the historical
 * `ksafe_key_` prefix — the frozen KSafe ≤ 2.0 on-disk format, so it doubles as the
 * migration source. No protection beyond OS file permissions; selected only when no OS
 * store is available.
 */
internal class DataStoreKeyVault(
    dataStore: DataStore<Preferences>,
) : JvmKeyVault {

    private val store = DataStorePrefStore(dataStore, KEY_PREFIX)

    override val name: String = "DataStore (software, plaintext — no OS protection)"
    override val isOsBacked: Boolean = false

    override fun get(alias: String): ByteArray? =
        store.getString(alias)?.let { decodeBase64(it) }

    override fun put(alias: String, keyBytes: ByteArray) {
        store.putString(alias, encodeBase64(keyBytes))
    }

    override fun delete(alias: String) = store.remove(alias)

    fun legacyAliases(): List<String> = store.listAliases()

    companion object {
        const val KEY_PREFIX = KSAFE_LEGACY_KEY_RECORD_PREFIX
    }
}

/**
 * Resolves and holds the active [JvmKeyVault] plus the legacy [DataStoreKeyVault]
 * (always available for migration / fallback). Each OS vault must pass a self-test
 * (store → read-back → delete of a canary) before being accepted, so a present-but-broken
 * keyring degrades to the fallback rather than failing every encrypt/decrypt.
 */
internal class JvmKeyVaultProvider(
    /**
     * DataStore backing the legacy [DataStoreKeyVault] and OS-vault detection. Null on the
     * JSON-file fallback path (no `sun.misc.Unsafe`), where [legacyOverride] is supplied.
     */
    dataStore: DataStore<Preferences>? = null,
    /**
     * App-isolation namespace applied to the OS-vault **destination** only (Keychain service
     * / DPAPI prefix / Secret Service attribute) so apps sharing the per-user store don't
     * collide. Blank = no namespace. The legacy [DataStoreKeyVault] is intentionally NOT
     * namespaced — its `ksafe_key_` layout is the frozen migration source.
     */
    private val appNamespace: String = "",
    /**
     * The vault namespace an older release resolved for this same configuration when it
     * differs from [appNamespace] (see [legacyResolvedJvmAppNamespace]). Probed first as a
     * read-only migration source; never reclaim-deleted — a not-yet-upgraded sibling
     * instance may still own keys under it.
     */
    private val legacyAppNamespace: String? = null,
    /**
     * The namespaces the property/env tiers would have resolved, shadowed by an explicit
     * `KSafeConfig.appNamespace` (see [shadowedJvmAppNamespaces]). Probe-only.
     */
    private val shadowedAppNamespaces: List<String> = emptyList(),
    /** Test seam: force a specific vault and skip OS detection. */
    forced: JvmKeyVault? = null,
    /** Replaces the default software vault (JSON-file fallback supplies a [FileKeyVault]). */
    legacyOverride: JvmKeyVault? = null,
    /**
     * Test seam: candidate OS vault for [pick] to self-test, replacing `os.name` detection.
     * Unlike [forced], selection still runs through [pick]/[selfTest], so tests can drive
     * both the self-test-pass and the data-loss-critical self-test-fail paths.
     */
    private val osCandidateForTest: JvmKeyVault? = null,
    /** Test seam: stands in for the lazily-built legacy-namespace twin (see [legacyProbes]). */
    private val legacyNamespaceCandidateForTest: JvmKeyVault? = null,
    /**
     * Test seam: the namespace [legacyNamespaceCandidateForTest] stands for. `null` = a
     * derived legacy namespace (safe to delete after verified migration);
     * [DEFAULT_JVM_NAMESPACE] = the stable `"shared"` source, which must NEVER be deleted —
     * a co-existing no-namespace instance may own that key.
     */
    private val legacyNamespaceNameForTest: String? = null,
    /**
     * Test seam: multiple legacy-namespace twins paired with the namespace each stands for,
     * in probe order. Takes precedence over the single-candidate seams.
     */
    private val legacyNamespaceCandidatesForTest: List<Pair<JvmKeyVault, String?>>? = null,
    /** Test seam: builds the twin for a computed probe namespace, in place of OS detection. */
    private val legacyNamespaceVaultFactoryForTest: ((String) -> JvmKeyVault?)? = null,
) {
    private val dataStoreForTwin: DataStore<Preferences>? = dataStore

    /**
     * True when a test injected the active vault or OS candidate. Guards [legacyProbes] from
     * lazily building a REAL OS vault (probing the developer's keyring) in tests.
     */
    private val usingTestSeams: Boolean = forced != null || osCandidateForTest != null
    val legacy: JvmKeyVault = legacyOverride ?: DataStoreKeyVault(
        requireNotNull(dataStore) {
            "JvmKeyVaultProvider requires a dataStore unless legacyOverride is provided"
        }
    )

    /**
     * Set when the OS vault's native bridge dies in-process — typically a jlink-trimmed JRE
     * missing `jdk.unsupported`, so JNA throws `NoClassDefFoundError: sun/misc/Unsafe` — either
     * on a later call or already inside the construction [selfTest] (Windows resolves JNA
     * lazily, so the link failure lands there). [degradeToLegacy] flips this; [active] then
     * returns [legacy]. Unlike [osVaultSelfTestFailed] the OS vault is dead *in-process*, so
     * there is no reachable OS key to overwrite and persisting to legacy is safe.
     */
    private val degraded = AtomicBoolean(false)

    /**
     * Set when an OS vault was constructible but failed its construction-time [selfTest] (a
     * locked Keychain, a login keyring not yet on D-Bus). The real keys almost certainly live
     * in the OS store and it'll be reachable on a healthy launch, so treating the software
     * store as healthy would destroy data two ways:
     *  - a null lookup is ambiguous, so reads must report "unavailable" not "absent"
     *    ([hasDegraded]), else the orphan sweep deletes recoverable OS-only ciphertext;
     *  - key creation must not mint into the legacy migration source ([osVaultUnavailable]) —
     *    the next healthy launch's legacy-first migration would overwrite the real OS key.
     */
    private val osVaultSelfTestFailed = AtomicBoolean(false)

    /**
     * Set when the explicit software opt-out (`-Dksafe.jvm.keyVault=software`) selected the
     * legacy store. Like [osVaultSelfTestFailed] a null lookup is ambiguous (a previously
     * OS-backed store still holds OS-only ciphertext), so reads report "unavailable" not
     * "absent"; unlike it, key creation is allowed. We can't tell whether an opt-out store was
     * ever OS-backed, so we preserve ALL of them — the safe bias for a security library.
     */
    private val softwareOptOut = AtomicBoolean(false)

    /**
     * Declared *after* [degraded] / [osVaultSelfTestFailed] because [pick] writes either on
     * a self-test failure — ordering it earlier would touch a not-yet-constructed flag and NPE.
     */
    private val picked: JvmKeyVault =
        forced ?: if (dataStore != null) pick(dataStore) else legacy

    val active: JvmKeyVault
        get() = if (degraded.get()) legacy else picked

    /**
     * True when the OS vault is expected to exist but is currently unreachable (runtime
     * degrade, failed construction-time [selfTest], or software opt-out). A null lookup is then
     * ambiguous, so callers report "vault unavailable" not "key absent", keeping the orphan
     * sweep from deleting recoverable ciphertext.
     */
    val hasDegraded: Boolean
        get() = degraded.get() || osVaultSelfTestFailed.get() || softwareOptOut.get()

    /**
     * True when an OS vault exists but was unavailable at construction. Callers must NOT mint
     * new keys into the legacy migration source while this holds — the next healthy launch's
     * legacy-first migration would overwrite the real OS key. Distinct from [hasDegraded]: the
     * runtime degrade path *may* persist to legacy.
     */
    val osVaultUnavailable: Boolean
        get() = osVaultSelfTestFailed.get()

    /**
     * Flips the provider into degraded mode after a runtime JNA failure on [picked], so
     * [active] returns [legacy] thereafter. Called when a `LinkageError` /
     * `ExceptionInInitializerError` escapes a get/put/delete on the active vault, and by [pick]
     * when the same failure surfaces in the construction self-test.
     */
    internal fun degradeToLegacy(cause: Throwable) = degradeToLegacy(cause, picked.name)

    /** Name passed in because [pick] degrades before [picked] is assigned. */
    private fun degradeToLegacy(cause: Throwable, vaultName: String) {
        if (degraded.compareAndSet(false, true)) {
            warnRuntimeDegrade(vaultName, cause)
        }
    }

    private fun pick(dataStore: DataStore<Preferences>): JvmKeyVault {
        if (jvmKeyVaultOptedOut()) {
            // Preserve, don't delete: a store OS-backed before the opt-out still holds OS-only
            // ciphertext, so flag it (a missing legacy key then reads "unavailable", not
            // "absent"). New keys still mint into the software store — the point of the opt-out.
            softwareOptOut.set(true)
            return legacy
        }

        val os = System.getProperty("os.name").orEmpty().lowercase()
        // Construction failure yields null: the OS vault never came up in-process, so there is
        // no reachable OS key to overwrite and the software store is a safe home.
        val candidate: JvmKeyVault? = osCandidateForTest ?: buildOsVault(os, appNamespace, dataStore)

        if (candidate != null) {
            when (val result = selfTest(candidate)) {
                is SelfTest.Passed -> return candidate
                // Dead in-process like a runtime LinkageError: no reachable OS key to overwrite.
                is SelfTest.Unlinkable -> {
                    degradeToLegacy(result.cause, candidate.name)
                    return legacy
                }
                // OS vault present but unreachable (locked Keychain, keyring not unlocked,
                // headless). Flag it rather than trust the software store — otherwise the orphan
                // sweep deletes OS-only ciphertext and junk keys minted here overwrite the real
                // OS key next launch.
                is SelfTest.Failed -> {
                    osVaultSelfTestFailed.set(true)
                    warnOsVaultUnavailableOnce(os)
                    return legacy
                }
            }
        }

        warnFallbackOnce(os)
        return legacy
    }

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
     * The legacy-namespace read-fallback: the OS-vault twin used as a migration source,
     * paired with the namespace it lives under (from [legacyFallbackNamespaces]). Without
     * this, pre-upgrade keys become invisible, every decrypt fails, and the orphan sweep
     * deletes the ciphertext.
     *
     * The paired namespace gates destructive cleanup ([mayReclaimFrom]): a derived legacy
     * namespace may be deleted after a verified migration, but [DEFAULT_JVM_NAMESPACE] and
     * the pre-canonicalization [legacyAppNamespace] must NEVER be — a co-existing instance
     * may own that key.
     *
     * Built lazily and only when it can matter: production wiring, an OS-backed pick, and a
     * fallback namespace that differs from the active one.
     */
    private val legacyProbes: List<Pair<JvmKeyVault, String?>> by lazy {
        legacyNamespaceCandidatesForTest?.let { return@lazy it }
        legacyNamespaceCandidateForTest?.let { return@lazy listOf(it to legacyNamespaceNameForTest) }
        val factory = legacyNamespaceVaultFactoryForTest
        if (factory == null && (usingTestSeams || !picked.isOsBacked)) return@lazy emptyList()
        val os = System.getProperty("os.name").orEmpty().lowercase()
        legacyFallbackNamespaces(
            appNamespace,
            legacyDerivedJvmNamespace(),
            legacyAppNamespace,
            shadowedAppNamespaces,
        ).mapNotNull { ns ->
            // Tagged with the shared default: the one tag mayReclaimFrom always refuses.
            val tag = if (ns in shadowedAppNamespaces) DEFAULT_JVM_NAMESPACE else ns
            (if (factory != null) factory(ns) else buildOsVault(os, ns, dataStoreForTwin))?.let { it to tag }
        }
    }

    /**
     * False for namespaces that may still have a live owner — the shared default (a
     * co-existing no-namespace instance) and the pre-canonicalization [legacyAppNamespace]
     * (a not-yet-upgraded instance of this same app) — so probe-recovery copies from them
     * but never reclaim-deletes. The property/env namespaces an override shadows are tagged
     * as the shared default by [legacyProbes], so the same refusal covers them. `null` stands
     * for a derived legacy namespace (test seams), which has no live owner and stays
     * reclaimable.
     */
    private fun mayReclaimFrom(sourceNamespace: String?): Boolean =
        sourceNamespace != DEFAULT_JVM_NAMESPACE &&
            (sourceNamespace == null || sourceNamespace != legacyAppNamespace)

    /**
     * Read-fallback for a key that misses under the current namespace: probes the legacy twin
     * and, on a hit, migrates it to the active vault — write, read-back-verify, then delete
     * the old entry ONLY for a genuine derived legacy namespace (never `"shared"`). On any
     * hiccup the bytes are still returned so this session decrypts and the migration retries;
     * the old entry is never deleted unverified.
     *
     * Reached only after a successful-but-null [active] lookup, so the vault is healthy here.
     */
    internal fun recoverFromLegacyNamespace(alias: String): ByteArray? {
        if (legacyProbes.isEmpty()) return null
        // A deletion tombstone (written by [deleteFromLegacyNamespace] for sources that can't
        // be reclaim-deleted) records that THIS namespace deliberately deleted the key.
        // Re-copying it from the retained shared source would resurrect erased key material —
        // old ciphertext backups would decrypt again and new writes would reuse pre-delete
        // key bytes — defeating the cryptographic-erasure contract of delete()/clearAll().
        if (runCatching { picked.get(deletionTombstoneAlias(alias)) }.getOrNull() != null) return null
        for ((source, sourceNamespace) in legacyProbes) {
            val bytes = try {
                source.get(alias)
            } catch (e: LinkageError) {
                throw e
            } catch (e: Throwable) {
                // OS vaults THROW "vault unavailable" (never null) when unreachable. Propagate
                // it so the caller reports "unavailable" (non-deletable to the orphan sweep)
                // instead of collapsing to null and letting the sweep delete recoverable
                // ciphertext. All probes read the same store, so one outage means all fail.
                if (e.message?.contains(KSafeEngineMessage.VAULT_UNAVAILABLE, ignoreCase = true) == true) throw e
                null
            } ?: continue
            try {
                picked.put(alias, bytes)
                // Reclaim the old entry only for a derived legacy namespace (no live owner).
                // NEVER delete from `"shared"` or the pre-canonicalization namespace: a
                // co-existing instance may still use that key, and a move would orphan its
                // ciphertext.
                if (mayReclaimFrom(sourceNamespace) &&
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
     * Best-effort delete from the legacy twin, so a delete-then-recreate of the same alias
     * can't resurrect the pre-upgrade key via [recoverFromLegacyNamespace]. Namespaces a
     * co-existing instance may still own (see [mayReclaimFrom]) are never deleted; when such
     * a source currently holds this alias, a persistent tombstone is written into the active
     * namespace instead, so a fresh engine can't re-copy the deleted key from the retained
     * source (which would make old ciphertext backups decryptable again).
     */
    internal fun deleteFromLegacyNamespace(alias: String) {
        for ((twin, twinNamespace) in legacyProbes) {
            if (mayReclaimFrom(twinNamespace)) {
                runCatching { twin.delete(alias) }
            } else if (runCatching { twin.get(alias) }.getOrNull() != null) {
                runCatching { picked.put(deletionTombstoneAlias(alias), DELETION_TOMBSTONE) }
            }
        }
    }

    /** Alias of the persistent per-namespace deletion tombstone for [alias] in the active vault. */
    private fun deletionTombstoneAlias(alias: String) = "$alias.${KSafeReservedKeys.VAULT_TOMBSTONE}"

    /**
     * Round-trips a canary to confirm the native store works. The alias must be unique per
     * attempt: the OS stores are shared machine-wide, so a FIXED alias lets two concurrent
     * self-tests interleave (A.put, B.put, A.get, A.delete, B.get → null) and flip a healthy
     * engine into fail-closed.
     */
    private fun selfTest(vault: JvmKeyVault): SelfTest = try {
        val alias = "__ksafe_selftest__" + java.util.UUID.randomUUID()
        val canary = byteArrayOf(0x4B, 0x53, 0x61, 0x66, 0x65) // "KSafe"
        vault.put(alias, canary)
        val read = vault.get(alias)
        vault.delete(alias)
        if (read != null && read.contentEquals(canary)) SelfTest.Passed else SelfTest.Failed
    } catch (e: LinkageError) {
        SelfTest.Unlinkable(e)
    } catch (t: Throwable) {
        SelfTest.Failed
    }

    /**
     * [Unlinkable] stays apart from [Failed]: an unreachable vault still owns the real keys, an
     * unlinkable one is dead in-process and can own nothing this session.
     */
    private sealed interface SelfTest {
        object Passed : SelfTest
        object Failed : SelfTest
        class Unlinkable(val cause: LinkageError) : SelfTest
    }

    private companion object {
        val DELETION_TOMBSTONE = byteArrayOf(1)

        val fallbackWarning = OneShotWarning()
        val osUnavailableWarning = OneShotWarning()
        val runtimeDegradeWarning = OneShotWarning()

        fun warnFallbackOnce(os: String) {
            fallbackWarning.warn {
                "KSafe SECURITY WARNING: no OS secret store is available on " +
                    "this JVM host (os=\"$os\"). Encryption keys will be stored " +
                    "Base64-encoded in the DataStore file, protected only by " +
                    "OS file permissions and recoverable by anyone who can read " +
                    "that file as this user. Install/enable a keyring " +
                    "(Linux: gnome-keyring/ksecretservice) or run on a host " +
                    "with DPAPI (Windows) / Keychain (macOS) for OS-backed " +
                    "key protection."
            }
        }

        fun warnOsVaultUnavailableOnce(os: String) {
            osUnavailableWarning.warn {
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
            }
        }

        fun warnRuntimeDegrade(vaultName: String, cause: Throwable) {
            runtimeDegradeWarning.warn {
                val typed = "${cause::class.java.simpleName}: ${cause.message}"
                "KSafe SECURITY WARNING: the OS keyvault ($vaultName) failed at " +
                    "runtime ($typed); key custody has degraded to the software " +
                    "vault. This usually means the JNA native bridge could not load: a " +
                    "jlink-trimmed runtime missing `jdk.unsupported` (sun.misc.Unsafe), a " +
                    "stripped or AV-blocked `jna-platform`/`jnidispatch`, or a temp dir JNA " +
                    "cannot extract into. If it is the missing module, note that the same " +
                    "module is REQUIRED by Jetpack DataStore (KSafe's storage " +
                    "backend) — without it DataStore itself crashes and data will " +
                    "NOT persist; KSafe cannot work around that. Add " +
                    "`modules(\"jdk.unsupported\")` to your " +
                    "`compose.desktop.application.nativeDistributions` block " +
                    "(or run `./gradlew :<app>:suggestRuntimeModules`)."
            }
        }
    }
}

/**
 * The stable default OS-vault namespace. Never derived from the launcher, so it cannot
 * silently move between runs/releases — a moving default would leave the un-namespaced data
 * file behind, hide every key, and let the orphan sweep delete the user's data on upgrade.
 */
internal const val DEFAULT_JVM_NAMESPACE = "shared"

/**
 * The OS-vault namespaces to probe, in order, as migration sources for a key that misses
 * under [currentNamespace]: the pre-canonicalization [legacyConfigNamespace] first (it was
 * this app's ACTIVE namespace right up to the upgrade, so it holds the newest keys — letting
 * `"shared"` hit first could migrate a stale pre-namespace key over the live one), then the
 * launcher-**derived** [derivedNamespace] and the stable default [DEFAULT_JVM_NAMESPACE],
 * minus whichever equals [currentNamespace]. An explicit `appNamespace` probes
 * `[derived, "shared"]` since an app that ran un-namespaced holds keys under `"shared"`
 * while a stable-launcher app that later set one holds them under the derived.
 *
 * [shadowedNamespaces] sit between the two: they were the active namespace until the
 * override, so they outrank the launcher-derived guess.
 */
internal fun legacyFallbackNamespaces(
    currentNamespace: String,
    derivedNamespace: String?,
    legacyConfigNamespace: String? = null,
    shadowedNamespaces: List<String> = emptyList(),
): List<String> =
    (listOfNotNull(legacyConfigNamespace) + shadowedNamespaces + listOfNotNull(derivedNamespace, DEFAULT_JVM_NAMESPACE))
        .filter { it != currentNamespace }
        .distinct()

/**
 * The single canonical `appNamespace` normalization, shared by the data-directory token
 * (`buildJvmKSafe`) and the OS-vault namespace ([resolveJvmAppNamespace]). One shared rule,
 * because divergent normalizations split one configured identity in two: different data dirs
 * sharing one vault namespace (a sibling's `clearAll()` destroys keys this store still
 * needs) or one shared data dir with different vault namespaces (mutually undecryptable
 * writes). Delegates to [canonicalNamespaceToken]: whitespace padding and leading dots are
 * equivalences (`" foo "`/`".foo"`/`"foo"` agree; never `"."`/`".."` → no path traversal), a
 * token that cancels out entirely means "no namespace" on both sides, and a lossy mapping
 * (substituted chars / truncation) carries a collision digest so distinct configured ids
 * can't share one identity.
 */
internal fun canonicalJvmNamespaceToken(raw: String?): String? = canonicalNamespaceToken(raw)

/**
 * The FROZEN pre-3.0.0 normalization. [legacyDerivedJvmNamespace] and
 * [legacyResolvedJvmAppNamespace] must reproduce old on-disk identities byte-for-byte, so
 * this must never change — new callers use [canonicalJvmNamespaceToken].
 */
private fun String?.cleanNamespaceToken(): String? = legacyLossyNamespaceToken(this)

internal fun resolveJvmAppNamespace(override: String?): String {
    canonicalJvmNamespaceToken(override)?.let { return it }
    canonicalJvmNamespaceToken(System.getProperty("ksafe.appNamespace"))?.let { return it }
    canonicalJvmNamespaceToken(System.getenv("KSAFE_APP_NAMESPACE"))?.let { return it }

    // Deliberately NO `sun.java.command` derivation — it changes with the launcher and would
    // silently orphan data on upgrade. Keys under an old derived namespace are recovered on
    // read by [JvmKeyVaultProvider.recoverFromLegacyNamespace].
    return DEFAULT_JVM_NAMESPACE
}

/**
 * The vault namespace an OLDER release resolved for these same inputs, when it differs from
 * what [resolveJvmAppNamespace] now returns — the pre-canonical normalization kept leading
 * dots, so e.g. `".foo"` (now `"foo"`) or `"..."` (now no namespace) resolved differently.
 * Existing installs hold their keys under it, so [JvmKeyVaultProvider] probes it as a
 * read-only migration source — never reclaimed, since a not-yet-upgraded sibling instance
 * may still own keys there.
 */
internal fun legacyResolvedJvmAppNamespace(override: String?): String? {
    val legacy = override.cleanNamespaceToken()
        ?: System.getProperty("ksafe.appNamespace").cleanNamespaceToken()
        ?: System.getenv("KSAFE_APP_NAMESPACE").cleanNamespaceToken()
        ?: DEFAULT_JVM_NAMESPACE
    return legacy.takeIf { it != resolveJvmAppNamespace(override) }
}

/**
 * The namespaces the property (`-Dksafe.appNamespace`) and env (`KSAFE_APP_NAMESPACE`) tiers of
 * [resolveJvmAppNamespace] would have resolved, once [override] outranks them — property first,
 * each in both the canonical and the frozen pre-3.0.0 spelling. Probe-only, never reclaimed, and
 * only recoverable while the property/env is still set.
 */
internal fun shadowedJvmAppNamespaces(override: String?): List<String> {
    val current = canonicalJvmNamespaceToken(override) ?: return emptyList()
    return listOfNotNull(
        System.getProperty("ksafe.appNamespace"),
        System.getenv("KSAFE_APP_NAMESPACE"),
    ).flatMap { listOfNotNull(canonicalJvmNamespaceToken(it), it.cleanNamespaceToken()) }
        .filter { it != current }
        .distinct()
}

/**
 * Reproduces — byte for byte — the legacy default-namespace derivation (`sun.java.command`
 * first token; jar path → bare jar name; same sanitization), so
 * [JvmKeyVaultProvider.recoverFromLegacyNamespace] can probe where an older release stored a
 * stable-launcher app's keys. Null when no launcher token exists or it lands on
 * [DEFAULT_JVM_NAMESPACE].
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

/**
 * The JVM key-vault opt-out switch: `-Dksafe.jvm.keyVault=software` (or env `KSAFE_JVM_KEY_VAULT`).
 *
 * One declaration because two consumers act on it — the vault selection here and
 * `protectionInfo`'s `jvm_user_opted_out` note. A value taught to only one of them makes
 * `protectionInfo` report the wrong REASON custody is degraded.
 */
private const val PROP_KEY_VAULT = "ksafe.jvm.keyVault"
private const val ENV_KEY_VAULT = "KSAFE_JVM_KEY_VAULT"
private val OPT_OUT_VALUES = setOf("software", "datastore", "off", "false", "none")

internal fun jvmKeyVaultOptedOut(): Boolean =
    (System.getProperty(PROP_KEY_VAULT) ?: System.getenv(ENV_KEY_VAULT))
        ?.lowercase() in OPT_OUT_VALUES
