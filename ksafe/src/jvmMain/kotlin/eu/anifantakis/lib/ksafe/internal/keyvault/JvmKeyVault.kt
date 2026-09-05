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

/** Where the raw AES key bytes live on the JVM: an OS secret store, or [DataStoreKeyVault]. */
internal interface JvmKeyVault {

    val name: String

    val isOsBacked: Boolean

    fun get(alias: String): ByteArray?

    fun put(alias: String, keyBytes: ByteArray)

    fun delete(alias: String)

    /** Wipes every key this vault owns. Default no-op: an OS-backed vault is shared machine-wide. */
    fun clearAll() { }
}

/** String store over DataStore Preferences. [runBlocking] is fine: key access is never on a hot path. */
internal class DataStorePrefStore(
    private val dataStore: DataStore<Preferences>,
    private val prefix: String,
) {
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

/** Fallback vault: the AES key Base64-encoded under the frozen `ksafe_key_` migration prefix. */
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

/** Holds the active [JvmKeyVault]. An OS vault must pass a self-test, so a broken keyring degrades. */
internal class JvmKeyVaultProvider(
    /** Backs the legacy vault and OS-vault detection; null on the JSON-file fallback path. */
    dataStore: DataStore<Preferences>? = null,
    /** Namespaces the OS-vault destination only; the legacy vault stays un-namespaced. */
    private val appNamespace: String = "",
    /** Read-only migration source, never deleted: a not-yet-upgraded sibling may still own its keys. */
    private val legacyAppNamespace: String? = null,
    /** Namespaces the property/env tiers would have resolved before an explicit override. Probe-only. */
    private val shadowedAppNamespaces: List<String> = emptyList(),
    /** Test seam: force a specific vault and skip OS detection. */
    forced: JvmKeyVault? = null,
    /** Replaces the default software vault (JSON-file fallback supplies a [FileKeyVault]). */
    legacyOverride: JvmKeyVault? = null,
    /** Test seam: candidate OS vault for [pick] to self-test, replacing `os.name` detection. */
    private val osCandidateForTest: JvmKeyVault? = null,
    /** Test seam: stands in for the lazily-built legacy-namespace twin (see [legacyProbes]). */
    private val legacyNamespaceCandidateForTest: JvmKeyVault? = null,
    /** Test seam: the namespace the twin stands for; [DEFAULT_JVM_NAMESPACE] must not be deleted. */
    private val legacyNamespaceNameForTest: String? = null,
    /** Test seam: legacy-namespace twins paired with their namespace, in probe order. */
    private val legacyNamespaceCandidatesForTest: List<Pair<JvmKeyVault, String?>>? = null,
    /** Test seam: builds the twin for a computed probe namespace, in place of OS detection. */
    private val legacyNamespaceVaultFactoryForTest: ((String) -> JvmKeyVault?)? = null,
) {
    private val dataStoreForTwin: DataStore<Preferences>? = dataStore

    /** Guards [legacyProbes] from building a real OS vault (the developer's keyring) in tests. */
    private val usingTestSeams: Boolean = forced != null || osCandidateForTest != null
    val legacy: JvmKeyVault = legacyOverride ?: DataStoreKeyVault(
        requireNotNull(dataStore) {
            "JvmKeyVaultProvider requires a dataStore unless legacyOverride is provided"
        }
    )

    /** OS bridge dead in-process: nothing reachable can be overwritten, so [legacy] is a safe home. */
    private val degraded = AtomicBoolean(false)

    /**
     * OS vault present but unreachable, so the real keys are probably in it: reads must report
     * "unavailable" not "absent", and no key may be minted into the legacy source.
     */
    private val osVaultSelfTestFailed = AtomicBoolean(false)

    /** Software opt-out: reads report "unavailable" (OS-only ciphertext may remain), minting is allowed. */
    private val softwareOptOut = AtomicBoolean(false)

    /** Must follow [degraded] / [osVaultSelfTestFailed]: [pick] writes them on a self-test failure. */
    private val picked: JvmKeyVault =
        forced ?: if (dataStore != null) pick(dataStore) else legacy

    val active: JvmKeyVault
        get() = if (degraded.get()) legacy else picked

    /** The OS vault should exist but is unreachable, so a null lookup means "unavailable", not "absent". */
    val hasDegraded: Boolean
        get() = degraded.get() || osVaultSelfTestFailed.get() || softwareOptOut.get()

    /** Unavailable since construction: a key minted into the legacy source is overwritten next launch. */
    val osVaultUnavailable: Boolean
        get() = osVaultSelfTestFailed.get()

    /** Flips into degraded mode after a runtime JNA failure, so [active] returns [legacy]. */
    internal fun degradeToLegacy(cause: Throwable) = degradeToLegacy(cause, picked.name)

    /** Name passed in because [pick] degrades before [picked] is assigned. */
    private fun degradeToLegacy(cause: Throwable, vaultName: String) {
        if (degraded.compareAndSet(false, true)) {
            warnRuntimeDegrade(vaultName, cause)
        }
    }

    private fun pick(dataStore: DataStore<Preferences>): JvmKeyVault {
        if (jvmKeyVaultOptedOut()) {
            // A store that was OS-backed before the opt-out still holds OS-only ciphertext, so a
            // missing legacy key must read "unavailable", not "absent".
            softwareOptOut.set(true)
            return legacy
        }

        val os = System.getProperty("os.name").orEmpty().lowercase()
        // Null on construction failure: the OS vault never came up, so nothing reachable can be
        // overwritten and the software store is a safe home.
        val candidate: JvmKeyVault? = osCandidateForTest ?: buildOsVault(os, appNamespace, dataStore)

        if (candidate != null) {
            when (val result = selfTest(candidate)) {
                is SelfTest.Passed -> return candidate
                // Dead in-process like a runtime LinkageError: no reachable OS key to overwrite.
                is SelfTest.Unlinkable -> {
                    degradeToLegacy(result.cause, candidate.name)
                    return legacy
                }
                // Present but unreachable: flagging beats trusting the software store, which would
                // let the sweep delete OS-only ciphertext and junk keys overwrite the real one.
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

    /** Migration-source twins paired with their namespace; the pairing gates deletion ([mayReclaimFrom]). */
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

    /** False where a live owner may remain: recovery copies from that namespace but never deletes. */
    private fun mayReclaimFrom(sourceNamespace: String?): Boolean =
        sourceNamespace != DEFAULT_JVM_NAMESPACE &&
            (sourceNamespace == null || sourceNamespace != legacyAppNamespace)

    /**
     * Migrates a legacy-namespace hit into the active vault: write, read-back-verify, then delete
     * only where reclaimable. The bytes are returned even when the migration fails.
     */
    internal fun recoverFromLegacyNamespace(alias: String): ByteArray? {
        if (legacyProbes.isEmpty()) return null
        // A tombstone records that this namespace deleted the key; re-copying it from a retained
        // shared source would resurrect erased key material.
        if (runCatching { picked.get(deletionTombstoneAlias(alias)) }.getOrNull() != null) return null
        for ((source, sourceNamespace) in legacyProbes) {
            val bytes = try {
                source.get(alias)
            } catch (e: LinkageError) {
                throw e
            } catch (e: Throwable) {
                // OS vaults throw "vault unavailable" instead of returning null; propagate so the
                // caller can't collapse to null and let the sweep delete recoverable ciphertext.
                if (e.message?.contains(KSafeEngineMessage.VAULT_UNAVAILABLE, ignoreCase = true) == true) throw e
                null
            } ?: continue
            try {
                picked.put(alias, bytes)
                // Never delete from a namespace a co-existing instance may still use: the move
                // would orphan its ciphertext.
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

    /** Deletes from the legacy twins; a source that may have a live owner gets a tombstone instead. */
    internal fun deleteFromLegacyNamespace(alias: String) {
        for ((twin, twinNamespace) in legacyProbes) {
            if (mayReclaimFrom(twinNamespace)) {
                runCatching { twin.delete(alias) }
            } else if (runCatching { twin.get(alias) }.getOrNull() != null) {
                runCatching { picked.put(deletionTombstoneAlias(alias), DELETION_TOMBSTONE) }
            }
        }
    }

    private fun deletionTombstoneAlias(alias: String) = "$alias.${KSafeReservedKeys.VAULT_TOMBSTONE}"

    /**
     * Round-trips a canary. The alias must be unique per attempt: the OS stores are machine-wide,
     * so a fixed one lets two concurrent self-tests interleave and flip a healthy engine closed.
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

    /** [Unlinkable] is not [Failed]: an unreachable vault still owns the real keys, a dead one owns none. */
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

/** Stable default OS-vault namespace: never launcher-derived, which would hide every key on upgrade. */
internal const val DEFAULT_JVM_NAMESPACE = "shared"

/**
 * Namespaces to probe, in order, as migration sources for a key missing under [currentNamespace]:
 * the pre-canonicalization one first (it holds the newest keys), then shadowed, derived, default.
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

/** One normalization for data dir and vault namespace: divergent rules would split one identity. */
internal fun canonicalJvmNamespaceToken(raw: String?): String? = canonicalNamespaceToken(raw)

/** Frozen legacy spelling: it must reproduce old on-disk identities byte for byte. */
private fun String?.cleanNamespaceToken(): String? = legacyLossyNamespaceToken(this)

internal fun resolveJvmAppNamespace(override: String?): String {
    canonicalJvmNamespaceToken(override)?.let { return it }
    canonicalJvmNamespaceToken(System.getProperty("ksafe.appNamespace"))?.let { return it }
    canonicalJvmNamespaceToken(System.getenv("KSAFE_APP_NAMESPACE"))?.let { return it }

    // Not derived from `sun.java.command`: it changes with the launcher and would silently
    // orphan data on upgrade.
    return DEFAULT_JVM_NAMESPACE
}

/** The namespace an older release resolved: a read-only migration source, never reclaimed. */
internal fun legacyResolvedJvmAppNamespace(override: String?): String? {
    val legacy = override.cleanNamespaceToken()
        ?: System.getProperty("ksafe.appNamespace").cleanNamespaceToken()
        ?: System.getenv("KSAFE_APP_NAMESPACE").cleanNamespaceToken()
        ?: DEFAULT_JVM_NAMESPACE
    return legacy.takeIf { it != resolveJvmAppNamespace(override) }
}

/** Namespaces the property/env tiers would have resolved before [override]. Probe-only. */
internal fun shadowedJvmAppNamespaces(override: String?): List<String> {
    val current = canonicalJvmNamespaceToken(override) ?: return emptyList()
    return listOfNotNull(
        System.getProperty("ksafe.appNamespace"),
        System.getenv("KSAFE_APP_NAMESPACE"),
    ).flatMap { listOfNotNull(canonicalJvmNamespaceToken(it), it.cleanNamespaceToken()) }
        .filter { it != current }
        .distinct()
}

/** Reproduces the legacy `sun.java.command` derivation byte for byte, so old keys stay probeable. */
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

/** Opt-out switch. One declaration: vault selection and `protectionInfo` must not disagree on it. */
private const val PROP_KEY_VAULT = "ksafe.jvm.keyVault"
private const val ENV_KEY_VAULT = "KSAFE_JVM_KEY_VAULT"
private val OPT_OUT_VALUES = setOf("software", "datastore", "off", "false", "none")

internal fun jvmKeyVaultOptedOut(): Boolean =
    (System.getProperty(PROP_KEY_VAULT) ?: System.getenv(ENV_KEY_VAULT))
        ?.lowercase() in OPT_OUT_VALUES
