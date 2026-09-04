package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.keyvault.DEFAULT_JVM_NAMESPACE
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import eu.anifantakis.lib.ksafe.internal.keyvault.legacyFallbackNamespaces
import eu.anifantakis.lib.ksafe.internal.keyvault.legacyResolvedJvmAppNamespace
import eu.anifantakis.lib.ksafe.internal.keyvault.resolveJvmAppNamespace
import eu.anifantakis.lib.ksafe.internal.keyvault.shadowedJvmAppNamespaces
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import java.io.File
import java.nio.file.Files
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in: an app that ran with only `-Dksafe.appNamespace` / `KSAFE_APP_NAMESPACE` keeps its
 * keys when a later release adds an explicit [KSafeConfig.appNamespace].
 *
 * The config tier outranks the property/env tiers, so the namespace those tiers resolved stops
 * being probed the moment a config override appears — every alias misses, every decrypt reports
 * "No encryption key found", and the startup orphan sweep deletes the ciphertext while the keys
 * still sit intact under the old namespace.
 */
class JvmPropertyNamespaceCarryForwardTest {

    private val PROP = "ksafe.appNamespace"

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val tmp: File = Files.createTempDirectory("ksafe-propns").toFile()
    private val dataStore: DataStore<Preferences> =
        PreferenceDataStoreFactory.create(scope = scope, produceFile = { File(tmp, "kv.preferences_pb") })

    @AfterTest
    fun tearDown() {
        scope.cancel()
        tmp.deleteRecursively()
    }

    private inline fun withAppNamespaceProperty(value: String, block: () -> Unit) {
        val prev = System.getProperty(PROP)
        System.setProperty(PROP, value)
        try {
            block()
        } finally {
            if (prev == null) System.clearProperty(PROP) else System.setProperty(PROP, prev)
        }
    }

    /** In-memory stand-in for an OS-backed vault. */
    private class FakeOsVault : JvmKeyVault {
        val store = ConcurrentHashMap<String, ByteArray>()
        override val name = "FakeOsVault (test)"
        override val isOsBacked = true
        override fun get(alias: String): ByteArray? = store[alias]?.copyOf()
        override fun put(alias: String, keyBytes: ByteArray) { store[alias] = keyBytes.copyOf() }
        override fun delete(alias: String) { store.remove(alias) }
    }

    @Test
    fun propertyNamespace_isProbedWhenAConfigOverrideShadowsIt() = withAppNamespaceProperty("acme") {
        assertEquals(listOf("acme"), shadowedJvmAppNamespaces("com.acme.desktop"))
        assertEquals(
            listOf("acme", DEFAULT_JVM_NAMESPACE),
            legacyFallbackNamespaces(
                resolveJvmAppNamespace("com.acme.desktop"),
                derivedNamespace = null,
                legacyConfigNamespace = legacyResolvedJvmAppNamespace("com.acme.desktop"),
                shadowedNamespaces = shadowedJvmAppNamespaces("com.acme.desktop"),
            ),
            "the namespace the property tier resolved must be probed before the shared default",
        )
    }

    @Test
    fun shadowedNamespaces_sitAfterThePreCanonicalConfigNamespaceAndBeforeTheDerivedOne() {
        assertEquals(
            listOf(".foo", "acme", "myapp", DEFAULT_JVM_NAMESPACE),
            legacyFallbackNamespaces(
                "foo",
                derivedNamespace = "myapp",
                legacyConfigNamespace = ".foo",
                shadowedNamespaces = listOf("acme"),
            ),
        )
    }

    @Test
    fun bothSpellingsOfThePropertyTierAreProbed() = withAppNamespaceProperty(".acme") {
        // Pre-3.0.0 kept the leading dot; the canonical spelling drops it. Either may hold keys.
        assertEquals(listOf("acme", ".acme"), shadowedJvmAppNamespaces("com.acme.desktop"))
    }

    @Test
    fun withoutAConfigOverride_thereIsNothingToProbe() = withAppNamespaceProperty("acme") {
        // No override => the property tier IS the current namespace.
        assertEquals(emptyList(), shadowedJvmAppNamespaces(null))
    }

    @Test
    fun aShadowedNamespaceEqualToTheCurrentOneIsDropped() = withAppNamespaceProperty("acme") {
        assertEquals(emptyList(), shadowedJvmAppNamespaces("acme"))
    }

    @Test
    fun shadowedNamespace_isProbedButNeverReclaimed() = withAppNamespaceProperty("acme") {
        val alias = "user:token"
        val key = ByteArray(32) { it.toByte() }
        val acmeTwin = FakeOsVault().apply { store[alias] = key.copyOf() }
        val active = FakeOsVault()
        val provider = providerFor("com.acme.desktop", active, acmeTwin)

        assertContentEquals(
            key, provider.recoverFromLegacyNamespace(alias),
            "the namespace the property tier resolved must still be probed after a config override",
        )
        assertContentEquals(key, active.store[alias], "the key must be copied into the new namespace")
        assertContentEquals(
            key, acmeTwin.store[alias],
            "a sibling process still launched with the property owns this key — never reclaim it",
        )
    }

    @Test
    fun deleteFromShadowedNamespace_leavesTheSiblingsKeyAlone() = withAppNamespaceProperty("acme") {
        val alias = "user:token"
        val key = ByteArray(32) { 7 }
        val acmeTwin = FakeOsVault().apply { store[alias] = key.copyOf() }
        val active = FakeOsVault()
        val provider = providerFor("com.acme.desktop", active, acmeTwin)

        provider.deleteFromLegacyNamespace(alias)

        assertContentEquals(
            key, acmeTwin.store[alias],
            "deleting here must not scrub a namespace another live process may own",
        )
        assertEquals(
            null, provider.recoverFromLegacyNamespace(alias),
            "the tombstone must keep the deleted key from being re-copied out of the retained source",
        )
    }

    @Test
    fun addingAnAppNamespaceAfterRunningWithThePropertyKeepsEncryptedValues() =
        withAppNamespaceProperty("acme") {
            runBlocking {
                val fileName = "propns_${System.nanoTime()}"
                val propertyVault = FakeOsVault()

                // Release N: only the property is set, so keys land under "acme".
                val first = KSafe(
                    fileName = fileName,
                    baseDir = tmp,
                    testEngine = JvmSoftwareEncryption(
                        dataStore = dataStore,
                        vaultProvider = JvmKeyVaultProvider(dataStore, forced = propertyVault),
                    ),
                )
                first.put("token", "v1", KSafeWriteMode.Encrypted())
                first.close()
                assertTrue(propertyVault.store.isNotEmpty(), "premise: keys were minted under the property namespace")

                // Release N+1 adds an explicit appNamespace; the property is still set.
                val second = KSafe(
                    fileName = fileName,
                    baseDir = tmp,
                    config = KSafeConfig(appNamespace = "com.acme.desktop"),
                    testEngine = JvmSoftwareEncryption(
                        dataStore = dataStore,
                        vaultProvider = providerFor("com.acme.desktop", FakeOsVault(), propertyVault),
                    ),
                )
                val read = second.get("token", "")
                second.close()

                assertEquals(
                    "v1", read,
                    "the encrypted value must survive adding an appNamespace on top of -Dksafe.appNamespace",
                )
            }
        }

    @Test
    fun jvmSoftwareEncryptionWiresTheShadowedNamespacesIntoItsProvider() =
        withAppNamespaceProperty("acme") {
            val engine = JvmSoftwareEncryption(
                config = KSafeConfig(appNamespace = "com.acme.desktop"),
                dataStore = dataStore,
            )
            val provider = JvmSoftwareEncryption::class.java.getDeclaredField("vaults")
                .apply { isAccessible = true }
                .get(engine)
            val shadowed = JvmKeyVaultProvider::class.java.getDeclaredField("shadowedAppNamespaces")
                .apply { isAccessible = true }
                .get(provider)

            assertEquals(
                listOf("acme"), shadowed,
                "the production wiring must pass the shadowed namespaces to the vault provider",
            )
        }

    /**
     * A provider wired the way `JvmSoftwareEncryption` wires the production one, with the
     * legacy-namespace twins served from memory instead of the host's OS secret store.
     */
    private fun providerFor(
        configNamespace: String,
        active: FakeOsVault,
        propertyTwin: FakeOsVault,
    ): JvmKeyVaultProvider = JvmKeyVaultProvider(
        dataStore,
        appNamespace = resolveJvmAppNamespace(configNamespace),
        legacyAppNamespace = legacyResolvedJvmAppNamespace(configNamespace),
        shadowedAppNamespaces = shadowedJvmAppNamespaces(configNamespace),
        forced = active,
        legacyNamespaceVaultFactoryForTest = { ns ->
            if (ns == "acme") propertyTwin else FakeOsVault()
        },
    )
}
