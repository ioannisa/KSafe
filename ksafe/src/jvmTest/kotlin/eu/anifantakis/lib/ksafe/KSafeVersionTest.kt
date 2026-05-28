package eu.anifantakis.lib.ksafe

import java.util.Properties
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Pins the single-source-of-truth contract for the artifact version.
 *
 * `gradle.properties` → `ksafe.version` feeds both the Maven coordinates
 * (via `version = providers.gradleProperty(...)` in each module) and the
 * generated `KSAFE_VERSION` constant (via the `generateKSafeBuildConfig`
 * task), which is in turn surfaced as [KSafe.VERSION] and
 * [KSafeProtectionInfo.kSafeVersion].
 *
 * If any branch of that wiring drifts (someone hardcodes a version in
 * `build.gradle.kts`, the codegen task gets removed, a platform factory
 * forgets to forward the default, …), these tests fail.
 */
class KSafeVersionTest {

    @Test
    fun versionMatchesGradleProperty() {
        val versionInProperties = readGradleProperty("ksafe.version")
        assertNotNull(versionInProperties, "ksafe.version must be defined in gradle.properties")
        assertEquals(
            versionInProperties,
            KSafe.VERSION,
            "KSafe.VERSION must equal `ksafe.version` from gradle.properties — the " +
                "generated KSafeBuildConfig.kt is out of sync. Run " +
                "`./gradlew :ksafe:generateKSafeBuildConfig` if the property changed.",
        )
    }

    @Test
    fun protectionInfoCarriesTheVersion() {
        // Cheap construction — no opt-in to OS keychain (jvmTest forces
        // software fallback via systemProperty `ksafe.jvm.keyVault=software`).
        val ksafe = KSafe(fileName = "version_smoke_${System.nanoTime()}")
        try {
            assertEquals(
                KSafe.VERSION,
                ksafe.protectionInfo.kSafeVersion,
                "protectionInfo.kSafeVersion must mirror KSafe.VERSION",
            )
        } finally {
            ksafe.close()
        }
    }

    @Test
    fun versionLooksLikeSemver() {
        // Smoke check — catches an empty string or trailing whitespace leaking
        // out of the generator template, without locking us to a fixed value.
        assertTrue(
            KSafe.VERSION.matches(Regex("""\d+\.\d+\.\d+(?:-[A-Za-z0-9.+-]+)?""")),
            "KSafe.VERSION should be SemVer-shaped, was \"${KSafe.VERSION}\"",
        )
    }

    private fun readGradleProperty(key: String): String? {
        // Test JVM is forked per class with `user.home` overridden to a build
        // dir, but `user.dir` still points at the project root.
        val projectRoot = java.io.File(System.getProperty("user.dir"))
        // Walk up to find gradle.properties (handles `:ksafe` vs root invocation).
        var dir: java.io.File? = projectRoot
        while (dir != null) {
            val candidate = java.io.File(dir, "gradle.properties")
            if (candidate.isFile) {
                return candidate.inputStream().use { stream ->
                    Properties().apply { load(stream) }.getProperty(key)
                }
            }
            dir = dir.parentFile
        }
        return null
    }
}
