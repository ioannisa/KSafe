import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.vanniktech.mavenPublish)

    alias(libs.plugins.kotlin.serialization)

    // CI-only flaky-test retry. The full jvmTest suite has timing/durability
    // -sensitive tests that flake on a shared, variable-speed 2-vCPU runner
    // (same commit: 2m21s vs 4m17s). Retry distinguishes runner-variance
    // flakes (pass on retry) from real regressions (fail every attempt).
    alias(libs.plugins.gradle.test.retry)
}

group = "eu.anifantakis"
// Single source of truth — see `ksafe.version` in the root gradle.properties.
// The same property feeds the generated `KSAFE_VERSION` constant below.
version = providers.gradleProperty("ksafe.version").get()

kotlin {
    android {
        namespace = "eu.anifantakis"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
        minSdk = libs.versions.android.minSdk.get().toInt()

        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_11)
        }

        withHostTestBuilder {
        }

        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
            instrumentationRunnerArguments["clearPackageData"] = "true"
        }
    }
    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64(),
        macosX64(),
        macosArm64(),
    ).forEach {
        it.binaries.framework {
            baseName = "ksafe"
            isStatic = true
        }
    }

    // Add a JVM target to support desktop platforms.
    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_11)
        }
    }

    // Add a WASM/JS target for browser-based web apps.
    @OptIn(ExperimentalWasmDsl::class)
    wasmJs {
        browser()
    }

    // Add a plain JS/IR target for legacy JS projects and projects that
    // need both js + wasmJs artifacts.
    js(IR) {
        browser()
    }

    // Explicitly apply the default KMP hierarchy template. This creates
    // the intermediate source sets we use (nativeMain/appleMain/iosMain
    // for the Apple targets, and webMain/webTest shared between js and
    // wasmJs). Without this call, `webMain` does not exist.
    applyDefaultHierarchyTemplate()

    sourceSets {
        @Suppress("unused")
        val commonMain by getting {
            dependencies {
                // api (not implementation) — Json is part of KSafe's public API (KSafeConfig.json),
                // so consumers get kotlinx-serialization-json transitively without declaring it themselves.
                api(libs.kotlinx.serialization.json)
                implementation(libs.kotlinx.coroutines.core)

                // compileOnly — used solely for the @Stable marker on the KSafe class so
                // Compose consumers (via :ksafe-compose) get accurate stability inference
                // and skip recompositions when passing a KSafe instance as a Composable
                // parameter. @Stable has BINARY retention and no runtime effect, so
                // non-Compose consumers (Ktor servers, CLI tools, plain JVM) do NOT
                // need compose-runtime on their classpath at runtime.
                //
                // Kotlin/JS, Kotlin/Native and Kotlin/WASM don't model compileOnly the
                // same way as JVM — klib metadata requires annotation references to
                // resolve at consumer compile-time, which triggers
                // IncorrectCompileOnlyDependencyWarning. We suppress that warning in
                // gradle.properties (kotlin.suppressGradlePluginWarnings=...). A
                // non-Compose consumer on those targets would need to declare
                // compose-runtime themselves to compile against this klib — an
                // accepted trade-off; promoting this to `api` for those targets would
                // leak compose-runtime onto every consumer's runtime classpath, which
                // is exactly what we're avoiding.
                compileOnly(libs.runtime)
            }
        }

        // Intermediate source set shared by Android, iOS and JVM — all three use
        // Jetpack DataStore Preferences as their on-disk backend, so the
        // DataStoreStorage adapter lives here instead of being duplicated.
        val datastoreMain by creating {
            dependsOn(commonMain)
            dependencies {
                implementation(libs.androidx.datastore.preferences.core)
            }
        }

        androidMain {
            dependsOn(datastoreMain)
            dependencies {
                implementation(libs.androidx.datastore.preferences)
            }
        }
        // appleMain is shared by iosX64/iosArm64/iosSimulatorArm64 + macosX64/macosArm64.
        // The default hierarchy template (applyDefaultHierarchyTemplate above) wires it up.
        appleMain {
            dependsOn(datastoreMain)
            dependencies {
                implementation(libs.cryptography.core)
                implementation(libs.cryptography.provider.base)
                implementation(libs.cryptography.provider.cryptokit)
            }
        }

        // Dependencies for the JVM target
        val jvmMain by getting {
            dependsOn(datastoreMain)
            dependencies {
                implementation(libs.androidx.datastore.preferences)
                // JVM-only OS secret-store interop. `api` is intentional: the
                // public diagnostic surface (which vault is active) never leaks
                // JNA types, but consumers that subclass/replace the engine may
                // touch it, and keeping it on the compile classpath of desktop
                // apps is harmless. Switch to implementation() if footprint matters.
                implementation(libs.jna)
                implementation(libs.jna.platform)
            }
        }

        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }

        // Dependencies shared by wasmJs + js targets.
        @Suppress("UNUSED_VARIABLE")
        val webMain by getting {
        }

        val webTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }

        compilerOptions {
            freeCompilerArgs.add("-Xexpect-actual-classes")
        }

        commonTest.dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.kotlinx.coroutines.test)
            implementation(libs.turbine)
        }

        getByName("androidDeviceTest") {
            dependencies {
                implementation(libs.androidx.runner)
                implementation(libs.androidx.core)
                implementation(libs.androidx.junit)
                implementation(kotlin("test"))
                implementation(libs.kotlinx.coroutines.test)
                implementation(libs.turbine)
            }
        }
    }

    // Configure iOS tests to run sequentially
    targets.withType<org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget>().configureEach {
        binaries.all {
            if (this is org.jetbrains.kotlin.gradle.plugin.mpp.TestExecutable) {
                // Force sequential test execution
                linkerOpts("-single_module")
            }
        }
    }
}

dependencies {
    "androidTestUtil"(libs.androidx.orchestrator)
}

// ============================================================================
// Generated `KSafeBuildConfig.kt` — single source of truth for the version
// string is `ksafe.version` in the root gradle.properties. This task writes
// `internal const val KSAFE_VERSION` into commonMain so the public
// `KSafe.VERSION` companion val and `KSafeProtectionInfo.kSafeVersion` always
// match the Maven coordinates produced by the same property. Bumping the
// property in one place propagates to artifact + runtime + diagnostic.
// ============================================================================
// All providers and dir layouts are resolved before the `registering` block so
// `doLast` captures only plain locals — script object references aren't
// serialisable by the configuration cache.
private val ksafeVersionProvider = providers.gradleProperty("ksafe.version")
private val ksafeBuildConfigOutDir =
    layout.buildDirectory.dir("generated/source/ksafe-version/commonMain/kotlin")

val generateKSafeBuildConfig by tasks.registering {
    val versionProvider = ksafeVersionProvider
    val outDirProvider = ksafeBuildConfigOutDir
    inputs.property("ksafeVersion", versionProvider)
    outputs.dir(outDirProvider)
    doLast {
        val version = versionProvider.get()
        val file = outDirProvider.get().asFile.resolve(
            "eu/anifantakis/lib/ksafe/KSafeBuildConfig.kt"
        )
        file.parentFile.mkdirs()
        file.writeText(
            """
            // Generated — do not edit by hand.
            // Source: gradle.properties → `ksafe.version`.
            // Regenerate via `./gradlew :ksafe:generateKSafeBuildConfig`.
            package eu.anifantakis.lib.ksafe

            internal const val KSAFE_VERSION: String = "$version"

            """.trimIndent(),
        )
    }
}

kotlin.sourceSets.named("commonMain") {
    kotlin.srcDir(generateKSafeBuildConfig)
}

mavenPublishing {
    publishToMavenCentral()

    // Release builds sign; local `publishToMavenLocal` runs and contributors
    // without GPG keys can opt out with `-Pksafe.skipSign=true`. CI release
    // jobs leave the property unset, so they continue to require signatures.
    if (!project.hasProperty("ksafe.skipSign")) signAllPublications()
    coordinates(
        groupId =  group.toString(),
        artifactId = "ksafe",
        version = version.toString()
    )

    pom {
        name = "KSafe MultiPlatform Encrypted Persistence"
        description = "Library to allow for multiplatform seamless encrypted persistence using DataStore Preferences"
        inceptionYear = "2025"
        url = "https://github.com/ioannisa/ksafe"
        licenses {
            license {
                name = "Apache-2.0"
                url = "https://www.apache.org/licenses/LICENSE-2.0"
            }
        }
        developers {
            developer {
                id = "ioannis-anifantakis"
                name = "Ioannis Anifantakis"
                url = "https://anifantakis.eu"
                email = "ioannisanif@gmail.com"
            }
        }
        scm {
            url = "https://github.com/ioannisa/ksafe"
            connection = "scm:git:https://github.com/ioannisa/ksafe.git"
            developerConnection = "scm:git:ssh://git@github.com/ioannisa/ksafe.git"
        }
    }
}

// try and configure iOS test tasks to run sequentially
tasks.withType<org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeTest>().configureEach {
    // Set environment variable to help with debugging
    environment("KSAFE_TEST_MODE", "sequential")
}

// Set by the keyvault integration CI jobs (Linux/Windows/macOS). When present,
// the jvmTest suite does NOT force the software fallback, so the real OS secret
// store (DPAPI / Keychain / Secret Service) is exercised and
// JvmKeyVaultIntegrationTest activates. Read via the providers API so the
// configuration cache stays valid.
val keyVaultItEnv = providers.environmentVariable("KSAFE_KEYVAULT_IT")

// `-PksafeTestLog` (used by the nightly/manual full-suite CI job) logs each
// test as it starts, so a hung run's log shows the exact test that never
// completed (last STARTED with no PASSED/FAILED). Off by default to keep
// local output quiet. providers API => configuration-cache safe.
val ksafeTestLog = providers.gradleProperty("ksafeTestLog")

// GitHub Actions (and most CI) set CI=true. Used to enable flaky-test retry
// ONLY on CI — local runs must pass first try (no retry masking).
val ciEnv = providers.environmentVariable("CI")

// `-PksafeStressScale=<0.01..1.0>` shrinks the JvmKSafeTest concurrency-stress
// magnitudes so the full suite is drainable on a 2-vCPU CI runner (the
// documented livelock). Default (absent) = full local intensity.
val ksafeStressScale = providers.gradleProperty("ksafeStressScale")

tasks.named<Test>("jvmTest") {
    // Stress tests in JvmKSafeTest each launch tens of thousands of concurrent
    // putDirect operations whose state (memoryCache + dirtyKeys + DataStore write
    // queue) accumulates faster than the test class's tearDown + GC can drain it.
    // Forking a fresh JVM per test class bounds the live set to a single class
    // and keeps the suite well under any reasonable heap.
    maxHeapSize = "2g"
    forkEvery = 1
    // Keep the JVM test suite off the real OS Keychain/keyring by default:
    // avoids interactive Keychain-access prompts on macOS dev machines and
    // keyring pollution. The keyvault integration CI jobs set
    // KSAFE_KEYVAULT_IT to skip this and run against the real store.
    if (keyVaultItEnv.orNull.isNullOrBlank()) {
        systemProperty("ksafe.jvm.keyVault", "software")
    }
    if (ksafeTestLog.isPresent) {
        testLogging {
            events("started", "passed", "skipped", "failed")
            showStandardStreams = false
        }
    }
    if (ksafeStressScale.isPresent) {
        systemProperty("ksafe.stressScale", ksafeStressScale.get())
    }
    // Flaky-test retry — CI only. A runner-variance flake passes on retry
    // (build green, still listed in the report so it's tracked, not hidden);
    // a real regression fails all attempts and still reds the build.
    // maxFailures caps a genuinely broken suite so it fails fast instead of
    // retrying everything. Local runs: maxRetries=0 (must pass first try).
    retry {
        val onCi = ciEnv.orNull?.equals("true", ignoreCase = true) == true
        maxRetries.set(if (onCi) 2 else 0)
        maxFailures.set(8)
        failOnPassedAfterRetry.set(false)
    }
    // Isolate the test JVM from the real user home. KSafe's JVM default
    // datastore dir is `<user.home>/.eu_anifantakis_ksafe`; tests that don't
    // pass an explicit baseDir would otherwise read/WRITE/DELETE the real
    // user's (or a dev's demo) data — the pre-2.1.1 cleanup below
    // recursively deleted `~/.eu_anifantakis_ksafe` and destroyed real demo
    // data. Overriding `user.home` for the (forked) test JVM transparently
    // redirects that default into build/, so the cleanup can only ever touch
    // an isolated, disposable directory — never real user data.
    val testHome = layout.buildDirectory.dir("ksafe-test-home").get().asFile
    systemProperty("user.home", testHome.absolutePath)
    doFirst {
        val ksafeDir = File(testHome, ".eu_anifantakis_ksafe")
        if (ksafeDir.exists()) {
            ksafeDir.deleteRecursively()
            println("Cleaned up isolated KSafe test data directory: $ksafeDir")
        }
        testHome.mkdirs()
    }
}

// ============================================================================
// Kotlin/JS test-truncation guard.
//
// The legacy Kotlin/JS kotlin-test runner silently stops registering the
// trailing @Test methods of an oversized test class (observed: KSafeTest
// truncated at ~62) — methods are compiled into the bundle but never run,
// with NO failure/skip/error signal. wasmJs/JVM/Native run the full set from
// identical `webTest` source. This task fails the build if any shared web
// test class ran fewer tests on jsBrowserTest than on wasmJsBrowserTest, so a
// future silent JS drop is loud instead of invisible.
// ============================================================================
val verifyWebTestParity by tasks.registering {
    group = "verification"
    description = "Fails if Kotlin/JS registered fewer tests than wasmJs (truncation guard)."
    dependsOn("jsBrowserTest", "wasmJsBrowserTest")

    val jsDir = layout.buildDirectory.dir("test-results/jsBrowserTest")
    val wasmDir = layout.buildDirectory.dir("test-results/wasmJsBrowserTest")

    doLast {
        fun counts(dir: File): Map<String, Int> {
            require(dir.isDirectory) { "Missing test-results dir: $dir (did the browser tests run?)" }
            val suite = Regex("<testsuite[^>]*\\btests=\"(\\d+)\"")
            return (dir.listFiles { f -> f.name.startsWith("TEST-") && f.extension == "xml" } ?: emptyArray())
                .associate { f ->
                    val cls = "eu.anifantakis" + f.name.substringAfter("eu.anifantakis").removeSuffix(".xml")
                    cls to (suite.find(f.readText())?.groupValues?.get(1)?.toInt() ?: 0)
                }
        }

        val js = counts(jsDir.get().asFile)
        val wasm = counts(wasmDir.get().asFile)
        val dropped = wasm.mapNotNull { (cls, w) ->
            val j = js[cls] ?: 0
            if (j < w) "  $cls: js=$j wasmJs=$w (Kotlin/JS dropped ${w - j})" else null
        }

        if (dropped.isNotEmpty()) {
            throw GradleException(
                "Kotlin/JS test truncation detected — these shared webTest classes ran " +
                    "FEWER tests on Kotlin/JS than wasmJs (identical source):\n" +
                    dropped.joinToString("\n") +
                    "\n\nKotlin/JS silently stops registering trailing @Tests of oversized " +
                    "classes. Split the offending class into smaller focused classes " +
                    "(see KSafeNullableDefaultTest)."
            )
        }
        logger.lifecycle(
            "Web test parity OK: js total=${js.values.sum()} == wasmJs total=" +
                "${wasm.values.sum()} across ${wasm.size} shared classes."
        )
    }
}

// Run test
// ./gradlew :ksafe:jvmTest
