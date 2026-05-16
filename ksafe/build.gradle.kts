import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.vanniktech.mavenPublish)

    alias(libs.plugins.kotlin.serialization)
}

group = "eu.anifantakis"
version = "2.0.0"

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

                implementation(libs.cryptography.core)
                implementation(libs.cryptography.provider.base)

                // compileOnly — used solely for the @Stable marker on the KSafe class so
                // Compose consumers (via :ksafe-compose) get accurate stability inference
                // and skip recompositions when passing a KSafe instance as a Composable
                // parameter. @Stable has BINARY retention and no runtime effect, so
                // non-Compose consumers (Ktor servers, CLI tools, plain JVM) do NOT
                // need compose-runtime on their classpath at runtime.
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
                implementation(libs.cryptography.provider.jdk)
            }
        }
        // appleMain is shared by iosX64/iosArm64/iosSimulatorArm64 + macosX64/macosArm64.
        // The default hierarchy template (applyDefaultHierarchyTemplate above) wires it up.
        appleMain {
            dependsOn(datastoreMain)
            dependencies {
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
        val webMain by getting {
            dependencies {
                implementation(libs.cryptography.provider.webcrypto)
            }
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

mavenPublishing {
    publishToMavenCentral()

    signAllPublications()
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
    doFirst {
        val ksafeDir = File(System.getProperty("user.home"), ".eu_anifantakis_ksafe")
        if (ksafeDir.exists()) {
            ksafeDir.deleteRecursively()
            println("Cleaned up KSafe test data directory: $ksafeDir")
        }
    }
}

// Run test
// ./gradlew :ksafe:jvmTest
