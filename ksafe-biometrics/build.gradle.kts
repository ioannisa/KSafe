import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinAndroidTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.vanniktech.mavenPublish)
}

kotlin {
    android {
        namespace = "eu.anifantakis.lib.ksafe.biometrics"
        compileSdk = 36
        minSdk = 24

        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_11)
        }

        // The shared authorization-cache tests run on every target, and the Android actual reads
        // SystemClock.elapsedRealtime() — a stub that throws in host tests. The tests assert on
        // entry PRESENCE and on differences of two readings, never on the clock's origin, so a
        // stubbed constant exercises exactly the same behaviour the real clock does.
        withHostTestBuilder {
        }.configure {
            isReturnDefaultValues = true
        }

        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }

    val xcfName = "ksafe-biometricsKit"

    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64(),
        macosX64(),
        macosArm64(),
    ).forEach {
        it.binaries.framework {
            baseName = xcfName
        }
    }

    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_11)
        }
    }

    @OptIn(ExperimentalWasmDsl::class)
    wasmJs {
        browser()
    }

    js(IR) {
        browser()
    }

    // Apply the default KMP hierarchy explicitly so the intermediate source
    // sets we use (appleMain shared by iOS + macOS) are wired up.
    applyDefaultHierarchyTemplate()

    sourceSets {
        compilerOptions {
            freeCompilerArgs.add("-Xexpect-actual-classes")
        }

        commonMain {
            dependencies {
                implementation(libs.kotlin.stdlib)
                implementation(libs.kotlinx.coroutines.core)
            }
        }

        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }

        // Shared js + wasmJs tests (the WebAuthn gate) need runTest for suspend ceremonies.
        getByName("webTest") {
            dependencies {
                implementation(libs.kotlinx.coroutines.test)
            }
        }

        androidMain {
            dependencies {
                implementation(libs.androidx.biometric)
            }
        }

        getByName("androidDeviceTest") {
            dependencies {
                implementation(libs.androidx.runner)
                implementation(libs.androidx.core)
                implementation(libs.androidx.junit)
            }
        }

        // appleMain is shared by iosX64/iosArm64/iosSimulatorArm64 + macosX64/macosArm64.
        // LocalAuthentication framework is part of the Apple SDKs — no extra dep needed.

        jvmMain {
            dependencies {
                // Native bridges for real desktop prompts: macOS Touch ID via the ObjC
                // runtime (LocalAuthentication) and Windows Hello via WinRT COM interop.
                implementation(libs.jna)
                implementation(libs.jna.platform)
            }
        }
    }

    targets.withType<KotlinAndroidTarget>().configureEach {
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_11)
        }
    }
}

tasks.withType<Test>().configureEach {
    // Forward the live-probe opt-in (`-Dksafe.biometrics.live=1`) to test workers:
    // it gates DesktopBiometricsTest.livePrompt, which pops a REAL system prompt.
    System.getProperty("ksafe.biometrics.live")?.let { systemProperty("ksafe.biometrics.live", it) }
}

// Coordinates, licence, developer and SCM metadata come from the root build script.
mavenPublishing {
    pom {
        name = "KSafe Biometrics - Standalone Biometric Authentication"
        description = "Standalone biometric authentication helper for Kotlin Multiplatform. Independent of the KSafe storage library — use it on its own or alongside KSafe."
    }
}
