import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinAndroidTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.vanniktech.mavenPublish)
}

group = "eu.anifantakis"
// Single source of truth — see `ksafe.version` in the root gradle.properties.
version = providers.gradleProperty("ksafe.version").get()

kotlin {
    android {
        namespace = "eu.anifantakis.lib.ksafe.biometrics"
        compileSdk = 36
        minSdk = 24

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
        }
    }

    val xcfName = "ksafe-biometricsKit"

    iosX64 {
        binaries.framework {
            baseName = xcfName
        }
    }

    iosArm64 {
        binaries.framework {
            baseName = xcfName
        }
    }

    iosSimulatorArm64 {
        binaries.framework {
            baseName = xcfName
        }
    }

    macosX64 {
        binaries.framework {
            baseName = xcfName
        }
    }

    macosArm64 {
        binaries.framework {
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

        androidMain {
            dependencies {
                implementation(libs.androidx.biometric)
            }
        }

        // appleMain is shared by iosX64/iosArm64/iosSimulatorArm64 + macosX64/macosArm64.
        // LocalAuthentication framework is part of the Apple SDKs — no extra dep needed.
    }

    targets.withType<KotlinAndroidTarget>().configureEach {
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_11)
        }
    }
}

mavenPublishing {
    publishToMavenCentral()

    signAllPublications()
    coordinates(
        groupId = group.toString(),
        artifactId = "ksafe-biometrics",
        version = version.toString()
    )

    pom {
        name = "KSafe Biometrics - Standalone Biometric Authentication"
        description = "Standalone biometric authentication helper for Kotlin Multiplatform. Independent of the KSafe storage library — use it on its own or alongside KSafe."
        inceptionYear = "2026"
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
