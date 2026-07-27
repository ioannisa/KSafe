import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinAndroidTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    // Compose compiler plugin — required so @Composable functions in this
    // module (e.g. rememberKSafeState) get the Composer parameter injected
    // and `remember`/`LaunchedEffect` codegen properly. Without it, the
    // Kotlin compiler reports "couldn't find inline method ... remember".
    alias(libs.plugins.kotlin.compose)
    // Add the maven publish plugin
    alias(libs.plugins.vanniktech.mavenPublish)
}

// Set the same group and version as your main library
kotlin {
    android {
        namespace = "eu.anifantakis.lib.ksafe.compose"
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

    val xcfName = "ksafe-composeKit"

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

    // Mirror :ksafe — the default hierarchy gives us the shared webMain/webTest
    // intermediate source sets used by both wasmJs and js(IR). Without this
    // call, `webTest` does not exist.
    applyDefaultHierarchyTemplate()

    sourceSets {
        commonMain {
            dependencies {
                implementation(libs.kotlin.stdlib)
                // Use api() for your main library so it's exposed to consumers
                api(project(":ksafe"))

                implementation(libs.runtime)
            }
        }

        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.kotlinx.coroutines.test)
                implementation(libs.runtime)
            }
        }

        androidMain {
            dependencies {
                // Add Android-specific dependencies here
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
        // No Apple-specific dependencies needed today; the source set exists so downstream
        // consumers can target both iOS and macOS with the same Compose extensions.

        getByName("webTest") {
            dependencies {
                implementation(libs.kotlinx.coroutines.test)
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

//publishing {
//    publications {
//        val kotlinMultiplatformPublication = publications.getByName("kotlinMultiplatform") as MavenPublication
//        kotlinMultiplatformPublication.groupId = group.toString()
//        kotlinMultiplatformPublication.artifactId = "ksafe-compose"
//        kotlinMultiplatformPublication.version = version.toString()
//    }
//    repositories {
//        mavenLocal()
//    }
//}

// Add the same publishing configuration as your main library
// Coordinates, licence, developer and SCM metadata come from the root build script.
mavenPublishing {
    pom {
        name = "KSafe Compose - Jetpack Compose Extensions"
        description = "Jetpack Compose extensions for KSafe MultiPlatform Encrypted Persistence library"
    }
}


// task() is deprecated
// task("testClasses") {}
