import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)

    alias(libs.plugins.kotlin.serialization)
}

group = "eu.anifantakis"
version = "1.4.2"

kotlin {
    androidTarget {
        publishLibraryVariants("release")
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_1_8)
        }
    }
    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64()
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

    sourceSets {
        androidMain.dependencies {
            implementation(libs.androidx.datastore.preferences)
            implementation(libs.cryptography.provider.jdk)
            implementation(libs.androidx.biometric)
            implementation(libs.play.integrity)
            implementation(libs.play.services.base)
        }
        @Suppress("unused")
        val commonMain by getting {
            dependencies {
                implementation(libs.kotlinx.serialization.json)
                implementation(libs.kotlinx.coroutines.core)

                implementation(libs.androidx.datastore.preferences.core)

                implementation(libs.cryptography.core)
                implementation(libs.cryptography.provider.base)
            }
        }
        iosMain.dependencies {
            implementation(libs.cryptography.provider.cryptokit)
        }

        // Dependencies for the JVM target
        val jvmMain by getting {
            dependencies {
                implementation(libs.androidx.datastore.preferences)
                implementation(libs.kotlinx.serialization.json)
                implementation(libs.kotlinx.coroutines.core)
            }
        }

        val jvmTest by getting {
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

        val androidInstrumentedTest by getting {
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

android {
    namespace = "eu.anifantakis"
    compileSdk = libs.versions.android.compileSdk.get().toInt()
    defaultConfig {
        minSdk = libs.versions.android.minSdk.get().toInt()
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testInstrumentationRunnerArguments["clearPackageData"] = "true"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
        }
        execution = "ANDROIDX_TEST_ORCHESTRATOR"
        animationsDisabled = true
    }

    dependencies {
        androidTestUtil(libs.androidx.orchestrator)
    }
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

tasks.named<Test>("jvmTest") {
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