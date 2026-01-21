import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinAndroidTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    // Add the maven publish plugin
    alias(libs.plugins.vanniktech.mavenPublish)
}

// Set the same group and version as your main library
group = "eu.anifantakis"
version = "1.4.1"

kotlin {
    androidLibrary {
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

    jvm()

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

        iosMain {
            dependencies {
                // Add iOS-specific dependencies here
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
mavenPublishing {
    publishToMavenCentral()

    signAllPublications()
    coordinates(
        groupId = group.toString(),
        artifactId = "ksafe-compose",  // Different artifactId
        version = version.toString()
    )

    pom {
        name = "KSafe Compose - Jetpack Compose Extensions"
        description = "Jetpack Compose extensions for KSafe MultiPlatform Encrypted Persistence library"
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


// task() is deprecated
// task("testClasses") {}
