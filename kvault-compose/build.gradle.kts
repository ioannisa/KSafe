import com.vanniktech.maven.publish.SonatypeHost
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    // Add the maven publish plugin
    alias(libs.plugins.vanniktech.mavenPublish)
}

// Set the same group and version as your main library
group = "eu.anifantakis"
version = "1.1.0"

kotlin {
    androidLibrary {
        namespace = "eu.anifantakis.kvault.compose"
        compileSdk = 34
        minSdk = 24

        withHostTestBuilder {
        }

        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }

    val xcfName = "kvault-composeKit"

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

    sourceSets {
        commonMain {
            dependencies {
                implementation(libs.kotlin.stdlib)
                // Use api() for your main library so it's exposed to consumers
                api(project(":kvault"))

                implementation(libs.runtime)
            }
        }

        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
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
}

//publishing {
//    publications {
//        val kotlinMultiplatformPublication = publications.getByName("kotlinMultiplatform") as MavenPublication
//        kotlinMultiplatformPublication.groupId = group.toString()
//        kotlinMultiplatformPublication.artifactId = "kvault-compose"
//        kotlinMultiplatformPublication.version = version.toString()
//    }
//    repositories {
//        mavenLocal()
//    }
//}

// Add the same publishing configuration as your main library
mavenPublishing {
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)

    signAllPublications()
    coordinates(
        groupId = group.toString(),
        artifactId = "kvault-compose",  // Different artifactId
        version = version.toString()
    )

    pom {
        name = "KVault Compose - Jetpack Compose Extensions"
        description = "Jetpack Compose extensions for KVault MultiPlatform Encrypted Persistence library"
        inceptionYear = "2025"
        url = "https://github.com/ioannisa/kvault"
        licenses {
            license {
                name = "MIT"
                url = "https://opensource.org/licenses/MIT"
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
            url = "https://github.com/ioannisa/kvault"
            connection = "scm:git:https://github.com/ioannisa/kvault.git"
            developerConnection = "scm:git:ssh://git@github.com/ioannisa/kvault.git"
        }
    }
}

task("testClasses") {}