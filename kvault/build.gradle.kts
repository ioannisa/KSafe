import com.vanniktech.maven.publish.SonatypeHost
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)

    alias(libs.plugins.kotlin.serialization)
    //id("maven-publish")
}

group = "eu.anifantakis"
version = "1.0.1"

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
            baseName = "kvault"
            isStatic = true
        }
    }

    sourceSets {
        androidMain.dependencies {
            // data store preferences
            implementation(cryptographyLibs.provider.jdk)
            implementation(libs.androidx.datastore.preferences)
        }
        val commonMain by getting {
            dependencies {
                //put your multiplatform dependencies here
                //put your multiplatform dependencies here
                implementation(libs.kotlinx.serialization.json)
                implementation(libs.kotlinx.coroutines.core)

                implementation(libs.androidx.datastore.preferences.core)

                implementation(cryptographyLibs.core)
                implementation(cryptographyLibs.provider.base)
            }
        }
        iosMain.dependencies {
            implementation(cryptographyLibs.provider.openssl3.prebuilt)
        }

        compilerOptions {
            freeCompilerArgs.add("-Xexpect-actual-classes")
        }
    }
}

android {
    namespace = "eu.anifantakis"
    compileSdk = libs.versions.android.compileSdk.get().toInt()
    defaultConfig {
        minSdk = libs.versions.android.minSdk.get().toInt()
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}

//publishing {
//    publications {
//        val kotlinMultiplatformPublication = publications.getByName("kotlinMultiplatform") as MavenPublication
//        kotlinMultiplatformPublication.groupId = group.toString()
//        kotlinMultiplatformPublication.artifactId = "kvault"
//        kotlinMultiplatformPublication.version = version.toString()
//    }
//    repositories {
//        mavenLocal()
//    }
//}

mavenPublishing {
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)

    signAllPublications()
    coordinates(
        groupId =  group.toString(),
        artifactId = "kvault",
        version = version.toString()
    )

    pom {
        name = "KVault MultiPlatform Encrypted Persistence"
        description = "Library to allow for multiplatform seamless encrypted persistence using DataStore Preferences"
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