// A small Android app that uses KSafe the way an app does, built with R8 and without it. A probe
// inside it writes and reads back delegates, plain, encrypted and hardware-isolated values,
// serializable, sealed and enum types, collections and a secret, so the CI job can check that R8
// breaks nothing and that a minified and an unminified build read each other's data.
//
//   ./gradlew :android-shrink-test:assembleFullRelease :android-shrink-test:assembleFullUnminified \
//             :android-shrink-test:assembleBareRelease :android-shrink-test:assembleBareUnminified
//   # copy the APKs into <apk dir> as full-release.apk, full-unminified.apk, bare-release.apk and
//   # bare-unminified.apk (docs/TESTING.md shows how, and how to add the compat-mode APKs)
//   .github/scripts/android-shrink-probe.sh <apk dir> <output dir> <ksafe version>
//
// Nothing here keeps anything: the app gets only what the KSafe artifacts and AGP give any app.

plugins {
    alias(libs.plugins.androidApplication)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "eu.anifantakis.ksafe.shrinktest.android"
    compileSdk = libs.versions.android.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "eu.anifantakis.ksafe.shrinktest.android"
        minSdk = libs.versions.android.minSdk.get().toInt()
        targetSdk = libs.versions.android.compileSdk.get().toInt()
        versionCode = 1
        versionName = "1.0"
    }

    flavorDimensions += "deps"
    productFlavors {
        // A typical app: Compose and Biometrics on board, and the template's default rules.
        create("full") {
            dimension = "deps"
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
        // KSafe alone and no default rules, so no blanket -dontwarn for androidx.
        create("bare") {
            dimension = "deps"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles("app-rules.pro")
            signingConfig = signingConfigs.getByName("debug")
        }
        // Release in every way but R8, so the two builds share data and differ only in shrinking.
        create("unminified") {
            initWith(getByName("release"))
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    lint {
        checkReleaseBuilds = false
    }
}

dependencies {
    implementation(project(":ksafe"))
    "fullImplementation"(project(":ksafe-compose"))
    "fullImplementation"(project(":ksafe-biometrics"))
    // Compiles ProbeActivity against FragmentActivity; ksafe-biometrics brings it at run time anyway.
    "fullImplementation"(libs.androidx.biometric)
}
