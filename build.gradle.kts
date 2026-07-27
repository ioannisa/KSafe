plugins {
    alias(libs.plugins.androidLibrary) apply false
    alias(libs.plugins.kotlinMultiplatform) apply  false
    alias(libs.plugins.vanniktech.mavenPublish) apply false
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    id("org.jetbrains.kotlinx.binary-compatibility-validator") version "0.18.1"
}

// Locks the public ABI of every published module: `apiCheck` (wired into `check` and run in
// CI) fails any build whose public API no longer matches the committed dumps under each
// module's `api/` directory. After an INTENTIONAL API change, regenerate with `./gradlew
// apiDump` and commit the diff — the dump review is the API review.
apiValidation {
    // Klib ABI dumps cover the non-JVM targets (iOS/macOS/JS/Wasm) too, so a
    // platform-specific `actual` signature change can't slip past the JVM-only check.
    @OptIn(kotlinx.validation.ExperimentalBCVApi::class)
    klib {
        enabled = true
    }
}

// Coordinates and POM metadata are identical for all three published modules apart from the
// artifact name and its one-line description, so they are written here once.
subprojects {
    group = "eu.anifantakis"
    // The same property feeds the generated `KSAFE_VERSION` constant in :ksafe.
    version = providers.gradleProperty("ksafe.version").get()

    plugins.withId("com.vanniktech.maven.publish") {
        extensions.configure<com.vanniktech.maven.publish.MavenPublishBaseExtension> {
            publishToMavenCentral()

            // Release builds sign; local `publishToMavenLocal` runs and contributors
            // without GPG keys can opt out with `-Pksafe.skipSign=true`. CI release
            // jobs leave the property unset, so they continue to require signatures.
            if (!project.hasProperty("ksafe.skipSign")) signAllPublications()

            coordinates(
                groupId = group.toString(),
                artifactId = project.name,
                version = version.toString(),
            )

            pom {
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
    }
}
