import kotlinx.validation.KotlinApiBuildTask
import kotlinx.validation.KotlinApiCompareTask
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinPlatformType

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
    // `api/jvm/*.api` covers the JVM target, the klib dumps cover iOS/macOS/JS/Wasm, and
    // `api/android/*.api` (registered below) covers Android — so a platform-specific `actual`
    // signature change can't slip past on any target.
    @OptIn(kotlinx.validation.ExperimentalBCVApi::class)
    klib {
        enabled = true
    }
}

// The validator only dumps an Android compilation named `release`; the AGP KMP library plugin
// names it `main`, so it registered nothing. Register its own task types over that compilation.
subprojects {
    val module = this
    plugins.withId("org.jetbrains.kotlin.multiplatform") {
        val kotlin = extensions.getByType(KotlinMultiplatformExtension::class.java)
        kotlin.targets.matching { it.platformType == KotlinPlatformType.androidJvm }.configureEach {
            val targetName = name
            compilations.matching { it.name == "main" }.configureEach {
                val classesDirs = output.classesDirs
                val dumpFileName = "${module.name}.api"
                val dumpDir = module.layout.projectDirectory.dir("api/$targetName")

                val apiBuild = module.tasks.register<KotlinApiBuildTask>("${targetName}ApiBuild") {
                    description = "Builds Kotlin API for the '$targetName' target of ${module.name}. " +
                        "Complementary task and shouldn't be called manually"
                    inputClassesDirs.from(classesDirs)
                    outputApiFile.set(module.layout.buildDirectory.file("api/$targetName/$dumpFileName"))
                    runtimeClasspath.from(module.configurations.named("bcv-rt-jvm-cp-resolver"))
                }

                val apiCheck = module.tasks.register<KotlinApiCompareTask>("${targetName}ApiCheck") {
                    group = "verification"
                    description = "Checks signatures of the $targetName public API against the " +
                        "golden value in API folder for ${module.name}"
                    projectApiFile.set(dumpDir.file(dumpFileName))
                    generatedApiFile.set(apiBuild.flatMap { it.outputApiFile })
                }

                val apiDump = module.tasks.register<Copy>("${targetName}ApiDump") {
                    group = "other"
                    description = "Syncs the $targetName API file for ${module.name}"
                    from(apiBuild.flatMap { it.outputApiFile })
                    into(dumpDir)
                }
                apiCheck.configure { mustRunAfter(apiDump) }

                module.tasks.named("apiCheck") { dependsOn(apiCheck) }
                module.tasks.named("apiDump") { dependsOn(apiDump) }
            }
        }
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
