import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

// Fails the build when Compose stops seeing KSafe, KSafePlain, KSafeEncrypted or
// KSafeHardwareIsolated as stable. :ksafe is not compiled with the Compose compiler, so only their
// @Stable markers make them stable. This module compiles composables that take each type, plus a
// class that holds a KSafe, with Compose compiler reports on, and reads the reports back.
//
//   ./gradlew :stability-check:verifyStability      (also part of :stability-check:check)
//
// One compile with strong skipping on (the default) is enough: the stability the report prints for
// each parameter is the same with it off; only the "skippable" flag on the function differs.

plugins {
    alias(libs.plugins.kotlinJvm)
    alias(libs.plugins.kotlin.compose)
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

dependencies {
    implementation(project(":ksafe"))
    // :ksafe declares the Compose runtime compile-only, so it does not come along.
    implementation(libs.runtime)
}

val reportsDir = layout.buildDirectory.dir("compose_reports")

composeCompiler {
    reportsDestination = reportsDir
}

tasks.named<KotlinCompile>("compileKotlin") {
    // Not an output by default, so a build-cache hit would restore the classes without the reports.
    outputs.dir(reportsDir)
    // The plugin passes the destination as an internal option: moving it must still recompile.
    inputs.property(
        "composeReportsDestination",
        composeCompiler.reportsDestination.map { it.asFile.relativeTo(projectDir).invariantSeparatorsPath },
    ).optional(true)
    // An incremental compile rewrites the reports with the changed files only.
    incremental = false
}

val verifyStability = tasks.register("verifyStability") {
    group = "verification"
    description = "Fails if KSafe, its mode views, or a class holding a KSafe is no longer stable to Compose."
    dependsOn(tasks.named("compileKotlin"))

    val reports = reportsDir
    val reportPrefix = project.name
    inputs.dir(reports)

    doLast {
        // Each report line starts with the stability, then the declaration. The KSafe types' own
        // lines, and the lines of the fixture class that holds one.
        val ownTypes = setOf(
            "ksafe: KSafe", "plain: KSafePlain", "encrypted: KSafeEncrypted",
            "hardwareIsolated: KSafeHardwareIsolated", "val ksafe: KSafe",
        )
        val expected = mapOf(
            "composables" to listOf(
                "ksafe: KSafe",
                "plain: KSafePlain",
                "encrypted: KSafeEncrypted",
                "hardwareIsolated: KSafeHardwareIsolated",
                "holder: HoldsKSafe",
            ),
            "classes" to listOf(
                "class eu.anifantakis.ksafe.stabilitycheck.HoldsKSafe {",
                "val ksafe: KSafe",
            ),
        )

        val missing = mutableListOf<String>()
        val unstable = mutableListOf<Pair<String, String>>()
        expected.forEach { (kind, declarations) ->
            val file = reports.get().file("$reportPrefix-$kind.txt").asFile
            if (!file.isFile) throw GradleException("Compose compiler report missing: $file")
            val lines = file.readLines().map(String::trim)
            declarations.forEach { declaration ->
                // Whole-line match: "unstable ksafe: KSafe" contains "stable ksafe: KSafe".
                val line = lines.firstOrNull { it.substringAfter(' ') == declaration }
                when {
                    line == null -> missing += "  ${file.name}: no line for \"$declaration\""
                    line != "stable $declaration" ->
                        unstable += declaration to "  ${file.name}: \"$line\", expected \"stable $declaration\""
                }
            }
        }

        if (missing.isNotEmpty() || unstable.isNotEmpty()) {
            val hints = buildList {
                if (unstable.any { it.first in ownTypes }) add(
                    "Each of KSafe, KSafePlain, KSafeEncrypted and KSafeHardwareIsolated needs its own @Stable. " +
                        "Without it, a composable taking one cannot skip when strong skipping is off, and an " +
                        "app class holding one turns unstable."
                )
                if (unstable.isNotEmpty() && unstable.none { it.first in ownTypes }) add(
                    "Only the HoldsKSafe fixture turned unstable: it must hold nothing but a KSafe."
                )
                if (missing.isNotEmpty()) add(
                    "Expected lines are missing: the Compose compiler may have changed its report format."
                )
            }
            throw GradleException(
                "Compose stability check failed:\n" +
                    (missing + unstable.map { it.second }).joinToString("\n") +
                    "\n\n" + hints.joinToString("\n") + "\nReports: ${reports.get().asFile}"
            )
        }
        logger.lifecycle(
            "Compose stability OK: KSafe, KSafePlain, KSafeEncrypted, KSafeHardwareIsolated and a class holding a KSafe are stable."
        )
    }
}

tasks.named("check") { dependsOn(verifyStability) }
