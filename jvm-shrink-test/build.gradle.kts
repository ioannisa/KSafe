import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.time.Duration
import java.util.zip.ZipFile

// Shrinks two tiny desktop apps, runs them, and fails if shrinking broke KSafe. Both modules reach
// the OS through JNA, which shrinkers break unless the rules in the module's jar
// (META-INF/proguard/ksafe.pro, META-INF/proguard/ksafe-biometrics.pro) keep what JNA looks up by name.
//   vault      — uses :ksafe; must still keep its keys in the OS secret store, read back every stored
//                type, and read what the unshrunk app wrote (and the other way round).
//   biometrics — uses :ksafe-biometrics alone; its native bridges must still load and answer as
//                they do unshrunk. It never shows a prompt.
//   compose    — uses :ksafe-compose; a mutableStateOf delegate must still save and read back.
//
//   ./gradlew :jvm-shrink-test:shrinkTest
//
// Needs a reachable OS secret store (the key vault CI jobs set one up), so `check` does not run it.

plugins {
    alias(libs.plugins.kotlinJvm)
    alias(libs.plugins.kotlin.serialization)
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

val biometrics = sourceSets.create("biometrics")
val compose = sourceSets.create("compose")

val r8 = configurations.create("r8")
val proguardDefault = configurations.create("proguard")
val proguardLatest = configurations.create("proguardLatest")
val composeGradlePlugin = configurations.create("composeGradlePlugin") { isTransitive = false }

dependencies {
    implementation(project(":ksafe"))
    "biometricsImplementation"(project(":ksafe-biometrics"))
    "biometricsImplementation"(libs.kotlinx.coroutines.core)
    // The probe binds the Touch ID reply callback through JNA itself.
    "biometricsImplementation"(libs.jna)
    "composeImplementation"(project(":ksafe-compose"))
    r8(libs.r8)
    proguardDefault(libs.proguard.base)
    proguardLatest(libs.proguard.base.latest)
    composeGradlePlugin(libs.compose.gradle.plugin)
}

val biometricsJar = tasks.register<Jar>("biometricsJar") {
    archiveClassifier.set("biometrics")
    from(biometrics.output)
}

val composeJar = tasks.register<Jar>("composeJar") {
    archiveClassifier.set("compose")
    from(compose.output)
}

val shrinkDir = layout.buildDirectory.dir("shrink-test")

/** One way of running ProGuard; [obfuscate] is Compose's `proguard { obfuscate }`, off by default. */
class ProguardSetup(val tool: String, val proguard: Configuration, val obfuscate: Boolean)

val proguardSetups = listOf(
    ProguardSetup("Proguard", proguardDefault, obfuscate = false),
    ProguardSetup("ProguardObfuscated", proguardDefault, obfuscate = true),
    ProguardSetup("ProguardLatest", proguardLatest, obfuscate = false),
)

/**
 * Shrinks [app] with R8 and with each [proguardSetups] entry, and runs each result; the app exits
 * non-zero when its own checks fail. [compareWithUnshrunk]: the shrunk app's result.txt must match an
 * unshrunk run. [crossBuild]: where a shrinker renames classes, an unshrunk build reads what the shrunk
 * one wrote and the other way round. [forbiddenEntries]: jar entries the app's classpath must not
 * carry, so another module's rules cannot hide a gap in this one's.
 */
fun registerShrinkTest(
    app: String,
    appJar: TaskProvider<Jar>,
    runtimeClasspath: Configuration,
    mainClassName: String,
    rulesEntry: String,
    compareWithUnshrunk: Boolean,
    crossBuild: Boolean,
    forbiddenEntries: List<String> = emptyList(),
): List<TaskProvider<JavaExec>> {
    val name = app.replaceFirstChar(Char::uppercase)
    val programJars = files(appJar, runtimeClasspath)

    // One file per shrink task: they run in parallel.
    fun Task.prepare(appRules: Provider<RegularFile>) = doFirst {
        appRules.get().asFile.apply { parentFile.mkdirs() }.writeText(
            "-keep class $mainClassName {\n    public static void main(java.lang.String[]);\n}\n"
        )
        programJars.files.forEach { jar ->
            ZipFile(jar).use { zip ->
                forbiddenEntries.forEach { check(zip.getEntry(it) == null) { "$jar must not carry $it" } }
            }
        }
    }

    // R8 in full mode, as a desktop build would run it. R8 reads the rules embedded in the jars itself.
    val r8Task = tasks.register<JavaExec>("r8$name") {
        // Locals, not script properties: the configuration cache cannot serialize the script.
        val jars = programJars
        val jdkHome = javaToolchains.launcherFor(java.toolchain).map { it.metadata.installationPath.asFile.absolutePath }
        val rules = shrinkDir.map { it.file("$app/r8-app-rules.pro") }
        val output = shrinkDir.map { it.file("$app/r8/app.jar") }
        inputs.files(jars)
        outputs.file(output)
        classpath(r8)
        mainClass.set("com.android.tools.r8.R8")
        prepare(rules)
        argumentProviders.add(CommandLineArgumentProvider {
            listOf(
                "--release", "--classfile",
                "--lib", jdkHome.get(),
                "--pg-conf", rules.get().asFile.absolutePath,
                "--output", output.get().asFile.absolutePath,
            ) + jars.files.map { it.absolutePath }
        })
    }

    // ProGuard configured the way a Compose Desktop release build configures it: optimize on, the
    // JDK's jmods as library jars, Compose's default rules, plus the app's rule files. Compose does
    // not read rules from jars, so the app lists KSafe's file itself; this takes it from the jar.
    val proguardTasks = proguardSetups.map { setup ->
        setup to tasks.register<JavaExec>("${setup.tool.replaceFirstChar(Char::lowercase)}$name") {
            val jars = programJars
            val composePluginJars = files(composeGradlePlugin)
            // A JDK with jmods: some, like the JetBrains Runtime, ship without them.
            val launcher = javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }
            val rules = shrinkDir.map { it.file("$app/${setup.tool.lowercase()}-app-rules.pro") }
            val ksafeRulesEntry = rulesEntry
            val obfuscate = setup.obfuscate
            val output = shrinkDir.map { it.dir("$app/${setup.tool.lowercase()}") }
            val configDir = shrinkDir.map { it.dir("$app/${setup.tool.lowercase()}-config") }
            inputs.files(jars, composePluginJars)
            inputs.property("obfuscate", obfuscate)
            outputs.dir(output)
            javaLauncher.set(launcher)
            classpath(setup.proguard)
            mainClass.set("proguard.ProGuard")
            prepare(rules)
            argumentProviders.add(CommandLineArgumentProvider {
                listOf("-include", configDir.get().file("root.pro").asFile.absolutePath)
            })
            doFirst {
                val dir = configDir.get().asFile.apply { deleteRecursively(); mkdirs() }
                val outDir = output.get().asFile.apply { deleteRecursively(); mkdirs() }

                fun extract(from: Iterable<File>, entryName: String, target: File): File {
                    val jar = from.singleOrNull { ZipFile(it).use { zip -> zip.getEntry(entryName) != null } }
                        ?: error("Expected exactly one jar with $entryName")
                    ZipFile(jar).use { zip -> zip.getInputStream(zip.getEntry(entryName)).use { target.writeBytes(it.readBytes()) } }
                    return target
                }
                val composeRules = extract(composePluginJars, "default-compose-desktop-rules.pro", File(dir, "compose.pro"))
                val ksafeRules = extract(jars, ksafeRulesEntry, File(dir, ksafeRulesEntry.substringAfterLast('/')))

                // Forward slashes: ProGuard reads a backslash in its configuration as an escape.
                fun File.path() = "'$invariantSeparatorsPath'"
                val config = StringBuilder(if (obfuscate) "" else "-dontobfuscate\n")
                jars.files.forEach { config.append("-injars ${it.path()}\n-outjars ${File(outDir, it.name).path()}\n") }
                val jmods = launcher.get().metadata.installationPath.dir("jmods").asFile
                check(jmods.isDirectory) { "ProGuard needs a JDK with jmods, and $jmods is missing" }
                jmods.listFiles { f -> f.name.endsWith(".jmod") }.orEmpty().sorted().forEach {
                    config.append("-libraryjars ${it.path()}(!**.jar;!module-info.class)\n")
                }
                listOf(composeRules, rules.get().asFile, ksafeRules).forEach { config.append("-include ${it.path()}\n") }
                File(dir, "root.pro").writeText(config.toString())
            }
        }
    }

    fun registerRun(
        taskName: String,
        classpathFiles: FileCollection,
        workDirName: String,
        phase: String? = null,
        clearWorkDir: Boolean = true,
        compareWith: Provider<Directory>? = null,
    ) = tasks.register<JavaExec>(taskName) {
        group = "verification"
        val workDir = shrinkDir.map { it.dir("$app/$workDirName") }
        val appName = app
        classpath(classpathFiles)
        mainClass.set(mainClassName)
        timeout.set(Duration.ofMinutes(5))
        // A shrunk run that is compared also gets the unshrunk run's directory.
        argumentProviders.add(CommandLineArgumentProvider {
            listOfNotNull(workDir.get().asFile.absolutePath, phase, compareWith?.get()?.asFile?.absolutePath)
        })
        if (clearWorkDir) doFirst { workDir.get().asFile.let { it.deleteRecursively(); it.mkdirs() } }
        if (compareWith != null) doLast {
            val unshrunk = compareWith.get().file("result.txt").asFile.readText()
            val shrunk = workDir.get().file("result.txt").asFile.readText()
            check(shrunk == unshrunk) {
                "The shrunk $appName app answered differently from the unshrunk one.\n" +
                    "unshrunk:\n$unshrunk\nshrunk:\n$shrunk"
            }
        }
    }

    fun shrunk(task: TaskProvider<JavaExec>) = files(task).asFileTree.matching { include("**/*.jar") }

    val unshrunkRun = if (compareWithUnshrunk) registerRun("run${name}Unshrunk", programJars, "run${name}Unshrunk") else null
    val baseline = unshrunkRun?.let { shrinkDir.map { it.dir("$app/run${name}Unshrunk") } }
    val shrinkers = listOf(Triple("R8", r8Task, true)) +
        proguardTasks.map { (setup, task) -> Triple(setup.tool, task, setup.obfuscate) }

    return shrinkers.flatMap { (tool, shrinkTask, renames) ->
        val run = registerRun("run$name$tool", shrunk(shrinkTask), "run$name$tool", compareWith = baseline)
        unshrunkRun?.let { u -> run.configure { dependsOn(u) } }
        if (!crossBuild || !renames) return@flatMap listOf(run)
        // Each pair shares a work directory, and so a store and its OS-store keys.
        fun pair(writerName: String, writer: FileCollection, readerName: String, reader: FileCollection): TaskProvider<JavaExec> {
            val dirName = "${writerName}To$readerName"
            val write = registerRun("run$name${dirName}Write", writer, dirName, phase = "write")
            return registerRun("run$name${dirName}Read", reader, dirName, phase = "read", clearWorkDir = false)
                .also { it.configure { dependsOn(write) } }
        }
        listOf(
            run,
            pair("Unshrunk", programJars, tool, shrunk(shrinkTask)),
            pair(tool, shrunk(shrinkTask), "Unshrunk", programJars),
        )
    }
}

val vaultRuns = registerShrinkTest(
    app = "vault",
    appJar = tasks.jar,
    runtimeClasspath = configurations.runtimeClasspath.get(),
    mainClassName = "eu.anifantakis.ksafe.shrinktest.MainKt",
    rulesEntry = "META-INF/proguard/ksafe.pro",
    compareWithUnshrunk = false,
    crossBuild = true,
)

val biometricsRuns = registerShrinkTest(
    app = "biometrics",
    appJar = biometricsJar,
    runtimeClasspath = configurations[biometrics.runtimeClasspathConfigurationName],
    mainClassName = "eu.anifantakis.ksafe.shrinktest.biometrics.MainKt",
    rulesEntry = "META-INF/proguard/ksafe-biometrics.pro",
    compareWithUnshrunk = true,
    crossBuild = false,
    forbiddenEntries = listOf("META-INF/proguard/ksafe.pro"),
)

val composeRuns = registerShrinkTest(
    app = "compose",
    appJar = composeJar,
    runtimeClasspath = configurations[compose.runtimeClasspathConfigurationName],
    mainClassName = "eu.anifantakis.ksafe.shrinktest.compose.MainKt",
    rulesEntry = "META-INF/proguard/ksafe.pro",
    compareWithUnshrunk = false,
    crossBuild = false,
)

tasks.register("shrinkTest") {
    group = "verification"
    description = "Shrinks KSafe desktop apps with R8 and ProGuard and checks the OS store, Compose state and biometric bridges still work."
    dependsOn(vaultRuns + biometricsRuns + composeRuns)
}
