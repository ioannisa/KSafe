package eu.anifantakis.lib.ksafe.biometrics

import org.junit.runner.notification.RunNotifier
import org.junit.runners.BlockJUnit4ClassRunner
import org.junit.runners.model.FrameworkMethod
import kotlin.reflect.KClass

/** A precondition a test needs: the reason it is not met, or null when it is. */
internal interface SkipCondition {
    fun skipReason(): String?
}

/** Skips the test unless every condition holds; a class-level one applies to all its tests. */
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS)
@Retention(AnnotationRetention.RUNTIME)
internal annotation class SkipUnless(vararg val conditions: KClass<out SkipCondition>)

// Reported as ignored, not as an Assume failure: Gradle hands the latter to the test-retry
// plugin as a failure, which retries the skip and finally counts it as failed.
internal class SkipConditionRunner(klass: Class<*>) : BlockJUnit4ClassRunner(klass) {

    override fun runChild(method: FrameworkMethod, notifier: RunNotifier) {
        val reason = skipReason(method)
        if (reason == null) {
            super.runChild(method, notifier)
            return
        }
        println("${testClass.javaClass.simpleName}.${method.name} skipped: $reason")
        notifier.fireTestIgnored(describeChild(method))
    }

    private fun skipReason(method: FrameworkMethod): String? {
        val declared = listOfNotNull(
            testClass.javaClass.getAnnotation(SkipUnless::class.java),
            method.getAnnotation(SkipUnless::class.java),
        )
        return declared.asSequence()
            .flatMap { it.conditions.asSequence() }
            .map { instantiate(it.java) }
            .firstNotNullOfOrNull { it.skipReason() }
    }

    // Plain reflection: kotlin-reflect is not on the test classpath. Objects expose INSTANCE.
    private fun instantiate(type: Class<out SkipCondition>): SkipCondition {
        val singleton = runCatching {
            type.getDeclaredField("INSTANCE").apply { isAccessible = true }.get(null)
        }.getOrNull()
        return (singleton ?: type.getDeclaredConstructor().apply { isAccessible = true }.newInstance()) as SkipCondition
    }
}
