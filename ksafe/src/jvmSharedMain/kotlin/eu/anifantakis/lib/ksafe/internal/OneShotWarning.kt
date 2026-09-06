package eu.anifantakis.lib.ksafe.internal

import java.util.concurrent.atomic.AtomicBoolean

/** Prints at most once, so keep one instance per notice — a shared one would swallow the others.
 *  `System.err`, so key-custody warnings are not buried in application stdout. */
internal class OneShotWarning {
    private val fired = AtomicBoolean(false)

    fun warn(message: () -> String) {
        if (fired.compareAndSet(false, true)) System.err.println(message())
    }
}
