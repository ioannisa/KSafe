package eu.anifantakis.lib.ksafe.internal

import java.util.concurrent.atomic.AtomicBoolean

/**
 * A notice that prints at most once for the lifetime of the instance — one instance per distinct
 * notice, so an unrelated warning can never suppress another's first occurrence.
 *
 * Deliberately `System.err`, not [ksafeLogWarning]: these are security/degradation notices about
 * key custody and storage, and moving them onto stdout would bury them in application output.
 */
internal class OneShotWarning {
    private val fired = AtomicBoolean(false)

    fun warn(message: () -> String) {
        if (fired.compareAndSet(false, true)) System.err.println(message())
    }
}
