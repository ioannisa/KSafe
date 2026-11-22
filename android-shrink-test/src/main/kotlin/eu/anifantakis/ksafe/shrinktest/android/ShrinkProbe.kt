package eu.anifantakis.ksafe.shrinktest.android

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import android.util.Log
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

/**
 * `adb shell am instrument -w -e phase write|read -e expectedVersion <v> <pkg>/<pkg>.ShrinkProbe`
 *
 * Prints its results as `INSTRUMENTATION_RESULT: key=value` lines and ends with `probe=PASS` or
 * `probe=FAIL`. `am instrument` exits 0 either way, so the caller has to read the output.
 */
class ShrinkProbe : Instrumentation() {
    private var arguments = Bundle()

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        this.arguments = arguments ?: Bundle()
        start()
    }

    override fun onStart() {
        super.onStart()
        val results = Bundle()
        val passed = try {
            val probe = Probe(this, arguments.getString("expectedVersion"))
            val values = runBlocking {
                withTimeout(120_000) { probe.run(arguments.getString("phase") ?: "write") }
            }
            values.forEach { (key, value) -> results.putString(key, value) }
            if (probe.failed.isNotEmpty()) results.putString("failures", probe.failed.joinToString(" | "))
            probe.failed.isEmpty()
        } catch (t: Throwable) {
            results.putString("error", Log.getStackTraceString(t))
            false
        }
        results.putString("probe", if (passed) "PASS" else "FAIL")
        finish(if (passed) Activity.RESULT_OK else Activity.RESULT_CANCELED, results)
    }
}
