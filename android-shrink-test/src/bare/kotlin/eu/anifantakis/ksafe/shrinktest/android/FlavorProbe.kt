package eu.anifantakis.ksafe.shrinktest.android

import android.app.Instrumentation
import eu.anifantakis.lib.ksafe.KSafe

/** KSafe alone: no ksafe-compose or ksafe-biometrics in this flavor. */
object FlavorProbe {
    val KEYS = emptyList<String>()

    fun write(ksafe: KSafe) = Unit

    fun verify(ksafe: KSafe, stage: String, check: (String, Any?, Any?) -> Unit) = Unit

    fun describe(
        instrumentation: Instrumentation,
        fact: (String, Any?) -> Unit,
        check: (String, Any?, Any?) -> Unit,
    ) = Unit
}
