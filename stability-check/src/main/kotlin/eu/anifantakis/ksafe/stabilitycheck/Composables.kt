package eu.anifantakis.ksafe.stabilitycheck

import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.KSafeEncrypted
import eu.anifantakis.lib.ksafe.KSafeHardwareIsolated
import eu.anifantakis.lib.ksafe.KSafePlain

// Never called. verifyStability reads what the Compose compiler reports about these signatures.

@Composable
fun TakesKSafe(ksafe: KSafe) {
    SideEffect { println(ksafe) }
}

@Composable
fun TakesPlain(plain: KSafePlain) {
    SideEffect { println(plain) }
}

@Composable
fun TakesEncrypted(encrypted: KSafeEncrypted) {
    SideEffect { println(encrypted) }
}

@Composable
fun TakesHardwareIsolated(hardwareIsolated: KSafeHardwareIsolated) {
    SideEffect { println(hardwareIsolated) }
}

/** An app class that holds a KSafe, such as a dependency container passed down to the UI. */
class HoldsKSafe(val ksafe: KSafe)

@Composable
fun TakesHoldsKSafe(holder: HoldsKSafe) {
    SideEffect { println(holder) }
}
