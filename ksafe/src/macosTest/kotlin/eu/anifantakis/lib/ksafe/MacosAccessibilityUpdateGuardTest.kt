package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.accessibilityUpdateNeeded
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * FEEDBACK_4 FB3-M4: [AppleKeychainEncryption.updateKeyAccessibility] fired three
 * `SecItemUpdate` IPC round-trips on EVERY HARDWARE_ISOLATED write. Those are only
 * needed on an actual policy change; a same-policy rewrite (the common case) is pure
 * overhead. The guard skips the IPC when the target policy equals the last one applied
 * this process. The live SecItemUpdate can't run in a sandboxed test, so the pure guard
 * decision is verified here.
 */
class MacosAccessibilityUpdateGuardTest {

    @Test
    fun updateNeeded_onlyWhenPolicyChangesFromLastApplied() {
        // Not yet applied this process → must update (assert the correct accessibility).
        assertTrue(accessibilityUpdateNeeded(lastApplied = null, target = true))
        assertTrue(accessibilityUpdateNeeded(lastApplied = null, target = false))

        // Same policy as last applied → skip the IPC (the FB3-M4 win).
        assertFalse(accessibilityUpdateNeeded(lastApplied = true, target = true))
        assertFalse(accessibilityUpdateNeeded(lastApplied = false, target = false))

        // Policy changed (tighten or loosen) → must re-assert.
        assertTrue(accessibilityUpdateNeeded(lastApplied = false, target = true), "loosen→tighten must update")
        assertTrue(accessibilityUpdateNeeded(lastApplied = true, target = false), "tighten→loosen must update")
    }
}
