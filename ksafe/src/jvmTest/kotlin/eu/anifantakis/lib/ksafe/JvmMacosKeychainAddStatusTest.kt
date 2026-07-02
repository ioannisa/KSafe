package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.keyvault.macosKeychainAddIsFailure
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * FEEDBACK_4 low: [MacosKeychainKeyVault.put] is a delete-then-add upsert. If the add
 * returns `errSecDuplicateItem`, the preceding delete failed to remove the existing item —
 * the NEW key was never stored and the stale one remains. Swallowing it (the old behavior)
 * reported success while silently losing the write, making data re-encrypted under the
 * intended key undecryptable. `put` must fail closed. The keychain I/O can't run in a unit
 * test, so the pure status decision is verified here.
 */
class JvmMacosKeychainAddStatusTest {

    @Test
    fun onlyErrSecSuccessIsNotAFailure_duplicateItemMustFailClosed() {
        assertFalse(macosKeychainAddIsFailure(0), "errSecSuccess (0) is the only success")
        assertTrue(
            macosKeychainAddIsFailure(-25299),
            "errSecDuplicateItem must be treated as a failure (the delete-then-add didn't replace the key) — low",
        )
        assertTrue(macosKeychainAddIsFailure(-25300), "errSecItemNotFound on add is a failure")
        assertTrue(macosKeychainAddIsFailure(-25308), "any other non-success OSStatus is a failure")
    }
}
