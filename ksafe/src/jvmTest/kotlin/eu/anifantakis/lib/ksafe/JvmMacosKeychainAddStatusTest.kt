package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.keyvault.macosKeychainAddIsFailure
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: only `errSecSuccess` counts as a successful keychain add — `errSecDuplicateItem` means the delete-then-add upsert never replaced the key, so `put` must fail closed.
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
