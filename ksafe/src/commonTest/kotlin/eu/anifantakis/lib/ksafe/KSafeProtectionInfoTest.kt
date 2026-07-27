package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class KSafeProtectionInfoTest {

    private fun info(
        intended: KSafeProtectionLevel,
        effective: KSafeProtectionLevel,
        notes: List<String>,
    ) = KSafeProtectionInfo(
        intendedLevel = intended,
        effectiveLevel = effective,
        custody = "test",
        notes = notes,
    )

    @Test
    fun operationalWhenNoNotes() {
        val i = info(KSafeProtectionLevel.SANDBOX_PROTECTED, KSafeProtectionLevel.SANDBOX_PROTECTED, emptyList())
        assertTrue(i.isEncryptionOperational)
    }

    @Test
    fun nonOperationalOnlyForWebSubtleUnavailable() {
        val i = info(
            KSafeProtectionLevel.SANDBOX_PROTECTED,
            KSafeProtectionLevel.SOFTWARE,
            listOf("web_crypto_subtle_unavailable"),
        )
        assertFalse(i.isEncryptionOperational)
    }

    @Test
    fun weakerButWorkingFallbacksStayOperational() {
        // A degrade to SOFTWARE that still encrypts (JVM software vault, iOS Simulator sandbox
        // store) must NOT be reported as broken — strength dropped, operability did not.
        val jvm = info(
            KSafeProtectionLevel.SANDBOX_PROTECTED,
            KSafeProtectionLevel.SOFTWARE,
            listOf("jvm_os_vault_unavailable"),
        )
        val simulator = info(
            KSafeProtectionLevel.HARDWARE_BACKED,
            KSafeProtectionLevel.SOFTWARE,
            listOf("apple_keychain_entitlement_missing", "apple_secure_enclave_absent"),
        )
        assertTrue(jvm.isEncryptionOperational)
        assertTrue(simulator.isEncryptionOperational)
    }
}
