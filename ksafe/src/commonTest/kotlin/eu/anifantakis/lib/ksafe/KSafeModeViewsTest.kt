package eu.anifantakis.lib.ksafe

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlinx.coroutines.test.runTest

/**
 * Locks in the mode-view contract: `KSafePlain` / `KSafeEncrypted` / `KSafeHardwareIsolated`
 * freeze the write mode at the type level, share the underlying store, and preserve the
 * delegate key-from-property-name derivation through forwarding.
 */
abstract class KSafeModeViewsTest {
    private val tracked = mutableListOf<KSafe>()

    protected abstract fun newKSafe(fileName: String? = null): KSafe

    fun createKSafe(fileName: String? = null): KSafe =
        newKSafe(fileName).also { tracked += it }

    @AfterTest
    fun tearDown() {
        tracked.forEach { runCatching { it.close() } }
        tracked.clear()
    }

    // ── frozen modes ─────────────────────────────────────────────────────────

    @Test
    fun plainViewFreezesPlainMode() = runTest {
        val ksafe = createKSafe()
        assertEquals(KSafeWriteMode.Plain, KSafePlain(ksafe).mode)
    }

    @Test
    fun encryptedViewInheritsTheInstanceUnlockPolicyByDefault() = runTest {
        val ksafe = createKSafe()
        // The default-constructed view must behave exactly like a modeless ksafe.put.
        assertEquals(ksafe.defaultWriteMode, KSafeEncrypted(ksafe).mode)
    }

    @Test
    fun encryptedViewFreezesAnExplicitUnlockPolicy() = runTest {
        val ksafe = createKSafe()
        assertEquals(
            KSafeWriteMode.Encrypted(KSafeEncryptedProtection.DEFAULT, requireUnlockedDevice = true),
            KSafeEncrypted(ksafe, requireUnlockedDevice = true).mode,
        )
    }

    @Test
    fun hardwareIsolatedViewFreezesTheIsolatedTier() = runTest {
        val ksafe = createKSafe()
        val expectedUnlock =
            (ksafe.defaultWriteMode as? KSafeWriteMode.Encrypted)?.requireUnlockedDevice ?: false
        assertEquals(
            KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED, expectedUnlock),
            KSafeHardwareIsolated(ksafe).mode,
        )
    }

    // ── writes record the frozen tier ────────────────────────────────────────

    @Test
    fun writesThroughEachViewRecordTheFrozenTier() = runTest {
        val ksafe = createKSafe()

        KSafePlain(ksafe).put("view_plain", "p")
        KSafeEncrypted(ksafe).put("view_encrypted", "e")
        KSafeHardwareIsolated(ksafe).put("view_isolated", "h")

        // A plain entry records no protection tier; the encrypted tiers record the REQUEST
        // (hardware isolation may still degrade in custody — that is reported elsewhere).
        assertNull(ksafe.getKeyInfo("view_plain")?.protection)
        assertEquals(KSafeProtection.DEFAULT, ksafe.getKeyInfo("view_encrypted")?.protection)
        assertEquals(KSafeProtection.HARDWARE_ISOLATED, ksafe.getKeyInfo("view_isolated")?.protection)
    }

    @Test
    fun directWritesThroughEachViewRecordTheFrozenTier() = runTest {
        val ksafe = createKSafe()

        KSafePlain(ksafe).putDirect("view_plain_d", 1)
        KSafeHardwareIsolated(ksafe).putDirect("view_isolated_d", 3)

        assertNull(ksafe.getKeyInfo("view_plain_d")?.protection)
        assertEquals(KSafeProtection.HARDWARE_ISOLATED, ksafe.getKeyInfo("view_isolated_d")?.protection)
    }

    // ── direct handles — the invoke result used without `by` ─────────────────

    @Test
    fun handleReadsAndWritesWithoutDelegation() = runTest {
        val ksafe = createKSafe()
        val counter = ksafe(0, key = "ref_counter")

        assertEquals(0, counter.value)
        counter.value++
        counter.value++
        assertEquals(2, counter.value)
        assertEquals(2, ksafe.getDirect("ref_counter", 0))
    }

    @Test
    fun handlesThroughEachViewRecordTheFrozenTier() = runTest {
        val ksafe = createKSafe()

        KSafePlain(ksafe)(0, key = "ref_plain").value = 1
        KSafeEncrypted(ksafe)(0, key = "ref_encrypted").value = 2
        KSafeHardwareIsolated(ksafe)(0, key = "ref_isolated").value = 3

        assertNull(ksafe.getKeyInfo("ref_plain")?.protection)
        assertEquals(KSafeProtection.DEFAULT, ksafe.getKeyInfo("ref_encrypted")?.protection)
        assertEquals(KSafeProtection.HARDWARE_ISOLATED, ksafe.getKeyInfo("ref_isolated")?.protection)
    }

    @Test
    fun handleSharesTheStoreWithTheDirectApi() = runTest {
        val ksafe = createKSafe()
        val handle = KSafePlain(ksafe)("", key = "ref_shared")

        ksafe.putDirect("ref_shared", "written-directly")
        assertEquals("written-directly", handle.value)

        handle.value = "written-via-handle"
        assertEquals("written-via-handle", ksafe.getDirect("ref_shared", ""))
    }

    @Test
    fun keylessHandleRejectsDirectValueAccess() = runTest {
        val ksafe = createKSafe()
        // Without a key the handle is delegate-only: `=` gives Kotlin no property name.
        val handle = ksafe(0)

        assertFailsWith<IllegalStateException> { handle.value }
        assertFailsWith<IllegalStateException> { handle.value = 1 }
    }

    // ── views share the store; reads are untyped ─────────────────────────────

    @Test
    fun viewsShareTheUnderlyingStoreAndReadsAreUntyped() = runTest {
        val ksafe = createKSafe()

        KSafePlain(ksafe).put("shared_key", "written-plain")

        // Same value through the raw instance AND through a differently-typed view:
        // the type constrains writes, never reads.
        assertEquals("written-plain", ksafe.get("shared_key", ""))
        assertEquals("written-plain", KSafeEncrypted(ksafe).get("shared_key", ""))
        assertEquals("written-plain", KSafeHardwareIsolated(ksafe).getDirect("shared_key", ""))
    }

    @Test
    fun sugarAccessorsBindToTheSameInstance() = runTest {
        val ksafe = createKSafe()
        assertSame(ksafe, ksafe.plain.ksafe)
        assertSame(ksafe, ksafe.encrypted.ksafe)
        assertSame(ksafe, ksafe.hardwareIsolated.ksafe)
    }

    // ── delegates: key derivation survives forwarding ────────────────────────

    @Test
    fun delegateWithoutKeyStillUsesThePropertyName() = runTest {
        val ksafe = createKSafe()
        val prefs = KSafePlain(ksafe)

        var viewCounter by prefs(0)
        viewCounter = 41

        // The delegate resolved `property.name` at the real property site, not in the view.
        assertEquals(41, ksafe.getDirect("viewCounter", 0))
        assertNull(ksafe.getKeyInfo("viewCounter")?.protection)
    }

    @Test
    fun delegateExplicitKeyIsForwardedUntouched() = runTest {
        val ksafe = createKSafe()
        val vault = KSafeHardwareIsolated(ksafe)

        var token by vault("", key = "vault.token")
        token = "secret"

        assertEquals("secret", ksafe.getDirect("vault.token", ""))
        assertEquals(KSafeProtection.HARDWARE_ISOLATED, ksafe.getKeyInfo("vault.token")?.protection)
    }

    @Test
    fun writableFlowThroughAViewWritesWithTheFrozenMode() = runTest {
        val ksafe = createKSafe()
        val prefs = KSafePlain(ksafe)

        val favourite by prefs.asWritableFlow("", key = "wf_plain")
        favourite.set("value")

        assertEquals("value", ksafe.getDirect("wf_plain", ""))
        assertNull(ksafe.getKeyInfo("wf_plain")?.protection)
    }

    @Test
    fun mutableStateFlowThroughAViewWritesWithTheFrozenMode() = runTest {
        val ksafe = createKSafe()
        val vault = KSafeEncrypted(ksafe)

        val state by vault.asMutableStateFlow(0, backgroundScope, key = "msf_encrypted")
        state.value = 9

        assertEquals(9, ksafe.get("msf_encrypted", 0))
        assertEquals(KSafeProtection.DEFAULT, ksafe.getKeyInfo("msf_encrypted")?.protection)
    }
}
