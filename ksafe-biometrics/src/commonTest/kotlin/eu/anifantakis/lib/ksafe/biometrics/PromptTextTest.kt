package eu.anifantakis.lib.ksafe.biometrics

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Locks in that blank prompt text is treated as absent rather than passed through.
 *
 * Android's `PromptInfo` rejects an empty title, and that rejection reaches the caller as a plain
 * `false` from `verifyBiometric` — so a caller whose string resource or config field resolved to
 * `""` would see every authentication deny, with a stderr line as the only trace. `null` already
 * means "choose a default for me"; blank means the same thing from code that did not know to send
 * `null`.
 */
class PromptTextTest {

    @Test
    fun blankTextIsAbsent_soThePlatformDefaultIsUsed() {
        assertNull(promptTextOrNull(""), "an empty string must not reach the platform prompt")
        assertNull(promptTextOrNull(" "), "whitespace is not a usable prompt title")
        assertNull(promptTextOrNull("\t\n"), "neither are other blank runs")
        assertNull(promptTextOrNull(null), "null keeps meaning absent")
    }

    @Test
    fun realTextSurvivesVerbatim() {
        assertEquals("My App", promptTextOrNull("My App"))
        // Leading/trailing space is the caller's wording, not ours to trim: only a fully blank
        // value is meaningless, and a prompt reading " Sign in " is odd but honours what was asked.
        assertEquals(" Sign in ", promptTextOrNull(" Sign in "))
        assertEquals("0", promptTextOrNull("0"), "a short title is still a title")
    }
}
