package eu.anifantakis.lib.ksafe

/**
 * Web (wasmJs + js) [KSafeTest] runner. Uses [FakeEncryption] (WebCrypto needs a
 * browser) and a unique fileName per test to avoid `localStorage` collisions.
 */
class WebKSafeTest : KSafeTest() {

    companion object {
        private var testCounter = 0

        fun generateUniqueFileName(): String {
            testCounter++
            return numberToLetters(testCounter.toLong())
        }

    }

    override fun newKSafe(fileName: String?): KSafe {
        val uniqueName = fileName ?: generateUniqueFileName()
        return KSafe(
            fileName = uniqueName,
            testEngine = FakeEncryption()
        )
    }
}
