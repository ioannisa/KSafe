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

        private fun numberToLetters(num: Long): String {
            var n = num
            val sb = StringBuilder()
            while (n > 0) {
                n--
                sb.insert(0, ('a' + (n % 26).toInt()))
                n /= 26
            }
            return if (sb.isEmpty()) "a" else sb.toString()
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
