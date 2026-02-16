package eu.anifantakis.lib.ksafe

/**
 * WASM/JS test implementation.
 *
 * Uses FakeEncryption (synchronous XOR) for testing since WebCrypto
 * requires a browser environment. The test engine is injected via
 * the internal constructor.
 *
 * Each test gets a unique KSafe instance with a unique file name
 * to avoid localStorage key collisions between tests.
 */
class WasmJsKSafeTest : KSafeTest() {

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

    override fun createKSafe(fileName: String?): KSafe {
        val uniqueName = fileName ?: generateUniqueFileName()
        return KSafe(
            fileName = uniqueName,
            testEngine = FakeEncryption()
        )
    }
}
