package eu.anifantakis.lib.ksafe

/**
 * Implementation of the common KSafe test suite for the JVM/desktop
 * platform.  This class bridges the abstract [KSafeTest] from
 * `commonTest` to the concrete JVM implementation by providing
 * an actual [KSafe] instance when requested.  The heavy lifting of
 * verifying encryption, decryption, flows and delegates is done in
 * the parent class.
 */
class JvmKSafeTest : KSafeTest() {
    /**
     * Create a new JVM implementation of [KSafe].  To avoid the DataStore
     * error "There are multiple DataStores active for the same file"
     * when tests run in parallel, we ensure that each test instance
     * creates a unique data store file by appending a random suffix
     * whenever [fileName] is `null`.  When a non‑null filename is
     * provided, we respect it unchanged.
     */
    override fun createKSafe(fileName: String?): KSafe {
        return if (fileName == null) {
            // Generate a random lower‑case alphabetic suffix to keep the
            // filename valid (`[a-z]+`).
            val rnd = kotlin.random.Random
            val randomSuffix = (1..12)
                .map { ('a' + rnd.nextInt(26)) }
                .joinToString("")
            KSafe("test_$randomSuffix")
        } else {
            KSafe(fileName)
        }
    }
}
