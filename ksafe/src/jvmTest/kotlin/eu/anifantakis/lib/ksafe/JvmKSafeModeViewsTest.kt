package eu.anifantakis.lib.ksafe

/** JVM binding for the shared mode-views suite. */
class JvmKSafeModeViewsTest : KSafeModeViewsTest() {
    override fun newKSafe(fileName: String?): KSafe =
        KSafe(fileName ?: JvmKSafeTest.generateUniqueFileName())
}
