package eu.anifantakis.lib.ksafe

class JvmKSafeModeViewsTest : KSafeModeViewsTest() {
    override fun newKSafe(fileName: String?): KSafe =
        KSafe(fileName ?: JvmKSafeTest.generateUniqueFileName())
}
