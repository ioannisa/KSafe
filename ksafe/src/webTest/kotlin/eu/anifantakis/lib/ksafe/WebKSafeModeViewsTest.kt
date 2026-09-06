package eu.anifantakis.lib.ksafe

class WebKSafeModeViewsTest : KSafeModeViewsTest() {
    override fun newKSafe(fileName: String?): KSafe =
        KSafe(
            fileName = fileName ?: WebKSafeTest.generateUniqueFileName(),
            testEngine = FakeEncryption(),
        )
}
