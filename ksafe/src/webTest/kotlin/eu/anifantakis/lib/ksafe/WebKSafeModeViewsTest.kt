package eu.anifantakis.lib.ksafe

/** Web (wasmJs + js) binding for the shared mode-views suite. */
class WebKSafeModeViewsTest : KSafeModeViewsTest() {
    override fun newKSafe(fileName: String?): KSafe =
        KSafe(
            fileName = fileName ?: WebKSafeTest.generateUniqueFileName(),
            testEngine = FakeEncryption(),
        )
}
