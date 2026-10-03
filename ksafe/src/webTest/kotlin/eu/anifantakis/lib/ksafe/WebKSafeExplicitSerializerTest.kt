package eu.anifantakis.lib.ksafe

class WebKSafeExplicitSerializerTest : KSafeExplicitSerializerTest() {
    override fun newKSafe(fileName: String?): KSafe =
        KSafe(
            fileName = fileName ?: WebKSafeTest.generateUniqueFileName(),
            testEngine = FakeEncryption(),
        )
}
