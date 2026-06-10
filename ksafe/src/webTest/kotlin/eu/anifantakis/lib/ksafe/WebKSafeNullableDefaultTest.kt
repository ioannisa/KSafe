package eu.anifantakis.lib.ksafe

/** Web (wasmJs + js) binding for the nullable-default regression suite. */
class WebKSafeNullableDefaultTest : KSafeNullableDefaultTest() {
    override fun newKSafe(fileName: String?): KSafe =
        KSafe(
            fileName = fileName ?: WebKSafeTest.generateUniqueFileName(),
            testEngine = FakeEncryption(),
        )
}
