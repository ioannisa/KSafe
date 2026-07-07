package eu.anifantakis.lib.ksafe

/** JVM binding for the shared nullable-default suite. */
class JvmKSafeNullableDefaultTest : KSafeNullableDefaultTest() {
    override fun newKSafe(fileName: String?): KSafe =
        KSafe(JvmKSafeTest.generateUniqueFileName())
}
