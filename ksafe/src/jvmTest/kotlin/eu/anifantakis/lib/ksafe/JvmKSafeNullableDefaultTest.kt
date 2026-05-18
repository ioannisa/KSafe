package eu.anifantakis.lib.ksafe

/** JVM binding for the issue #31 regression suite. */
class JvmKSafeNullableDefaultTest : KSafeNullableDefaultTest() {
    override fun newKSafe(fileName: String?): KSafe =
        KSafe(JvmKSafeTest.generateUniqueFileName())
}
