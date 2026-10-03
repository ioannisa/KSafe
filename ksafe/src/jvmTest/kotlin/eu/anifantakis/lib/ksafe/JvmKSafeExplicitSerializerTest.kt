package eu.anifantakis.lib.ksafe

/** JVM binding for the shared explicit-serializer suite. */
class JvmKSafeExplicitSerializerTest : KSafeExplicitSerializerTest() {
    override fun newKSafe(fileName: String?): KSafe =
        KSafe(fileName ?: JvmKSafeTest.generateUniqueFileName())
}
