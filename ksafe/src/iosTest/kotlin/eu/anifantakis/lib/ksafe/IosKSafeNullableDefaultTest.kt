package eu.anifantakis.lib.ksafe

import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/** iOS (native) binding for the nullable-default regression suite. */
class IosKSafeNullableDefaultTest : KSafeNullableDefaultTest() {
    @OptIn(ExperimentalUuidApi::class)
    override fun newKSafe(fileName: String?): KSafe {
        val name = fileName ?: Uuid.random().toString()
            .lowercase()
            .filter { it in 'a'..'z' }
            .take(20)
        return KSafe(fileName = name, testEngine = FakeEncryption())
    }
}
