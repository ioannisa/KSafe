package eu.anifantakis.lib.ksafe

import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

class IosKSafeTest : KSafeTest() {
    
    @OptIn(ExperimentalUuidApi::class)
    override fun createKSafe(fileName: String?): KSafe {
        // If no filename is provided, generate a unique one for each test
        // to avoid DataStore conflicts on iOS
        val actualFileName = fileName ?: Uuid.random().toString()
            .lowercase()
            .filter { it in 'a'..'z' }
            .take(20) // Limit length to keep it reasonable
        return KSafe(actualFileName)
    }
}