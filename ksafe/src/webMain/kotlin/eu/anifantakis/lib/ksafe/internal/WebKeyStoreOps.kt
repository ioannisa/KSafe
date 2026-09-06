package eu.anifantakis.lib.ksafe.internal

/**
 * Wire protocol between the Kotlin actuals and the shared JS dispatcher, spelled once. The routing
 * has no default-reject arm — its fallthrough is [DELETE] — so a token typo'd on one side deletes.
 */
internal object WebKeyStoreOps {
    const val ENSURE: String = "ensure"
    const val ENSURE_NO_MINT: String = "ensureNoMint"
    const val ENCRYPT: String = "enc"
    const val DECRYPT: String = "dec"
    const val COPY_KEY: String = "copyKey"
    const val DELETE: String = "del"
    const val DELETE_NO_WAIT: String = "delnw"
}
