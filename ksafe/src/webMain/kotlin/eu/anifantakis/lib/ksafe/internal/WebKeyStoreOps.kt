package eu.anifantakis.lib.ksafe.internal

/**
 * The wire protocol between the Kotlin actuals and the shared JS dispatcher.
 *
 * Both the js and wasmJs bindings and [WebKeyStoreJsSource.OP_ROUTING] used to spell these seven
 * tokens independently, three times over. The routing has no default-reject — its fallthrough is
 * [DELETE] — so a token typo'd or renamed on one side alone does not error: it falls through and
 * DELETES the key instead. Spelling them once removes that failure mode entirely.
 *
 * `const val`s so [WebKeyStoreJsSource.OP_ROUTING] (itself a `const val`, as both targets' interop
 * requires) can interpolate them.
 */
internal object WebKeyStoreOps {
    const val ENSURE: String = "ensure"
    const val ENSURE_NO_MINT: String = "ensureNoMint"
    const val ENCRYPT: String = "enc"
    const val DECRYPT: String = "dec"
    const val COPY_KEY: String = "copyKey"

    /** The dispatcher's fallthrough: it needs no `if` arm, which also makes it the one typo-safe token. */
    const val DELETE: String = "del"
    const val DELETE_NO_WAIT: String = "delnw"
}
