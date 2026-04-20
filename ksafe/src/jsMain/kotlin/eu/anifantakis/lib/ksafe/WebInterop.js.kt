package eu.anifantakis.lib.ksafe

import kotlinx.browser.localStorage
import kotlin.js.Date

/**
 * Kotlin/JS actual implementations of the web-interop surface.
 *
 * Unlike wasmJs, Kotlin/JS has rich built-in bindings for browser globals
 * (`kotlinx.browser.localStorage`, `kotlin.js.Date`), so these actuals are
 * noticeably shorter than their wasmJs counterparts.
 */

@PublishedApi
internal actual fun localStorageGet(key: String): String? = localStorage.getItem(key)

@PublishedApi
internal actual fun localStorageSet(key: String, value: String) {
    localStorage.setItem(key, value)
}

@PublishedApi
internal actual fun localStorageRemove(key: String) {
    localStorage.removeItem(key)
}

@PublishedApi
internal actual fun localStorageLength(): Int = localStorage.length

@PublishedApi
internal actual fun localStorageKey(index: Int): String? = localStorage.key(index)

@PublishedApi
internal actual fun currentTimeMillisWeb(): Long = Date.now().toLong()
