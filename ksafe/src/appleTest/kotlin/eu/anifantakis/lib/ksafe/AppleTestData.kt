package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.get
import kotlinx.cinterop.reinterpret
import platform.Foundation.NSData

/**
 * Copies an [NSData] out as a Kotlin [ByteArray]. Shared by the iOS and macOS encryption-proof
 * tests, whose enclosing readers deliberately differ (iOS resolves the app-support directory
 * itself; macOS is handed an explicit temp directory so it never touches `~/Library`).
 */
@OptIn(ExperimentalForeignApi::class)
internal fun NSData.toTestByteArray(): ByteArray {
    val length = this.length.toInt()
    if (length == 0) return ByteArray(0)
    val ptr = this.bytes!!.reinterpret<UByteVar>()
    return ByteArray(length) { ptr[it].toByte() }
}
