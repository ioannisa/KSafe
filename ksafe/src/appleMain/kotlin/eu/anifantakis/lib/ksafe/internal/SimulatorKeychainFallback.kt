package eu.anifantakis.lib.ksafe.internal

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.autoreleasepool
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.refTo
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH
import platform.Foundation.NSApplicationSupportDirectory
import platform.Foundation.NSData
import platform.Foundation.NSFileManager
import platform.Foundation.NSUserDomainMask
import platform.Foundation.create
import platform.Foundation.dataWithContentsOfFile
import platform.Foundation.writeToFile
import platform.posix.memcpy

// Simulator-only escape hatch for an entitlement-blocked (-34018) Keychain: the Simulator's own
// Keychain is just a file on the host Mac, so a sandbox-file key is the same trust tier. Never
// built on a device. Sticky: once an alias has a fallback key it wins over the Keychain for good.
internal interface SimulatorFallbackKeyStore {
    fun read(account: String): ByteArray?

    /** Throws if the bytes cannot be durably written. */
    fun write(account: String, bytes: ByteArray)

    /** No-op if absent; never throws. */
    fun delete(account: String)
}

// One file per account, named by SHA-256 because accounts embed arbitrary user key strings.
@OptIn(ExperimentalForeignApi::class)
internal class FileSimulatorFallbackKeyStore(
    private val serviceName: String,
) : SimulatorFallbackKeyStore {

    private val dirPath: String by lazy {
        val base = NSFileManager.defaultManager.URLForDirectory(
            directory = NSApplicationSupportDirectory,
            inDomain = NSUserDomainMask,
            appropriateForURL = null,
            create = true,
            error = null,
        )?.path ?: throw IllegalStateException(
            "KSafe: cannot resolve NSApplicationSupportDirectory for the Simulator fallback key store"
        )
        "$base/$serviceName.simfallback"
    }

    private fun filePath(account: String): String = "$dirPath/${sha256Hex(account)}.key"

    override fun read(account: String): ByteArray? =
        autoreleasepool {
            NSData.dataWithContentsOfFile(filePath(account))?.toByteArray()
        }

    @OptIn(ExperimentalForeignApi::class)
    override fun write(account: String, bytes: ByteArray) {
        val ok = autoreleasepool {
            // Pooled: the bridged NSStrings would otherwise pile up on the caller's pool.
            NSFileManager.defaultManager.createDirectoryAtPath(
                dirPath,
                withIntermediateDirectories = true,
                attributes = null,
                error = null,
            )
            memScoped {
                val nsData = if (bytes.isEmpty()) NSData() else NSData.create(
                    bytes = bytes.refTo(0).getPointer(this),
                    length = bytes.size.toULong(),
                )
                nsData.writeToFile(filePath(account), atomically = true)
            }
        }
        // Fail closed: a key that lives only in memory makes its ciphertext unreadable after
        // the next relaunch.
        if (!ok) throw IllegalStateException(
            "KSafe: failed to persist the Simulator fallback key for account $account"
        )
    }

    override fun delete(account: String) {
        autoreleasepool {
            NSFileManager.defaultManager.removeItemAtPath(filePath(account), error = null)
        }
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun NSData.toByteArray(): ByteArray =
        ByteArray(this.length.toInt()).apply {
            if (isNotEmpty()) usePinned {
                memcpy(it.addressOf(0), this@toByteArray.bytes, this@toByteArray.length)
            }
        }

    @OptIn(ExperimentalForeignApi::class)
    private fun sha256Hex(s: String): String {
        val input = s.encodeToByteArray()
        val digest = UByteArray(CC_SHA256_DIGEST_LENGTH)
        digest.usePinned { out ->
            if (input.isEmpty()) {
                CC_SHA256(null, 0u, out.addressOf(0))
            } else {
                input.usePinned { pinned ->
                    CC_SHA256(pinned.addressOf(0), input.size.toUInt(), out.addressOf(0))
                }
            }
        }
        return ByteArray(digest.size) { digest[it].toByte() }.toLowercaseHex()
    }
}
