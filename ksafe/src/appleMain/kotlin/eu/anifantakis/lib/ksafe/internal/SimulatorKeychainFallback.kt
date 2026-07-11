package eu.anifantakis.lib.ksafe.internal

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
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

/**
 * Simulator-only escape hatch for an entitlement-blocked Keychain.
 *
 * An app with no signing team / no Keychain Sharing capability gets
 * `errSecMissingEntitlement` (-34018) from every Keychain call on the iOS Simulator.
 * When that exact status is hit *on the Simulator*, [AppleKeychainEncryption] falls
 * back to this store instead of failing every encrypted write.
 *
 * Security: the Simulator's Keychain is itself just a file on the host Mac — no SEP,
 * no hardware — so a sandbox-file key here is the same trust tier, not a downgrade of
 * anything real. Real devices never construct this store (the factory gate is
 * [SecurityChecker.isEmulator]), so on-device a -34018 still fails loudly.
 *
 * Precedence is sticky: once a fallback key exists for an alias it wins over the
 * Keychain unconditionally, so every run of an install decrypts with the same key even
 * if the entitlement problem is later fixed. The degrade is reported through
 * `KSafe.protectionInfo` (`apple_keychain_entitlement_missing`).
 */
internal interface SimulatorFallbackKeyStore {
    /** Key bytes stored for [account], or null if none. */
    fun read(account: String): ByteArray?

    /** Persists [bytes] for [account]. Throws if the bytes cannot be durably written. */
    fun write(account: String, bytes: ByteArray)

    /** Removes the key for [account]. No-op if absent; never throws. */
    fun delete(account: String)
}

/**
 * Production [SimulatorFallbackKeyStore]: one file per account under
 * `Application Support/<serviceName>.simfallback/`, named by the SHA-256 of the account
 * (accounts embed arbitrary user key strings, so they can't be used as file names
 * directly). Writes are atomic (`NSDataWritingAtomic` semantics via `writeToFile`).
 */
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
        NSData.dataWithContentsOfFile(filePath(account))?.toByteArray()

    @OptIn(ExperimentalForeignApi::class)
    override fun write(account: String, bytes: ByteArray) {
        NSFileManager.defaultManager.createDirectoryAtPath(
            dirPath,
            withIntermediateDirectories = true,
            attributes = null,
            error = null,
        )
        val ok = memScoped {
            val nsData = if (bytes.isEmpty()) NSData() else NSData.create(
                bytes = bytes.refTo(0).getPointer(this),
                length = bytes.size.toULong(),
            )
            nsData.writeToFile(filePath(account), atomically = true)
        }
        // Fail closed: a key that only exists in memory would make everything encrypted
        // under it unreadable after the next relaunch.
        if (!ok) throw IllegalStateException(
            "KSafe: failed to persist the Simulator fallback key for account $account"
        )
    }

    override fun delete(account: String) {
        NSFileManager.defaultManager.removeItemAtPath(filePath(account), error = null)
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
        val hexDigits = "0123456789abcdef"
        val sb = StringBuilder(digest.size * 2)
        for (b in digest) {
            val v = b.toInt()
            sb.append(hexDigits[v ushr 4]).append(hexDigits[v and 0x0f])
        }
        return sb.toString()
    }
}
