import CryptoKit
import Foundation

private let kSafeCryptoSuccess: Int32 = 0
private let kSafeCryptoInvalidArgument: Int32 = 1
private let kSafeCryptoAuthenticationFailed: Int32 = 2
private let kSafeCryptoFailure: Int32 = 3

@inline(__always)
private func inputData(
    _ pointer: UnsafePointer<UInt8>?,
    count: Int32
) -> Data? {
    guard count >= 0 else { return nil }
    if count == 0 { return Data() }
    guard let pointer else { return nil }
    return Data(bytes: pointer, count: Int(count))
}

@inline(__always)
private func copyData(
    _ data: Data,
    to output: UnsafeMutablePointer<UInt8>?,
    expectedCount: Int
) -> Bool {
    guard data.count == expectedCount else { return false }
    if expectedCount == 0 { return true }
    guard let output else { return false }
    _ = data.copyBytes(to: UnsafeMutableBufferPointer(start: output, count: expectedCount))
    return true
}

/// C ABI kept deliberately byte-oriented: Kotlin/Native owns every input/output buffer, while
/// CryptoKit owns the AES-GCM primitive. No Swift or third-party type crosses the boundary.
@_cdecl("ksafe_cryptokit_aes_gcm_encrypt")
public func ksafeCryptoKitAesGcmEncrypt(
    keyPointer: UnsafePointer<UInt8>?,
    keyCount: Int32,
    noncePointer: UnsafePointer<UInt8>?,
    nonceCount: Int32,
    plaintextPointer: UnsafePointer<UInt8>?,
    plaintextCount: Int32,
    authenticatedDataPointer: UnsafePointer<UInt8>?,
    authenticatedDataCount: Int32,
    ciphertextOutput: UnsafeMutablePointer<UInt8>?,
    tagOutput: UnsafeMutablePointer<UInt8>?
) -> Int32 {
    guard keyCount == 16 || keyCount == 32,
          nonceCount == 12,
          let keyData = inputData(keyPointer, count: keyCount),
          let nonceData = inputData(noncePointer, count: nonceCount),
          let plaintext = inputData(plaintextPointer, count: plaintextCount),
          let authenticatedData = inputData(
              authenticatedDataPointer,
              count: authenticatedDataCount
          )
    else {
        return kSafeCryptoInvalidArgument
    }

    do {
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: keyData),
            nonce: nonce,
            authenticating: authenticatedData
        )
        guard copyData(
            sealedBox.ciphertext,
            to: ciphertextOutput,
            expectedCount: Int(plaintextCount)
        ),
            copyData(sealedBox.tag, to: tagOutput, expectedCount: 16)
        else {
            return kSafeCryptoFailure
        }
        return kSafeCryptoSuccess
    } catch {
        return kSafeCryptoFailure
    }
}

/// Authenticated decrypt. Plaintext is copied only after CryptoKit has verified the GCM tag.
@_cdecl("ksafe_cryptokit_aes_gcm_decrypt")
public func ksafeCryptoKitAesGcmDecrypt(
    keyPointer: UnsafePointer<UInt8>?,
    keyCount: Int32,
    noncePointer: UnsafePointer<UInt8>?,
    nonceCount: Int32,
    ciphertextPointer: UnsafePointer<UInt8>?,
    ciphertextCount: Int32,
    tagPointer: UnsafePointer<UInt8>?,
    tagCount: Int32,
    authenticatedDataPointer: UnsafePointer<UInt8>?,
    authenticatedDataCount: Int32,
    plaintextOutput: UnsafeMutablePointer<UInt8>?
) -> Int32 {
    guard keyCount == 16 || keyCount == 32,
          nonceCount == 12,
          tagCount == 16,
          let keyData = inputData(keyPointer, count: keyCount),
          let nonceData = inputData(noncePointer, count: nonceCount),
          let ciphertext = inputData(ciphertextPointer, count: ciphertextCount),
          let tag = inputData(tagPointer, count: tagCount),
          let authenticatedData = inputData(
              authenticatedDataPointer,
              count: authenticatedDataCount
          )
    else {
        return kSafeCryptoInvalidArgument
    }

    do {
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let sealedBox = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
        let plaintext = try AES.GCM.open(
            sealedBox,
            using: SymmetricKey(data: keyData),
            authenticating: authenticatedData
        )
        guard copyData(
            plaintext,
            to: plaintextOutput,
            expectedCount: Int(ciphertextCount)
        ) else {
            return kSafeCryptoFailure
        }
        return kSafeCryptoSuccess
    } catch CryptoKitError.authenticationFailure {
        return kSafeCryptoAuthenticationFailed
    } catch {
        return kSafeCryptoFailure
    }
}
