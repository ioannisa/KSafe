import XCTest
import ksafe

/// On-device (real Secure Enclave + Keychain) validation of the KSafe Apple engine.
///
/// The typed `put`/`get` are inline-reified in Kotlin and NOT callable from Swift (Kotlin/Native
/// exposes them as throwing stubs), so the encrypt/decrypt path is exercised through
/// `getOrCreateSecret` — the same AppleKeychainEncryption engine (SE envelope, keyBytesCache
/// double-fence, autoreleasepool bridging, rotation re-wrap) that the recent fixes touched.
final class KSafeDeviceTests: XCTestCase {

    private func makeSafe(_ name: String) -> KSafe {
        let config = KSafeConfig(
            keySize: 256,
            requireUnlockedDevice: false,
            json: KSafeDefaults.shared.json,
            appNamespace: nil,
            keyRotationPolicy: KSafeKeyRotationPolicyNever.shared
        )
        return KSafe_appleKt.KSafe(
            fileName: name,
            lazyLoad: false,
            memoryPolicy: KSafeMemoryPolicy.lazyPlainText,
            config: config,
            securityPolicy: KSafeSecurityPolicy.companion.Default,
            plaintextCacheTtl: 0,
            useSecureEnclave: true,
            directory: nil
        )
    }

    private func uniqueName() -> String { "devtest_\(abs(UUID().hashValue) % 1_000_000)" }

    private func secret(_ s: KSafe, _ key: String,
                        _ prot: KSafeEncryptedProtection = KSafeEncryptedProtection.default_) async throws -> NSData {
        try await s.getOrCreateSecret(key: key, size: 32, protection: prot, requireUnlockedDevice: false).toNSData()
    }

    // Real Keychain-backed encrypt/decrypt: a secret created on one instance is recovered
    // (decrypted) identically by a fresh instance — proving it was persisted, not regenerated.
    func testSecretPersistsAndDecryptsAcrossInstances() async throws {
        let name = uniqueName()
        let a = makeSafe(name)
        let s1 = try await secret(a, "db.pass")
        a.close()

        let b = makeSafe(name)
        let s2 = try await secret(b, "db.pass")
        XCTAssertEqual(s1, s2, "secret must decrypt to the same bytes on a fresh instance (real Keychain key)")
        try await b.clearAll()
        b.close()
    }

    // Secure Enclave envelope: a HARDWARE_ISOLATED secret round-trips across instances on device.
    func testHardwareIsolatedSecretAcrossInstances() async throws {
        let name = uniqueName()
        let a = makeSafe(name)
        let s1 = try await secret(a, "se.pass", KSafeEncryptedProtection.hardwareIsolated)
        a.close()

        let b = makeSafe(name)
        let s2 = try await secret(b, "se.pass", KSafeEncryptedProtection.hardwareIsolated)
        XCTAssertEqual(s1, s2, "Secure-Enclave-wrapped secret must decrypt on device")
        try await b.clearAll()
        b.close()
    }

    // Idempotent within an instance (same call → same value).
    func testGetOrCreateSecretIsIdempotent() async throws {
        let s = makeSafe(uniqueName())
        let first = try await secret(s, "k")
        let second = try await secret(s, "k")
        XCTAssertEqual(first.length, 32)
        XCTAssertEqual(first, second, "getOrCreateSecret must return the same secret each call")
        try await s.clearAll()
        s.close()
    }

    // rotateKeys re-wraps the key on the real Keychain/SE; the secret VALUE must survive.
    func testRotateKeysPreservesSecret() async throws {
        let name = uniqueName()
        let s = makeSafe(name)
        let before = try await secret(s, "rot")

        let result = try await s.rotateKeys()
        XCTAssertNotNil(result)

        let after = try await secret(s, "rot")
        XCTAssertEqual(before, after, "the secret value must survive key rotation (only the wrapping key changes)")
        try await s.clearAll()
        s.close()
    }

    // clearAll durably wipes: a fresh instance generates a DIFFERENT secret for the same key.
    func testClearAllWipesSecret() async throws {
        let name = uniqueName()
        let a = makeSafe(name)
        let s1 = try await secret(a, "wipe")
        try await a.clearAll()
        a.close()

        let b = makeSafe(name)
        let s2 = try await secret(b, "wipe")
        XCTAssertNotEqual(s1, s2, "clearAll must erase the secret so a fresh one is generated")
        try await b.clearAll()
        b.close()
    }

    // protectionInfo must be honest on a real device: hardware-backed and operational.
    func testProtectionInfoHardwareBackedAndOperational() {
        let s = makeSafe(uniqueName())
        let info = s.protectionInfo
        XCTAssertTrue(info.isEncryptionOperational, "encryption must be operational on a real signed device")
        XCTAssertEqual(info.notes.count, 0, "no degrade notes expected on a real device: \(info.notes)")
        XCTAssertEqual(info.effectiveLevel, KSafeProtectionLevel.hardwareBacked, "custody=\(info.custody)")
        s.close()
    }

    // iPhone 15 Pro Max has a Secure Enclave → HARDWARE_ISOLATED must be an available tier.
    func testDeviceKeyStoragesIncludesHardwareIsolated() {
        let s = makeSafe(uniqueName())
        XCTAssertTrue(s.deviceKeyStorages.contains(KSafeKeyStorage.hardwareIsolated),
                      "Secure Enclave device must report HARDWARE_ISOLATED available: \(s.deviceKeyStorages)")
        s.close()
    }
}

private extension KotlinByteArray {
    func toNSData() -> NSData {
        let d = NSMutableData()
        for i in 0..<self.size { var b = self.get(index: i); d.append(&b, length: 1) }
        return d
    }
}
