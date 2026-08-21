import XCTest
@testable import PockCore

final class PockCoreTests: XCTestCase {
    func testCreateVaultEmitsJSON() throws {
        let json = try createVault(passphrase: "correct horse battery staple")
        let obj = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        XCTAssertNotNil(obj["secretKey"])
    }

    /// The error category is the whole point of the Swift surface: a caller has
    /// to be able to tell "you typed the wrong passphrase" from "this payload is
    /// malformed" without string-matching. Drive a real wrong-passphrase unlock
    /// and pattern-match the case the bindings actually throw.
    func testUnlockVaultWithWrongPassphraseThrowsWrongCredential() throws {
        let created = try createVault(passphrase: "correct horse battery staple")
        let vault = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(created.utf8)) as? [String: Any])
        let secretKey = try XCTUnwrap(vault["secretKey"] as? String)
        let wrappedIdentity = try XCTUnwrap(vault["wrappedIdentity"] as? String)
        // `wrappedAukPassphrase` is a nested object; the Rust side wants it back
        // as its own JSON document, not as a Swift dictionary.
        let wrappedAuk = try XCTUnwrap(vault["wrappedAukPassphrase"] as? [String: Any])
        let wrappedAukJson = String(
            decoding: try JSONSerialization.data(withJSONObject: wrappedAuk), as: UTF8.self)

        XCTAssertThrowsError(
            try unlockVault(
                passphrase: "not the passphrase",
                secretKeyB64: secretKey,
                wrappedAukJson: wrappedAukJson,
                wrappedIdentityB64: wrappedIdentity)
        ) { error in
            guard case PockCoreError.WrongCredential(let message) = error else {
                return XCTFail("expected PockCoreError.WrongCredential, got \(error)")
            }
            XCTAssertEqual(message, "wrong passphrase or secret key")
        }
    }

    func testSymmetricRoundtrip() throws {
        let key = generateSymmetricKey()
        let sealed = try sealSymmetric(keyB64: key, plaintext: Data("hi".utf8), aad: Data())
        let opened = try openSymmetric(keyB64: key, blob: sealed, aad: Data())
        XCTAssertEqual(String(decoding: opened, as: UTF8.self), "hi")
    }
}
