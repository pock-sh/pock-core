import XCTest
@testable import PockCore

final class PockCoreTests: XCTestCase {
    func testCreateVaultEmitsJSON() throws {
        let json = try createVault(passphrase: "correct horse battery staple")
        let obj = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        XCTAssertNotNil(obj["secretKey"])
    }

    func testSymmetricRoundtrip() throws {
        let key = generateSymmetricKey()
        let sealed = try sealSymmetric(keyB64: key, plaintext: Data("hi".utf8), aad: Data())
        let opened = try openSymmetric(keyB64: key, blob: sealed, aad: Data())
        XCTAssertEqual(String(decoding: opened, as: UTF8.self), "hi")
    }
}
