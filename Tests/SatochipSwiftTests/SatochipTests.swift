import XCTest
@testable import SatochipSwift

final class SatochipTests: XCTestCase {

    // MARK: DER signature parsing

    func testParseDerIntegerShorterThan32Bytes() throws {
        // r is 31 bytes (minimal DER of a value below 2^248), s is 33 bytes with a sign byte
        let r31 = [UInt8](repeating: 0x11, count: 31)
        let s32 = [UInt8](repeating: 0x81, count: 32)
        let header: [UInt8] = [0x30, 2 + 31 + 2 + 33, 0x02, 31]
        let der: [UInt8] = header + r31 + [0x02, 33, 0x00] + s32

        let (r, s, compact) = try Util.shared.parseToCompactSignature(sigIn: der)

        XCTAssertEqual(r, [0x00] + r31)
        XCTAssertEqual(s, s32)
        XCTAssertEqual(compact, [0x00] + r31 + s32)
    }

    func testParseDerRejectsMalformedInput() {
        let r = [UInt8](repeating: 0x11, count: 32)
        XCTAssertThrowsError(try Util.shared.parseToCompactSignature(sigIn: [0x31, 0x00]))
        XCTAssertThrowsError(try Util.shared.parseToCompactSignature(sigIn: [0x30]))
        // truncated s
        XCTAssertThrowsError(try Util.shared.parseToCompactSignature(sigIn: [0x30, 0x44, 0x02, 0x20] + r + [0x02, 0x20, 0x01]))
        // integer longer than 32 bytes once the sign byte is stripped
        let r33 = [UInt8](repeating: 0x11, count: 33)
        XCTAssertThrowsError(try Util.shared.parseToCompactSignature(sigIn: [0x30, 0x46, 0x02, 0x21] + r33 + [0x02, 0x20] + r))
    }

    /// Signs many random messages and checks that every signature parses and recovers the signer,
    /// including those with a DER component shorter than 32 bytes (about 1 in 256).
    func testRecoverPubkeyFromRandomSignatures() throws {
        let privkey = Crypto.shared.random(count: 32)
        let pubkey = Crypto.shared.secp256k1PublicFromPrivate(privkey)
        let coordx = Array(pubkey[1...32])

        var shortComponents = 0
        for _ in 0..<2000 {
            let msg = Crypto.shared.random(count: 32)
            let der = Crypto.shared.secp256k1Sign(hash: Crypto.shared.sha256(msg), privKey: privkey)
            if der[3] < 0x20 || der[4 + Int(der[3]) + 1] < 0x20 {
                shortComponents += 1
            }

            let sig = try RecoverableSignature(msg: msg, sig: der, coordx: coordx)
            XCTAssertEqual(sig.publicKey, pubkey)

            let list = try ListRecoverableSignature(msg: msg, sig: der)
            XCTAssertTrue(list.pubkeys.contains(pubkey))
        }
        XCTAssertGreaterThan(shortComponents, 0, "no short DER component exercised; rerun")
    }

    func testRecoverPubkeyWithWrongCoordxThrowsInsteadOfCrashing() throws {
        let privkey = Crypto.shared.random(count: 32)
        let msg = Crypto.shared.random(count: 32)
        let der = Crypto.shared.secp256k1Sign(hash: Crypto.shared.sha256(msg), privKey: privkey)

        // no recovery id matches, so recovery ids 2 and 3 (which yield no point) are also tried
        XCTAssertThrowsError(try RecoverableSignature(msg: msg, sig: der, coordx: [UInt8](repeating: 0x42, count: 32))) { error in
            XCTAssertEqual(error as? CardError, CardError.unrecoverableSignature)
        }
    }
}
