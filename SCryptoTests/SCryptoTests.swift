//
//  SCryptoTests.swift
//  SCryptoTests
//
//  Created by Maksym Shcheglov on 21/01/16.
//  Copyright © 2016 Maksym Shcheglov. All rights reserved.
//

import XCTest
@testable import SCrypto

extension NSData {
    func hexString() -> String {
        let hexString = NSMutableString()
        let bytes: [UInt8] = self.bytesArray()
        for byte in bytes {
            hexString.appendFormat("%02x", UInt(byte))
        }
        return hexString as String
    }
}

class SCryptoTests: XCTestCase {

    struct Consts {
        static let key = "key"
        static let message = "The quick brown fox jumps over the lazy dog"

        static let MD2 = "03d85a0d629d2c442e987525319fc471"
        static let MD4 = "1bee69a46ba811185c194762abaeae90"
        static let MD5 = "9e107d9d372bb6826bd81d3542a419d6"
        static let SHA1 = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        static let SHA224 = "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525"
        static let SHA256 = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        static let SHA384 = "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"
        static let SHA512 = "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"

        static let hmacMD5 = "80070713463e7749b90c2dc24911e275"
        static let hmacSHA1 = "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
        static let hmacSHA256 = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        static let hmacSHA384 = "d7f4727e2c0b39ae0f1e40cc96f60242d5b7801841cea6fc592c5d3e1ae50700582a96cf35e1e554995fe4e03381c237"
        static let hmacSHA512 = "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"
        static let hmacSHA224 = "88ff8b54675d39b8f72322e65ff945c52d96379988ada25639747e69"
    }

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    // MARK: Digest

    func testMD2() {
        digest(Consts.message, expectedDigest: Consts.MD2) { $0.MD2() }
    }

    func testMD4() {
        digest(Consts.message, expectedDigest: Consts.MD4) { $0.MD4() }
    }

    func testMD5() {
        digest(Consts.message, expectedDigest: Consts.MD5) { $0.MD5() }
    }

    func testSHA224() {
        digest(Consts.message, expectedDigest: Consts.SHA224) { $0.SHA224() }
    }

    func testSHA256() {
        digest(Consts.message, expectedDigest: Consts.SHA256) { $0.SHA256() }
    }

    func testSHA384() {
        digest(Consts.message, expectedDigest: Consts.SHA384) { $0.SHA384() }
    }

    func testSHA512() {
        digest(Consts.message, expectedDigest: Consts.SHA512) { $0.SHA512() }
    }

    private func digest(message: String, expectedDigest: String, algorithm: (NSData) -> NSData) {
        let message = message.dataUsingEncoding(NSUTF8StringEncoding)!
        let digest = algorithm(message).hexString()
        XCTAssertEqual(digest, expectedDigest)
    }

    // MARK: Random

    func testRandom() {
        let randomData1 = try! NSData.random(16)
        let randomData2 = try! NSData.random(16)
        let randomData3 = try! NSData.random(16)
        XCTAssertNotEqual(randomData1, randomData2)
        XCTAssertNotEqual(randomData1, randomData3)
        XCTAssertNotEqual(randomData2, randomData3)
    }

    // MARK: HMAC

    func testHMAC_MD5() {
        hmac(.MD5, key: Consts.key, message: Consts.message, expectedHMAC: Consts.hmacMD5)
    }

    func testHMAC_SHA1() {
        hmac(.SHA1, key: Consts.key, message: Consts.message, expectedHMAC: Consts.hmacSHA1)
    }

    func testHMAC_SHA256() {
        hmac(.SHA256, key: Consts.key, message: Consts.message, expectedHMAC: Consts.hmacSHA256)
    }

    func testHMAC_SHA384() {
        hmac(.SHA384, key: Consts.key, message: Consts.message, expectedHMAC: Consts.hmacSHA384)
    }

    func testHMAC_SHA512() {
        hmac(.SHA512, key: Consts.key, message: Consts.message, expectedHMAC: Consts.hmacSHA512)
    }

    func testHMAC_SHA224() {
        hmac(.SHA224, key: Consts.key, message: Consts.message, expectedHMAC: Consts.hmacSHA224)
    }

    private func hmac(algorithm: HMAC.Algorithm, key: String, message: String, expectedHMAC: String) {
        let key = key.dataUsingEncoding(NSUTF8StringEncoding)!
        let message = message.dataUsingEncoding(NSUTF8StringEncoding)!
        let hmac = message.hmac(algorithm, key: key).hexString()
        XCTAssertEqual(hmac, expectedHMAC)
    }

}
