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
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testHMAC_MD5() {
        hmac(.MD5, key: "key", message: "The quick brown fox jumps over the lazy dog", expectedHMAC: "80070713463e7749b90c2dc24911e275")
    }

    func testHMAC_SHA1() {
        hmac(.SHA1, key: "key", message: "The quick brown fox jumps over the lazy dog", expectedHMAC: "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")
    }

    func testHMAC_SHA256() {
        hmac(.SHA256, key: "key", message: "The quick brown fox jumps over the lazy dog", expectedHMAC: "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
    }

    func testHMAC_SHA384() {
        hmac(.SHA384, key: "key", message: "The quick brown fox jumps over the lazy dog", expectedHMAC: "d7f4727e2c0b39ae0f1e40cc96f60242d5b7801841cea6fc592c5d3e1ae50700582a96cf35e1e554995fe4e03381c237")
    }

    func testHMAC_SHA512() {
        hmac(.SHA512, key: "key", message: "The quick brown fox jumps over the lazy dog", expectedHMAC: "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a")
    }

    func testHMAC_SHA224() {
        hmac(.SHA224, key: "key", message: "The quick brown fox jumps over the lazy dog", expectedHMAC: "88ff8b54675d39b8f72322e65ff945c52d96379988ada25639747e69")
    }

    private func hmac(algorithm: HMAC.Algorithm, key: String, message: String, expectedHMAC: String) {
        let key = key.dataUsingEncoding(NSUTF8StringEncoding)!
        let message = message.dataUsingEncoding(NSUTF8StringEncoding)!
        let hmac = message.hmac(algorithm, key: key).hexString()
        XCTAssertEqual(hmac, expectedHMAC)
    }

}
