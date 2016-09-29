//
//  SCryptoTests.swift
//  SCryptoTests
//
//  Created by Maksym Shcheglov on 21/01/16.
//  Copyright © 2016 Maksym Shcheglov. All rights reserved.
//

import XCTest
import SCrypto

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

        static let pbkdfSalt = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        static let pbkdfSHA1 = "70f0bf06e5fb0972e8cf89e3d03c25ca"
        static let pbkdfSHA256 = "80420b8832af8a5111901f1a7b46aeeae719badbedf9bf69249efc5dbe09c9b1"
        static let pbkdfSHA512 = "84efb05ae06660f2b6f7bbb1e0cf5da539fc04cb2ae6171bb6b8b48854d2055afd2346f0eba86076ce237e862ddb0cd28dfdb82c18f570206ae8cf4d1e48284d"

        static let aesPlaintext = "cUeHxclgAgRNxETQfukCh6XoATh5Swi/OmNW97Sdz49fnw8BGMREZmginSD1pDbG58AjvEvPF0n5Jop8PiLrVA=="
        static let aesIV_128 = "96s40AnfurPVbdo/JNUmvQ=="
        static let aesIV_256 = "uw7aQlOL3Wndbz/Nogs9+osF6FskVsukS0EnqOzWCNE="
        static let aesKey_128 = "0cd2/U7XFvIce+Mm+vX8Yw=="
        static let aesKey_256 = "XhrsgcHsNo6c170hQ2GY5jI3uMA+A6y724nxJ1vCZ7o="
        static let aesCiphertext_CBC_128_Padding = "rJT3N1XTd6zfUSrnnfj2OuPhbkzbpWbH7qT0KToXJbd6CdAh13s3jPBksPQ0QtS/"
        static let aesCiphertext_CBC_256_Padding = "4UYbAgd7ZhjdCKtPubBdeRlVbjb5PZeG0EIPdRxNedD+z8ItF12THTTcILliYi+p"
        static let aesCiphertext_CBC_128 = "Y45fkXZe4KifkzAqaB7VW1MEqTnxVY3GtAt/OBTTQq984uyWQk58JulbA/YfW1duVvKTrOzcE+DLt2X8UwS1KA=="
        static let aesCiphertext_CBC_256 = "JOpLDp1r2SkHWhlaWmDUdSqJ7T/185Dpa41g7Hv8wXg6gzJNAfGdodk48ganQ3bNIcG3wamflgO4YPHl8na6cg=="
        static let aesCiphertext_CBC_128_IV = "/zxZ2j1AE4MgKkf8k+UFT0RzNM6F3Yu8L+8dT1ppzYu64MAF9ZA0pkqCdER1h4RqTeYg5oOkEVo3PvdONwI5Bw=="
        static let aesCiphertext_CBC_256_IV = "O49HzhxdRYMgzqQYx+pECj98Mxn+EtFy7ZnBE9yr+fPZXwgzWaLnLasoKszifIlHRnY3W0ehdWT2Zysaguorcw=="
    }

    // MARK: SCryptoError

    func testSCryptoError() {
        XCTAssertTrue(SCryptoError(rawValue: 0) == nil)
        XCTAssertTrue(SCryptoError(rawValue: -4300)! == .paramError)
        XCTAssertTrue(SCryptoError(rawValue: -4301)! == .bufferTooSmall)
        XCTAssertTrue(SCryptoError(rawValue: -4302)! == .memoryFailure)
        XCTAssertTrue(SCryptoError(rawValue: -4303)! == .alignmentError)
        XCTAssertTrue(SCryptoError(rawValue: -4304)! == .decodeError)
        XCTAssertTrue(SCryptoError(rawValue: -4305)! == .unimplemented)
        XCTAssertTrue(SCryptoError(rawValue: -4306)! == .overflow)
        XCTAssertTrue(SCryptoError(rawValue: -4307)! == .rngFailure)

        XCTAssertTrue(SCryptoError.paramError.rawValue == -4300)
        XCTAssertTrue(SCryptoError.bufferTooSmall.rawValue == -4301)
        XCTAssertTrue(SCryptoError.memoryFailure.rawValue == -4302)
        XCTAssertTrue(SCryptoError.alignmentError.rawValue == -4303)
        XCTAssertTrue(SCryptoError.decodeError.rawValue == -4304)
        XCTAssertTrue(SCryptoError.unimplemented.rawValue == -4305)
        XCTAssertTrue(SCryptoError.overflow.rawValue == -4306)
        XCTAssertTrue(SCryptoError.rngFailure.rawValue == -4307)

        XCTAssertNotNil(SCryptoError.paramError.description)
        XCTAssertNotNil(SCryptoError.bufferTooSmall.description)
        XCTAssertNotNil(SCryptoError.memoryFailure.description)
        XCTAssertNotNil(SCryptoError.alignmentError.description)
        XCTAssertNotNil(SCryptoError.decodeError.description)
        XCTAssertNotNil(SCryptoError.unimplemented.description)
        XCTAssertNotNil(SCryptoError.overflow.description)
        XCTAssertNotNil(SCryptoError.rngFailure.description)
    }

    // MARK: Digest

    func testMD2() {
        digest(Consts.message, expectedDigest: Consts.MD2) { $0.MD2() }
        XCTAssertEqual(Consts.message.MD2(), Consts.MD2)
    }

    func testMD4() {
        digest(Consts.message, expectedDigest: Consts.MD4) { $0.MD4() }
        XCTAssertEqual(Consts.message.MD4(), Consts.MD4)
    }

    func testMD5() {
        digest(Consts.message, expectedDigest: Consts.MD5) { $0.MD5() }
        XCTAssertEqual(Consts.message.MD5(), Consts.MD5)
    }

    func testSHA1() {
        digest(Consts.message, expectedDigest: Consts.SHA1) { $0.SHA1() }
        XCTAssertEqual(Consts.message.SHA1(), Consts.SHA1)
    }

    func testSHA224() {
        digest(Consts.message, expectedDigest: Consts.SHA224) { $0.SHA224() }
        XCTAssertEqual(Consts.message.SHA224(), Consts.SHA224)
    }

    func testSHA256() {
        digest(Consts.message, expectedDigest: Consts.SHA256) { $0.SHA256() }
        XCTAssertEqual(Consts.message.SHA256(), Consts.SHA256)
    }

    func testSHA384() {
        digest(Consts.message, expectedDigest: Consts.SHA384) { $0.SHA384() }
        XCTAssertEqual(Consts.message.SHA384(), Consts.SHA384)
    }

    func testSHA512() {
        digest(Consts.message, expectedDigest: Consts.SHA512) { $0.SHA512() }
        XCTAssertEqual(Consts.message.SHA512(), Consts.SHA512)
    }

    fileprivate func digest(_ message: String, expectedDigest: String, algorithm: (Data) -> Data) {
        let messageData = message.data(using: String.Encoding.utf8)!
        let digest = algorithm(messageData).hexString()
        XCTAssertEqual(digest, expectedDigest)
    }

    // MARK: Random

    func testRandom() {
        let randomData1 = try! Data.random(16)
        let randomData2 = try! Data.random(16)
        let randomData3 = try! Data.random(16)
        XCTAssertNotEqual(randomData1, randomData2)
        XCTAssertNotEqual(randomData1, randomData3)
        XCTAssertNotEqual(randomData2, randomData3)
    }

    // MARK: HMAC

    func testHMAC_MD5() {
        hmac(.md5, key: Consts.key, message: Consts.message, expectedHMAC: Consts.hmacMD5)
    }

    func testHMAC_SHA1() {
        hmac(.sha1, key: Consts.key, message: Consts.message, expectedHMAC: Consts.hmacSHA1)
    }

    func testHMAC_SHA256() {
        hmac(.sha256, key: Consts.key, message: Consts.message, expectedHMAC: Consts.hmacSHA256)
    }

    func testHMAC_SHA384() {
        hmac(.sha384, key: Consts.key, message: Consts.message, expectedHMAC: Consts.hmacSHA384)
    }

    func testHMAC_SHA512() {
        hmac(.sha512, key: Consts.key, message: Consts.message, expectedHMAC: Consts.hmacSHA512)
    }

    func testHMAC_SHA224() {
        hmac(.sha224, key: Consts.key, message: Consts.message, expectedHMAC: Consts.hmacSHA224)
    }

    fileprivate func hmac(_ algorithm: HMAC.Algorithm, key: String, message: String, expectedHMAC: String) {
        let keyData = key.data(using: String.Encoding.utf8)!
        let messageData = message.data(using: String.Encoding.utf8)!
        let hmac = messageData.hmac(algorithm, key: keyData).hexString()
        XCTAssertEqual(hmac, expectedHMAC)
        XCTAssertEqual(hmac, message.hmac(algorithm, key: key))
    }

    // MARK: PBKDF

    func testDerivedKey_SHA1() {
        calibrate(Consts.key, saltLength: Consts.pbkdfSalt.data(using: String.Encoding.utf8)!.count, pseudoRandomAlgorithm: .sha1, derivedKeyLength: 16, msec: 100)
        PBKDF2(Consts.key, salt: Consts.pbkdfSalt, pseudoRandomAlgorithm: .sha1, rounds: 20, derivedKeyLength: 16, expectedDerivedKey: Consts.pbkdfSHA1)
    }

    func testDerivedKey_SHA256() {
        calibrate(Consts.key, saltLength: Consts.pbkdfSalt.data(using: String.Encoding.utf8)!.count, pseudoRandomAlgorithm: .sha256, derivedKeyLength: 32, msec: 100)
        PBKDF2(Consts.key, salt: Consts.pbkdfSalt, pseudoRandomAlgorithm: .sha256, rounds: 20, derivedKeyLength: 32, expectedDerivedKey: Consts.pbkdfSHA256)
    }

    func testDerivedKey_SHA512() {
        calibrate(Consts.key, saltLength: Consts.pbkdfSalt.data(using: String.Encoding.utf8)!.count, pseudoRandomAlgorithm: .sha512, derivedKeyLength: 64, msec: 100)
        PBKDF2(Consts.key, salt: Consts.pbkdfSalt, pseudoRandomAlgorithm: .sha512, rounds: 20, derivedKeyLength: 64, expectedDerivedKey: Consts.pbkdfSHA512)
    }

    fileprivate func PBKDF2(_ password: String, salt: String, pseudoRandomAlgorithm: PBKDF.PseudoRandomAlgorithm, rounds: UInt32, derivedKeyLength: Int, expectedDerivedKey: String) {
        let password = password.data(using: String.Encoding.utf8)!
        let salt = salt.data(using: String.Encoding.utf8)!
        let derivedKey = try! password.derivedKey(salt, pseudoRandomAlgorithm: pseudoRandomAlgorithm, rounds: rounds, derivedKeyLength: derivedKeyLength)
        XCTAssertEqual(derivedKey.count, derivedKeyLength)
        XCTAssertEqual(derivedKey.hexString(), expectedDerivedKey)
    }

    fileprivate func calibrate(_ password: String, saltLength: Int, pseudoRandomAlgorithm: PBKDF.PseudoRandomAlgorithm, derivedKeyLength: Int, msec: UInt32) {
        let password = password.data(using: String.Encoding.utf8)!
        let iterations = password.calibrate(saltLength, pseudoRandomAlgorithm: pseudoRandomAlgorithm, derivedKeyLength: derivedKeyLength, msec: msec)
        XCTAssertTrue(iterations > 0)
    }

    // MARK: Cryptor

    func testAES_CBC_128() {
        cipher(Consts.aesPlaintext, key: Consts.aesKey_128, IV: nil, expectedCyphertext: Consts.aesCiphertext_CBC_128, algorithm: .aes, options: [])
        cipher(Consts.aesPlaintext, key: Consts.aesKey_128, IV: Consts.aesIV_128, expectedCyphertext: Consts.aesCiphertext_CBC_128_IV, algorithm: .aes, options: [])

        cipher((Consts.message.data(using: String.Encoding.utf8)?.base64EncodedString())!, key: Consts.aesKey_128, IV: nil, expectedCyphertext: Consts.aesCiphertext_CBC_128_Padding, algorithm: .aes, options: .PKCS7Padding)
    }

    func testAES_CBC_256() {
        cipher(Consts.aesPlaintext, key: Consts.aesKey_256, IV: nil, expectedCyphertext: Consts.aesCiphertext_CBC_256, algorithm: .aes, options: [])
        cipher(Consts.aesPlaintext, key: Consts.aesKey_256, IV: Consts.aesIV_256, expectedCyphertext: Consts.aesCiphertext_CBC_256_IV, algorithm: .aes, options: [])
        cipher((Consts.message.data(using: String.Encoding.utf8)?.base64EncodedString())!, key: Consts.aesKey_256, IV: nil, expectedCyphertext: Consts.aesCiphertext_CBC_256_Padding, algorithm: .aes, options: .PKCS7Padding)
    }

    func testThrowsAlignmentError() {
        var didFail = false
        do {
            let plaintext = Consts.message.data(using: String.Encoding.utf8)!
            let aesKey = Data(base64Encoded: Consts.aesKey_256, options: [])!
            try _ = plaintext.encrypt(.aes, options: [], key: aesKey, iv: nil)
        } catch SCryptoError.alignmentError {
            didFail = true
        } catch {
            XCTFail()
        }
        XCTAssertTrue(didFail, "AES requires padding in CBC mode!")
    }

    func cipher(_ plaintext: String, key: String, IV: String?, expectedCyphertext: String, algorithm: Cipher.Algorithm, options: Cipher.Options) {
        let plaintext = Data(base64Encoded: plaintext, options: [])!
        let aesKey = Data(base64Encoded: key, options: [])!
        let IV = IV == nil ? nil : Data(base64Encoded: IV!, options: [])
        let ciphertext = try! plaintext.encrypt(algorithm, options: options, key: aesKey, iv: IV)
        let plaintextProof = try! ciphertext.decrypt(algorithm, options: options, key: aesKey, iv: IV)
        XCTAssertEqual(plaintext, plaintextProof)
        XCTAssertEqual(ciphertext.base64EncodedString(), expectedCyphertext)
    }

}
