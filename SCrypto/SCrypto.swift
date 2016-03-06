//
//  SCrypto.swift
//  SCrypto
//
//  Created by Maksym Shcheglov on 21/01/16.
//  Copyright © 2016 Maksym Shcheglov. All rights reserved.
//

import CommonCrypto

public class Digest {

    public enum Algorithm {
        case MD2, MD4, MD5, SHA1, SHA224, SHA256, SHA384, SHA512

        internal var digest : (length: Int32, function: (data: UnsafePointer<Void>, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>) {
            switch self {
            case .MD2:
                return (CC_MD2_DIGEST_LENGTH, CC_MD2)
            case .MD4:
                return (CC_MD4_DIGEST_LENGTH, CC_MD4)
            case .MD5:
                return (CC_MD5_DIGEST_LENGTH, CC_MD5)
            case .SHA1:
                return (CC_SHA1_DIGEST_LENGTH, CC_SHA1)
            case .SHA224:
                return (CC_SHA224_DIGEST_LENGTH, CC_SHA224)
            case .SHA256:
                return (CC_SHA256_DIGEST_LENGTH, CC_SHA256)
            case .SHA384:
                return (CC_SHA384_DIGEST_LENGTH, CC_SHA384)
            case .SHA512:
                return (CC_SHA512_DIGEST_LENGTH, CC_SHA512)
            }
        }
    }

    private let algorithm: Algorithm
    private let data = NSMutableData()

    init(_ algorithm: Algorithm) {
        self.algorithm = algorithm
    }

    public func update(bytes: UnsafePointer<Void>, length: Int) {
        self.data.appendBytes(bytes, length: length)
    }

    public func final() -> [UInt8] {
        var digest = [UInt8](count: Int(self.algorithm.digest.length), repeatedValue: UInt8(0))
        self.algorithm.digest.function(data: self.data.bytes, len: CC_LONG(self.data.length), md: &digest)
        return digest
    }

    public static func MD2(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.MD2, bytes: bytes, length: length)
    }

    public static func MD4(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.MD4, bytes: bytes, length: length)
    }

    public static func MD5(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.MD5, bytes: bytes, length: length)
    }

    public static func SHA1(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.SHA1, bytes: bytes, length: length)
    }

    public static func SHA224(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.SHA224, bytes: bytes, length: length)
    }

    public static func SHA256(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.SHA256, bytes: bytes, length: length)
    }

    public static func SHA384(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.SHA384, bytes: bytes, length: length)
    }

    public static func SHA512(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.SHA512, bytes: bytes, length: length)
    }

    private static func digest(algorithm: Algorithm, bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        let digest = Digest(algorithm)
        digest.update(bytes, length: length)
        return digest.final()
    }

}

public extension NSData {

    public func MD2() -> NSData {
        return digest(Digest.MD2)
    }

    public func MD4() -> NSData {
        return digest(Digest.MD4)
    }

    public func MD5() -> NSData {
        return digest(Digest.MD5)
    }

    public func SHA1() -> NSData {
        return digest(Digest.SHA1)
    }

    public func SHA224() -> NSData {
        return digest(Digest.SHA224)
    }

    public func SHA256() -> NSData {
        return digest(Digest.SHA256)
    }

    public func SHA384() -> NSData {
        return digest(Digest.SHA384)
    }

    public func SHA512() -> NSData {
        return digest(Digest.SHA512)
    }

    private func digest(digestFunc: (bytes: UnsafePointer<Void>, length: Int) -> [UInt8]) -> NSData {
        let digest = digestFunc(bytes: self.bytes, length: self.length)
        return NSData(bytes: digest, length: digest.count)
    }

}

public class Random {

    public static func generateBytes(bytes : UnsafeMutablePointer<Void>, length : Int) {
        let statusCode = CCRandomGenerateBytes(bytes, length)
        assert(statusCode != 1, "CCRandomGenerateBytes failed with status code: \(statusCode)")
    }
}

public extension NSData {

    public static func random(length : Int) -> NSData {
        let bytes = UnsafeMutablePointer<UInt8>.alloc(length)
        Random.generateBytes(bytes, length: length)
        let data = NSData(bytes: bytes, length: length)
        bytes.dealloc(length)
        return data
    }

}

