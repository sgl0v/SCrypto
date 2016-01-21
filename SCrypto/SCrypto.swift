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

        internal var digestLength: Int32 {
            switch self {
            case .MD2:
                return CC_MD2_DIGEST_LENGTH
            case .MD4:
                return CC_MD4_DIGEST_LENGTH
            case .MD5:
                return CC_MD5_DIGEST_LENGTH
            case .SHA1:
                return CC_SHA1_DIGEST_LENGTH
            case .SHA224:
                return CC_SHA224_DIGEST_LENGTH
            case .SHA256:
                return CC_SHA256_DIGEST_LENGTH
            case .SHA384:
                return CC_SHA384_DIGEST_LENGTH
            case .SHA512:
                return CC_SHA512_DIGEST_LENGTH
            }
        }

        internal var digestFunction: (data: UnsafePointer<Void>, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
            switch self {
            case .MD2:
                return CC_MD2
            case .MD4:
                return CC_MD4
            case .MD5:
                return CC_MD5
            case .SHA1:
                return CC_SHA1
            case .SHA224:
                return CC_SHA224
            case .SHA256:
                return CC_SHA256
            case .SHA384:
                return CC_SHA384
            case .SHA512:
                return CC_SHA512
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
        var digest = [UInt8](count: Int(self.algorithm.digestLength), repeatedValue: 0)
        self.algorithm.digestFunction(data: self.data.bytes, len: CC_LONG(self.data.length), md: &digest)
        return digest
    }

    public static func MD2(bytes bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        let digest = Digest(.MD2)
        digest.update(bytes, length: length)
        return digest.final()
    }

    public static func MD4(bytes bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        let digest = Digest(.MD4)
        digest.update(bytes, length: length)
        return digest.final()
    }

    public static func MD5(bytes bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        let digest = Digest(.MD5)
        digest.update(bytes, length: length)
        return digest.final()
    }

    public static func SHA1(bytes bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        let digest = Digest(.SHA1)
        digest.update(bytes, length: length)
        return digest.final()
    }

    public static func SHA224(bytes bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        let digest = Digest(.SHA224)
        digest.update(bytes, length: length)
        return digest.final()
    }

    public static func SHA256(bytes bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        let digest = Digest(.SHA256)
        digest.update(bytes, length: length)
        return digest.final()
    }

    public static func SHA384(bytes bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        let digest = Digest(.SHA384)
        digest.update(bytes, length: length)
        return digest.final()
    }

    public static func SHA512(bytes bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        let digest = Digest(.SHA512)
        digest.update(bytes, length: length)
        return digest.final()
    }

}