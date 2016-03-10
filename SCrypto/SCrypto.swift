//
//  SCrypto.swift
//  SCrypto
//
//  Created by Maksym Shcheglov on 21/01/16.
//  Copyright © 2016 Maksym Shcheglov. All rights reserved.
//

import CommonCrypto

// MARK: Message Digest

/// The Digest class defines methods to evaluate message digest.
public class Digest {

    /**
     The cryptographic algorithm types to evaluate message digest.

     MD2, MD4, and MD5 are recommended only for compatibility with existing applications.
     In new applications, SHA-256(or greater) should be preferred.
     */
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

    /**
     Initializes a new digest object with the provided cryptographic algorithm.

     - Parameters:
     - algorithm: The cryptographic algorithm to use.

     - Returns: A newly created object to compute the message digest.
     */
    init(_ algorithm: Algorithm) {
        self.algorithm = algorithm
    }

    /**
     Appends specified bytes to the internal buffer. Can be called repeatedly with chunks of the message to be hashed.

     - parameter bytes:  The message to be hashed.
     - parameter length: The message length.
     */
    public func update(bytes: UnsafePointer<Void>, length: Int) {
        self.data.appendBytes(bytes, length: length)
    }

    /**
     Computes the message digest.

     - returns: the message digest.
     */
    public func final() -> [UInt8] {
        var digest = [UInt8](count: Int(self.algorithm.digest.length), repeatedValue: UInt8(0))
        self.algorithm.digest.function(data: self.data.bytes, len: CC_LONG(self.data.length), md: &digest)
        return digest
    }

     /**
     Computes the MD2 message digest at data and returns the result.
     Recommended only for compatibility with existing applications. In new applications, SHA-256(or greater) should be preferred.

     - parameter bytes:  The message to be hashed.
     - parameter length: The message length.

     - returns: the MD2 message digest.
     */
    public static func MD2(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.MD2, bytes: bytes, length: length)
    }

    /**
     Computes the MD4 message digest at data and returns the result.
     Recommended only for compatibility with existing applications. In new applications, SHA-256(or greater) should be preferred.

     - parameter bytes:  The message to be hashed.
     - parameter length: The message length.

     - returns: the MD4 message digest.
     */
    public static func MD4(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.MD4, bytes: bytes, length: length)
    }

    /**
     Computes the MD5 message digest at data and returns the result.
     Recommended only for compatibility with existing applications. In new applications, SHA-256(or greater) should be preferred.

     - parameter bytes:  The message to be hashed.
     - parameter length: The message length.

     - returns: the MD5 message digest.
     */
    public static func MD5(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.MD5, bytes: bytes, length: length)
    }

    /**
     Computes the SHA1 message digest at data and returns the result.

     - parameter bytes:  The message to be hashed.
     - parameter length: The message length.

     - returns: the SHA1 message digest.
     */
    public static func SHA1(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.SHA1, bytes: bytes, length: length)
    }

    /**
     Computes the SHA224 message digest at data and returns the result.

     - parameter bytes:  The message to be hashed.
     - parameter length: The message length.

     - returns: the SHA224 message digest.
     */
    public static func SHA224(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.SHA224, bytes: bytes, length: length)
    }

    /**
     Computes the SHA256 message digest at data and returns the result.

     - parameter bytes:  The message to be hashed.
     - parameter length: The message length.

     - returns: the SHA256 message digest.
     */
    public static func SHA256(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.SHA256, bytes: bytes, length: length)
    }

    /**
     Computes the SHA384 message digest at data and returns the result.

     - parameter bytes:  The message to be hashed.
     - parameter length: The message length.

     - returns: the SHA384 message digest.
     */
    public static func SHA384(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.SHA384, bytes: bytes, length: length)
    }

    /**
     Computes the SHA512 message digest at data and returns the result.

     - parameter bytes:  The message to be hashed.
     - parameter length: The message length.

     - returns: the SHA512 message digest.
     */
    public static func SHA512(bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        return digest(.SHA512, bytes: bytes, length: length)
    }

    private static func digest(algorithm: Algorithm, bytes: UnsafePointer<Void>, length: Int) -> [UInt8] {
        let digest = Digest(algorithm)
        digest.update(bytes, length: length)
        return digest.final()
    }

}

/// The NSData extension defines methods to compute the message digest.
public extension NSData {

    /**
     Computes the MD2 message digest at data and returns the result.
     Recommended only for compatibility with existing applications. In new applications, SHA-256(or greater) should be preferred.

     - returns: the MD2 message digest.
     */
    public func MD2() -> NSData {
        return digest(Digest.MD2)
    }

    /**
     Computes the MD4 message digest at data and returns the result.
     Recommended only for compatibility with existing applications. In new applications, SHA-256(or greater) should be preferred.

     - returns: the MD4 message digest.
     */
    public func MD4() -> NSData {
        return digest(Digest.MD4)
    }

    /**
     Computes the MD5 message digest at data and returns the result.
     Recommended only for compatibility with existing applications. In new applications, SHA-256(or greater) should be preferred.

     - returns: the MD5 message digest.
     */
    public func MD5() -> NSData {
        return digest(Digest.MD5)
    }

    /**
     Computes the SHA-1 message digest at data and returns the result.

     - returns: the SHA-1 message digest.
     */
    public func SHA1() -> NSData {
        return digest(Digest.SHA1)
    }

    /**
     Computes the SHA224 message digest at data and returns the result.

     - returns: the SHA224 message digest.
     */
    public func SHA224() -> NSData {
        return digest(Digest.SHA224)
    }

    /**
     Computes the SHA256 message digest at data and returns the result.

     - returns: the SHA256 message digest.
     */
    public func SHA256() -> NSData {
        return digest(Digest.SHA256)
    }

    /**
     Computes the SHA384 message digest at data and returns the result.

     - returns: the SHA384 message digest.
     */
    public func SHA384() -> NSData {
        return digest(Digest.SHA384)
    }

    /**
     Computes the SHA512 message digest at data and returns the result.

     - returns: the SHA512 message digest.
     */
    public func SHA512() -> NSData {
        return digest(Digest.SHA512)
    }

    private func digest(digestFunc: (bytes: UnsafePointer<Void>, length: Int) -> [UInt8]) -> NSData {
        let digest = digestFunc(bytes: self.bytes, length: self.length)
        return NSData(bytes: digest, length: digest.count)
    }

}

// MARK: Random

/// The Random class defines a method for random bytes generation.
public class Random {

    /**
     Returns random bytes in a buffer allocated by the caller.

     - parameter bytes:  Pointer to the return buffer.
     - parameter length: Number of random bytes to return.
     */
    public static func generateBytes(bytes : UnsafeMutablePointer<Void>, length : Int) {
        let statusCode = CCRandomGenerateBytes(bytes, length)
        assert(statusCode != 1, "CCRandomGenerateBytes failed with status code: \(statusCode)")
    }
}

/// The NSData extension defines a method for random bytes generation.
public extension NSData {

    /**
     Creates NSData object of the specified length and populates it with randomly generated bytes.
     The created object has cryptographically strong random bits suitable for use as cryptographic keys, IVs, nonces etc.

     - parameter length: Number of random bytes to return.

     - returns: newly created NSData object populated with randomly generated bytes.
     */
    public static func random(length : Int) -> NSData {
        let bytes = UnsafeMutablePointer<UInt8>.alloc(length)
        Random.generateBytes(bytes, length: length)
        let data = NSData(bytes: bytes, length: length)
        bytes.dealloc(length)
        return data
    }

}

