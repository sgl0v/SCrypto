//
//  SCrypto.swift
//  SCrypto
//
//  Created by Maksym Shcheglov on 21/01/16.
//  Copyright © 2016 Maksym Shcheglov. All rights reserved.
//

import CommonCrypto

public extension NSData {

    func bytesArray<T: IntegerLiteralConvertible>() -> [T] {
        var bytes = Array<T>(count: self.length, repeatedValue: 0)
        self.getBytes(&bytes, length:self.length * sizeof(T))
        return bytes
    }

    func hexString() -> String {
        let hexString = NSMutableString()
        let bytes: [UInt8] = self.bytesArray()
        for byte in bytes {
            hexString.appendFormat("%02x", UInt(byte))
        }
        return hexString as String
    }
}


internal protocol RawConvertable {
    typealias RawValue
    var rawValue: RawValue { get }
}

/**
    The error values for SCrypto operations

    - ParamError: Illegal parameter value.
    - BufferTooSmall: Insufficent buffer provided for specified operation.
    - MemoryFailure: Memory allocation failure.
    - AlignmentError: Input size was not aligned properly.
    - DecodeError: Input data did not decode or decrypt properly.
    - Unimplemented: Function not implemented for the current algorithm.
    - Overflow: Overflow error.
    - RNGFailure: Random Number Generator Error.
*/
public enum SCryptoError: ErrorType, RawRepresentable, CustomStringConvertible {
    case ParamError, BufferTooSmall, MemoryFailure, AlignmentError, DecodeError, Unimplemented, Overflow, RNGFailure

    public typealias RawValue = CCCryptorStatus

    public init?(rawValue: RawValue) {
        switch Int(rawValue) {
        case kCCParamError : self = .ParamError
        case kCCBufferTooSmall : self = .BufferTooSmall
        case kCCMemoryFailure : self = .MemoryFailure
        case kCCAlignmentError: self = .AlignmentError
        case kCCDecodeError: self = .DecodeError
        case kCCUnimplemented : self = .Unimplemented
        case kCCOverflow: self = .Overflow
        case kCCRNGFailure: self = .RNGFailure
        default: return nil
        }
    }

    public var rawValue: RawValue {
        switch self {
        case ParamError : return CCCryptorStatus(kCCParamError)
        case BufferTooSmall : return CCCryptorStatus(kCCBufferTooSmall)
        case MemoryFailure : return CCCryptorStatus(kCCMemoryFailure)
        case AlignmentError: return CCCryptorStatus(kCCAlignmentError)
        case DecodeError: return CCCryptorStatus(kCCDecodeError)
        case Unimplemented : return CCCryptorStatus(kCCUnimplemented)
        case Overflow: return CCCryptorStatus(kCCOverflow)
        case RNGFailure: return CCCryptorStatus(kCCRNGFailure)
        }
    }

    /// The error's textual representation
    public var description: String {
        let descriptions = [ParamError: "ParamError", BufferTooSmall: "BufferTooSmall", MemoryFailure: "MemoryFailure",
            AlignmentError: "AlignmentError", DecodeError: "DecodeError", Unimplemented: "Unimplemented", Overflow: "Overflow",
            RNGFailure: "RNGFailure"]
        return descriptions[self] ?? ""
    }

}

// MARK: Message Digest

/// The `Digest` class defines methods to evaluate message digest.
public final class Digest {

    /**
     The cryptographic algorithm types to evaluate message digest.

     MD2, MD4, and MD5 are recommended only for compatibility with existing applications.
     In new applications, SHA-256(or greater) should be preferred.
     */
    public enum Algorithm: RawConvertable {
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

        typealias RawValue = (data: UnsafePointer<Void>, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>
        internal var rawValue: RawValue {
            switch self {
            case .MD2 : return CC_MD2
            case .MD4 : return CC_MD4
            case .MD5 : return CC_MD5
            case .SHA1 : return CC_SHA1
            case .SHA224: return CC_SHA224
            case .SHA256: return CC_SHA256
            case .SHA384: return CC_SHA384
            case .SHA512: return CC_SHA512
            }
        }

    }

    private let algorithm: Algorithm
    private let data = NSMutableData()

    /**
     Initializes a new digest object with the provided cryptographic algorithm.

     - parameter algorithm: The cryptographic algorithm to use.

     - Returns: A newly created object to compute the message digest.
     */
    init(_ algorithm: Algorithm) {
        self.algorithm = algorithm
    }

    /**
     Appends specified bytes to the internal buffer. Can be called repeatedly with chunks of the message to be hashed.

     - parameter bytes:  The message to be hashed.
     */
    public func update(bytes: [UInt8]) {
        self.data.appendBytes(bytes, length: bytes.count)
    }

    /**
     Computes the message digest.

     - returns: the message digest.
     */
    public func final() -> [UInt8] {
        var digest = [UInt8](count: Int(self.algorithm.digestLength), repeatedValue: UInt8(0))
        // the one-shot routine returns the pointer passed in via the md parameter
        self.algorithm.rawValue(data: self.data.bytes, len: CC_LONG(self.data.length), md: &digest)
        return digest
    }

}

/// The `MessageDigestProducible` protocol defines methods to compute the message digest.
public protocol MessageDigestProducible {

    /**
     Computes the message digest.

     - parameter algorithm: The cryptographic algorithm to use.

     - returns: the message digest.
     */
    func digest(algorithm: Digest.Algorithm) -> Self
}

public extension MessageDigestProducible {
    /**
     Computes the MD2 message digest at data and returns the result.
     Recommended only for compatibility with existing applications. In new applications, SHA-256(or greater) should be preferred.

     - returns: the MD2 message digest.
     */
    public func MD2() -> Self {
        return digest(.MD2)
    }

    /**
     Computes the MD4 message digest at data and returns the result.
     Recommended only for compatibility with existing applications. In new applications, SHA-256(or greater) should be preferred.

     - returns: the MD4 message digest.
     */
    public func MD4() -> Self {
        return digest(.MD4)
    }

    /**
     Computes the MD5 message digest at data and returns the result.
     Recommended only for compatibility with existing applications. In new applications, SHA-256(or greater) should be preferred.

     - returns: the MD5 message digest.
     */
    public func MD5() -> Self {
        return digest(.MD5)
    }

    /**
     Computes the SHA-1 message digest at data and returns the result.

     - returns: the SHA-1 message digest.
     */
    public func SHA1() -> Self {
        return digest(.SHA1)
    }

    /**
     Computes the SHA224 message digest at data and returns the result.

     - returns: the SHA224 message digest.
     */
    public func SHA224() -> Self {
        return digest(.SHA224)
    }

    /**
     Computes the SHA256 message digest at data and returns the result.

     - returns: the SHA256 message digest.
     */
    public func SHA256() -> Self {
        return digest(.SHA256)
    }

    /**
     Computes the SHA384 message digest at data and returns the result.

     - returns: the SHA384 message digest.
     */
    public func SHA384() -> Self {
        return digest(.SHA384)
    }

    /**
     Computes the SHA512 message digest at data and returns the result.

     - returns: the SHA512 message digest.
     */
    public func SHA512() -> Self {
        return digest(.SHA512)
    }
}

/// The `NSData` extension defines methods to compute the message digest.
extension NSData: MessageDigestProducible {

    public func digest(algorithm: Digest.Algorithm) -> Self {
        let digest = Digest(algorithm)
        digest.update(self.bytesArray())
        let messageDigest = digest.final()
        return self.dynamicType.init(data: NSData(bytes: messageDigest, length: messageDigest.count))
    }

}

/// The `String` extension defines methods to compute the message digest.
extension String: MessageDigestProducible {

    public func digest(algorithm: Digest.Algorithm) -> String {
        let digest = Digest(algorithm)
        digest.update(self.dataUsingEncoding(NSUTF8StringEncoding)!.bytesArray())
        let messageDigest = digest.final()
        return String(data: NSData(bytes: messageDigest, length: messageDigest.count), encoding: NSUTF8StringEncoding)!
    }

}

// MARK: Random

/// The Random class defines a method for random bytes generation.
public final class Random {

    /**
     Returns random bytes in a buffer allocated by the caller.

     - parameter length: Number of random bytes to return.
     - returns: An array populated with randomly generated bytes.
     
     - throws: `SCryptoError` instance in case of eny errors.
     */
    public static func generateBytes(length : Int) throws -> [UInt8] {
        var bytes = [UInt8](count: length, repeatedValue: UInt8(0))
        let statusCode = CCRandomGenerateBytes(&bytes, bytes.count)
        if statusCode != CCRNGStatus(kCCSuccess) {
            throw SCryptoError(rawValue: statusCode)!
        }
        return bytes
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
    public static func random(length : Int) throws -> NSData {
        let bytes = try Random.generateBytes(length)
        let data = NSData(bytes: bytes, length: bytes.count)
        return data
    }

}

// MARK: HMAC

/// The HMAC class
public final class HMAC {

    public typealias Message = [UInt8]
    public typealias SecretKey = [UInt8]

    /**
     Cryptographic hash functions, that may be used in the calculation of an HMAC.
     */
    public enum Algorithm: RawConvertable {
        case SHA1, MD5, SHA256, SHA384, SHA512, SHA224

        internal var digestLength : Int32 {
            switch self {
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

        typealias RawValue = CCHmacAlgorithm
        internal var rawValue: RawValue {
            switch self {
            case SHA1 : return CCHmacAlgorithm(kCCHmacAlgSHA1)
            case MD5 : return CCHmacAlgorithm(kCCHmacAlgMD5)
            case SHA256 : return CCHmacAlgorithm(kCCHmacAlgSHA256)
            case SHA384 : return CCHmacAlgorithm(kCCHmacAlgSHA384)
            case SHA512: return CCHmacAlgorithm(kCCHmacAlgSHA512)
            case SHA224: return CCHmacAlgorithm(kCCHmacAlgSHA224)
            }
        }
    }

    private let algorithm: Algorithm
    private let message = NSMutableData()
    private let key: SecretKey

    /**
     Initializes a new HMAC object with the provided cryptographic algorithm and raw key bytes.

     - parameter algorithm: The cryptographic hash algorithm to use.
     - parameter key: The secret cryptographic key.

     - Returns: A newly created object to compute the HMAC.
     */
    init(_ algorithm: Algorithm, key: SecretKey) {
        self.algorithm = algorithm
        self.key = key
    }

    /**
     Appends specified bytes to the internal buffer. Can be called repeatedly with chunks of the message.

     - parameter message: The message to be authenticated.
     */
    public func update(message: Message) {
        self.message.appendBytes(message, length: message.count)
    }

    /**
     Computes the HMAC.

     - returns: the message authentication code.
     */
    public func final() -> [UInt8] {
        var hmac = [UInt8](count: Int(self.algorithm.digestLength), repeatedValue: UInt8(0))
        CCHmac(self.algorithm.rawValue, key, key.count, self.message.bytes, self.message.length, &hmac)
        return hmac
    }

}

/// The NSData extension defines methods to compute the HMAC.
public extension NSData {

    /**
     Calculates the keyed-hash message authentication code (HMAC).

     - parameter algorithm: The cryptographic hash algorithm to use.
     - parameter key:       The secret cryptographic key.

     - returns:  the message authentication code.
     */
    public func hmac(algorithm: HMAC.Algorithm, key: NSData) -> NSData {
        let hmac = HMAC(algorithm, key: key.bytesArray())
        hmac.update(self.bytesArray())
        let result = hmac.final()
        return NSData(bytes: result, length: result.count)
    }

}

/// The String extension defines methods to compute the HMAC.
public extension String {

    /**
     Calculates the keyed-hash message authentication code (HMAC).
     The message string and key will be interpreted as UTF8.

     - parameter algorithm: The cryptographic hash algorithm to use.
     - parameter key:       The secret cryptographic key.

     - returns:  the message authentication code (string of hexadecimal digits).
     */
    public func hmac(algorithm: HMAC.Algorithm, key: String) -> String {
        let key = key.dataUsingEncoding(NSUTF8StringEncoding)!
        let message = self.dataUsingEncoding(NSUTF8StringEncoding)!
        return message.hmac(algorithm, key: key).hexString()
    }

}

// MARK: Cryptor

/// The Cryptor class provides access to a number of symmetric encryption algorithms (stream and block ones).
public final class Cryptor {

    public typealias Data = [UInt8]
    public typealias Key = [UInt8]
    public typealias IV = [UInt8]

    /**
     The encryption algorithms that are supported by the Cryptor.
     */
    public enum Algorithm: RawConvertable {
        case AES, DES, TripleDES, CAST, RC2, RC4, Blowfish

        typealias RawValue = CCAlgorithm
        internal var rawValue: RawValue {
            switch self {
            case AES : return CCAlgorithm(kCCAlgorithmAES)
            case DES : return CCAlgorithm(kCCAlgorithmDES)
            case TripleDES : return CCAlgorithm(kCCAlgorithm3DES)
            case CAST : return CCAlgorithm(kCCAlgorithmCAST)
            case RC2: return CCAlgorithm(kCCAlgorithmRC2)
            case RC4: return CCAlgorithm(kCCAlgorithmRC4)
            case Blowfish : return CCAlgorithm(kCCAlgorithmBlowfish)
            }
        }

        /// Block sizes, in bytes, for supported algorithms.
        public var blockSize: Int {
            switch self {
            case AES : return kCCBlockSizeAES128
            case DES : return kCCBlockSizeDES
            case TripleDES : return kCCBlockSize3DES
            case CAST : return kCCBlockSizeCAST
            case RC2: return kCCBlockSizeRC2
            case RC4: return 0
            case Blowfish : return kCCBlockSizeBlowfish
            }
        }
    }

    private enum Operation: RawConvertable {
        case Encrypt, Decrypt

        typealias RawValue = CCOperation
        var rawValue: RawValue {
            switch self {
            case Encrypt : return CCOperation(kCCEncrypt)
            case Decrypt : return CCOperation(kCCDecrypt)
            }
        }
    }

    /**
     *  Options for block ciphers
     */
    public struct Options : OptionSetType {
        public typealias RawValue = CCOptions
        public let rawValue: RawValue

        public init(rawValue: RawValue) {
            self.rawValue = rawValue
        }

        /// Perform the PKCS7 padding.
        public static let PKCS7Padding =  Options(rawValue: RawValue(kCCOptionPKCS7Padding))
        /// Electronic Code Book Mode. Default is CBC.
        public static let ECBMode = Options(rawValue: RawValue(kCCOptionECBMode))
    }


    private let algorithm: Algorithm
    private let options: Options
    private let iv: IV?

    /**
     Initializes a new cryptor with the provided algorithm and options.

     - parameter algorithm: The symmetric algorithm to use for encryption
     - parameter options:   The encryption options.
     - parameter iv:        Initialization vector, optional. Used by block ciphers when Cipher Block Chaining (CBC) mode is enabled.
     If present, must be the same length as the selected algorithm's block size. This parameter is ignored if ECB mode is used or
     if a stream cipher algorithm is selected. nil by default.
     
     - returns: A newly created and initialized cryptor object.
     */
    init(algorithm: Algorithm, options: Options, iv: IV? = nil) {
        self.algorithm = algorithm
        self.options = options
        self.iv = iv
    }

    /**
     Encrypts the plaintext.

     - parameter data: The data to encrypt.
     - parameter key:  The shared secret key.

     - throws: `SCryptoError` instance in case of eny errors.

     - returns: Encrypted data.
     */
    public func encrypt(data: Data, key: Key) throws -> [UInt8] {
        return try cryptoOperation(data, key: key, operation: .Encrypt)
    }

    /**
     Decrypts the ciphertext.

     - parameter data: The encrypted data.
     - parameter key:  The shared secret key.

     - throws: `SCryptoError` instance in case of eny errors.

     - returns: Decrypted data.
     */
    public func decrypt(data: Data, key: Key) throws -> [UInt8] {
        return try cryptoOperation(data, key: key, operation: .Decrypt)
    }

    private func cryptoOperation(data: Data, key: Key, operation: Operation) throws -> [UInt8] {
        var dataOutMoved = 0
        var outData = [UInt8](count: Int(data.count + self.algorithm.blockSize), repeatedValue: UInt8(0))
        let ivData = self.iv == nil ? nil : UnsafePointer<Void>(self.iv!)
        let status = CCCrypt(operation.rawValue, // operation
            self.algorithm.rawValue, // algorithm
            self.options.rawValue, // options
            key, // key
            key.count, // keylength
            ivData, // iv
            data, // input data
            data.count, // input length
            &outData, // output buffer
            outData.count, // output buffer length
            &dataOutMoved) // output bytes real length
        if status == CCCryptorStatus(kCCSuccess) {
            return Array(outData[0..<dataOutMoved])
        } else {
            throw SCryptoError(rawValue: status)!
        }
    }

}

/// The NSData extension defines methods for symmetric encryption algorithms.
public extension NSData {

    /**
     Encrypts the plaintext.

     - parameter algorithm: The symmetric algorithm to use for encryption
     - parameter options:   The encryption options.
     - parameter key:  The shared secret key.
     - parameter iv:        Initialization vector, optional.

     - throws: `SCryptoError` instance in case of eny errors.

     - returns: Encrypted data.
     */
    public func encrypt(algorithm: Cryptor.Algorithm, options: Cryptor.Options, key: NSData, iv: NSData? = nil) throws -> NSData {
        let cryptor = Cryptor(algorithm: algorithm, options: options, iv: iv?.bytesArray())
        let encryptedBytes = try cryptor.encrypt(self.bytesArray(), key: key.bytesArray())
        return NSData(bytes: encryptedBytes, length: encryptedBytes.count)
    }

    /**
     Decrypts the ciphertext.

     - parameter algorithm: The symmetric algorithm to use for encryption
     - parameter options:   The encryption options.
     - parameter key:  The shared secret key.
     - parameter iv:        Initialization vector, optional.

     - throws: `SCryptoError` instance in case of eny errors.

     - returns: Decrypted data.
     */
    public func decrypt(algorithm: Cryptor.Algorithm, options: Cryptor.Options, key: NSData, iv: NSData? = nil) throws -> NSData {
        let cryptor = Cryptor(algorithm: algorithm, options: options, iv: iv?.bytesArray())
        let decryptedBytes = try cryptor.decrypt(self.bytesArray(), key: key.bytesArray())
        return NSData(bytes: decryptedBytes, length: decryptedBytes.count)
    }

}

// MARK: PBKDF

/// The `PBKDF` class defines methods to derive a key from a text password/passphrase.
public final class PBKDF {

    public typealias Password = [Int8]
    public typealias Salt = [UInt8]
    public typealias DerivedKey = [UInt8]
    private static let algorithm = CCPBKDFAlgorithm(kCCPBKDF2) // Currently only PBKDF2 is available via kCCPBKDF2

    /**
     The Pseudo Random Algorithm to use for the derivation iterations.
     */
    public enum PseudoRandomAlgorithm: RawConvertable {
        case SHA1, SHA224, SHA256, SHA384, SHA512

        typealias RawValue = CCPseudoRandomAlgorithm
        internal var rawValue: RawValue {
            switch self {
            case SHA1 : return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
            case SHA224 : return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224)
            case SHA256 : return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
            case SHA384 : return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
            case SHA512: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
            }
        }
    }

    /**
     Derive a key from a text password/passphrase.

     - parameter length:                The expected length of the derived key in bytes.
     - parameter password:              The text password used as input to the derivation function.
     - parameter salt:                  The salt byte values used as input to the derivation function.
     - parameter pseudoRandomAlgorithm: The Pseudo Random Algorithm to use for the derivation iterations.
     - parameter rounds:                The number of rounds of the Pseudo Random Algorithm to use.

     - throws: `SCryptoError` instance in case of eny errors.

     - returns: The resulting derived key.
     */
    public static func derivedKey(withLength length: Int, password: Password, salt: Salt, pseudoRandomAlgorithm: PseudoRandomAlgorithm, rounds: UInt32) throws -> DerivedKey {
        var derivedKey = DerivedKey(count: length, repeatedValue: UInt8(0))
        let statusCode = CCKeyDerivationPBKDF(self.algorithm,
            password,
            password.count,
            salt,
            salt.count,
            pseudoRandomAlgorithm.rawValue,
            rounds,
            &derivedKey,
            derivedKey.count)
        if statusCode != CCRNGStatus(kCCSuccess) {
            throw SCryptoError(rawValue: statusCode)!
        }
        return derivedKey
    }

    /**
    Determine the approximate number of PRF rounds to use for a specific delay on the current platform.

    - parameter passwordLength:        The length of the text password in bytes.
    - parameter saltLength:            The length of the salt in bytes.
    - parameter pseudoRandomAlgorithm: The Pseudo Random Algorithm to use for the derivation iterations.
    - parameter derivedKeyLength:      The expected length of the derived key in bytes.
    - parameter msec:                  The targetted duration we want to achieve for a key derivation with these parameters.

    - returns: the number of iterations to use for the desired processing time.
    */
    public static func calibrate(passwordLength: Int, saltLength: Int, pseudoRandomAlgorithm: PseudoRandomAlgorithm, derivedKeyLength: Int, msec : UInt32) -> UInt
    {
        return UInt(CCCalibratePBKDF(CCPBKDFAlgorithm(kCCPBKDF2), passwordLength, saltLength, pseudoRandomAlgorithm.rawValue, derivedKeyLength, msec))
    }
}


/// The NSData extension defines methods for deriving a key from a text password/passphrase.
public extension NSData {

    /**
     Derive a key from a text password/passphrase.

     - parameter salt:                  The salt byte values used as input to the derivation function.
     - parameter pseudoRandomAlgorithm: The Pseudo Random Algorithm to use for the derivation iterations.
     - parameter rounds:                he number of rounds of the Pseudo Random Algorithm to use.
     - parameter derivedKeyLength:      The expected length of the derived key in bytes.

     - throws: `SCryptoError` instance in case of eny errors.

     - returns: The resulting derived key.
     */
    public func derivedKey(salt: NSData, pseudoRandomAlgorithm: PBKDF.PseudoRandomAlgorithm, rounds: UInt32, derivedKeyLength: Int) throws -> NSData {
        let key = try PBKDF.derivedKey(withLength: derivedKeyLength, password: self.bytesArray(), salt: salt.bytesArray(), pseudoRandomAlgorithm: pseudoRandomAlgorithm, rounds: rounds)
        return NSData(bytes: key, length: key.count)
    }

    /**
    Determine the approximate number of PRF rounds to use for a specific delay on the current platform.

    - parameter saltLength:            The length of the salt in bytes.
    - parameter pseudoRandomAlgorithm: The Pseudo Random Algorithm to use for the derivation iterations.
    - parameter derivedKeyLength:      The expected length of the derived key in bytes.
    - parameter msec:                  The targetted duration we want to achieve for a key derivation with these parameters.

    - returns: the number of iterations to use for the desired processing time.
    */
    public func calibrate(saltLength: Int, pseudoRandomAlgorithm: PBKDF.PseudoRandomAlgorithm, derivedKeyLength: Int, msec : UInt32) -> UInt {
        return PBKDF.calibrate(self.length, saltLength: saltLength, pseudoRandomAlgorithm: pseudoRandomAlgorithm, derivedKeyLength: derivedKeyLength, msec: msec)
    }

}
