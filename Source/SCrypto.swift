//
//  SCrypto.swift
//  SCrypto
//
//  Created by Maksym Shcheglov on 21/01/16.
//  Copyright © 2016 Maksym Shcheglov. All rights reserved.
//

import CommonCrypto

public extension Data {

    func bytesArray<T: ExpressibleByIntegerLiteral>() -> [T] {
        var bytes = Array<T>(repeating: 0, count: self.count)
        (self as NSData).getBytes(&bytes, length:self.count * MemoryLayout<T>.size)
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


internal protocol RawConvertible {
    associatedtype RawValue
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
public enum SCryptoError: Error, RawRepresentable, CustomStringConvertible {
    case paramError, bufferTooSmall, memoryFailure, alignmentError, decodeError, unimplemented, overflow, rngFailure

    public typealias RawValue = CCCryptorStatus

    public init?(rawValue: RawValue) {
        switch Int(rawValue) {
        case kCCParamError : self = .paramError
        case kCCBufferTooSmall : self = .bufferTooSmall
        case kCCMemoryFailure : self = .memoryFailure
        case kCCAlignmentError: self = .alignmentError
        case kCCDecodeError: self = .decodeError
        case kCCUnimplemented : self = .unimplemented
        case kCCOverflow: self = .overflow
        case kCCRNGFailure: self = .rngFailure
        default: return nil
        }
    }

    public var rawValue: RawValue {
        switch self {
        case .paramError : return CCCryptorStatus(kCCParamError)
        case .bufferTooSmall : return CCCryptorStatus(kCCBufferTooSmall)
        case .memoryFailure : return CCCryptorStatus(kCCMemoryFailure)
        case .alignmentError: return CCCryptorStatus(kCCAlignmentError)
        case .decodeError: return CCCryptorStatus(kCCDecodeError)
        case .unimplemented : return CCCryptorStatus(kCCUnimplemented)
        case .overflow: return CCCryptorStatus(kCCOverflow)
        case .rngFailure: return CCCryptorStatus(kCCRNGFailure)
        }
    }

    /// The error's textual representation
    public var description: String {
        let descriptions = [SCryptoError.paramError: "ParamError", SCryptoError.bufferTooSmall: "BufferTooSmall", SCryptoError.memoryFailure: "MemoryFailure",
            SCryptoError.alignmentError: "AlignmentError", SCryptoError.decodeError: "DecodeError", SCryptoError.unimplemented: "Unimplemented", SCryptoError.overflow: "Overflow",
            SCryptoError.rngFailure: "RNGFailure"]
        return descriptions[self] ?? ""
    }

}

// MARK: Message Digest

/// The `MessageDigest` class provides applications functionality of a message digest algorithms, such as MD5 or SHA.
public final class MessageDigest {

    /**
     The cryptographic algorithm types to evaluate message digest.

     MD2, MD4, and MD5 are recommended only for compatibility with existing applications.
     In new applications, SHA-256(or greater) should be preferred.
     */
    public enum Algorithm {
        case md2, md4, md5, sha1, sha224, sha256, sha384, sha512

        typealias Function = (_ data: UnsafeRawPointer, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>?

        internal var digest: (length: Int32, function: Function) {
            switch self {
            case .md2:
                return (CC_MD2_DIGEST_LENGTH, CC_MD2)
            case .md4:
                return (CC_MD4_DIGEST_LENGTH, CC_MD4)
            case .md5:
                return (CC_MD5_DIGEST_LENGTH, CC_MD5)
            case .sha1:
                return (CC_SHA1_DIGEST_LENGTH, CC_SHA1)
            case .sha224:
                return (CC_SHA224_DIGEST_LENGTH, CC_SHA224)
            case .sha256:
                return (CC_SHA256_DIGEST_LENGTH, CC_SHA256)
            case .sha384:
                return (CC_SHA384_DIGEST_LENGTH, CC_SHA384)
            case .sha512:
                return (CC_SHA512_DIGEST_LENGTH, CC_SHA512)
            }
        }
    }

    fileprivate let algorithm: Algorithm
    fileprivate let data = NSMutableData()

    /**
     Initializes a new digest object with the specified cryptographic algorithm.

     - parameter algorithm: The cryptographic algorithm to use.

     - Returns: A newly created object to compute the message digest.
     */
    init(_ algorithm: Algorithm) {
        self.algorithm = algorithm
    }

    /**
     Updates the digest using the specified array of bytes. Can be called repeatedly with chunks of the message to be hashed.

     - parameter bytes:  The array of bytes to append.
     */
    public func update(_ bytes: [UInt8]) {
        self.data.append(bytes, length: bytes.count)
    }

    /**
     Evaluates the message digest.

     - returns: the message digest.
     */
    public func final() -> [UInt8] {
        var digest = [UInt8](repeating: UInt8(0), count: Int(self.algorithm.digest.length))
        // the one-shot routine returns the pointer passed in via the md parameter
        _ = self.algorithm.digest.function(self.data.bytes, CC_LONG(self.data.length), &digest)
        return digest
    }

}

/// The `MessageDigestProducible` protocol defines methods to compute the message digest.
public protocol MessageDigestProducible {

    /**
     Produces the message digest.

     - parameter algorithm: The cryptographic algorithm to use.

     - returns: the message digest.
     */
    func digest(_ algorithm: MessageDigest.Algorithm) -> Self
}

public extension MessageDigestProducible {
    /**
     Evaluates the MD2 message digest at data and returns the result.
     Recommended only for compatibility with existing applications. In new applications, SHA-256(or greater) should be preferred.

     - returns: the MD2 message digest.
     */
    public func MD2() -> Self {
        return digest(.md2)
    }

    /**
     Evaluates the MD4 message digest at data and returns the result.
     Recommended only for compatibility with existing applications. In new applications, SHA-256(or greater) should be preferred.

     - returns: the MD4 message digest.
     */
    public func MD4() -> Self {
        return digest(.md4)
    }

    /**
     Evaluates the MD5 message digest at data and returns the result.
     Recommended only for compatibility with existing applications. In new applications, SHA-256(or greater) should be preferred.

     - returns: the MD5 message digest.
     */
    public func MD5() -> Self {
        return digest(.md5)
    }

    /**
     Evaluates the SHA-1 message digest at data and returns the result.

     - returns: the SHA-1 message digest.
     */
    public func SHA1() -> Self {
        return digest(.sha1)
    }

    /**
     Evaluates the SHA224 message digest at data and returns the result.

     - returns: the SHA224 message digest.
     */
    public func SHA224() -> Self {
        return digest(.sha224)
    }

    /**
     Evaluates the SHA256 message digest at data and returns the result.

     - returns: the SHA256 message digest.
     */
    public func SHA256() -> Self {
        return digest(.sha256)
    }

    /**
     Evaluates the SHA384 message digest at data and returns the result.

     - returns: the SHA384 message digest.
     */
    public func SHA384() -> Self {
        return digest(.sha384)
    }

    /**
     Evaluates the SHA512 message digest at data and returns the result.

     - returns: the SHA512 message digest.
     */
    public func SHA512() -> Self {
        return digest(.sha512)
    }
}

/// The `Data` extension defines methods to compute the message digest.
extension Data: MessageDigestProducible {

    /**
     Produces the message digest.

     - parameter algorithm: The cryptographic algorithm to use.

     - returns:  the message digest.
     */
    public func digest(_ algorithm: MessageDigest.Algorithm) -> Data {
        let digest = MessageDigest(algorithm)
        digest.update(self.bytesArray())
        let messageDigest = digest.final()
        return type(of: self).init(Data(bytes: UnsafePointer<UInt8>(messageDigest), count: messageDigest.count))
    }

}

/// The `String` extension defines methods to compute the message digest.
extension String: MessageDigestProducible {

    /**
     Produces the message digest.

     - parameter algorithm: The cryptographic algorithm to use.

     - returns:  the message digest (string of hexadecimal digits).
     */
    public func digest(_ algorithm: MessageDigest.Algorithm) -> String {
        let digest = MessageDigest(algorithm)
        digest.update(self.data(using: String.Encoding.utf8)!.bytesArray())
        let messageDigest = digest.final()
        return Data(bytes: UnsafePointer<UInt8>(messageDigest), count: messageDigest.count).hexString()
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
    public static func generateBytes(_ length : Int) throws -> [UInt8] {
        var bytes = [UInt8](repeating: UInt8(0), count: length)
        let statusCode = CCRandomGenerateBytes(&bytes, bytes.count)
        if statusCode != CCRNGStatus(kCCSuccess) {
            throw SCryptoError(rawValue: statusCode)!
        }
        return bytes
    }
}

/// The Data extension defines a method for random bytes generation.
public extension Data {

    /**
     Creates Data object of the specified length and populates it with randomly generated bytes.
     The created object has cryptographically strong random bits suitable for use as cryptographic keys, IVs, nonces etc.

     - parameter length: Number of random bytes to return.

     - returns: newly created Data object populated with randomly generated bytes.
     */
    public static func random(_ length : Int) throws -> Data {
        let bytes = try Random.generateBytes(length)
        let data = Data(bytes: UnsafePointer<UInt8>(bytes), count: bytes.count)
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
    public enum Algorithm: RawConvertible {
        case sha1, md5, sha256, sha384, sha512, sha224

        internal var digestLength : Int32 {
            switch self {
            case .md5:
                return CC_MD5_DIGEST_LENGTH
            case .sha1:
                return CC_SHA1_DIGEST_LENGTH
            case .sha224:
                return CC_SHA224_DIGEST_LENGTH
            case .sha256:
                return CC_SHA256_DIGEST_LENGTH
            case .sha384:
                return CC_SHA384_DIGEST_LENGTH
            case .sha512:
                return CC_SHA512_DIGEST_LENGTH
            }
        }

        typealias RawValue = CCHmacAlgorithm
        internal var rawValue: RawValue {
            switch self {
            case .sha1 : return CCHmacAlgorithm(kCCHmacAlgSHA1)
            case .md5 : return CCHmacAlgorithm(kCCHmacAlgMD5)
            case .sha256 : return CCHmacAlgorithm(kCCHmacAlgSHA256)
            case .sha384 : return CCHmacAlgorithm(kCCHmacAlgSHA384)
            case .sha512: return CCHmacAlgorithm(kCCHmacAlgSHA512)
            case .sha224: return CCHmacAlgorithm(kCCHmacAlgSHA224)
            }
        }
    }

    fileprivate let algorithm: Algorithm
    fileprivate let message = NSMutableData()
    fileprivate let key: SecretKey

    /**
     Initializes a new HMAC object with the provided cryptographic algorithm and raw key bytes.

     - parameter algorithm: The cryptographic hash algorithm to use.
     - parameter key: The secret cryptographic key. The key should be randomly generated bytes and is recommended to be equal in length to the digest size of the hash function chosen.

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
    public func update(_ message: Message) {
        self.message.append(message, length: message.count)
    }

    /**
     Evaluates the HMAC.

     - returns: the message authentication code.
     */
    public func final() -> [UInt8] {
        var hmac = [UInt8](repeating: UInt8(0), count: Int(self.algorithm.digestLength))
        CCHmac(self.algorithm.rawValue, key, key.count, self.message.bytes, self.message.length, &hmac)
        return hmac
    }

}

/// The Data extension defines methods to compute the HMAC.
public extension Data {

    /**
     Produces the keyed-hash message authentication code (HMAC).

     - parameter algorithm: The cryptographic hash algorithm to use.
     - parameter key:       The secret cryptographic key. The key should be randomly generated bytes and is recommended to be equal in length to the digest size of the hash function chosen.

     - returns:  the message authentication code.
     */
    public func hmac(_ algorithm: HMAC.Algorithm, key: Data) -> Data {
        let hmac = HMAC(algorithm, key: key.bytesArray())
        hmac.update(self.bytesArray())
        let result = hmac.final()
        return Data(bytes: UnsafePointer<UInt8>(result), count: result.count)
    }

}

/// The String extension defines methods to compute the HMAC.
public extension String {

    /**
     Produces the keyed-hash message authentication code (HMAC).
     The key and message string and key are interpreted as UTF8.

     - parameter algorithm: The cryptographic hash algorithm to use.
     - parameter key:       The secret cryptographic key.

     - returns:  the message authentication code (string of hexadecimal digits).
     */
    public func hmac(_ algorithm: HMAC.Algorithm, key: String) -> String {
        let key = key.data(using: String.Encoding.utf8)!
        let message = self.data(using: String.Encoding.utf8)!
        return message.hmac(algorithm, key: key).hexString()
    }

}

// MARK: Cipher

/// The Cipher provides the functionality of a cryptographic cipher for encryption and decryption (stream and block algorithms).
public final class Cipher {

    public typealias Data = [UInt8]
    public typealias Key = [UInt8]
    public typealias IV = [UInt8]

    /**
     The encryption algorithms that are supported by the Cipher.
     
     - AES: Advanced Encryption Standard is a block cipher standardized by NIST. AES is both fast, and cryptographically strong. It is a good default choice for encryption.
            The secret key must be either 128, 192, or 256 bits long.
     - DES: A block cipher. The key should be either 64 bits long.
     - TripleDES: A block cipher standardized by NIST and not recommended for new applications because it is incredibly slow. The key should be 192 bits long.
     - CAST: A block cipher approved for use in the Canadian government by the Communications Security Establishment. It is a variable key length cipher and supports keys from 40-128 bits in length in increments of 8 bits.
     - RC2: A block cipher with variable key length from 8 to 1024 bits, in steps of 8 bits.
     - RC4: A stream cipher with serious weaknesses in its initial stream output. Its use is strongly discouraged. The secret key must be either 40, 56, 64, 80, 128, 192, or 256 bits in length.
     - Blowfish: A block cipher with variable key length from 32 to 448 bits in increments of 8 bits. Known to be susceptible to attacks when using weak keys.
     */
    public enum Algorithm: RawConvertible {
        case aes, des, tripleDES, cast, rc2, rc4, blowfish

        typealias RawValue = CCAlgorithm
        internal var rawValue: RawValue {
            switch self {
            case .aes : return CCAlgorithm(kCCAlgorithmAES)
            case .des : return CCAlgorithm(kCCAlgorithmDES)
            case .tripleDES : return CCAlgorithm(kCCAlgorithm3DES)
            case .cast : return CCAlgorithm(kCCAlgorithmCAST)
            case .rc2: return CCAlgorithm(kCCAlgorithmRC2)
            case .rc4: return CCAlgorithm(kCCAlgorithmRC4)
            case .blowfish : return CCAlgorithm(kCCAlgorithmBlowfish)
            }
        }

        /// Block sizes, in bytes, for supported algorithms.
        public var blockSize: Int {
            switch self {
            case .aes : return kCCBlockSizeAES128
            case .des : return kCCBlockSizeDES
            case .tripleDES : return kCCBlockSize3DES
            case .cast : return kCCBlockSizeCAST
            case .rc2: return kCCBlockSizeRC2
            case .rc4: return 0
            case .blowfish : return kCCBlockSizeBlowfish
            }
        }
    }

    fileprivate enum Operation: RawConvertible {
        case encrypt, decrypt

        typealias RawValue = CCOperation
        var rawValue: RawValue {
            switch self {
            case .encrypt : return CCOperation(kCCEncrypt)
            case .decrypt : return CCOperation(kCCDecrypt)
            }
        }
    }

    /**
     *  Options for block ciphers
     */
    public struct Options : OptionSet {
        public typealias RawValue = CCOptions
        public let rawValue: RawValue

        public init(rawValue: RawValue) {
            self.rawValue = rawValue
        }

        /// Perform the PKCS7 padding.
        public static let PKCS7Padding =  Options(rawValue: RawValue(kCCOptionPKCS7Padding))
        /// Electronic Code Book Mode. This block cipher mode is not recommended for use. Default mode is CBC.
        public static let ECBMode = Options(rawValue: RawValue(kCCOptionECBMode))
    }


    fileprivate let algorithm: Algorithm
    fileprivate let options: Options
    fileprivate let iv: IV?

    /**
     Initializes a new cipher with the provided algorithm and options.

     - parameter algorithm: The symmetric algorithm to use for encryption
     - parameter options:   The encryption options.
     - parameter iv:        Initialization vector, optional. Used by block ciphers when Cipher Block Chaining (CBC) mode is enabled. If present, must be the same length as the selected algorithm's block size. This parameter is ignored if ECB mode is used or if a stream cipher algorithm is selected. nil by default.
     
     - returns: A newly created and initialized cipher object.
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
    public func encrypt(_ data: Data, key: Key) throws -> [UInt8] {
        return try cryptoOperation(data, key: key, operation: .encrypt)
    }

    /**
     Decrypts the ciphertext.

     - parameter data: The encrypted data.
     - parameter key:  The shared secret key.

     - throws: `SCryptoError` instance in case of eny errors.

     - returns: Decrypted data.
     */
    public func decrypt(_ data: Data, key: Key) throws -> [UInt8] {
        return try cryptoOperation(data, key: key, operation: .decrypt)
    }

    fileprivate func cryptoOperation(_ data: Data, key: Key, operation: Operation) throws -> [UInt8] {
        var dataOutMoved = 0
        var outData = [UInt8](repeating: UInt8(0), count: Int(data.count + self.algorithm.blockSize))
        let ivData = self.iv == nil ? nil : UnsafeRawPointer(self.iv!)
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

/// The Data extension defines methods for symmetric encryption algorithms.
public extension Data {

    /**
     Encrypts the plaintext.

     - parameter algorithm: The symmetric algorithm to use for encryption
     - parameter options:   The encryption options.
     - parameter key:       The shared secret key.
     - parameter iv:        Initialization vector, optional. Used by block ciphers when Cipher Block Chaining (CBC) mode is enabled. If present, must be the same length as the selected algorithm's block size. This parameter is ignored if ECB mode is used or if a stream cipher algorithm is selected. nil by default.

     - throws: `SCryptoError` instance in case of eny errors.

     - returns: Encrypted data.
     */
    public func encrypt(_ algorithm: Cipher.Algorithm, options: Cipher.Options, key: Data, iv: Data? = nil) throws -> Data {
        let cipher = Cipher(algorithm: algorithm, options: options, iv: iv?.bytesArray())
        let encryptedBytes = try cipher.encrypt(self.bytesArray(), key: key.bytesArray())
        return Data(bytes: UnsafePointer<UInt8>(encryptedBytes), count: encryptedBytes.count)
    }

    /**
     Decrypts the ciphertext.

     - parameter algorithm: The symmetric algorithm to use for encryption
     - parameter options:   The encryption options.
     - parameter key:       The shared secret key.
     - parameter iv:        Initialization vector, optional. Used by block ciphers when Cipher Block Chaining (CBC) mode is enabled. If present, must be the same length as the selected algorithm's block size. This parameter is ignored if ECB mode is used or if a stream cipher algorithm is selected. nil by default.

     - throws: `SCryptoError` instance in case of eny errors.

     - returns: Decrypted data.
     */
    public func decrypt(_ algorithm: Cipher.Algorithm, options: Cipher.Options, key: Data, iv: Data? = nil) throws -> Data {
        let cipher = Cipher(algorithm: algorithm, options: options, iv: iv?.bytesArray())
        let decryptedBytes = try cipher.decrypt(self.bytesArray(), key: key.bytesArray())
        return Data(bytes: UnsafePointer<UInt8>(decryptedBytes), count: decryptedBytes.count)
    }

}

// MARK: PBKDF

/// The `PBKDF` class defines methods to derive a key from a text password/passphrase.
public final class PBKDF {

    public typealias Password = [Int8]
    public typealias Salt = [UInt8]
    public typealias DerivedKey = [UInt8]
    fileprivate static let algorithm = CCPBKDFAlgorithm(kCCPBKDF2) // Currently only PBKDF2 is available via kCCPBKDF2

    /**
     The Pseudo Random Algorithm to use for the derivation iterations.
     */
    public enum PseudoRandomAlgorithm: RawConvertible {
        case sha1, sha224, sha256, sha384, sha512

        typealias RawValue = CCPseudoRandomAlgorithm
        internal var rawValue: RawValue {
            switch self {
            case .sha1 : return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
            case .sha224 : return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224)
            case .sha256 : return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
            case .sha384 : return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
            case .sha512: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
            }
        }
    }

    /**
     Derive a key from a text password/passphrase.

     - parameter length:                The expected length of the derived key in bytes.
     - parameter password:              The text password used as input to the derivation function.
     - parameter salt:                  The salt byte values used as input to the derivation function. Recommended to use 128-bits salt or longer.
     - parameter pseudoRandomAlgorithm: The Pseudo Random Algorithm to use for the derivation iterations.
     - parameter rounds:                The number of rounds of the Pseudo Random Algorithm to use. This can be used to control the length of time the operation takes. Higher numbers help mitigate brute force attacks against derived keys.

     - throws: `SCryptoError` instance in case of eny errors.

     - returns: The resulting derived key.
     */
    public static func derivedKey(withLength length: Int, password: Password, salt: Salt, pseudoRandomAlgorithm: PseudoRandomAlgorithm, rounds: UInt32) throws -> DerivedKey {
        var derivedKey = DerivedKey(repeating: UInt8(0), count: length)
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
    public static func calibrate(_ passwordLength: Int, saltLength: Int, pseudoRandomAlgorithm: PseudoRandomAlgorithm, derivedKeyLength: Int, msec : UInt32) -> UInt
    {
        return UInt(CCCalibratePBKDF(CCPBKDFAlgorithm(kCCPBKDF2), passwordLength, saltLength, pseudoRandomAlgorithm.rawValue, derivedKeyLength, msec))
    }
}


/// The Data extension defines methods for deriving a key from a text password/passphrase.
public extension Data {

    /**
     Derive a key from a text password/passphrase.

     - parameter salt:                  The salt byte values used as input to the derivation function. Recommended to use 128-bits salt or longer.
     - parameter pseudoRandomAlgorithm: The Pseudo Random Algorithm to use for the derivation iterations.
     - parameter rounds:                The number of rounds of the Pseudo Random Algorithm to use. This can be used to control the length of time the operation takes. Higher numbers help mitigate brute force attacks against derived keys.
     - parameter derivedKeyLength:      The expected length of the derived key in bytes.

     - throws: `SCryptoError` instance in case of eny errors.

     - returns: The resulting derived key.
     */
    public func derivedKey(_ salt: Data, pseudoRandomAlgorithm: PBKDF.PseudoRandomAlgorithm, rounds: UInt32, derivedKeyLength: Int) throws -> Data {
        let key = try PBKDF.derivedKey(withLength: derivedKeyLength, password: self.bytesArray(), salt: salt.bytesArray(), pseudoRandomAlgorithm: pseudoRandomAlgorithm, rounds: rounds)
        return Data(bytes: UnsafePointer<UInt8>(key), count: key.count)
    }

    /**
    Determine the approximate number of PRF rounds to use for a specific delay on the current platform.

    - parameter saltLength:            The length of the salt in bytes.
    - parameter pseudoRandomAlgorithm: The Pseudo Random Algorithm to use for the derivation iterations.
    - parameter derivedKeyLength:      The expected length of the derived key in bytes.
    - parameter msec:                  The targetted duration we want to achieve for a key derivation with these parameters.

    - returns: the number of iterations to use for the desired processing time.
    */
    public func calibrate(_ saltLength: Int, pseudoRandomAlgorithm: PBKDF.PseudoRandomAlgorithm, derivedKeyLength: Int, msec : UInt32) -> UInt {
        return PBKDF.calibrate(self.count, saltLength: saltLength, pseudoRandomAlgorithm: pseudoRandomAlgorithm, derivedKeyLength: derivedKeyLength, msec: msec)
    }

}
