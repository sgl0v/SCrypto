#<p align="center">SCrypto</p>

[![Build Status](https://travis-ci.org/sgl0v/SCrypto.svg?branch=master)](https://travis-ci.org/sgl0v/SCrypto) 
[![codecov.io](https://codecov.io/github/sgl0v/SCrypto/coverage.svg?branch=master)](https://codecov.io/github/sgl0v/SCrypto?branch=master)
[![Version](https://img.shields.io/cocoapods/v/SCrypto.svg?style=flat)](http://cocoadocs.org/docsets/SCrypto)
[![Carthage Compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
[![License](https://img.shields.io/cocoapods/l/SCrypto.svg?style=flat)](http://cocoadocs.org/docsets/SCrypto)
[![Platform](https://img.shields.io/cocoapods/p/SCrypto.svg?style=flat)](http://cocoadocs.org/docsets/SCrypto)

[[Overview](#overview) &bull; [Requirements](#requirements) &bull; [Installation](#installation) &bull; [Usage](#usage) &bull; [Alternatives](#alternatives) &bull; [Licence](#licence)] 

---

##Overview
SCrypto provides neat Swift interface to access the CommonCrypto routines.
### Features

- [x] Essential `Data` and `String` extensions for message digest, HMAC, PBKDF, symmetric encryption calculation
- [x] Swift 2.2 and Swift 3.0 support
- [x] Cocoapods and Carthage compatible
- [x] Comprehensive Unit Test Coverage
- [x] [Complete Documentation](http://cocoadocs.org/docsets/SCrypto)
- [x] iOS and OS X support
- [ ] Swift Package Manager support

---

##Requirements

- iOS 9.0+ / macOS 10.11+
- Swift 3.0+
- Xcode 8.0+

---

##Installation
### Cocoapods

[CocoaPods](http://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:

```bash
$ gem install cocoapods
```

To integrate SCrypto into your Xcode project using CocoaPods, specify it in your `Podfile`:

```ruby
source 'https://github.com/CocoaPods/Specs.git'
platform :ios, '9.0'
use_frameworks!

pod 'SCrypto', '~> 2.0.0'
```

Then, run the following command:

```bash
$ pod install
```

### Carthage
[Carthage](https://github.com/Carthage/Carthage) is a decentralized dependency manager that builds your dependencies and provides you with binary frameworks. You can install Carthage with [Homebrew](http://brew.sh/) using the following command:

```bash
$ brew update
$ brew install carthage
```

To integrate SCrypto into your Xcode project using Carthage, specify it in your `Cartfile`:

```ogdl
github "sgl0v/SCrypto" ~> 1.0.0
```

Run `carthage update` to build the framework and drag the built `SCrypto.framework` into your Xcode project.

### Manually
If you prefer not to use either of the mentioned dependency managers, you can integrate SCrypto into your project manually.

- Open up Terminal, `cd` into your top-level project directory, and run the following command "if" your project is not initialized as a git repository:

```bash
$ git init
```

- Add SCrypto as a git [submodule](http://git-scm.com/docs/git-submodule) by running the following command:

```bash
$ git submodule add https://github.com/sgl0v/SCrypto.git
```

- Open the new `SCrypto` folder, and drag the `SCrypto.xcodeproj` into the Project Navigator of your application's Xcode project.

    > The `SCrypto.xcodeproj` should appear nested underneath your application's blue project icon. Whether it is above or below all the other Xcode groups does not matter.

- Select the `SCrypto.xcodeproj` in the Project Navigator and verify the deployment target matches that of your application target.
- Next, select your application project in the Project Navigator (blue project icon) to navigate to the target configuration window and select the application target under the "Targets" heading in the sidebar.
- In the tab bar at the top of that window, open the "General" panel.
- Click on the `+` button under the "Embedded Binaries" section.
- You will see two different `SCrypto.xcodeproj` folders each with two different versions of the `SCrypto.framework iOS` nested inside a `Products` folder.

    > It doesn't matter which `Products` folder you choose from.
    
- Just select the `SCrypto.framework iOS` and that's it!

	> The `SCrypto.framework` is automagically added as a target dependency and should appear as a linked and embedded framework in the `Build Phases` section.

---

##Usage
### Message Digest ([MD5](https://en.wikipedia.org/wiki/MD5), [SHA](https://en.wikipedia.org/wiki/Secure_Hash_Algorithm))
Message digests are secure one-way [cryptographic hash functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function) that take arbitrary-sized data and output a fixed-length hash value.

```swift
let sha256 = "message".SHA256()
```

### Keyed-hash message authentication code ([HMAC](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code))
Hash-based message authentication codes (or HMACs) provides a way for calculating message authentication codes using a cryptographic hash function coupled with a secret key. You can use an HMAC to verify both the integrity and authenticity of a message. The following standard hash algorithm are supported: SHA1, MD5, SHA256, SHA384, SHA512, SHA224.

```swift
let secretKey = try! Data.random(32) 
let message = "message".data(using: String.Encoding.utf8)!
let hmac = message.hmac(.SHA256, key: secretKey)
```

### Pseudorandom number generator ([PRNG](https://en.wikipedia.org/wiki/Pseudorandom_number_generator))
Generates cryptographically strong random bits suitable for use as cryptographic keys, IVs, nonces etc.

```swift
let randomBytes = try! Data.random(16)
```

### Symmetric-key algorithms ([AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard), [TripleDES](https://en.wikipedia.org/wiki/Triple_DES), [CAST](https://en.wikipedia.org/wiki/CAST5), [RC2](https://en.wikipedia.org/wiki/RC2), [RC4](https://en.wikipedia.org/wiki/RC4), [Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher)))

Symmetric-key algorithms use the same cryptographic keys for both encryption of plaintext and decryption of ciphertext. Note that symmetric encryption only provides secrecy but not integrity. There are recent encryption modes which combine symmetric encryption and checked integrity (not supported by CommonCrypto). For this reason it is strongly recommended to combine encryption with a HMAC.

Here is the way to encrypt and decrypt data via AES algorithm in CBC mode with PKCS7 Padding:

```swift
let plaintext = "plain text".data(using: String.Encoding.utf8)!
let sharedSecretKey = "shared_secret_key".data(using: String.Encoding.utf8)!.SHA256() // AES-256
let IV = try! Data.random(16) // Randomly generated IV. Length is equal to the AES block size(128)
let ciphertext = try! plaintext.encrypt(.AES, options: .PKCS7Padding, key: sharedSecretKey, iv: IV)
let plaintext2 = try! ciphertext.decrypt(.AES, options: .PKCS7Padding, key: sharedSecretKey, iv: IV)
```

### Password-Based Key Derivation Function ([PBKDF2](https://en.wikipedia.org/wiki/PBKDF2))
Key derivation functions are used for turning a passphrase into an arbitrary length key for use as a cryptographic key in subsequent operations.

```swift
let password = "password".data(using: String.Encoding.utf8)!
let salt = try! Data.random(32)
let derivedKey = try! password.derivedKey(salt, pseudoRandomAlgorithm: .SHA256, rounds: 20, derivedKeyLength: 32)
```

---

##Alternatives
Looking for something else? Try another Swift CommonCrypto wrappers:

- [RNCryptor](https://github.com/RNCryptor/RNCryptor)
- [IDZSwiftCommonCrypto](https://github.com/iosdevzone/IDZSwiftCommonCrypto)
- [Crypto](https://github.com/soffes/Crypto)

---
 
##Licence

`SCrypto` is MIT-licensed. See `LICENSE`. 