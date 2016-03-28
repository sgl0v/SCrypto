SCrypto
===============
[![Build Status](https://travis-ci.org/sgl0v/SCrypto.svg?branch=master)](https://travis-ci.org/sgl0v/SCrypto) 
[![Version](https://img.shields.io/cocoapods/v/SCrypto.svg?style=flat)](http://cocoadocs.org/docsets/SCrypto)
[![Carthage Compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
[![License](https://img.shields.io/cocoapods/l/SCrypto.svg?style=flat)](http://cocoadocs.org/docsets/SCrypto)
[![Platform](https://img.shields.io/cocoapods/p/SCrypto.svg?style=flat)](http://cocoadocs.org/docsets/SCrypto)

[[Overview](#overview) &bull; [Installation](#installation) &bull; [Demo](#demo) &bull; [Requirements](#requirements) &bull; [Licence](#licence)] 

<br>

##<a name="overview"></a>Overview
SCrypto provides neat Swift interface to access the CommonCrypto routines.
### Features

- [x] Essential `NSData` and `String` extensions for message digest, HMAC, PBKDF, symmetric encryption calculation
- [x] Supports Swift 2.0 and Swift 2.2
- [x] Comprehensive Unit Test Coverage
- [x] [Complete Documentation](http://cocoadocs.org/docsets/SCrypto)

##<a name="requirements"></a>Requirements

- iOS 9.0 or later
- Swift 2.0+
- Xcode 7.2+

##<a name="installation"></a>Installation
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

pod 'SCrypto', '~> 1.0'
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
github "sgl0v/SCrypto" ~> 1.0
```

Run `carthage update` to build the framework and drag the built `SCrypto.framework` into your Xcode project.


##<a name="demo"></a>Demo

 
##<a name="licence"></a>Licence

`SCrypto` is MIT-licensed. See `LICENSE`. 