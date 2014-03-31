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
- [x] Cocoapods and Carthage compatible
- [x] Comprehensive Unit Test Coverage
- [x] [Complete Documentation](http://cocoadocs.org/docsets/SCrypto)
- [ ] iOS and OS X support
- [ ] Swift Package Manager support

##<a name="requirements"></a>Requirements

- iOS 9.0 or later
- Swift 2.0+
- Xcode 7.3+

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

##<a name="usage"></a>Usage

 
##<a name="licence"></a>Licence

`SCrypto` is MIT-licensed. See `LICENSE`. 