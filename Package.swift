// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SCrypto",
    platforms: [
        .macOS(.v10_11),
        .iOS(.v9),
    ],
    products: [
        .library(name: "SCrypto", type: .dynamic, targets: ["SCrypto"]),
    ],
    targets: [
        .target(name: "SCrypto", path: "Source"),
        .testTarget(name: "SCrypto Tests", dependencies: ["SCrypto"], path: "Tests")
    ]
)