// swift-tools-version:5.9
import PackageDescription

// The binary target points at a locally built xcframework during development;
// the release workflow rewrites it to url:/checksum: on tag.
let package = Package(
    name: "PockCore",
    // Spelled as a string: the `.v18` enum case needs tools-version 6.0, and
    // that would flip the generated bindings into Swift 6 language mode.
    platforms: [.iOS("18.0"), .macOS(.v14)],
    products: [.library(name: "PockCore", targets: ["PockCore"])],
    targets: [
        .binaryTarget(name: "PockCoreFFI", url: "https://github.com/pock-sh/pock-core/releases/download/v0.2.0/PockCoreFFI.xcframework.zip", checksum: "c263cddbf48fad3a08f2210f39dba816447f08d25c7269ec31d481ae828c1184"),
        .target(name: "PockCore", dependencies: ["PockCoreFFI"], path: "swift/Sources/PockCore"),
        .testTarget(name: "PockCoreTests", dependencies: ["PockCore"], path: "swift/Tests/PockCoreTests"),
    ]
)
