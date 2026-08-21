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
        .binaryTarget(name: "PockCoreFFI", path: "PockCoreFFI.xcframework"),
        .target(name: "PockCore", dependencies: ["PockCoreFFI"], path: "swift/Sources/PockCore"),
        .testTarget(name: "PockCoreTests", dependencies: ["PockCore"], path: "swift/Tests/PockCoreTests"),
    ]
)
