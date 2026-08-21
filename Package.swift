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
        .binaryTarget(name: "PockCoreFFI", url: "https://github.com/pock-sh/pock-core/releases/download/v0.3.0/PockCoreFFI.xcframework.zip", checksum: "79998da47d546f08fe6d43699a43a85e8ad83d5bef88c0ab39b77980e810e38e"),
        .target(name: "PockCore", dependencies: ["PockCoreFFI"], path: "swift/Sources/PockCore"),
        .testTarget(name: "PockCoreTests", dependencies: ["PockCore"], path: "swift/Tests/PockCoreTests"),
    ]
)
