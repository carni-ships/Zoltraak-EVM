// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "EVMetal",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "EVMetal",
            targets: ["EVMetal"]),
        .executable(
            name: "EVMetalRunner",
            targets: ["EVMetalRunner"])
    ],
    dependencies: [
        .package(path: "../zkMetal"),
    ],
    targets: [
        .target(
            name: "EVMetal",
            dependencies: [
                .product(name: "zkMetal", package: "zkMetal"),
            ],
            path: "Sources/EVMetal",
            swiftSettings: [
                .enableExperimentalFeature("macros"),
            ]
        ),
        .target(
            name: "EVMetalRunner",
            dependencies: ["EVMetal"],
            path: "Sources/EVMetalTestRunner"
        ),
        .testTarget(
            name: "EVMetalTests",
            dependencies: ["EVMetal"],
            path: "Tests/EVMetalTests"
        ),
    ]
)
