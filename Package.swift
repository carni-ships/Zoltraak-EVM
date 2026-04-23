// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "Zoltraak",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "Zoltraak",
            targets: ["Zoltraak"]),
        .executable(
            name: "ZoltraakRunner",
            targets: ["ZoltraakRunner"])
    ],
    dependencies: [
        .package(path: "../zkMetal"),
    ],
    targets: [
        .target(
            name: "Zoltraak",
            dependencies: [
                .product(name: "zkMetal", package: "zkMetal"),
            ],
            path: "Sources/Zoltraak",
            swiftSettings: [
                .enableExperimentalFeature("macros"),
            ]
        ),
        .target(
            name: "ZoltraakRunner",
            dependencies: ["Zoltraak"],
            path: "Sources/ZoltraakTestRunner"
        ),
        .testTarget(
            name: "ZoltraakTests",
            dependencies: ["Zoltraak"],
            path: "Tests/ZoltraakTests"
        ),
    ]
)
