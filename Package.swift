// swift-tools-version:5.3

import PackageDescription

let major = 3, minor = 2, patch = 16

let package = Package(
    name: "libce",
    platforms: [.iOS(.v8), .macOS(.v10_10)],
    products: [
        .library(name: "libce", targets: ["libce"])
    ],
    targets: [
        .target(
            name: "libce",
            path: ".",
            sources: [
                "src",
                "lib/crypto-algorithms/aes.c",
                "lib/crypto-algorithms/sha256.c",
                "lib/curve25519-donna/curve25519-donna.c"
            ],
            cSettings: [
                .headerSearchPath("lib"),
                .define("LIBCE_VERSION_MAJOR", to: "\(major)"),
                .define("LIBCE_VERSION_MINOR", to: "\(minor)"),
                .define("LIBCE_VERSION_PATCH", to: "\(patch)")
            ]
        )
    ],
    cLanguageStandard: .c99,
    cxxLanguageStandard: .cxx11
)
