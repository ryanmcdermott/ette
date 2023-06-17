CFLAGS = [
    "-std=c++17",
    "-Wall",
    "-Wextra",
    "-Wshadow",
    "-Wnon-virtual-dtor",
    "-Wpedantic",
]

cc_library(
    name = "crypto",
    srcs = [
        "constants.h",
        "crypto.cc",
        "crypto.h",
        "status.h",
    ],
    hdrs = ["crypto.h"],
    copts = CFLAGS,
    deps = [
        "//third_party/picosha2",
        "//third_party/plusaes",
    ],
)

cc_library(
    name = "editor",
    srcs = [
        "constants.h",
        "editor.cc",
        "editor.h",
        "status.h",
    ],
    copts = CFLAGS,
    deps = [":crypto"],
)

cc_test(
    name = "editor_test",
    srcs = ["editor_test.cc"],
    copts = ["-std=c++17"],
    deps = [
        ":editor",
        "@googletest//:gtest_main",
    ],
)

cc_binary(
    name = "ette",
    srcs = ["ette.cc"],
    copts = CFLAGS,
    deps = [":editor"],
)

cc_test(
    name = "crypto_test",
    srcs = [
        "crypto_test.cc",
    ],
    copts = ["-std=c++17"],
    deps = [
        ":crypto",
        "//third_party/picosha2",
        "@googletest//:gtest_main",
    ],
)

cc_binary(
    name = "decrypt_example",
    srcs = ["decrypt_example.cc"],
    copts = ["-std=c++17"],
    deps = [
        ":crypto",
    ],
)
