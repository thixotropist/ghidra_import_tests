cc_library(
    name = "samples",
    srcs = [
        "pcodeSamples.cpp",
        "pcodeTests.h",
    ],
    deps = [
        "@glog//:glog",
    ],
)

cc_binary(
    name = "pcodeTests",
    srcs = [
        "pcodeTests.cpp",
        "pcodeTests.h",
    ],
    deps = [
        ":samples",
        "@glog//:glog",
        "@googletest//:gtest",
    ],
)
