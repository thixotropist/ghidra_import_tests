# Collect code fragments using - or contributing to - the C++ standard library.
# These can be built with various platforms to look for the use of customizations.

# a simple unordered hash lookup
cc_binary(
    name = "hashmap",
    srcs = [
        "hashmap.cc",
    ],
    copts = ["-O2"],
)

# a simple ordered tree-based lookup
cc_binary(
    name = "treemap",
    srcs = [
        "treemap.cc",
    ],
    copts = ["-O2"],
)

# extract code used to generate the Murmur hash used in stdlib++
cc_library(
    name = "stdlib",
    srcs = ["hash.cc"],
    copts = ["-O2",]
)