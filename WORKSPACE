load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# whisper.cpp is an open source voice-to-text inference app built on Meta's LLaMA model.
# It is a useful exemplar of autovectorization of ML code with some examples of hand-coded
# riscv intrinsics.
http_archive(
    name = "whisper_cpp",
    urls = ["https://github.com/ggerganov/whisper.cpp/archive/refs/tags/v1.6.2.tar.gz"],
    strip_prefix = "whisper.cpp-1.6.2/",
    build_file = "//:whisper-cpp.BUILD",
    sha256 = "da7988072022acc3cfa61b370b3c51baad017f1900c3dc4e68cb276499f66894"
)
