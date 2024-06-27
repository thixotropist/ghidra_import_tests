load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# whisper.cpp is an open source voice-to-text inference app built on Meta's LLaMA model.
# It is a useful exemplar of autovectorization of ML code with some examples of hand-coded
# riscv intrinsics.
http_archive(
    name = "whisper_cpp",
    urls = ["https://github.com/ggerganov/whisper.cpp/archive/refs/tags/v1.5.4.tar.gz"],
    strip_prefix = "whisper.cpp-1.5.4/",
    build_file = "//:whisper-cpp.BUILD",
    sha256 = "06eed84de310fdf5408527e41e863ac3b80b8603576ba0521177464b1b341a3a"
)
