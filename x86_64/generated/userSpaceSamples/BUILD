
# Build a simple HelloWorld x86_64 C executable
cc_binary(
    name = "helloworld",
    srcs = ["helloworld.c"],
)

# Build a simple HelloWorld x86_64 C++ executable
cc_binary(
    name = "helloworld++",
    srcs = ["helloworld.cc"],
)

# Build the relocation test object file with Position Independent Executable
#    - this might be typical of a kernel module where .data and .bss are
#      relocated together with .text and .rodata
cc_binary(
    name = "relocationTest_pie",
    srcs = ["relocationTest.c"],
    copts = ["-O3", "-Wa,-L", "-Wa,-a", "-Wa,-am", "-Wa,-a=/tmp/relocationTest_pie.listing", "-fpie"],
    features = ["-pic"]
)

# Build the relocation test object file with Position Independent Code
#    - this might be typical of a user space sharable library build, where 
#       .data and .bss are relocated independently of .text and .rodata
cc_binary(
    name = "relocationTest_pic",
    srcs = ["relocationTest.c"],
    copts = ["-O3", "-Wa,-L", "-Wa,-a", "-Wa,-am", "-Wa,-a=/tmp/relocationTest_pic.listing", "-fpic"],
)
