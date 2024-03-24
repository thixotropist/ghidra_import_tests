---
title: Deep Dive Openssl
linkTitle: Openssl
weight: 60
---

{{% pageinfo %}}
Openssl configuration for ISA Extensions provides a good example.
{{% /pageinfo %}}

```console
/home2/build_openssl$ ../vendor/openssl/Configure linux64-riscv64 --cross-compile-prefix=/opt/riscvx/bin/riscv64-unknown-linux-gnu- -march=rv64gcv_zkne_zknd_zknh_zvkng_zvksg
$ perl configdata.pm --dump

Command line (with current working directory = .):

    /usr/bin/perl ../vendor/openssl/Configure linux64-riscv64 --cross-compile-prefix=/opt/riscvx/bin/riscv64-unknown-linux-gnu- -march=rv64gcv_zkne_zknd_zknh_zvkng_zvksg

Perl information:

    /usr/bin/perl
    5.38.2 for x86_64-linux-thread-multi

Enabled features:

    afalgeng
    apps
    argon2
    aria
    asm
    async
    atexit
    autoalginit
    autoerrinit
    autoload-config
    bf
    blake2
    bulk
    cached-fetch
    camellia
    capieng
    cast
    chacha
    cmac
    cmp
    cms
    comp
    ct
    default-thread-pool
    deprecated
    des
    dgram
    dh
    docs
    dsa
    dso
    dtls
    dynamic-engine
    ec
    ec2m
    ecdh
    ecdsa
    ecx
    engine
    err
    filenames
    gost
    http
    idea
    legacy
    loadereng
    makedepend
    md4
    mdc2
    module
    multiblock
    nextprotoneg
    ocb
    ocsp
    padlockeng
    pic
    pinshared
    poly1305
    posix-io
    psk
    quic
    unstable-qlog
    rc2
    rc4
    rdrand
    rfc3779
    rmd160
    scrypt
    secure-memory
    seed
    shared
    siphash
    siv
    sm2
    sm2-precomp
    sm3
    sm4
    sock
    srp
    srtp
    sse2
    ssl
    ssl-trace
    static-engine
    stdio
    tests
    thread-pool
    threads
    tls
    ts
    ui-console
    whirlpool
    tls1
    tls1-method
    tls1_1
    tls1_1-method
    tls1_2
    tls1_2-method
    tls1_3
    dtls1
    dtls1-method
    dtls1_2
    dtls1_2-method

Disabled features:

    acvp-tests          [cascade]        OPENSSL_NO_ACVP_TESTS
    asan                [default]        OPENSSL_NO_ASAN
    brotli              [default]        OPENSSL_NO_BROTLI
    brotli-dynamic      [default]        OPENSSL_NO_BROTLI_DYNAMIC
    buildtest-c++       [default]        
    winstore            [not-windows]    OPENSSL_NO_WINSTORE
    crypto-mdebug       [default]        OPENSSL_NO_CRYPTO_MDEBUG
    devcryptoeng        [default]        OPENSSL_NO_DEVCRYPTOENG
    ec_nistp_64_gcc_128 [default]        OPENSSL_NO_EC_NISTP_64_GCC_128
    egd                 [default]        OPENSSL_NO_EGD
    external-tests      [default]        OPENSSL_NO_EXTERNAL_TESTS
    fips                [default]        
    fips-securitychecks [cascade]        OPENSSL_NO_FIPS_SECURITYCHECKS
    fuzz-afl            [default]        OPENSSL_NO_FUZZ_AFL
    fuzz-libfuzzer      [default]        OPENSSL_NO_FUZZ_LIBFUZZER
    ktls                [default]        OPENSSL_NO_KTLS
    md2                 [default]        OPENSSL_NO_MD2 (skip crypto/md2)
    msan                [default]        OPENSSL_NO_MSAN
    rc5                 [default]        OPENSSL_NO_RC5 (skip crypto/rc5)
    sctp                [default]        OPENSSL_NO_SCTP
    tfo                 [default]        OPENSSL_NO_TFO
    trace               [default]        OPENSSL_NO_TRACE
    ubsan               [default]        OPENSSL_NO_UBSAN
    unit-test           [default]        OPENSSL_NO_UNIT_TEST
    uplink              [no uplink_arch] OPENSSL_NO_UPLINK
    weak-ssl-ciphers    [default]        OPENSSL_NO_WEAK_SSL_CIPHERS
    zlib                [default]        OPENSSL_NO_ZLIB
    zlib-dynamic        [default]        OPENSSL_NO_ZLIB_DYNAMIC
    zstd                [default]        OPENSSL_NO_ZSTD
    zstd-dynamic        [default]        OPENSSL_NO_ZSTD_DYNAMIC
    ssl3                [default]        OPENSSL_NO_SSL3
    ssl3-method         [default]        OPENSSL_NO_SSL3_METHOD

Config target attributes:

    AR => "ar",
    ARFLAGS => "qc",
    CC => "gcc",
    CFLAGS => "-Wall -O3",
    CXX => "g++",
    CXXFLAGS => "-Wall -O3",
    HASHBANGPERL => "/usr/bin/env perl",
    RANLIB => "ranlib",
    RC => "windres",
    asm_arch => "riscv64",
    bn_ops => "SIXTY_FOUR_BIT_LONG RC4_CHAR",
    build_file => "Makefile",
    build_scheme => [ "unified", "unix" ],
    cflags => "-pthread",
    cppflags => "",
    cxxflags => "-std=c++11 -pthread",
    defines => [ "OPENSSL_BUILDING_OPENSSL" ],
    disable => [  ],
    dso_ldflags => "-Wl,-z,defs",
    dso_scheme => "dlfcn",
    enable => [ "afalgeng" ],
    ex_libs => "-ldl -pthread",
    includes => [  ],
    lflags => "",
    lib_cflags => "",
    lib_cppflags => "-DOPENSSL_USE_NODELETE",
    lib_defines => [  ],
    module_cflags => "-fPIC",
    module_cxxflags => undef,
    module_ldflags => "-Wl,-znodelete -shared -Wl,-Bsymbolic",
    perl_platform => "Unix",
    perlasm_scheme => "linux64",
    shared_cflag => "-fPIC",
    shared_defflag => "-Wl,--version-script=",
    shared_defines => [  ],
    shared_ldflag => "-Wl,-znodelete -shared -Wl,-Bsymbolic",
    shared_rcflag => "",
    shared_sonameflag => "-Wl,-soname=",
    shared_target => "linux-shared",
    thread_defines => [  ],
    thread_scheme => "pthreads",
    unistd => "<unistd.h>",

Recorded environment:

    AR = 
    BUILDFILE = 
    CC = 
    CFLAGS = 
    CPPFLAGS = 
    CROSS_COMPILE = 
    CXX = 
    CXXFLAGS = 
    HASHBANGPERL = 
    LDFLAGS = 
    LDLIBS = 
    OPENSSL_LOCAL_CONFIG_DIR = 
    PERL = 
    RANLIB = 
    RC = 
    RCFLAGS = 
    WINDRES = 
    __CNF_CFLAGS = 
    __CNF_CPPDEFINES = 
    __CNF_CPPFLAGS = 
    __CNF_CPPINCLUDES = 
    __CNF_CXXFLAGS = 
    __CNF_LDFLAGS = 
    __CNF_LDLIBS = 

Makevars:

    AR              = /opt/riscvx/bin/riscv64-unknown-linux-gnu-ar
    ARFLAGS         = qc
    ASFLAGS         = 
    CC              = /opt/riscvx/bin/riscv64-unknown-linux-gnu-gcc
    CFLAGS          = -Wall -O3 -march=rv64gcv_zkne_zknd_zknh_zvkng_zvksg
    CPPDEFINES      = 
    CPPFLAGS        = 
    CPPINCLUDES     = 
    CROSS_COMPILE   = /opt/riscvx/bin/riscv64-unknown-linux-gnu-
    CXX             = /opt/riscvx/bin/riscv64-unknown-linux-gnu-g++
    CXXFLAGS        = -Wall -O3 -march=rv64gcv_zkne_zknd_zknh_zvkng_zvksg
    HASHBANGPERL    = /usr/bin/env perl
    LDFLAGS         = 
    LDLIBS          = 
    PERL            = /usr/bin/perl
    RANLIB          = /opt/riscvx/bin/riscv64-unknown-linux-gnu-ranlib
    RC              = /opt/riscvx/bin/riscv64-unknown-linux-gnu-windres
    RCFLAGS         = 

NOTE: These variables only represent the configuration view.  The build file
template may have processed these variables further, please have a look at the
build file for more exact data:
    Makefile

build file:

    Makefile

build file templates:

    ../vendor/openssl/Configurations/common0.tmpl
    ../vendor/openssl/Configurations/unix-Makefile.tmpl
$ make
...
opt/riscvx/lib/gcc/riscv64-unknown-linux-gnu/14.0.1/../../../../riscv64-unknown-linux-gnu/bin/ld: cannot find -ldl: No such file or directory
```

The error is in the linking phase, since we did not provide the correct sysroot and path information needed by the crosscompiling linker.

A quick check of the object files generated includes:

```console
$  find . -name \*risc\*.o
./crypto/sm4/libcrypto-lib-sm4-riscv64-zvksed.o
./crypto/sm4/libcrypto-shlib-sm4-riscv64-zvksed.o
./crypto/aes/libcrypto-lib-aes-riscv64-zvkned.o
./crypto/aes/libcrypto-shlib-aes-riscv64-zvkned.o
./crypto/aes/libcrypto-shlib-aes-riscv64-zvbb-zvkg-zvkned.o
./crypto/aes/libcrypto-shlib-aes-riscv64-zkn.o
./crypto/aes/libcrypto-lib-aes-riscv64-zkn.o
./crypto/aes/libcrypto-shlib-aes-riscv64-zvkb-zvkned.o
./crypto/aes/libcrypto-shlib-aes-riscv64.o
./crypto/aes/libcrypto-lib-aes-riscv64-zvkb-zvkned.o
./crypto/aes/libcrypto-lib-aes-riscv64-zvbb-zvkg-zvkned.o
./crypto/aes/libcrypto-lib-aes-riscv64.o
./crypto/chacha/libcrypto-shlib-chacha_riscv.o
./crypto/chacha/libcrypto-lib-chacha_riscv.o
./crypto/chacha/libcrypto-lib-chacha-riscv64-zvkb.o
./crypto/chacha/libcrypto-shlib-chacha-riscv64-zvkb.o
./crypto/libcrypto-shlib-riscv64cpuid.o
./crypto/libcrypto-lib-riscv64cpuid.o
./crypto/sha/libcrypto-lib-sha_riscv.o
./crypto/sha/libcrypto-lib-sha256-riscv64-zvkb-zvknha_or_zvknhb.o
./crypto/sha/libcrypto-shlib-sha512-riscv64-zvkb-zvknhb.o
./crypto/sha/libcrypto-shlib-sha_riscv.o
./crypto/sha/libcrypto-shlib-sha256-riscv64-zvkb-zvknha_or_zvknhb.o
./crypto/sha/libcrypto-lib-sha512-riscv64-zvkb-zvknhb.o
./crypto/sm3/libcrypto-lib-sm3-riscv64-zvksh.o
./crypto/sm3/libcrypto-lib-sm3_riscv.o
./crypto/sm3/libcrypto-shlib-sm3-riscv64-zvksh.o
./crypto/sm3/libcrypto-shlib-sm3_riscv.o
./crypto/libcrypto-shlib-riscvcap.o
./crypto/modes/libcrypto-shlib-ghash-riscv64.o
./crypto/modes/libcrypto-shlib-ghash-riscv64-zvkg.o
./crypto/modes/libcrypto-lib-aes-gcm-riscv64-zvkb-zvkg-zvkned.o
./crypto/modes/libcrypto-lib-ghash-riscv64.o
./crypto/modes/libcrypto-shlib-ghash-riscv64-zvkb-zvbc.o
./crypto/modes/libcrypto-lib-ghash-riscv64-zvkg.o
./crypto/modes/libcrypto-shlib-aes-gcm-riscv64-zvkb-zvkg-zvkned.o
./crypto/modes/libcrypto-lib-ghash-riscv64-zvkb-zvbc.o
./crypto/libcrypto-lib-riscvcap.o
```

That suggests we need to cover more extensions:

* vbb
* vbc
* vkb
* vkg
* vkned

The openssl source code conditionally defines symbols like:

* RISCV_HAS_V
* RISCV_HAS_ZVBC
* RISCV_HAS_ZVKB
* RISCV_HAS_ZVKNHA
* RISCV_HAS_ZVKNHB
* RISCV_HAS_ZVKSH
* RISCV_HAS_ZBKB
* RISCV_HAS_ZBB
* RISCV_HAS_ZBC
* RISCV_HAS_ZKND
* RISCV_HAS_ZKNE
* RISCV_HAS_ZVKG - currently missing, or a union of zvkng and zvksg?
* RISCV_HAS_ZVKNED - currently missing or a union of zvkned and zvksed?
* RISCV_HAS_ZVKSED - currently missing, defined but unused?

These symbols are defined in `crypto/riscvcap.c` after analyzing the `march` string passed to the compiler.

So the next steps include:

* Define `LDFLAGS` and `LDLIBS` to enable building a riscv-64 `openssl.so`.
* add additional march elements to generate as many ISA extension exemplars as we can
* iterate on Ghidra sinc files to define any missing instructions
* extend riscv-64 assembly samples to include all riscv-64 ISA extensions appearing in openssl source
* verify that we have acceptable pcode opcodes for all riscv-64 ISA extensions appearing in openssl source

```console
$ build_openssl$../vendor/openssl/Configure linux64-riscv64 --cross-compile-prefix=/opt/riscvx/bin/riscv64-unknown-linux-gnu- -march=rv64gcv_zkne_zknd_zknh_zvkng_zvbb_zvbc_zvkb_zvkg_zvkned_zvksg
```

Patch the generated Makefile to:

```text
< CNF_EX_LIBS=-ldl -pthread
---
> CNF_EX_LIBS=/opt/riscvx/lib/libdl.a -pthread
```

```console
$ make
```

* open `libcrypto.so.3` and `libssl.so.3` in Ghidra.
* analyze and open bookmarks
* verify - in the Bookmarks window - that all instructions disassembled and no instructions lack pcode

## Integration testing (manual)

Disassembly testing against binutils reference dumps can follow these steps:

* Open `libcrypt.so.3` in Ghidra
* export as ascii to `/tmp/libcrypto.so.3.txt`
* export as C/C++ to `/tmp/libcrypto.so.3.c`
* generate reference disassembly via
    * `/opt/riscvx/bin/riscv64-unknown-linux-gnu-objdump -j .text -D libcrypto.so.3 > libcrypto.so.3_ref.txt`
* grep both `/tmp/libcrypto.so.3.txt` and `libcrypto.so.3_ref.txt` for `vset` instructions, comparing operands
* optionally parse vector instructions out of both files and compare decodings

## inspect extension management

How does openssl manage RISCV ISA extensions?  We'll use the `gcm_ghash` family of functions as examples.

* At compile time any `march=rv64gcv_z...` arguments are processed by the openssl configuration tool and
  turned into `#ifdef` variables. These can include combinations like `RISCV_HAS_ZVKB_AND_ZVKSED`.
  Multiple versions of key routines are compiled, each with different required extensions.
* The compiler can also use any of the bit manipulation and vector extensions in local optimization.
* At runtime the library queries the underlying system to see which extensions are supported.  The function
  `gcm_get_funcs` returns the preferred set of implementing functions.  The `gcm_ghash` set can include:
    * `gcm_ghash_4bit`
    * `gcm_ghash_rv64i_zvkb_zvbc`
    * `gcm_ghash_rv64i_zvkg`
    * `gcm_ghash_rv64i_zbc`
    * `gcm_ghash_rv64i_zbc__zbkb`

The `gcm_ghash_4bit` is the default version with 412 instructions, of which 11 are vector instructions inserted by the compiler.

The `gcm_ghash_rv64i_zvkg` is the most advanced version with only 32 instructions.  Ghidra decompiles this as:

```c
void gcm_ghash_rv64i_zvkg(undefined8 param_1,undefined8 param_2,long param_3,long param_4)
{
  undefined auVar1 [256];
  undefined auVar2 [256];
  vsetivli_e32m1tumu(4);
  auVar1 = vle32_v(param_2);
  vle32_v(param_1);
  do {
    auVar2 = vle32_v(param_3);
    param_3 = param_3 + 0x10;
    param_4 = param_4 + -0x10;
    auVar2 = vghsh_vv(auVar1,auVar2);
  } while (param_4 != 0);
  vse32_v(auVar2,param_1);
  return;
}
```

That shows an error in our sinc files - several instructions use the vd register as both an input and an output, so our
pcode semantics need updating.  Do this and inspect the Ghidra output again:

```c
void gcm_ghash_rv64i_zvkg(undefined8 param_1,undefined8 param_2,long param_3,long param_4)
{
  undefined auVar1 [256];
  undefined auVar2 [256];
  undefined auVar3 [256];
  vsetivli_e32m1tumu(4);
  auVar2 = vle32_v(param_2);
  auVar1 = vle32_v(param_1);
  do {
    auVar3 = vle32_v(param_3);
    param_3 = param_3 + 0x10;
    param_4 = param_4 + -0x10;
    auVar1 = vghsh_vv(auVar1,auVar2,auVar3);
  } while (param_4 != 0);
  vse32_v(auVar1,param_1);
  return;
}
```
That's better - commit and push.
