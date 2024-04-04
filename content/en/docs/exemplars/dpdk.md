---
title: Data Plane Development Kit
weight: 20
---

{{% pageinfo %}}
Intel's DPDK framework supports some Intel and Arm Neon vector instructions.  What does it for RISCV extensions?
Are ISA extensions materially useful to a network appliance?
{{% /pageinfo %}}

Check out DPDK from GitHub, patch the RISCV configuration with `riscv64/toolchains/dpdk/dpdk.pat`, and crosscompile with `meson`
and `ninja`.  Copy some of the examples into `riscv64/exemplars` and examine them in Ghidra.

* for this we use as many standard extensions as we can, excluding vendor-specific extensions.

Configure a build directory:

```console
$ patch -p1 < .../riscv64/toolchains/dpdk/dpdk.pat
$ meson setup build --cross-file config/riscv/riscv64_linux_gcc -Dexamples=all
$ cd build
```

Edit `build/build.ninja`:

* replace all occurrences of `-ldl` with `/opt/riscvx/lib/libdl.a` - you should see about 235 replacements

Build with:

```console
$ ninja -C build
```

Check the cross-compilation with:

```console
$ readelf -A build/examples/dpdk-l3fwd
Attribute Section: riscv
File Attributes
  Tag_RISCV_stack_align: 16-bytes
  Tag_RISCV_arch: "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_v1p0_zicsr2p0_zifencei2p0_zmmul1p0_zba1p0_zbb1p0_zbc1p0_zbkb1p0_zbkc1p0_zbkx1p0_zvbb1p0_zvbc1p0_zve32f1p0_zve32x1p0_zve64d1p0_zve64f1p0_zve64x1p0_zvkb1p0_zvl128b1p0_zvl32b1p0_zvl64b1p0"
  Tag_RISCV_priv_spec: 1
  Tag_RISCV_priv_spec_minor: 11
```

Import into Ghidra 11.1-DEV(isa_ext), noting multiple import messages similar to:

* Unsupported Thread-Local Symbol not loaded
* ELF Relocation Failure: R_RISCV_COPY (4, 0x4) at 00f0c400 (Symbol = stdout) - Runtime copy not supported

## Analysis

### source code examination

#### explicit vectorization

The source code has explicit parallel coding for Intel and Arm/Neon architectures, for instance within
the basic layer 3 forwarding example:

```c
struct acl_algorithms acl_alg[] = {
        {
                .name = "scalar",
                .alg = RTE_ACL_CLASSIFY_SCALAR,
        },
        {
                .name = "sse",
                .alg = RTE_ACL_CLASSIFY_SSE,
        },
        {
                .name = "avx2",
                .alg = RTE_ACL_CLASSIFY_AVX2,
        },
        {
                .name = "neon",
                .alg = RTE_ACL_CLASSIFY_NEON,
        },
        {
                .name = "altivec",
                .alg = RTE_ACL_CLASSIFY_ALTIVEC,
        },
        {
                .name = "avx512x16",
                .alg = RTE_ACL_CLASSIFY_AVX512X16,
        },
        {
                .name = "avx512x32",
                .alg = RTE_ACL_CLASSIFY_AVX512X32,
        },
};
```

If avx512x32 is selected, then basic trie search and other operations can proceed across 32 flows in parallel.
Other examples exist within the code.  For more information, search the `doc` directory for `SIMD`.  Check out `lib/fib/trie_avx512.c`
and the function `trie_vec_lookup_x16x2` for an AVX manual vectorization of a trie address to next hop lookup.

>Note: It won't be clear for some time which vectorization transforms actually improve performance on specific processors.  Vector
>      support adds a lot of local register space but vector loads and stores can saturate memory bandwidth and drive up processor
>      temperature.  We might see earlier adoption in contexts that tolerate higher latency, like firewalls, rather than low-latency
>      switches and routers.

#### explicit ML support

DPDK includes ML contributions from Marvell.  See `doc/guides/mldevs/cnxk.rst` for more information and references to the cnxk support.
Source code support exists under `drivers/ml/cnxk` and `lib/mldev`.  `lib/mldev/rte_mldev.c` may provide some insight into how
Marvell expects DPDK users to apply their component.
See the Marvell Octeon 10 [white paper](https://www.marvell.com/content/dam/marvell/en/public-collateral/embedded-processors/marvell-octeon-10-dpu-platform-white-paper.pdf) for some possible applications.

### Ghidra analysis

The DPDK exemplars stress test Ghidra in multiple ways:

* When compiled with RISCV-64 vector and bit manipulation extension support you get a good mix of autovectorization instructions.
* There are a number of unsupported thread-local relocations requested
* ELF replication failures are reported for `R_RISCV_COPY`, claiming "Runtime copy is not supported".
    * this relocation code apparently asks for a symbol to be copied from a shareable object into an executable. 
