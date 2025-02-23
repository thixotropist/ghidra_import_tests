---
title: vector intrinsics
weight: 30
---

{{% pageinfo %}}
Invoking RISCV vector instructions from C.
{{% /pageinfo %}}

RISCV [vector intrinsic functions](https://github.com/riscv-non-isa/rvv-intrinsic-doc/tree/v1.0.x) can be coded into C or C++.

That document includes examples of code that might be found shortly in libc:

```c
void *memcpy_vec(void *restrict destination, const void *restrict source,
                 size_t n) {
  unsigned char *dst = destination;
  const unsigned char *src = source;
  // copy data byte by byte
  for (size_t vl; n > 0; n -= vl, src += vl, dst += vl) {
    vl = __riscv_vsetvl_e8m8(n);
    vuint8m8_t vec_src = __riscv_vle8_v_u8m8(src, vl);
    __riscv_vse8_v_u8m8(dst, vec_src, vl);
  }
  return destination;
}
```

>Note: GCC-14 autovectorization will often convert normal calls to `memcpy` into something very similar to the `memcpy_vec` code above, then assemble it down to RISCV vector instructions.

As another example, here is a snippet of code from the [whisper.cc](https://github.com/ggerganov/whisper.cpp.git) voice to text open source project:

```c
...
#ifdef __riscv_v_intrinsic
#include <riscv_vector.h>
#endif
...
elif defined(__riscv_v_intrinsic)

    size_t vl = __riscv_vsetvl_e32m4(QK8_0);

    for (int i = 0; i < nb; i++) {
        // load elements
        vfloat32m4_t v_x   = __riscv_vle32_v_f32m4(x+i*QK8_0, vl);

        vfloat32m4_t vfabs = __riscv_vfabs_v_f32m4(v_x, vl);
        vfloat32m1_t tmp   = __riscv_vfmv_v_f_f32m1(0.0f, vl);
        vfloat32m1_t vmax  = __riscv_vfredmax_vs_f32m4_f32m1(vfabs, tmp, vl);
        float amax = __riscv_vfmv_f_s_f32m1_f32(vmax);
        ...
    }
```

Normally you would expect to see functions like `__riscv_vfabs_v_f32m4` defined in the include file `riscv_vector.h`, where Ghidra could process it and help identify calls to
these intrinsics.  The vector intrinsic functions are instead autogenerated directly into GCC's internal compiled header format when the compiler is built - there are just too many variants
to cope with.  The PDF listing of all intrinsic functions is currently over 4000 pages long.  For example, the signature for `__riscv_vfredmax_vs_f32m4_f32m1` is given on page 734 under
`Vector Reduction Operations` as

```c
vfloat32m1_t __riscv_vfredmax_vs_f32m4_f32m1(vfloat32m4_t vs2, vfloat32m1_t vs1, size_t vl);
```

There aren't all that many vector instruction genotypes, but there are an enormous number of contextual variations the compiler and assembler know about.
