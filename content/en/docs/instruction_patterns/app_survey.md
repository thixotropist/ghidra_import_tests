---
title: Application Survey
linkTitle: Application Survey
weight: 20
---

{{% pageinfo %}}
Survey a voice-to-text app for common vector instruction patterns
{{% /pageinfo %}}

Take an exemplar RISCV-64 binary like `whisper.cpp`, with its many vector instructions.
Which vector patterns are easy to recognize, either for a human Ghidra user or for a hypothetical Ghidra plugin?

Some of the most common patterns correspond to `memcpy` or `memset` invocations where the number of bytes is known at
compile time as is the alignment of operands.

ML apps like `whisper.cpp` often work with parameters of less than 8 bits, so there can be a lot of demarshalling, unpacking,
and repacking operations.  That means lots of vector bit manipulation and width conversion operations.

ML apps also do a lot of vector, matrix, and tensor arithmetic, so we can expect to find vectorized arithmetic operations
mixed in with vector parameter conversion operations.

>Note: This page is likely to change rapidly as we get a better handle on the problem and develop better analytic tools
>      to guide the process.

## Survey for vector instruction blocks

Most vector instructions come in groups started with a `vsetvli` or `vsetivli` instruction to set up the vector context.
If the number of vector elements is known at compile time and less than 32, then the `vsetivli` instruction is often used.
Otherwise the `vsetvli` instruction is used.

Scanning for these instructions showed 673 `vsetvli` and 888 `vsetivli` instructions within `whisper.cpp`.

The most common `vsetvli` instruction (343 out of 673) is type 0xc3 or `e8,m8,ta,ma`.  That expands to:

* element width = 8 bits - no alignment checks are needed, 16 elements per vector register if VLEN=128
* multiplier = 8 - up to 8 vector registers are processed in parallel
* tail agnostic - we don't care about preserving unassigned vector register bits
* mask agnostic - we don't care about preserving unmasked vector register bits

The most common `vsetivli` instruction (565 out of 888) is type 0xd8 or `e64,m1,ta,ma`.  That expands to:

* element width = 64 bits - all memory operations should be 64 bit aligned, 2 elements per vector register if VLEN=128
* multiplier = 1 - only the named vector register is used
* tail agnostic - we don't care about preserving unassigned vector register bits
* mask agnostic - we don't care about preserving unmasked vector register bits

A similar common `vsetivli` instruction (102 out of 888) is type 0xdb or `e64,m8,ta,ma`.  That expands to:

* element width = 64 bits - all memory operations should be 64 bit aligned, 2 elements per vector register if VLEN=128
* multiplier = 8 - up to 8 vector registers are processed in parallel, or 16 64 bit elements if VLEN=128
* tail agnostic - we don't care about preserving unassigned vector register bits
* mask agnostic - we don't care about preserving unmasked vector register bits

The second most common `vsetivli` instruction (107 out of 888) is type 0xc7 or `e8,mf2,ta,ma`.  That expands to:

* element width = 8 bits
* multiplier = 1/2 - vector registers are only half used, perhaps to allow element widening to 16 bits
* tail agnostic - we don't care about preserving unassigned vector register bits
* mask agnostic - we don't care about preserving unmasked vector register bits

How many of these vector blocks can be treated as simple `memcpy` or `memset` invocations?

For example, this Ghidra listing snippet looks like a good candidate for `memcpy`:

```text
00090bdc 57 f0 b7 cd     vsetivli                       zero,0xf,e64,m8,ta,ma
00090be0 07 74 07 02     vle64.v                        v8,(a4)
00090be4 27 f4 07 02     vse64.v                        v8,(a5)
```

A pcode equivalent might be `__builtin_memcpy(dest=(a5), src=(a4), 8 * 15)` with a possible context note that v8 through v16 are changed.

A longer example might be a good candidate for `memset`:

```text
00090b84 57 70 81 cd     vsetivli                       zero,0x2,e64,m1,ta,ma
00090b88 93 07 07 01     addi                           a5,a4,0x10
00090b8c d7 30 00 5e     vmv.v.i                        v1,0x0
00090b90 a7 70 07 02     vse64.v                        v1,(a4)
00090b94 a7 f0 07 02     vse64.v                        v1,(a5)
00090b98 93 07 07 02     addi                           a5,a4,0x20
00090b9c a7 f0 07 02     vse64.v                        v1,(a5)
00090ba0 93 07 07 03     addi                           a5,a4,0x30
00090ba4 a7 f0 07 02     vse64.v                        v1,(a5)
00090ba8 93 07 07 04     addi                           a5,a4,0x40
00090bac a7 f0 07 02     vse64.v                        v1,(a5)
00090bb0 93 07 07 05     addi                           a5,a4,0x50
00090bb4 a7 f0 07 02     vse64.v                        v1,(a5)
00090bb8 93 07 07 06     addi                           a5,a4,0x60
00090bbc a7 f0 07 02     vse64.v                        v1,(a5)
00090bc0 fd 1b           c.addi                         s7,-0x1
00090bc2 23 38 07 06     sd                             zero,0x70(a4)
```

This example is based on a minimum VLEN of 128 bits, so the vector registers can hold 2 64 bit elements.  The `vmv.v.i` instruction sets those two elements of `v1` to zero.
Seven `vse64.v` instructions then store two 64 bit zeros each to successive memory locations, with a trailing scalar double word store to handle the tail.

A pcode equivalent for this sequence might be `__builtin_memset(dest=(a4), 0, 0x78)`.

## top down scan of vector blocks

The python script `objdump_analytic.py` provides a crude scan of a RISCV-64 binary, reporting on likely vector instruction blocks.  It doesn't handle blocks with more than one
`vsetvli` or `vsetivli` instruction, something common in vector narrowing or widening operations.  If we apply this script to `whisper_cpp_vector` we can collect a crude field guide to vector expansions.

VLEN in the following is the hart's vector length, determined at execution time.  It is usually something like 128 bits for a general purpose core (aka hart) and up to 1024 bits
for a dedicated accelerator hart.

### memcpy with known and limited nbytes

This pattern is often found when copying objects of known and limited size.  It is useful with objects as small as 4 bytes if the source alignment is
unknown and the destination object must be aligned on halfword, word, or doubleword boundaries.

```text
;                memcpy(dest=a0, src=a3, nbytes=a4) where a4 < 8 * (VLEN/8)
1d3da:  0c377057                vsetvli zero,a4,e8,m8,ta,ma
1d3de:  02068407                vle8.v  v8,(a3)
1d3e2:  02050427                vse8.v  v8,(a0)
```

### memcpy with unknown nbytes

This pattern is usually found in a simple loop, moving 8 * (VLEN/8) bytes at a time.
The a5 register holds the number of bytes processed per iteration.

```text
;                memcpy(dest=a6, src=a7, nbytes=a0) 
1d868:  0c3577d7                vsetvli a5,a0,e8,m8,ta,ma
1d86c:  02088407                vle8.v  v8,(a7)
1d872:  02080427                vse8.v  v8,(a6)
```

### widening floating point reduction

The next example appears to be compiled from `estimate_diarization_speaker` whose source is:

```c
double energy0 = 0.0f;
double energy1 = 0.0f;

for (int64_t j = is0; j < is1; j++) {
    energy0 += fabs(pcmf32s[0][j]);
    energy1 += fabs(pcmf32s[1][j]);
}
```

This is a typical reduction with widening pattern.

The vector instructions generated are:

```text
242ce:  0d8077d7                vsetvli a5,zero,e64,m1,ta,ma
242d2:  5e0031d7                vmv.v.i v3,0
242d6:  9e303257                vmv1r.v v4,v3
242da:  0976f7d7                vsetvli a5,a3,e32,mf2,tu,ma
242e4:  0205e107                vle32.v v2,(a1)
242e8:  02066087                vle32.v v1,(a2)
242ec:  2a211157                vfabs.v v2,v2
242f0:  2a1090d7                vfabs.v v1,v1
242f8:  d2411257                vfwadd.wv       v4,v4,v2
242fc:  d23091d7                vfwadd.wv       v3,v3,v1
24312:  0d8077d7                vsetvli a5,zero,e64,m1,ta,ma
24316:  4207d0d7                vfmv.s.f        v1,fa5
2431a:  063091d7                vfredusum.vs    v3,v3,v1
2431e:  42301757                vfmv.f.s        fa4,v3
24326:  06409257                vfredusum.vs    v4,v4,v1
2432a:  424017d7                vfmv.f.s        fa5,v4
```

A hypothetical vectorized Ghidra might decompile these instructions (ignoring the scalar instructions not displayed here) as:

```c
double vector v3, v4;  // SEW=64 bit
v3 := vector 0;  // load immediate
v4 := v3;        // vector copy
float vector v1, v2;  // SEW=32 bit
while(...) {
    v2 = vector *a1;
    v1 = vector *a2;
    v2 = abs(v2);
    v1 = abs(v1);
    v4 = v4 + v2;  // widening 32 to 64 bits
    v3 = v3 + v1;  // widening 32 to 64 bits
}
double vector v1, v3, v4;
v1[0] = fa5;   // fa5 is the scalar 'carry-in' 
v3[0] = v1[0] + ⅀ v3; // unordered vector reduction
fa4 = v3[0];
v4[0] = v1[0] + ⅀ v4;
fa5 = v4[0];
```

The vector instruction `vfredusum.vs` provides the *unordered* reduction sum over the elements of a single vector.  That's likely faster than an ordered sum,
but the floating point roundoff errors will not be deterministic.

>Note: this `whisper.cpp` routine attempts to recognize which of two speakers is responsible for each word of a conversation.  A speaker-misattribution
>      exploit might attack functions that call this.

### complex structure element copy

The source code includes:

```c
static drwav_uint64 drwav_read_pcm_frames_s16__msadpcm(drwav* pWav, drwav_uint64 framesToRead, drwav_int16* pBufferOut) {
    ...
    pWav->msadpcm.bytesRemainingInBlock = pWav->fmt.blockAlign - sizeof(header);

    pWav->msadpcm.predictor[0] = header[0];
    pWav->msadpcm.predictor[1] = header[1];
    pWav->msadpcm.delta[0] = drwav__bytes_to_s16(header + 2);
    pWav->msadpcm.delta[1] = drwav__bytes_to_s16(header + 4);
    pWav->msadpcm.prevFrames[0][1] = (drwav_int32)drwav__bytes_to_s16(header + 6);
    pWav->msadpcm.prevFrames[1][1] = (drwav_int32)drwav__bytes_to_s16(header + 8);
    pWav->msadpcm.prevFrames[0][0] = (drwav_int32)drwav__bytes_to_s16(header + 10);
    pWav->msadpcm.prevFrames[1][0] = (drwav_int32)drwav__bytes_to_s16(header + 12);

    pWav->msadpcm.cachedFrames[0] = pWav->msadpcm.prevFrames[0][0];
    pWav->msadpcm.cachedFrames[1] = pWav->msadpcm.prevFrames[1][0];
    pWav->msadpcm.cachedFrames[2] = pWav->msadpcm.prevFrames[0][1];
    pWav->msadpcm.cachedFrames[3] = pWav->msadpcm.prevFrames[1][1];
    pWav->msadpcm.cachedFrameCount = 2;
...
}
```

This gets vectorized into sequences containing:

```text
2c6ce:  ccf27057                vsetivli        zero,4,e16,mf2,ta,ma ; vl=4, SEW=16
2c6d2:  5e06c0d7                vmv.v.x v1,a3              ; v1[0..3] = a3
2c6d6:  3e1860d7                vslide1down.vx  v1,v1,a6   ; v1 = v1[1:3], a6
2c6da:  3e1760d7                vslide1down.vx  v1,v1,a4   ; v1 = v1[1:3], a4
2c6de:  3e1560d7                vslide1down.vx  v1,v1,a0   ; v1 = (a3,a6,a4,a0)

2c6e2:  0d007057                vsetvli zero,zero,e32,m1,ta,ma ; keep existing vl (=4), SEW=32
2c6e6:  4a13a157                vsext.vf2       v2,v1      ; v2 = vector sext(v1) // widening sign extend
2c6ea:  0207e127                vse32.v v2,(a5)            ; memcpy(a5, v2, 4 * 4)
2c6f2:  0a07d087                vlse16.v        v1,(a5),zero ; v1 = a5[]

2c6fa:  0cf07057                vsetvli zero,zero,e16,mf2,ta,ma
2c702:  3e1660d7                vslide1down.vx  v1,v1,a2   ; v1 = v1[1:3], a2
2c70a:  3e16e0d7                vslide1down.vx  v1,v1,a3   ; v1 = v1[1:3], a3
2c70e:  3e1760d7                vslide1down.vx  v1,v1,a4   ; v1 = v1[1:3], a4

2c712:  0d007057                vsetvli zero,zero,e32,m1,ta,ma
2c716:  4a13a157                vsext.vf2       v2,v1
2c71a:  0205e127                vse32.v v2,(a1)
```

That's the kind of messy code you could analyze if you had to.  Hopefully not.
