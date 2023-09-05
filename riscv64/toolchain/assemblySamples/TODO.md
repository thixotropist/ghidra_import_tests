# TODO

## h-ext-64 - hypervisor extensions


### unimplemented

```text
   0:   22000073                hfence.vvma
   4:   22050073                hfence.vvma     a0
   8:   22b00073                hfence.vvma     zero,a1
   c:   22c58073                hfence.vvma     a1,a2
  10:   62000073                hfence.gvma
  14:   62050073                hfence.gvma     a0
  18:   62b00073                hfence.gvma     zero,a1
  1c:   62c58073                hfence.gvma     a1,a2
```

### questionable disassembly

operands should be reversed

```text
  48:   62a5c073                hsv.b   a0,(a1)
  4c:   62a5c073                hsv.b   a0,(a1)
  50:   66a5c073                hsv.h   a0,(a1)
  54:   6aa5c073                hsv.w   a0,(a1)
  58:   6ea5c073                hsv.d   a0,(a1)
```

## vbb - vector bit manipulation

all unimplemented

```text
   1 0000 57028606              vandn.vv v4, v8, v12
   2 0004 57028604              vandn.vv v4, v8, v12, v0.t
   3 0008 57C28506              vandn.vx v4, v8, a1
   4 000c 57C28504              vandn.vx v4, v8, a1, v0.t
   5 0010 5722854A              vbrev.v v4, v8
   6 0014 57228548              vbrev.v v4, v8, v0.t
   7 0018 5722844A              vbrev8.v v4, v8
   8 001c 57228448              vbrev8.v v4, v8, v0.t
   9 0020 57A2844A              vrev8.v v4, v8
  10 0024 57A28448              vrev8.v v4, v8, v0.t
  11 0028 57A2844A              vrev8.v v4, v8
  12 002c 57A28448              vrev8.v v4, v8, v0.t
  13 0030 5722864A              vclz.v v4, v8
  14 0034 57228648              vclz.v v4, v8, v0.t
  15 0038 57A2864A              vctz.v v4, v8
  16 003c 57A28648              vctz.v v4, v8, v0.t
  17 0040 5722874A              vcpop.v v4, v8
  18 0044 57228748              vcpop.v v4, v8, v0.t
  19 0048 57028656              vrol.vv v4, v8, v12
  20 004c 57028654              vrol.vv v4, v8, v12, v0.t
  21 0050 57C28556              vrol.vx v4, v8, a1
  22 0054 57C28554              vrol.vx v4, v8, a1, v0.t
  23 0058 57028652              vror.vv v4, v8, v12
  24 005c 57028650              vror.vv v4, v8, v12, v0.t
  25 0060 57C28552              vror.vx v4, v8, a1
  26 0064 57C28550              vror.vx v4, v8, a1, v0.t
  27 0068 57328052              vror.vi v4, v8, 0
  28 006c 57B28F54              vror.vi v4, v8, 63, v0.t
  29 0070 570286D6              vwsll.vv v4, v8, v12
  30 0074 570286D4              vwsll.vv v4, v8, v12, v0.t
  31 0078 57C285D6              vwsll.vx v4, v8, a1
  32 007c 57C285D4              vwsll.vx v4, v8, a1, v0.t
  33 0080 573280D6              vwsll.vi v4, v8, 0
  34 0084 57B28FD4              vwsll.vi v4, v8, 31, v0.t
```

## zvbc - Vector carryless multiply

all unimplemented

```text
   1 0000 57228632              vclmul.vv v4, v8, v12
   2 0004 57228630              vclmul.vv v4, v8, v12, v0.t
   3 0008 57E28532              vclmul.vx v4, v8, a1
   4 000c 57E28530              vclmul.vx v4, v8, a1, v0.t
   5 0010 57228636              vclmulh.vv v4, v8, v12
   6 0014 57228634              vclmulh.vv v4, v8, v12, v0.t
   7 0018 57E28536              vclmulh.vx v4, v8, a1
   8 001c 57E28534              vclmulh.vx v4, v8, a1, v0.t
```

## zvkng - Vector Crypto NIST Algorithms including GHASH

all unimplemented

```text
   1 0000 77A280A2              vaesdf.vv v4, v8
   2 0004 772286BA              vsha2ch.vv v4, v8, v12
   3 0008 772286B2              vghsh.vv v4, v8, v12
   4 000c 77A2C8A2              vgmul.vv v4, v12
```

## zvksg - Vector Crypto ShangMi Algorithms including GHASH

all unimplemented

```text
   1 0000 77228086              vsm4k.vi v4, v8, 0
   2 0004 772280AE              vsm3c.vi v4, v8, 0
   3 0008 772286B2              vghsh.vv v4, v8, v12
   4 000c 77A2C8A2              vgmul.vv v4, v12
```

## vector instructions

### disassembly variance

| Objdump | Ghidra |
| -------| ------- |
| vsetvli a0, a1, e8,  m2 | vsetvli a0,a1,0x1 |
| vsetvli a0, a1, e16, m4, ta | vsetvli a0,a1,0x4a |
| vsetvli a0, a1, e32, mf4, mu | vsetvli  a0,a1,0x16 |
| vsetvli a0, a1, e64, mf8, tu, ma | vsetvli  a0,a1,0x9d |
| vloxei8.v v4, (a0), v12 | vlxei8.v v4,(a0),v12,0x1 |
| vloxei8.v v4, 0(a0), v12 | vlxei8.v v4,(a0),v12,0x1 |
| vsoxei8.v v4, (a0), v12 | vsxei8.v v4,(a0),v12,0x1 |
| vsoxei8.v v4, (a0), v12, v0.t | vsxei8.v v4,(a0),v12,0x0 |
| vloxei64.v v4, 0(a0), v12 | vlxei64.v v4,(a0),v12,0x1 |
| vloxei64.v v4, (a0), v12, v0.t | vlxei64.v v4,(a0),v12,0x0 |
| vsoxei64.v v4, (a0), v12 | vsxei64.v v4,(a0),v12,0x1 |
| vsoxei64.v v4, (a0), v12, v0.t | vsxei64.v v4,(a0),v12,0x0 |
| vlseg2e8.v v4, (a0) | vle8.v v4,(a0),0x1 |
| vlseg2e8.v v4, 0(a0) | vle8.v v4,(a0),0x1 |
| vlseg2e8.v v4, (a0), v0.t | vle8.v v4,(a0),0x0 |
| vsseg2e8.v v4, (a0) | vse8.v v4,(a0),0x1 |
| vsseg2e8.v v4, 0(a0) | vse8.v v4,(a0),0x1 |
| vsseg2e8.v v4, (a0), v0.t | vse8.v v4,(a0),0x0 |
| vlseg3e8.v v4, (a0) | vle8.v v4,(a0),0x1 |
| vlseg3e8.v v4, 0(a0) | vle8.v v4,(a0),0x1 |
| vlseg3e8.v v4, (a0), v0.t | vle8.v v4,(a0),0x0 |
| vsseg3e8.v v4, (a0) | vse8.v v4,(a0),0x1 |
| vsseg3e8.v v4, 0(a0) | vse8.v v4,(a0),0x1 |
| vsseg3e8.v v4, (a0), v0.t | vse8.v v4,(a0),0x0 |
| vlseg4e8.v v4, (a0) | vle8.v v4,(a0),0x1 |
| vlseg4e8.v v4, 0(a0) |  vle8.v v4,(a0),0x1 |
| vlseg4e8.v v4, (a0), v0.t |  vle8.v v4,(a0),0x0 |
| vsseg4e8.v v4, (a0) | vse8.v v4,(a0),0x1 |
| vsseg4e8.v v4, 0(a0) | vse8.v v4,(a0),0x1 |
| vsseg4e8.v v4, (a0), v0.t | vse8.v v4,(a0),0x0 |
| vlseg5e8.v v4, (a0) | vle8.v v4,(a0),0x1 |
| vlseg5e8.v v4, 0(a0) | vle8.v v4,(a0),0x1 |
| vlseg5e8.v v4, (a0), v0.t | vle8.v v4,(a0),0x0 |
| vsseg5e8.v v4, (a0) | vse8.v v4,(a0),0x1 |
| vsseg5e8.v v4, 0(a0) | vse8.v v4,(a0),0x1 |
| vsseg5e8.v v4, (a0), v0.t | vse8.v v4,(a0),0x0 |
| vlseg6e8.v v4, (a0) | vle8.v v4,(a0),0x1 |
| vlseg6e8.v v4, 0(a0) | vle8.v v4,(a0),0x1 |
| vlseg6e8.v v4, (a0), v0.t | vle8.v v4,(a0),0x0 |
| vsseg6e8.v v4, (a0) | vse8.v v4,(a0),0x1 |
| vsseg6e8.v v4, 0(a0) | vse8.v v4,(a0),0x1 |
| vsseg6e8.v v4, (a0), v0.t | vse8.v v4,(a0),0x0 |
| vlseg7e8.v v4, (a0) | vle8.v v4,(a0),0x1 |
| vlseg7e8.v v4, 0(a0) | vle8.v v4,(a0),0x1 |
| vlseg7e8.v v4, (a0), v0.t | vle8.v v4,(a0),0x0 |
| vsseg7e8.v v4, (a0) | vse8.v v4,(a0),0x1 |
| vsseg7e8.v v4, 0(a0) | vse8.v v4,(a0),0x1 |
| vsseg7e8.v v4, (a0), v0.t | vse8.v v4,(a0),0x0 |
| vlseg8e8.v v4, (a0) | vle8.v v4,(a0),0x1 |
| vlseg8e8.v v4, 0(a0) | vle8.v v4,(a0),0x1 |
| vlseg8e8.v v4, (a0), v0.t | vle8.v v4,(a0),0x0 |

to be contnued at 0x2c8

### unimplemented

| Objdump |
| ------- |
| 57F505C0 vsetivli a0, 0xb, 0 |
| 57F5F5FF vsetivli a0, 0xb, 0x3ff |
| 57F545C0 vsetivli a0, 0xb, 0x4 |
| 57F505C2 vsetivli a0, 0xb, 0x20 |
| 57F515C0 vsetivli a0, 0xb, e8,  m2 |
| 57F5A5C4 vsetivli a0, 0xb, e16, m4, ta |
| 57F565C1 vsetivli a0, 0xb, e32, mf4, mu |
| 57F5D5C9 vsetivli a0, 0xb, e64, mf8, tu, ma |
| 57F505F0 vsetivli a0, 0xb, 0x300 |
| 57F505D0 vsetivli a0, 0xb, 0x100 |
| 0702B502 vlm.v v4, (a0) |
| 0702B502 vlm.v v4, 0(a0) |
| 0702B502 vle1.v v4, (a0) |
| 0702B502 vle1.v v4, 0(a0) |
| 2702B502 vsm.v v4, (a0) |
| 2702B502 vsm.v v4, 0(a0) |
| 2702B502 vse1.v v4, (a0)  |
| 2702B502 vse1.v v4, 0(a0) |
| 0702C506 vluxei8.v v4, (a0), v12 |
| 0702C504 vluxei8.v v4, (a0), v12, v0.t |
| 0752C506 vluxei16.v v4, (a0), v12 |
| 0752C506 vluxei16.v v4, 0(a0), v12 |
| 0752C504 vluxei16.v v4, (a0), v12, v0.t |
| 0762C506 vluxei32.v v4, (a0), v12 |
| 0762C506 vluxei32.v v4, 0(a0), v12 |
| 0762C504 vluxei32.v v4, (a0), v12, v0.t |
| 0772C50E vloxei64.v v4, (a0), v12 |
| 0772C50C vloxei64.v v4, (a0), v12, v0.t |

