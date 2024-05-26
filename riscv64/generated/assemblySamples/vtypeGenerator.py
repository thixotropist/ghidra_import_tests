#!/usr/bin/python
"""
Decode RISCV vtype encodings to determine element size, multiplier, tail, and mask settings.
Suppress printing for reserved encodings.

The results can be used in decoding vsetvli and vsetivli vector instructions.
"""

tailHandling = ('tu', 'ta')
maskHandling = ('mu', 'ma')
vmulSymbolic = ('m1', 'm2', 'm4', 'm8', 'reserved', 'mf8', 'mf4', 'mf2')
vsewSymbolic = ('e8', 'e16', 'e32', 'e64', 'reserved', 'reserved', 'reserved', 'reserved')                


vtypes = []
vsetvliPcodes = []
vsetvliInstrs = []
vsetivliPcodes = []
vsetivliInstrs = []
for encoding in range(0,0x100):
    vmul = encoding & 0x07
    vsew = (encoding & 0x38) >> 3
    vta = (encoding & 0x40) >> 6
    vma = (encoding & 0x80) >> 7

    vtypeSymbolic = f"{vsewSymbolic[vsew]},{vmulSymbolic[vmul]},{tailHandling[vta]},{maskHandling[vma]}"
    if 'reserved' not in vtypeSymbolic:
        vtypePcode = f"{vsewSymbolic[vsew]}{vmulSymbolic[vmul]}{tailHandling[vta]}{maskHandling[vma]}"
        vsetvliPcodes.append(f"define pcodeop vsetvli_{vtypePcode};")
        vsetvliInstrs.append(f":vsetvli   rd, rs1, \"{vtypeSymbolic:13}\" is op2030={hex(encoding):3} & op3131=0x0 & rs1 & op1214=0x7 & rd & op0006=0x57 {{rd=vsetvli_{vtypePcode}(rs1);}}")
        vsetivliPcodes.append(f"define pcodeop vsetivli_{vtypePcode};")
        vsetivliInstrs.append(f":vsetivli  rd, op1519, \"{vtypeSymbolic:13}\" is op3031=0x3 & op2029={hex(encoding):3} & op1519 & op1214=0x7 & rd & op0006=0x57 {{rd=vsetivli_{vtypePcode}(op1519:5);}}")
print('\n'.join(vsetvliPcodes))
print('\n'.join(vsetvliInstrs))
print('\n'.join(vsetivliPcodes))
print('\n'.join(vsetivliInstrs))