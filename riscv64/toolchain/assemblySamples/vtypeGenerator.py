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

for encoding in range(0,0x100):
    vmul = encoding & 0x07
    vsew = (encoding & 0x38) >> 3
    vta = (encoding & 0x40) >> 6
    vma = (encoding & 0x80) >> 7
    vtypeSymbolic = f"{hex(encoding)} = {vsewSymbolic[vsew]},{vmulSymbolic[vmul]},{tailHandling[vta]},{maskHandling[vma]}"
    if 'reserved' not in vtypeSymbolic:
        print(vtypeSymbolic)
