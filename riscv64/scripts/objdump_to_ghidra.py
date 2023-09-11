#!/bin/python

"""
reformat objdump and ghidra ascii export files to make comparisons simpler
"""
import re

def hexToDecimal(s):
    hex_pattern = re.compile(r'(0x)([0-9a-fA-F]+)')
    match = hex_pattern.search(s)
    while match:
        int_value = int(match.group(2), 16)
        s = s.replace(match.group(0), f"{int_value}")
        match = hex_pattern.search(s)
    return s

objdump_pattern = re.compile(r"^\s+([0-9a-f]+):\s+([0-9a-f]+)\s+(v.*)")

reference_listing = open('/tmp/reference.lst', 'w', encoding='utf-8')
ghidra_listing = open('/tmp/ghidra.lst', 'w', encoding='utf-8')

with open('riscv64/exemplars/vector.objdump', 'r', encoding='utf-8') as objdump_file:
    for line in objdump_file:
        wanted_line = re.match(objdump_pattern, line)
        if wanted_line:
            addr = int(wanted_line.group(1), 16)
            addr += 0x100000
            instr = wanted_line.group(2).strip()
            byte_swapped_instr = instr[6:8] + instr[4:6] +instr[2:4] + instr[0:2]
            assembly = wanted_line.group(3)
            print(f'.text:{addr:08x} {byte_swapped_instr} {assembly}', file=reference_listing)

ghidra_pattern = re.compile(r"^\.text:([0-9a-f]+)\s+([0-9a-f]+)\s+(v.*)")
hex_pattern = re.compile(r"0x([0-9a-fA-F]{2:16})")

with open('/tmp/vector.o.txt', 'r', encoding='utf-8') as ghidra_ascii_file:
    for line in ghidra_ascii_file:
        wanted_line = re.match(ghidra_pattern, line)
        if wanted_line:
            addr = wanted_line.group(1)
            instr = wanted_line.group(2)
            # should translate any 0x fields within assembly to decimal
            assembly = hexToDecimal(wanted_line.group(3))
            assembly = "\t".join(assembly.strip().split())
            print(f'.text:{addr} {instr} {assembly}', file=ghidra_listing)
        