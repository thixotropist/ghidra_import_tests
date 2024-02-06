#!/usr/bin/python

"""
apply objdump and readelf to a RISCV executable to analyze vector instruction patterns.
"""
import subprocess
import re

BINARY = 'riscv64/exemplars/whisper_cpp_vector'
OBJDUMP = '/opt/riscvx/bin/riscv64-unknown-linux-gnu-objdump'
READELF = '/opt/riscvx/bin/riscv64-unknown-linux-gnu-readelf'

VSET_PAT = re.compile(r'\s+([0-9a-f]{5,8}):\s+([0-9a-f]{8})\s+vsetvli\s+(\S+)')
VSETI_PAT = re.compile(r'\s+([0-9a-f]{5,8}):\s+([0-9a-f]{8})\s+vsetivli\s+(\S+)')

analysis_file = open('/tmp/analysis.md', 'w', encoding='utf-8')
analysis_file.write(f'# analysis of {BINARY}\n\n')

command = [READELF,  '-A', BINARY]
result = subprocess.run(command, check=True, capture_output=True, encoding='utf8')
match = re.search(r'Tag_RISCV_arch:\s+"(.*)"', result.stdout)
if match:
    analysis_file.write(f'>Built for architecture {match.group(1)}\n\n')

command = [OBJDUMP, '-d', BINARY]
result = subprocess.run(command, check=True, capture_output=True, encoding='utf8')

vset_encodings = {}
vset_matches = re.findall(VSET_PAT,result.stdout)
if vset_matches:
    for m in vset_matches:
        (addr, encoding, args) = m
        vl = 0x7ff & (int(encoding,16) >> 20)
        mode = args.split(',')[2:6]
        mode_string = ','.join(mode)
        vset_encodings[vl] = mode_string

print("## Unique encodings for vsetvli opcode:\n\n```text", file=analysis_file)
for item,encoding in sorted(vset_encodings.items()):
    print(f"{hex(item)} ⇒ {encoding}", file=analysis_file)
print("```\n", file=analysis_file)

vseti_encodings = {}
vseti_matches = re.findall(VSETI_PAT,result.stdout)
if vseti_matches:
    for m in vseti_matches:
        (addr, encoding, args) = m
        vl = 0x3ff & (int(encoding,16) >> 20)
        mode = args.split(',')[2:6]
        mode_string = ','.join(mode)
        vseti_encodings[vl] = mode_string

print("## Unique encodings for vsetivli opcode:\n\n```text", file=analysis_file)
for item,encoding in sorted(vseti_encodings.items()):
    print(f"{hex(item)} ⇒ {encoding}", file=analysis_file)
print("```\n", file=analysis_file)