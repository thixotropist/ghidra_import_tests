#!/usr/bin/python

"""
apply objdump and readelf to a RISCV executable to analyze vector instruction patterns.
"""
import subprocess
import re
from collections import Counter

# regular expression to match an objdump -d disassembly, grouping on
# address, encoding, opcode, and arguments
LISTING_PAT = re.compile(r'([0-9a-f]*):\s+([0-9a-f]{4,8})\s+(\S+)\s+(\S+)')

# riscv-64 binary file to analyze
BINARY = 'riscv64/exemplars/whisper_cpp_vector'

# binutils utilities that can recognize riscv-64 vector instructions
READELF = '/opt/riscvx/bin/riscv64-unknown-linux-gnu-readelf'
OBJDUMP = '/opt/riscvx/bin/riscv64-unknown-linux-gnu-objdump'

# opcodes that indicate the end of the current vector block
TERMINAL_OPCODES = ('j', 'vsetvli', 'vsetivli')

def find_march(out_file):
    """
    Use readelf to look for RISCV architecture tags
    """
    cmd = [READELF,  '-A', BINARY]
    rslt = subprocess.run(cmd, check=True, capture_output=True, encoding='utf8')
    match = re.search(r'Tag_RISCV_arch:\s+"(.*)"', rslt.stdout)
    if match:
        out_file.write(f'>Built for architecture {match.group(1)}\n\n')
    else:
        out_file.write('>Unable to determine intended microarchitecture\n\n')

def find_vset_sequences(label, pattern, disassembly_listing, out_file):
    """
    Search for vsetvli or vsetivli instructions to locate vector instruction blocks.
    Params:
      * label - a string naming the instruction we are looking for
      * pattern - a compiled regex matching that type of instruction
      * disassembly-listing - the output of a binutils -d command, as a single string
      * analysis-file - a markdown file ready to receive analytic results
    Return:
      * encodings - a hex field that encodes element width, multiplier, tail and mask contexts
      * frequencies - the number of times each encoding is found in the disassembly
      * line_numbers - the set of line numbers containing vsetvli or vsetivli instruction
    """
    encodings = {}
    frequencies = Counter()
    line_numbers = []
    line_index = 0
    for line in disassembly_listing:
        match = re.search(pattern, line)
        if match:
            encoding = match.group(2)
            args = match.group(3)
            vl = 0x7ff & (int(encoding,16) >> 20)
            mode = args.split(',')[2:6]
            mode_string = ','.join(mode)
            encodings[vl] = mode_string
            frequencies[mode_string] += 1
            line_numbers.append(line_index)
        line_index += 1
    print(f"\n## Unique encodings for {label} opcode:\n\n```text", file=out_file)
    print(f'Total number of {label} instructions found: {frequencies.total()}\n', \
          file=out_file)
    for item,encoding in sorted(encodings.items()):
        counts = frequencies[encoding]
        print(f"{hex(item)} ⇒ {encoding} {counts} instances", file=out_file)
    print("```\n", file=out_file)
    return (encodings, frequencies, line_numbers)

def is_vector_op(opcode):
    """
    Return true if this opcode is likely part of the current vector block,
    false if it is a scalar opcode or the start of another vector block
    """
    return opcode.startswith('v')

def display_block(line_number, listing_lines, out_file):
    """
    Display a group of instructions following a vset* opcode, stopping
    at a branch or another vset operation
    """
    for line in listing_lines[line_number:line_number+25]:
        match = re.search(LISTING_PAT, line)
        if match is None:
            break
        opcode = match.group(3)
        if opcode in TERMINAL_OPCODES:
            break
        if is_vector_op(opcode):
            print(match.group(0), file=out_file)
    print('', file=out_file)

def find_vector_blocks(line_numbers, listing_lines, out_file):
    """
    search the listing for simple vector patterns
    """
    for line_number in line_numbers:
        match = re.search(LISTING_PAT, listing_lines[line_number])
        if match is None:
            print("failed to find a previous opcode!")
            continue
        print(match[0], file=out_file)
        display_block(line_number + 1, listing_lines, out_file)

COMMON_VECTOR_INSTRUCTIONS = (
    'vfmv.s.f', 'vfredsum', 'vfmv.f.s', 'vmv.v.i', 'vse32.v', 'vse8.v', 'vle8.v',
    'vse64.v', 'vid.v', 'vmv.v.x', 'vmul.vx', 'vadd.vx', 'vrgather.vv', 'vrgatherei16.vv',
    'vslide1down.vx', 'vslide1down.vi', 'vslidedown.vi','vslideup.vi',
)

analysis_file = open('/tmp/analysis.md', 'w', encoding='utf-8')
analysis_file.write(f'# analysis of {BINARY}\n\n')

find_march(analysis_file)

command = [OBJDUMP, '-d', BINARY]
result = subprocess.run(command, check=True, capture_output=True, encoding='utf8')

listing_as_array = result.stdout.splitlines()

VSET_PAT = re.compile(r'\s+([0-9a-f]{5,8}):\s+([0-9a-f]{8})\s+vsetvli\s+(\S+)')
(vset_encodings, vset_frequencies, vset_lines) = \
    find_vset_sequences('vsetvli', VSET_PAT, listing_as_array, analysis_file)

VSETI_PAT = re.compile(r'\s+([0-9a-f]{5,8}):\s+([0-9a-f]{8})\s+vsetivli\s+(\S+)')
(vseti_encodings, vseti_frequencies, vseti_lines) = \
    find_vset_sequences('vsetivli', VSETI_PAT, listing_as_array, analysis_file)

# merge the two lists, preserving order
vset_lines.extend(vseti_lines)
vset_lines.sort()
# display all vector blocks
find_vector_blocks(vset_lines, listing_as_array, analysis_file)

analysis_file.close()
