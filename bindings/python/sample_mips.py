#!/usr/bin/env python
# Sample code for MIPS of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.mips_const import *


# code to be emulated
MIPS_CODE_EB = "\x34\x21\x34\x56" # ori $at, $at, 0x3456;
MIPS_CODE_EL = "\x56\x34\x21\x34" # ori $at, $at, 0x3456;

# memory address where emulation starts
ADDRESS      = 0x10000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = %u" %(address, size))


# Test MIPS EB
def test_mips_eb():
    print("Emulate MIPS code (big-endian)")
    try:
        # Initialize emulator in MIPS32 + EB mode
        mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, MIPS_CODE_EB)

        # initialize machine registers
        mu.reg_write(UC_MIPS_REG_1, 0x6789)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(MIPS_CODE_EB))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r1 = mu.reg_read(UC_MIPS_REG_1)
        print(">>> r1 = 0x%x" %r1)

    except UcError as e:
        print("ERROR: %s" % e)


# Test MIPS EL
def test_mips_el():
    print("Emulate MIPS code (little-endian)")
    try:
        # Initialize emulator in MIPS32 + EL mode
        mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, MIPS_CODE_EL)

        # initialize machine registers
        mu.reg_write(UC_MIPS_REG_1, 0x6789)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(MIPS_CODE_EL))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r1 = mu.reg_read(UC_MIPS_REG_1)
        print(">>> r1 = 0x%x" %r1)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_mips_eb()
    print("=" * 20)
    test_mips_el()
