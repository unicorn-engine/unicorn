#!/usr/bin/env python
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.m68k_const import *


# code to be emulated
M68K_CODE  = "\x76\xed" # movq #-19, %d3
# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = %u" %(address, size))


# Test ARM
def test_m68k():
    print("Emulate M68K code")
    try:
        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, M68K_CODE)

        # initialize machine registers
        mu.reg_write(UC_M68K_REG_D3, 0x1234)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(M68K_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        d3 = mu.reg_read(UC_M68K_REG_D3)
        print(">>> D3 = 0x%x" %d3)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_m68k()
