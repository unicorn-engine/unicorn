#!/usr/bin/env python
# Sample code for TriCore of Unicorn. Eric Poole <pappypoole@gmail.com>
# Python sample ported by Eric Poole <pappypoole@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.tricore_const import *


# code to be emulated
TRICORE_CODE   = b"\x82\x72\x82\x4f\xa2\xf2" # mov d2, #0x7; mov d15, #0x4; sub d2, d15
# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


# Test TriCore
def test_tricore():
    print("Emulate TriCore code")
    try:
        # Initialize emulator in TriCore mode
        mu = Uc(UC_ARCH_TRICORE, UC_MODE_LITTLE_ENDIAN)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, TRICORE_CODE)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing one instruction at ADDRESS with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(TRICORE_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r0 = mu.reg_read(UC_TRICORE_REG_D2)
        r1 = mu.reg_read(UC_TRICORE_REG_D15)
        print(">>> D2 = 0x%x" %r0)
        print(">>> D15 = 0x%x" %r1)

    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == '__main__':
    test_tricore()
