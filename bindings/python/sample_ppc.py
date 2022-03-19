#!/usr/bin/env python
# Sample code for PPC of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
#

from __future__ import print_function
from unicorn import *
from unicorn.ppc_const import *


# code to be emulated
PPC_CODE = b"\x7F\x46\x1A\x14" 			# add       r26, r6, r3
# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


# Test PPC
def test_ppc():
    print("Emulate PPC code")
    try:
        # Initialize emulator in PPC EB mode
        mu = Uc(UC_ARCH_PPC, UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, PPC_CODE)

        # initialize machine registers
        mu.reg_write(UC_PPC_REG_3, 0x1234)
        mu.reg_write(UC_PPC_REG_6, 0x6789)
        mu.reg_write(UC_PPC_REG_26, 0x5555)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(PPC_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r26 = mu.reg_read(UC_PPC_REG_26)
        print(">>> r26 = 0x%x" % r26)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_ppc()

