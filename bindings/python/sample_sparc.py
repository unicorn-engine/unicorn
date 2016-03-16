#!/usr/bin/env python
# Sample code for SPARC of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.sparc_const import *


# code to be emulated
SPARC_CODE = "\x86\x00\x40\x02" # add %g1, %g2, %g3;
# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = %u" %(address, size))


# Test SPARC
def test_sparc():
    print("Emulate SPARC code")
    try:
        # Initialize emulator in SPARC EB mode
        mu = Uc(UC_ARCH_SPARC, UC_MODE_SPARC32|UC_MODE_BIG_ENDIAN)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, SPARC_CODE)

        # initialize machine registers
        mu.reg_write(UC_SPARC_REG_G1, 0x1230)
        mu.reg_write(UC_SPARC_REG_G2, 0x6789)
        mu.reg_write(UC_SPARC_REG_G3, 0x5555)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(SPARC_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        g3 = mu.reg_read(UC_SPARC_REG_G3)
        print(">>> G3 = 0x%x" %g3)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_sparc()
