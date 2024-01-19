#!/usr/bin/env python
# Sample code for RH850 of Unicorn. Damien Cauquil <dcauquil@quarkslab.com>
#

from __future__ import print_function
from unicorn import *
from unicorn.rh850_const import *


'''
 0  01 0e 06 addi 6, r1, r1
 4  00 c1 11 add  r1, r2
'''
RH850_CODE = b"\x01\x0e\x06\x00\xc1\x11"

# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


# Test RH850
def test_rh850():
    print("Emulate RH850 code")
    try:
        # Initialize emulator in RISCV32 mode
        mu = Uc(UC_ARCH_RH850, 0)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, RH850_CODE)

        # initialize machine registers
        mu.reg_write(UC_RH850_REG_R1, 0x1234)
        mu.reg_write(UC_RH850_REG_R2, 0x7890)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
<<<<<<< HEAD
        mu.emu_start(ADDRESS, ADDRESS + len(RH850_CODE) - 1)
=======
        mu.emu_start(ADDRESS, ADDRESS + len(RH850_CODE))
>>>>>>> 4abc05b3 (Removed hook-related code (causes some issues for now).)

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r1 = mu.reg_read(UC_RH850_REG_R1)
        r2 = mu.reg_read(UC_RH850_REG_R2)
        print(">>> R1 = 0x%x" % r1)
        print(">>> R2 = 0x%x" % r2)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_rh850()

