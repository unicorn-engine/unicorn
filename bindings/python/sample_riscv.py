#!/usr/bin/env python
# Sample code for RISCV of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
#

from __future__ import print_function
from unicorn import *
from unicorn.riscv_const import *


'''
$ cstool riscv64 1305100093850502
 0  13 05 10 00  addi	a0, zero, 1
 4  93 85 05 02  addi	a1, a1, 0x20
'''
RISCV_CODE = b"\x13\x05\x10\x00\x93\x85\x05\x02"

# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


# Test RISCV
def test_riscv():
    print("Emulate RISCV code")
    try:
        # Initialize emulator in RISCV32 mode
        mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, RISCV_CODE)

        # initialize machine registers
        mu.reg_write(UC_RISCV_REG_A0, 0x1234)
        mu.reg_write(UC_RISCV_REG_A1, 0x7890)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(RISCV_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        a0 = mu.reg_read(UC_RISCV_REG_A0)
        a1 = mu.reg_read(UC_RISCV_REG_A1)
        print(">>> A0 = 0x%x" %a0)
        print(">>> A1 = 0x%x" %a1)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_riscv()

