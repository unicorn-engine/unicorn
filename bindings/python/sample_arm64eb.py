#!/usr/bin/env python
# Sample code for ARM64 of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>
# AARCH64 Python sample ported by zhangwm <rustydaar@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.arm64_const import *


# code to be emulated
ARM64_CODE = b"\xab\x05\x00\xb8\xaf\x05\x40\x38" # str x11, [x13]; ldrb x15, [x13]

# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


# Test ARM64
def test_arm64():
    print("Emulate ARM64 Big-Endian code")
    try:
        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM | UC_MODE_BIG_ENDIAN)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, ARM64_CODE)

        # initialize machine registers
        mu.reg_write(UC_ARM64_REG_X11, 0x12345678)
        mu.reg_write(UC_ARM64_REG_X13, 0x10008)
        mu.reg_write(UC_ARM64_REG_X15, 0x33)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(ARM64_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")
        print(">>> As big endian, X15 should be 0x12:")

        x11 = mu.reg_read(UC_ARM64_REG_X11)
        x13 = mu.reg_read(UC_ARM64_REG_X13)
        x15 = mu.reg_read(UC_ARM64_REG_X15)
        print(">>> X15 = 0x%x" %x15)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_arm64()
