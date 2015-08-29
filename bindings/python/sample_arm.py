#!/usr/bin/env python
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *


# code to be emulated
ARM_CODE   = "\x37\x00\xa0\xe3\x03\x10\x42\xe0" # mov r0, #0x37; sub r1, r2, r3
THUMB_CODE = "\x83\xb0" # sub    sp, #0xc
# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = %u" %(address, size))


# Test ARM
def test_arm():
    print("Emulate ARM code")
    try:
        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, ARM_CODE)

        # initialize machine registers
        mu.reg_write(UC_ARM_REG_R0, 0x1234)
        mu.reg_write(UC_ARM_REG_R2, 0x6789)
        mu.reg_write(UC_ARM_REG_R3, 0x3333)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r0 = mu.reg_read(UC_ARM_REG_R0)
        r1 = mu.reg_read(UC_ARM_REG_R1)
        print(">>> R0 = 0x%x" %r0)
        print(">>> R1 = 0x%x" %r1)

    except UcError as e:
        print("ERROR: %s" % e)


def test_thumb():
    print("Emulate THUMB code")
    try:
        # Initialize emulator in thumb mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, THUMB_CODE)

        # initialize machine registers
        mu.reg_write(UC_ARM_REG_SP, 0x1234)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(THUMB_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        sp = mu.reg_read(UC_ARM_REG_SP)
        print(">>> SP = 0x%x" %sp)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_arm()
    print("=" * 20)
    test_thumb()
