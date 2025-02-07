# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>


import platform
import regress
import sys
import unittest
from unicorn import *
from unicorn.arm_const import *

# code to be emulated
ARM_CODE = (
    b"\x37\x00\xa0\xe3"  # mov      r0, #0x37
    b"\x03\x10\x42\xe0"  # sub      r1, r2, r3
)

THUMB_CODE = b"\x83\xb0"  # sub      sp, #0xc

# memory address where emulation starts
ADDRESS = 0xF0000000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    regress.logger.debug(">>> Tracing basic block at %#x, block size = %#x", address, size)


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    regress.logger.debug(">>> Tracing instruction at %#x, instruction size = %u", address, size)


class TestInitInputCrash(regress.RegressTest):
    @unittest.skipIf(sys.platform == 'win32' or platform.machine().lower() not in ('x86_64', 'arm64'), 'TO BE CHECKED!')
    def test_arm(self):
        regress.logger.debug("Emulate ARM code")

        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        mem_size = 2 * (1024 * 1024)
        mu.mem_map(ADDRESS, mem_size)

        stack_address = ADDRESS + mem_size
        stack_size = stack_address  # >>> here huge memory size
        mu.mem_map(stack_address, stack_size)

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
        regress.logger.debug(">>> Emulation done. Below is the CPU context")

        r0 = mu.reg_read(UC_ARM_REG_R0)
        r1 = mu.reg_read(UC_ARM_REG_R1)
        regress.logger.debug(">>> R0 = %#x", r0)
        regress.logger.debug(">>> R1 = %#x", r1)

    def test_thumb(self):
        regress.logger.debug("Emulate THUMB code")

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
        mu.emu_start(ADDRESS | 0b1, ADDRESS + len(THUMB_CODE))

        # now print out some registers
        regress.logger.debug(">>> Emulation done. Below is the CPU context")

        sp = mu.reg_read(UC_ARM_REG_SP)
        regress.logger.debug(">>> SP = %#x", sp)


if __name__ == '__main__':
    regress.main()
