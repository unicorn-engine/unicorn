#!/usr/bin/env python

# reg_write() can't modify PC from within trace callbacks
# issue #210

from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *

import regress

BASE_ADDRESS = 0x10000000

# sub sp, #0xc
THUMB_CODE = "\x83\xb0" * 5

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = %u" % (address, size))
    mu = user_data
    print(">>> Setting PC to 0xffffffff")
    mu.reg_write(UC_ARM_REG_PC, 0xffffffff)

# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))
    mu = user_data
    print(">>> Setting PC to 0xffffffff")
    mu.reg_write(UC_ARM_REG_PC, 0xffffffff)

class CallBackPCTest(regress.RegressTest):

    def test_instruction_trace(self):
        try:
            # initialize emulator in ARM's Thumb mode
            mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

            # map some memory
            mu.mem_map(BASE_ADDRESS, 2 * 1024 * 1024)

            # write machine code to be emulated to memory
            mu.mem_write(BASE_ADDRESS, THUMB_CODE)

            # setup stack
            mu.reg_write(UC_ARM_REG_SP, BASE_ADDRESS + 2 * 1024 * 1024)

            # tracing all instructions with customized callback
            mu.hook_add(UC_HOOK_CODE, hook_code, user_data=mu)

            # emulate one instruction
            mu.emu_start(BASE_ADDRESS, BASE_ADDRESS + len(THUMB_CODE), count=1)

            # the instruction trace callback set PC to 0xffffffff, so at this
            # point, the PC value should be 0xffffffff.
            pc = mu.reg_read(UC_ARM_REG_PC)
            self.assertEqual(pc, 0xffffffff, "PC not set to 0xffffffff by instruction trace callback")

        except UcError as e:
            self.assertFalse(0, "ERROR: %s" % e)

    def test_block_trace(self):
        try:
            # initialize emulator in ARM's Thumb mode
            mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

            # map some memory
            mu.mem_map(BASE_ADDRESS, 2 * 1024 * 1024)

            # write machine code to be emulated to memory
            mu.mem_write(BASE_ADDRESS, THUMB_CODE)

            # setup stack
            mu.reg_write(UC_ARM_REG_SP, BASE_ADDRESS + 2 * 1024 * 1024)

            # trace blocks with customized callback
            mu.hook_add(UC_HOOK_BLOCK, hook_block, user_data=mu)

            # emulate one instruction
            mu.emu_start(BASE_ADDRESS, BASE_ADDRESS + len(THUMB_CODE), count=1)

            # the block callback set PC to 0xffffffff, so at this point, the PC
            # value should be 0xffffffff.
            pc = mu.reg_read(UC_ARM_REG_PC)
            self.assertEqual(pc, 0xffffffff, "PC not set to 0xffffffff by block callback")

        except UcError as e:
            self.assertFalse(0, "ERROR: %s" % e)

if __name__ == '__main__':
    regress.main()
