# reg_write() can't modify PC from within trace callbacks
# issue #210

import regress
from unicorn import *
from unicorn.arm_const import *

BASE_ADDRESS = 0x10000000
THUMB_CODE = b"\x83\xb0" * 5  # sub sp, #0xc
TARGET_PC = 0xffffffff


class CallBackPCTest(regress.RegressTest):

    def test_instruction_trace(self):
        # initialize emulator in ARM's Thumb mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        # map some memory
        mu.mem_map(BASE_ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(BASE_ADDRESS, THUMB_CODE)

        # setup stack
        mu.reg_write(UC_ARM_REG_SP, BASE_ADDRESS + 2 * 1024 * 1024)

        def __hook_callback(uc, address, size, user_data):
            regress.logger.debug(">>> Tracing instruction at 0x%x, instruction size = %u", address, size)
            regress.logger.debug(">>> Setting PC to %#x", TARGET_PC)

            uc.reg_write(UC_ARM_REG_PC, TARGET_PC)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, __hook_callback)

        # emulate one instruction. since pc was modified to point to an unmapped
        # area, this is expected to fail
        with self.assertRaises(UcError) as raisedEx:
            mu.emu_start(BASE_ADDRESS, BASE_ADDRESS + len(THUMB_CODE), count=1)

        self.assertEqual(UC_ERR_FETCH_UNMAPPED, raisedEx.exception.errno)

        # the block callback set PC to 0xffffffff, so at this point, the PC
        # value should be 0xffffffff.
        self.assertEqual(TARGET_PC, mu.reg_read(UC_ARM_REG_PC) | 0b1)

    def test_block_trace(self):
        # initialize emulator in ARM's Thumb mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        # map some memory
        mu.mem_map(BASE_ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(BASE_ADDRESS, THUMB_CODE)

        # setup stack
        mu.reg_write(UC_ARM_REG_SP, BASE_ADDRESS + 2 * 1024 * 1024)

        def __hook_callback(uc, address, size, user_data):
            regress.logger.debug(">>> Tracing basic block at 0x%x, block size = 0x%x", address, size)
            regress.logger.debug(">>> Setting PC to %#x", TARGET_PC)

            uc.reg_write(UC_ARM_REG_PC, TARGET_PC)

        # trace blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, __hook_callback)

        # emulate one instruction. since pc was modified to point to an unmapped
        # area, this is expected to fail
        with self.assertRaises(UcError) as raisedEx:
            mu.emu_start(BASE_ADDRESS, BASE_ADDRESS + len(THUMB_CODE), count=1)

        self.assertEqual(UC_ERR_FETCH_UNMAPPED, raisedEx.exception.errno)

        # the block callback set PC to 0xffffffff, so at this point, the PC
        # value should be 0xffffffff.
        self.assertEqual(TARGET_PC, mu.reg_read(UC_ARM_REG_PC) | 0b1)


if __name__ == '__main__':
    regress.main()
