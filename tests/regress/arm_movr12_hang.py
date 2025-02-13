import regress
from unicorn import *
from unicorn.arm_const import *


class MovHang(regress.RegressTest):

    # NOTE: This test was failing when workflow was using ubuntu-latest + qemu. Fixed once switched to native arm runner
    def runTest(self):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x1000)
        uc.mem_write(0x1000, b'\x00\xc0\x00\xe3')  # movw r12, #0

        def hook_block(uc, addr, *args):
            regress.logger.debug('enter block 0x%#06x', addr)
            uc.count += 1

        uc.reg_write(UC_ARM_REG_R12, 0x123)
        self.assertEqual(0x123, uc.reg_read(UC_ARM_REG_R12))

        uc.hook_add(UC_HOOK_BLOCK, hook_block)
        uc.count = 0

        # print 'block should only run once'
        uc.emu_start(0x1000, 0x1004, timeout=500)

        self.assertEqual(0x0, uc.reg_read(UC_ARM_REG_R12))
        self.assertEqual(uc.count, 1)


if __name__ == '__main__':
    regress.main()
