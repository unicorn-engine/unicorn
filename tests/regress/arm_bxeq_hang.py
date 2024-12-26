import regress
from unicorn import *
from unicorn.arm_const import *


class BxHang(regress.RegressTest):
    def runTest(self):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x1000)
        uc.mem_write(0x1000, b'\x1e\xff\x2f\x01\x00\x00\xa0\xe1')  # bxeq lr; mov r0, r0
        uc.count = 0

        def hook_block(uc, addr, *args):
            regress.logger.debug('enter block %#06x', addr)
            uc.count += 1

        uc.reg_write(UC_ARM_REG_LR, 0x1004)
        uc.hook_add(UC_HOOK_BLOCK, hook_block)

        regress.logger.debug('block should only run once')
        uc.emu_start(0x1000, 0x1004)

        self.assertEqual(uc.count, 1)


if __name__ == '__main__':
    regress.main()
