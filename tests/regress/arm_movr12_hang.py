#!/usr/bin/python

from unicorn import *
from unicorn.arm_const import *

import regress

class MovHang(regress.RegressTest):

    def runTest(self):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x1000)
        uc.mem_write(0x1000, '00c000e3'.decode('hex'))  # movw r12, #0

        def hook_block(uc, addr, *args):
            print 'enter block 0x%04x' % addr
            uc.count += 1

        uc.reg_write(UC_ARM_REG_R12, 0x123)
        self.assertEquals(uc.reg_read(UC_ARM_REG_R12), 0x123)

        uc.hook_add(UC_HOOK_BLOCK, hook_block)
        uc.count = 0

        #print 'block should only run once'
        uc.emu_start(0x1000, 0x1004, timeout=500)

        self.assertEquals(uc.reg_read(UC_ARM_REG_R12), 0x0)
        self.assertEquals(uc.count, 1)

if __name__ == '__main__':
    regress.main()
