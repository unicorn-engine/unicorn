#!/usr/bin/python

from unicorn import *
from unicorn.arm_const import *

import regress

class VldrPcInsn(regress.RegressTest):

    def runTest(self):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x1000)
        uc.mem_write(0x1000, 'ed9f8a3d'.decode('hex')) # vldr s16, [pc, #244]
        # this will raise invalid insn
        uc.emu_start(0x1000, 0x1004)

if __name__ == '__main__':
    regress.main()
