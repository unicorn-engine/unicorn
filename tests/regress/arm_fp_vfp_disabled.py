#!/usr/bin/python
# coding=utf8

# Added by Peter Mackay, relating to issue 571
# "ARM NEON/VFP support seems to exist but is disabled by default"
# https://github.com/unicorn-engine/unicorn/issues/571

from unicorn import *
from unicorn.arm_const import *

import regress

class FpVfpDisabled(regress.RegressTest):

    def runTest(self):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.mem_map(0x1000, 0x1000)
        uc.mem_write(0x1000, '2ded028b'.decode('hex'))  # vpush {d8}
        uc.reg_write(UC_ARM_REG_SP, 0x2000)
        uc.emu_start(0x1000, 0x1004)

if __name__ == '__main__':
    regress.main()
