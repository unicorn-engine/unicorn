#!/usr/bin/python
# By Ryan Hileman, issue #16

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

import regress

class WrongSPArm(regress.RegressTest):

    def test_32(self):
        with self.assertRaises(UcError):
            uc = Uc(UC_ARCH_ARM, UC_MODE_32)
            uc.reg_write(UC_ARM_REG_SP, 4)

    def test_64(self):
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.reg_write(UC_ARM64_REG_SP, 4)
        self.assertEqual(0x4, uc.reg_read(UC_ARM64_REG_SP))

    def test_arm(self):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.reg_write(UC_ARM_REG_SP, 4)
        self.assertEqual(0x4, uc.reg_read(UC_ARM_REG_SP))

if __name__ == '__main__':
    regress.main()
