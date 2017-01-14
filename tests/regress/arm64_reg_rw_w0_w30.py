#!/usr/bin/python

from unicorn import *
from unicorn.arm64_const import *
from unicorn.x86_const import *

import regress

class Arm64RegReadWriteW0ThroughW30(regress.RegressTest):
    """
    Testing the functionality to read/write 32-bit registers in AArch64
    See issue #716 
    """

    def runTest(self):
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        
        uc.reg_write(UC_ARM64_REG_X0, 0x1234567890abcdef)
        self.assertEquals(uc.reg_read(UC_ARM64_REG_X0), 0x1234567890abcdef)
        self.assertEquals(uc.reg_read(UC_ARM64_REG_W0), 0x90abcdef)
        
        uc.reg_write(UC_ARM64_REG_X30, 0xa1b2c3d4e5f6a7b8)
        self.assertEquals(uc.reg_read(UC_ARM64_REG_W30), 0xe5f6a7b8)

        uc.reg_write(UC_ARM64_REG_W30, 0xaabbccdd)
        self.assertEquals(uc.reg_read(UC_ARM64_REG_X30), 0xa1b2c3d4aabbccdd)
        self.assertEquals(uc.reg_read(UC_ARM64_REG_W30), 0xaabbccdd)

if __name__ == '__main__':
    regress.main()
