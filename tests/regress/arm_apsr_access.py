#!/usr/bin/python

from unicorn import *
from unicorn.arm_const import *

import regress

class APSRAccess(regress.RegressTest):

    def runTest(self):
        code = (
            b'\x00\x00\xa0\xe1' + #  0: mov r0, r0
            b'\x08\x10\x9f\xe5' + #  4: ldr r1, [pc, #8]
            b'\x01\xf0\x28\xe1' + #  8: 01 f0 28 e1  msr apsr_nzcvq, r1
            b'\x00\x00\xa0\xe1' + #  c: mov r0, r0
            b'\x00\x00\xa0\xe1' + # 10: mov r0, r0
            b'\x00\x00\x00\xff')  # 14: data for inst @4

        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x1000)
        uc.mem_write(0x1000, code)  # bxeq lr; mov r0, r0

        uc.reg_write(UC_ARM_REG_APSR, 0)
        uc.emu_start(0x1000, 0x100c)

        self.assertEqual(uc.reg_read(UC_ARM_REG_APSR), 0xf8000000)
        self.assertEqual(uc.reg_read(UC_ARM_REG_APSR_NZCV), 0xf0000000)

if __name__ == '__main__':
    regress.main()
