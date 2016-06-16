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
        # MRC p15, #0, r1, c1, c0, #2
        # ORR r1, r1, #(0xf << 20)
        # MCR p15, #0, r1, c1, c0, #2
        # MOV r1, #0
        # MCR p15, #0, r1, c7, c5, #4
        # MOV r0,#0x40000000
        # FMXR FPEXC, r0
        code = '11EE501F'
        code += '41F47001'
        code += '01EE501F'
        code += '4FF00001'
        code += '07EE951F'
        code += '4FF08040'
        code += 'E8EE100A'
        # vpush {d8}
        code += '2ded028b'
        
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.mem_map(0x1000, 0x1000)
        uc.mem_write(0x1000, code.decode('hex'))
        uc.reg_write(UC_ARM_REG_SP, 0x2000)
        uc.emu_start(0x1000, 0x1004)

if __name__ == '__main__':
    regress.main()
