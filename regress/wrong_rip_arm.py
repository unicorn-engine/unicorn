#!/usr/bin/python

from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *

import regress

# adds  r1, #0x48
# ldrsb r7, [r7, r7]
# ldrsh r7, [r2, r1]
# ldr   r0, [pc, #0x168]
# cmp   r7, #0xbf
# str   r7, [r5, #0x20]
# ldr   r1, [r5, #0x64]
# strb  r7, [r5, #0xc]
# ldr   r0, [pc, #0x1a0]
binary1 = b'\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05'
# binary1 = b'\x48\x31\xff\x57'
#adds r1, #0x48
#ldrsb  r7, [r7, r7]

class WrongRIPArm(regress.RegressTest):

    def runTest(self):
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        mu.mem_map(0, 2 * 1024 * 1024)
        # write machine code to be emulated to memory
        mu.mem_write(0, binary1)
        mu.reg_write(UC_ARM_REG_R13, 1 * 1024 * 1024)
        # emu for maximum 1 instruction.
        mu.emu_start(0, len(binary1), 0, 1)
        self.assertEqual(0x48, mu.reg_read(UC_ARM_REG_R1))
        pos = mu.reg_read(UC_ARM_REG_R15)
        self.assertEqual(0x2, pos)

if __name__ == '__main__':
    regress.main()
