# Added by Peter Mackay, relating to issue 571
# ARM NEON/VFP support seems to exist but is disabled by default
# https://github.com/unicorn-engine/unicorn/issues/571

import regress
from unicorn import *
from unicorn.arm_const import *

CODE = (
    b'\x11\xEE\x50\x1F'  # MRC p15, #0, r1, c1, c0, #2
    b'\x41\xF4\x70\x01'  # ORR r1, r1, #(0xf << 20)
    b'\x01\xEE\x50\x1F'  # MCR p15, #0, r1, c1, c0, #2
    b'\x4F\xF0\x00\x01'  # MOV r1, #0
    b'\x07\xEE\x95\x1F'  # MCR p15, #0, r1, c7, c5, #4
    b'\x4F\xF0\x80\x40'  # MOV r0,#0x40000000
    b'\xE8\xEE\x10\x0A'  # FMXR FPEXC, r0
    b'\x2d\xed\x02\x8b'  # vpush {d8}
)

BASE = 0x1000


class FpVfpDisabled(regress.RegressTest):

    def runTest(self):
        mem_size = 0x1000

        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        uc.mem_map(BASE, mem_size)
        uc.mem_write(BASE, CODE)
        uc.reg_write(UC_ARM_REG_SP, BASE + mem_size - 4)

        uc.emu_start(BASE + 1, BASE + len(CODE))


if __name__ == '__main__':
    regress.main()
