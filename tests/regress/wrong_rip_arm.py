import regress
from unicorn import *
from unicorn.arm_const import *

CODE = (
    b'\x48\x31'  # adds    r1, #0x48
    b'\xff\x57'  # ldrsb   r7, [r7, r7]
    b'\x57\x5e'  # ldrsh   r7, [r2, r1]
    b'\x5a\x48'  # ldr     r0, [pc, #0x168]
    b'\xbf\x2f'  # cmp     r7, #0xbf
    b'\x2f\x62'  # str     r7, [r5, #0x20]
    b'\x69\x6e'  # ldr     r1, [r5, #0x64]
    b'\x2f\x73'  # strb    r7, [r5, #0xc]
    b'\x68\x48'  # ldr     r0, [pc, #0x1a0]

    b'\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05'  # data?
)

BASE = 0x00000000


class WrongRIPArm(regress.RegressTest):

    def runTest(self):
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        mu.mem_map(BASE, 2 * 1024 * 1024)
        # write machine code to be emulated to memory
        mu.mem_write(BASE, CODE)
        mu.reg_write(UC_ARM_REG_R13, 1 * 1024 * 1024)

        # emu for maximum 1 instruction.
        mu.emu_start(BASE | 0b1, BASE + len(CODE), count=1)

        self.assertEqual(0x48, mu.reg_read(UC_ARM_REG_R1))
        self.assertEqual(0x2, mu.reg_read(UC_ARM_REG_R15))


if __name__ == '__main__':
    regress.main()
