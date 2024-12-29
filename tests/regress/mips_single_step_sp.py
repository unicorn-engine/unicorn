import regress
import sys
import unittest
from unicorn import *
from unicorn.mips_const import *

CODE = (
    b'\xf8\xff\x01\x24'  # addiu $at, $zero, -8
    b'\x24\xe8\xa1\x03'  # and $sp, $sp, $at
    b'\x09\xf8\x20\x03'  # jalr $t9
    b'\xe8\xff\xbd\x23'  # addi $sp, $sp, -0x18
    b'\xb8\xff\xbd\x27'  # addiu $sp, $sp, -0x48
    b'\x00\x00\x00\x00'  # nop
)

BASE = 0x4010dc


def code_hook(uc, addr, size, user_data):
    regress.logger.debug('code hook: pc=%08x sp=%08x', addr, uc.reg_read(UC_MIPS_REG_SP))


def run(step):
    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)

    if step:
        uc.hook_add(UC_HOOK_CODE, code_hook)

    uc.reg_write(UC_MIPS_REG_SP, 0x60800000)
    uc.reg_write(UC_MIPS_REG_T9, BASE + len(CODE) - 8)

    regress.logger.debug('sp = %08x', uc.reg_read(UC_MIPS_REG_SP))
    regress.logger.debug('at = %08x', uc.reg_read(UC_MIPS_REG_AT))
    regress.logger.debug('<run> (single step: %s)', str(step))

    uc.mem_map(BASE & ~(0x1000 - 1), 0x2000)
    uc.mem_write(BASE, CODE)
    uc.emu_start(BASE, BASE + len(CODE))

    regress.logger.debug('sp = %08x', uc.reg_read(UC_MIPS_REG_SP))
    regress.logger.debug('at = %08x', uc.reg_read(UC_MIPS_REG_AT))

    return uc.reg_read(UC_MIPS_REG_SP)


class MipsSingleStep(regress.RegressTest):

    @unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
    def runTest(self):
        sp1 = run(step=False)
        sp2 = run(step=True)

        self.assertEqual(sp1, sp2)


if __name__ == '__main__':
    regress.main()
