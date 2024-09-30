#!/usr/bin/python

import regress

from unicorn import *
from unicorn.mips_const import *


def code_hook(uc, addr, size, user_data):
    regress.logger.info('code hook: pc=%08x sp=%08x', addr, uc.reg_read(UC_MIPS_REG_SP))


def run(step) -> int:
    addr = 0x4010dc

    code = (
        b'\xf8\xff\x01\x24'     #  addiu $at, $zero, -8
        b'\x24\xe8\xa1\x03'     #  and $sp, $sp, $at
        b'\x09\xf8\x20\x03'     #  jalr $t9
        b'\xe8\xff\xbd\x23'     #  addi $sp, $sp, -0x18
        b'\xb8\xff\xbd\x27'     #  addiu $sp, $sp, -0x48
        b'\x00\x00\x00\x00'     #  nop
    )

    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)

    if step:
        uc.hook_add(UC_HOOK_CODE, code_hook)

    uc.reg_write(UC_MIPS_REG_SP, 0x60800000)
    uc.reg_write(UC_MIPS_REG_T9, addr + len(code) - 8)

    regress.logger.info('sp = %08x', uc.reg_read(UC_MIPS_REG_SP))
    regress.logger.info('at = %08x', uc.reg_read(UC_MIPS_REG_AT))
    regress.logger.info('<run> (single step: %s)', str(step))

    uc.mem_map(addr & ~(0x1000 - 1), 0x2000)
    uc.mem_write(addr, code)
    uc.emu_start(addr, addr + len(code))

    regress.logger.info('sp = %08x', uc.reg_read(UC_MIPS_REG_SP))
    regress.logger.info('at = %08x', uc.reg_read(UC_MIPS_REG_AT))

    return uc.reg_read(UC_MIPS_REG_SP)


class MipsSingleStep(regress.RegressTest):
    def runTest(self):
        sp1 = run(step=False)
        sp2 = run(step=True)

        self.assertEqual(sp1, sp2)


if __name__ == '__main__':
    regress.main()
