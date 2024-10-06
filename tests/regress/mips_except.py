#!/usr/bin/python

import regress

from unicorn import *
from unicorn.mips_const import *

CODE = 0x400000
asm = b'\x00\x00\xa4\x8f'  # lw    $a0, ($sp)


def hook_intr(uc, intno, _):
    regress.logger.info('interrupt', intno)


class MipsExcept(regress.RegressTest):

    def runTest(self):
        uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
        uc.hook_add(UC_HOOK_INTR, hook_intr)
        uc.mem_map(CODE, 0x1000)
        uc.mem_write(CODE, asm)

        with self.assertRaises(UcError) as m:
            uc.reg_write(UC_MIPS_REG_SP, 0x400001)
            uc.emu_start(CODE, CODE + len(asm), 300)

        self.assertEqual(UC_ERR_READ_UNALIGNED, m.exception.errno)

        with self.assertRaises(UcError) as m:
            uc.reg_write(UC_MIPS_REG_SP, 0xFFFFFFF0)
            uc.emu_start(CODE, CODE + len(asm), 200)

        self.assertEqual(UC_ERR_READ_UNMAPPED, m.exception.errno)

        with self.assertRaises(UcError) as m:
            uc.reg_write(UC_MIPS_REG_SP, 0x80000000)
            uc.emu_start(CODE, CODE + len(asm), 100)

        self.assertEqual(UC_ERR_READ_UNMAPPED, m.exception.errno)


if __name__ == '__main__':
    regress.main()
