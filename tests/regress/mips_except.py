import regress
import sys
import unittest
from unicorn import *
from unicorn.mips_const import *

CODE = (
    b'\x00\x00\x00\x00'  # nop
    b'\x00\x00\xa4\x8f'  # lw    $a0, 0($sp)
)

BASE = 0x20000000


class MipsExcept(regress.RegressTest):

    @unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
    def runTest(self):
        uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)

        uc.mem_map(BASE, 0x1000)
        uc.mem_write(BASE, CODE)

        # execute nop. we should be ok
        uc.emu_start(BASE, BASE + len(CODE), count=1)

        # ----------------------------------------

        # set sp to a mapped but unaligned address to read from
        uc.reg_write(UC_MIPS_REG_SP, BASE + 0x801)

        with self.assertRaises(UcError) as m:
            uc.emu_start(BASE + 4, BASE + len(CODE), count=1)

        self.assertEqual(UC_ERR_READ_UNALIGNED, m.exception.errno)

        # ----------------------------------------

        # set sp to an umapped address to read from
        uc.reg_write(UC_MIPS_REG_SP, 0xfffffff0)

        with self.assertRaises(UcError) as m:
            uc.emu_start(BASE + 4, BASE + len(CODE), count=1)

        self.assertEqual(UC_ERR_READ_UNMAPPED, m.exception.errno)

        # ----------------------------------------

        uc.reg_write(UC_MIPS_REG_SP, 0x40000000)

        with self.assertRaises(UcError) as m:
            uc.emu_start(BASE + 4, BASE + len(CODE), count=1)

        self.assertEqual(UC_ERR_READ_UNMAPPED, m.exception.errno)


if __name__ == '__main__':
    regress.main()
