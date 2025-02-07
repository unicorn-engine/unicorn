import regress
from unicorn import *
from unicorn.mips_const import *

CODE = b'\x44\x43\xF8\x00'  # cfc1    $v1, FCSR
BASE = 0x416CB0


class TestMipsCp1(regress.RegressTest):
    def runTest(self):
        uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)

        uc.mem_map(BASE & ~(0x1000 - 1), 0x1000)
        uc.mem_write(BASE, CODE)

        # set a wrong value in v1
        uc.reg_write(UC_MIPS_REG_V1, 0x0badc0de)

        uc.emu_start(BASE, BASE + len(CODE))

        # default FCSR value should be 0
        self.assertEqual(0x0000, uc.reg_read(UC_MIPS_REG_V1))


if __name__ == '__main__':
    regress.main()
