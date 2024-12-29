import regress
from unicorn import *
from unicorn.mips_const import *

CODE = b'\x34\x21\x34\x56'  # ori $at, $at, 0x3456
BASE = 0x10000000


class MipsKernelMMU(regress.RegressTest):
    def test_syscall(self):
        uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)

        uc.mem_map(BASE, 0x1000)
        uc.mem_write(BASE, CODE)
        uc.reg_write(UC_MIPS_REG_AT, 0)

        uc.emu_start(BASE, BASE + len(CODE))

        self.assertEqual(0x3456, uc.reg_read(UC_MIPS_REG_AT))


if __name__ == '__main__':
    regress.main()
