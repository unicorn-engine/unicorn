import regress
from unicorn import *
from unicorn.mips_const import *

CODE = b'\x0c\x00\x00\x00'  # syscall
BASE = 0x40000


def intr_hook(uc, intno, data):
    regress.logger.debug('interrupt=%d, v0=%d, pc=%#010x', intno, uc.reg_read(UC_MIPS_REG_V0),
                         uc.reg_read(UC_MIPS_REG_PC))


class MipsSyscall(regress.RegressTest):
    def test(self):
        uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)

        uc.mem_map(BASE, 0x1000)
        uc.mem_write(BASE, CODE)
        uc.reg_write(UC_MIPS_REG_V0, 100)
        uc.hook_add(UC_HOOK_INTR, intr_hook)

        uc.emu_start(BASE, BASE + len(CODE))

        self.assertEqual(0x40004, uc.reg_read(UC_MIPS_REG_PC))


if __name__ == '__main__':
    regress.main()
