import regress
from unicorn import *
from unicorn.sparc_const import *

CODE = (
    b"\xb0\x06\x20\x01"  # 0: b0 06 20 01     inc  %i0
    b"\xb2\x06\x60\x01"  # 4: b2 06 60 01     inc  %i1
)

BASE = 0x00000000


class TestSparc64RegRead(regress.RegressTest):
    def runTest(self):
        uc = Uc(UC_ARCH_SPARC, UC_MODE_SPARC64 | UC_MODE_BIG_ENDIAN)

        uc.mem_map(BASE, 0x1000 ** 2)
        uc.mem_write(BASE, CODE)

        uc.reg_write(UC_SPARC_REG_SP, 100)

        uc.emu_start(BASE, BASE + len(CODE), count=2)

        regress.logger.debug('sp = %#x', uc.reg_read(UC_SPARC_REG_SP))
        regress.logger.debug('i0 = %#x', uc.reg_read(UC_SPARC_REG_I0))
        regress.logger.debug('i1 = %#x', uc.reg_read(UC_SPARC_REG_I1))


if __name__ == '__main__':
    regress.main()
