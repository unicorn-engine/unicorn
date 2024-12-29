import regress
import sys
import unittest
from unicorn import *
from unicorn.sparc_const import *

PAGE_SIZE = 1 * 1024 * 1024

CODE = (
    b"\x80\x00\x20\x01"  # add %g0, 1, %g0
    b"\x82\x00\x60\x01"  # add %g1, 1, %g1
    b"\x84\x00\xA0\x01"  # add %g2, 1, %g2
    b"\x86\x00\xE0\x01"  # add %g3, 1, %g3
    b"\x88\x01\x20\x01"  # add %g4, 1, %g4
    b"\x8A\x01\x60\x01"  # add %g5, 1, %g5
    b"\x8C\x01\xA0\x01"  # add %g6, 1, %g6
    b"\x8E\x01\xE0\x01"  # add %g7, 1, %g7
    b"\x90\x02\x20\x01"  # add %o0, 1, %o0
    b"\x92\x02\x60\x01"  # add %o1, 1, %o1
    b"\x94\x02\xA0\x01"  # add %o2, 1, %o2
    b"\x96\x02\xE0\x01"  # add %o3, 1, %o3
    b"\x98\x03\x20\x01"  # add %o4, 1, %o4
    b"\x9A\x03\x60\x01"  # add %o5, 1, %o5
    b"\x9C\x03\xA0\x01"  # add %sp, 1, %sp
    b"\x9E\x03\xE0\x01"  # add %o7, 1, %o7
    b"\xA0\x04\x20\x01"  # add %l0, 1, %l0
    b"\xA2\x04\x60\x01"  # add %l1, 1, %l1
    b"\xA4\x04\xA0\x01"  # add %l2, 1, %l2
    b"\xA6\x04\xE0\x01"  # add %l3, 1, %l3
    b"\xA8\x05\x20\x01"  # add %l4, 1, %l4
    b"\xAA\x05\x60\x01"  # add %l5, 1, %l5
    b"\xAC\x05\xA0\x01"  # add %l6, 1, %l6
    b"\xAE\x05\xE0\x01"  # add %l7, 1, %l7
    b"\xB0\x06\x20\x01"  # add %i0, 1, %i0
    b"\xB2\x06\x60\x01"  # add %i1, 1, %i1
    b"\xB4\x06\xA0\x01"  # add %i2, 1, %i2
    b"\xB6\x06\xE0\x01"  # add %i3, 1, %i3
    b"\xB8\x07\x20\x01"  # add %i4, 1, %i4
    b"\xBA\x07\x60\x01"  # add %i5, 1, %i5
    b"\xBC\x07\xA0\x01"  # add %fp, 1, %fp
    b"\xBE\x07\xE0\x01"  # add %i7, 1, %i7
)

BASE = 0x00000000


def hook_code(uc, addr, size, ud):
    regress.logger.debug("executing at 0x%04x", uc.reg_read(UC_SPARC_REG_PC))


class TestSparc32RegRead(regress.RegressTest):

    @unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
    def runTest(self):
        uc = Uc(UC_ARCH_SPARC, UC_MODE_SPARC32 | UC_MODE_BIG_ENDIAN)

        uc.reg_write(UC_SPARC_REG_SP, 100)
        uc.reg_write(UC_SPARC_REG_FP, 200)

        uc.mem_map(BASE, PAGE_SIZE)
        uc.mem_write(BASE, CODE)

        uc.hook_add(UC_HOOK_CODE, hook_code)
        uc.emu_start(BASE, len(CODE))

        self.assertEqual(0, uc.reg_read(UC_SPARC_REG_G0))  # G0 is always zero
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_G1))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_G2))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_G3))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_G4))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_G5))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_G6))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_G7))

        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_O0))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_O1))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_O2))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_O3))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_O4))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_O5))
        self.assertEqual(101, uc.reg_read(UC_SPARC_REG_O6))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_O7))

        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_L0))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_L1))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_L2))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_L3))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_L4))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_L5))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_L6))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_L7))

        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_I0))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_I1))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_I2))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_I3))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_I4))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_I5))
        self.assertEqual(201, uc.reg_read(UC_SPARC_REG_I6))
        self.assertEqual(1, uc.reg_read(UC_SPARC_REG_I7))

        # BUG: PC seems to get reset to 4 when done executing
        self.assertEqual(4 * 32, uc.reg_read(UC_SPARC_REG_PC))  # make sure we executed all instructions
        self.assertEqual(101, uc.reg_read(UC_SPARC_REG_SP))
        self.assertEqual(201, uc.reg_read(UC_SPARC_REG_FP))


if __name__ == '__main__':
    regress.main()
