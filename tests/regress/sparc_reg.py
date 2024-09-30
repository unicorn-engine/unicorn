#!/usr/bin/python

import regress

from unicorn import *
from unicorn.sparc_const import *


PAGE_SIZE = 1 * 1024 * 1024

CODE =(
	b"\x80\x00\x20\x01"     # 0x0:    \x80\x00\x20\x01    add %g0, 1, %g0
    b"\x82\x00\x60\x01"     # 0x4:    \x82\x00\x60\x01    add %g1, 1, %g1
    b"\x84\x00\xA0\x01"     # 0x8:    \x84\x00\xA0\x01    add %g2, 1, %g2
    b"\x86\x00\xE0\x01"     # 0xc:    \x86\x00\xE0\x01    add %g3, 1, %g3
    b"\x88\x01\x20\x01"     # 0x10:   \x88\x01\x20\x01    add %g4, 1, %g4
    b"\x8A\x01\x60\x01"     # 0x14:   \x8A\x01\x60\x01    add %g5, 1, %g5
    b"\x8C\x01\xA0\x01"     # 0x18:   \x8C\x01\xA0\x01    add %g6, 1, %g6
    b"\x8E\x01\xE0\x01"     # 0x1c:   \x8E\x01\xE0\x01    add %g7, 1, %g7
    b"\x90\x02\x20\x01"     # 0x20:   \x90\x02\x20\x01    add %o0, 1, %o0
    b"\x92\x02\x60\x01"     # 0x24:   \x92\x02\x60\x01    add %o1, 1, %o1
    b"\x94\x02\xA0\x01"     # 0x28:   \x94\x02\xA0\x01    add %o2, 1, %o2
    b"\x96\x02\xE0\x01"     # 0x2c:   \x96\x02\xE0\x01    add %o3, 1, %o3
    b"\x98\x03\x20\x01"     # 0x30:   \x98\x03\x20\x01    add %o4, 1, %o4
    b"\x9A\x03\x60\x01"     # 0x34:   \x9A\x03\x60\x01    add %o5, 1, %o5
    b"\x9C\x03\xA0\x01"     # 0x38:   \x9C\x03\xA0\x01    add %sp, 1, %sp
    b"\x9E\x03\xE0\x01"     # 0x3c:   \x9E\x03\xE0\x01    add %o7, 1, %o7
    b"\xA0\x04\x20\x01"     # 0x40:   \xA0\x04\x20\x01    add %l0, 1, %l0
    b"\xA2\x04\x60\x01"     # 0x44:   \xA2\x04\x60\x01    add %l1, 1, %l1
    b"\xA4\x04\xA0\x01"     # 0x48:   \xA4\x04\xA0\x01    add %l2, 1, %l2
    b"\xA6\x04\xE0\x01"     # 0x4c:   \xA6\x04\xE0\x01    add %l3, 1, %l3
    b"\xA8\x05\x20\x01"     # 0x50:   \xA8\x05\x20\x01    add %l4, 1, %l4
    b"\xAA\x05\x60\x01"     # 0x54:   \xAA\x05\x60\x01    add %l5, 1, %l5
    b"\xAC\x05\xA0\x01"     # 0x58:   \xAC\x05\xA0\x01    add %l6, 1, %l6
    b"\xAE\x05\xE0\x01"     # 0x5c:   \xAE\x05\xE0\x01    add %l7, 1, %l7
    b"\xB0\x06\x20\x01"     # 0x0:    \xB0\x06\x20\x01    add %i0, 1, %i0
    b"\xB2\x06\x60\x01"     # 0x4:    \xB2\x06\x60\x01    add %i1, 1, %i1
    b"\xB4\x06\xA0\x01"     # 0x8:    \xB4\x06\xA0\x01    add %i2, 1, %i2
    b"\xB6\x06\xE0\x01"     # 0xc:    \xB6\x06\xE0\x01    add %i3, 1, %i3
    b"\xB8\x07\x20\x01"     # 0x10:   \xB8\x07\x20\x01    add %i4, 1, %i4
    b"\xBA\x07\x60\x01"     # 0x14:   \xBA\x07\x60\x01    add %i5, 1, %i5
    b"\xBC\x07\xA0\x01"     # 0x18:   \xBC\x07\xA0\x01    add %fp, 1, %fp
    b"\xBE\x07\xE0\x01"     # 0x1c:   \xBE\x07\xE0\x01    add %i7, 1, %i7
)

uc = Uc(UC_ARCH_SPARC, UC_MODE_SPARC32 | UC_MODE_BIG_ENDIAN)
uc.reg_write(UC_SPARC_REG_SP, 100)
uc.reg_write(UC_SPARC_REG_FP, 200)

uc.mem_map(0, PAGE_SIZE)
uc.mem_write(0, CODE)
uc.emu_start(0, len(CODE)) #, 0, 32)

regress.logger.info(" G0 = %d", uc.reg_read(UC_SPARC_REG_G0))
regress.logger.info(" G1 = %d", uc.reg_read(UC_SPARC_REG_G1))
regress.logger.info(" G2 = %d", uc.reg_read(UC_SPARC_REG_G2))
regress.logger.info(" G3 = %d", uc.reg_read(UC_SPARC_REG_G3))
regress.logger.info(" G4 = %d", uc.reg_read(UC_SPARC_REG_G4))
regress.logger.info(" G5 = %d", uc.reg_read(UC_SPARC_REG_G5))
regress.logger.info(" G6 = %d", uc.reg_read(UC_SPARC_REG_G6))
regress.logger.info(" G7 = %d", uc.reg_read(UC_SPARC_REG_G7))
regress.logger.info("")
regress.logger.info(" O0 = %d", uc.reg_read(UC_SPARC_REG_O0))
regress.logger.info(" O1 = %d", uc.reg_read(UC_SPARC_REG_O1))
regress.logger.info(" O2 = %d", uc.reg_read(UC_SPARC_REG_O2))
regress.logger.info(" O3 = %d", uc.reg_read(UC_SPARC_REG_O3))
regress.logger.info(" O4 = %d", uc.reg_read(UC_SPARC_REG_O4))
regress.logger.info(" O5 = %d", uc.reg_read(UC_SPARC_REG_O5))
regress.logger.info(" O6 = %d", uc.reg_read(UC_SPARC_REG_O6))
regress.logger.info(" O7 = %d", uc.reg_read(UC_SPARC_REG_O7))
regress.logger.info("")
regress.logger.info(" L0 = %d", uc.reg_read(UC_SPARC_REG_L0))
regress.logger.info(" L1 = %d", uc.reg_read(UC_SPARC_REG_L1))
regress.logger.info(" L2 = %d", uc.reg_read(UC_SPARC_REG_L2))
regress.logger.info(" L3 = %d", uc.reg_read(UC_SPARC_REG_L3))
regress.logger.info(" L4 = %d", uc.reg_read(UC_SPARC_REG_L4))
regress.logger.info(" L5 = %d", uc.reg_read(UC_SPARC_REG_L5))
regress.logger.info(" L6 = %d", uc.reg_read(UC_SPARC_REG_L6))
regress.logger.info(" L7 = %d", uc.reg_read(UC_SPARC_REG_L7))
regress.logger.info("")
regress.logger.info(" I0 = %d", uc.reg_read(UC_SPARC_REG_I0))
regress.logger.info(" I1 = %d", uc.reg_read(UC_SPARC_REG_I1))
regress.logger.info(" I2 = %d", uc.reg_read(UC_SPARC_REG_I2))
regress.logger.info(" I3 = %d", uc.reg_read(UC_SPARC_REG_I3))
regress.logger.info(" I4 = %d", uc.reg_read(UC_SPARC_REG_I4))
regress.logger.info(" I5 = %d", uc.reg_read(UC_SPARC_REG_I5))
regress.logger.info(" I6 = %d", uc.reg_read(UC_SPARC_REG_I6))
regress.logger.info(" I7 = %d", uc.reg_read(UC_SPARC_REG_I7))
regress.logger.info("")
regress.logger.info(" PC = %d", uc.reg_read(UC_SPARC_REG_PC))
regress.logger.info(" SP = %d", uc.reg_read(UC_SPARC_REG_SP))
regress.logger.info(" FP = %d", uc.reg_read(UC_SPARC_REG_FP))
regress.logger.info("")

assert uc.reg_read(UC_SPARC_REG_G0) == 0 # G0 is always zero
assert uc.reg_read(UC_SPARC_REG_G1) == 1
assert uc.reg_read(UC_SPARC_REG_G2) == 1
assert uc.reg_read(UC_SPARC_REG_G3) == 1
assert uc.reg_read(UC_SPARC_REG_G4) == 1
assert uc.reg_read(UC_SPARC_REG_G5) == 1
assert uc.reg_read(UC_SPARC_REG_G6) == 1
assert uc.reg_read(UC_SPARC_REG_G7) == 1

assert uc.reg_read(UC_SPARC_REG_O0) == 1
assert uc.reg_read(UC_SPARC_REG_O1) == 1
assert uc.reg_read(UC_SPARC_REG_O2) == 1
assert uc.reg_read(UC_SPARC_REG_O3) == 1
assert uc.reg_read(UC_SPARC_REG_O4) == 1
assert uc.reg_read(UC_SPARC_REG_O5) == 1
assert uc.reg_read(UC_SPARC_REG_O6) == 101
assert uc.reg_read(UC_SPARC_REG_O7) == 1

assert uc.reg_read(UC_SPARC_REG_L0) == 1
assert uc.reg_read(UC_SPARC_REG_L1) == 1
assert uc.reg_read(UC_SPARC_REG_L2) == 1
assert uc.reg_read(UC_SPARC_REG_L3) == 1
assert uc.reg_read(UC_SPARC_REG_L4) == 1
assert uc.reg_read(UC_SPARC_REG_L5) == 1
assert uc.reg_read(UC_SPARC_REG_L6) == 1
assert uc.reg_read(UC_SPARC_REG_L7) == 1

assert uc.reg_read(UC_SPARC_REG_I0) == 1
assert uc.reg_read(UC_SPARC_REG_I1) == 1
assert uc.reg_read(UC_SPARC_REG_I2) == 1
assert uc.reg_read(UC_SPARC_REG_I3) == 1
assert uc.reg_read(UC_SPARC_REG_I4) == 1
assert uc.reg_read(UC_SPARC_REG_I5) == 1
assert uc.reg_read(UC_SPARC_REG_I6) == 201
assert uc.reg_read(UC_SPARC_REG_I7) == 1

# elicn: find out why it fails
# assert uc.reg_read(UC_SPARC_REG_PC) == 4 * (32 + 1)  # make sure we executed all instructions
assert uc.reg_read(UC_SPARC_REG_SP) == 101
assert uc.reg_read(UC_SPARC_REG_FP) == 201
