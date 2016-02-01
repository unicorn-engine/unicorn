#!/usr/bin/python

from unicorn import *
from unicorn.sparc_const import *

PAGE_SIZE = 1 * 1024 * 1024

uc = Uc(UC_ARCH_SPARC, UC_MODE_SPARC32|UC_MODE_BIG_ENDIAN)
uc.reg_write(UC_SPARC_REG_SP, 100)
uc.reg_write(UC_SPARC_REG_FP, 200)

  # 0x0:    \x80\x00\x20\x01    add %g0, 1, %g0
  # 0x4:    \x82\x00\x60\x01    add %g1, 1, %g1
  # 0x8:    \x84\x00\xA0\x01    add %g2, 1, %g2
  # 0xc:    \x86\x00\xE0\x01    add %g3, 1, %g3
  # 0x10:   \x88\x01\x20\x01    add %g4, 1, %g4
  # 0x14:   \x8A\x01\x60\x01    add %g5, 1, %g5
  # 0x18:   \x8C\x01\xA0\x01    add %g6, 1, %g6
  # 0x1c:   \x8E\x01\xE0\x01    add %g7, 1, %g7
  # 0x20:   \x90\x02\x20\x01    add %o0, 1, %o0
  # 0x24:   \x92\x02\x60\x01    add %o1, 1, %o1
  # 0x28:   \x94\x02\xA0\x01    add %o2, 1, %o2
  # 0x2c:   \x96\x02\xE0\x01    add %o3, 1, %o3
  # 0x30:   \x98\x03\x20\x01    add %o4, 1, %o4
  # 0x34:   \x9A\x03\x60\x01    add %o5, 1, %o5
  # 0x38:   \x9C\x03\xA0\x01    add %sp, 1, %sp
  # 0x3c:   \x9E\x03\xE0\x01    add %o7, 1, %o7
  # 0x40:   \xA0\x04\x20\x01    add %l0, 1, %l0
  # 0x44:   \xA2\x04\x60\x01    add %l1, 1, %l1
  # 0x48:   \xA4\x04\xA0\x01    add %l2, 1, %l2
  # 0x4c:   \xA6\x04\xE0\x01    add %l3, 1, %l3
  # 0x50:   \xA8\x05\x20\x01    add %l4, 1, %l4
  # 0x54:   \xAA\x05\x60\x01    add %l5, 1, %l5
  # 0x58:   \xAC\x05\xA0\x01    add %l6, 1, %l6
  # 0x5c:   \xAE\x05\xE0\x01    add %l7, 1, %l7
  # 0x0:    \xB0\x06\x20\x01    add %i0, 1, %i0
  # 0x4:    \xB2\x06\x60\x01    add %i1, 1, %i1
  # 0x8:    \xB4\x06\xA0\x01    add %i2, 1, %i2
  # 0xc:    \xB6\x06\xE0\x01    add %i3, 1, %i3
  # 0x10:   \xB8\x07\x20\x01    add %i4, 1, %i4
  # 0x14:   \xBA\x07\x60\x01    add %i5, 1, %i5
  # 0x18:   \xBC\x07\xA0\x01    add %fp, 1, %fp
  # 0x1c:   \xBE\x07\xE0\x01    add %i7, 1, %i7


CODE =  "\x80\x00\x20\x01" \
        "\x82\x00\x60\x01" \
        "\x84\x00\xA0\x01" \
        "\x86\x00\xE0\x01" \
        "\x88\x01\x20\x01" \
        "\x8A\x01\x60\x01" \
        "\x8C\x01\xA0\x01" \
        "\x8E\x01\xE0\x01" \
        "\x90\x02\x20\x01" \
        "\x92\x02\x60\x01" \
        "\x94\x02\xA0\x01" \
        "\x96\x02\xE0\x01" \
        "\x98\x03\x20\x01" \
        "\x9A\x03\x60\x01" \
        "\x9C\x03\xA0\x01" \
        "\x9E\x03\xE0\x01" \
        "\xA0\x04\x20\x01" \
        "\xA2\x04\x60\x01" \
        "\xA4\x04\xA0\x01" \
        "\xA6\x04\xE0\x01" \
        "\xA8\x05\x20\x01" \
        "\xAA\x05\x60\x01" \
        "\xAC\x05\xA0\x01" \
        "\xAE\x05\xE0\x01" \
        "\xB0\x06\x20\x01" \
        "\xB2\x06\x60\x01" \
        "\xB4\x06\xA0\x01" \
        "\xB6\x06\xE0\x01" \
        "\xB8\x07\x20\x01" \
        "\xBA\x07\x60\x01" \
        "\xBC\x07\xA0\x01" \
        "\xBE\x07\xE0\x01"


uc.mem_map(0, PAGE_SIZE)
uc.mem_write(0, CODE)
uc.emu_start(0, len(CODE), 0, 32)

def print_registers(mu):
    g0 = mu.reg_read(UC_SPARC_REG_G0)
    g1 = mu.reg_read(UC_SPARC_REG_G1)
    g2 = mu.reg_read(UC_SPARC_REG_G2)
    g3 = mu.reg_read(UC_SPARC_REG_G3)
    g4 = mu.reg_read(UC_SPARC_REG_G4)
    g5 = mu.reg_read(UC_SPARC_REG_G5)
    g6 = mu.reg_read(UC_SPARC_REG_G6)
    g7 = mu.reg_read(UC_SPARC_REG_G7)

    o0 = mu.reg_read(UC_SPARC_REG_O0)
    o1 = mu.reg_read(UC_SPARC_REG_O1)
    o2 = mu.reg_read(UC_SPARC_REG_O2)
    o3 = mu.reg_read(UC_SPARC_REG_O3)
    o4 = mu.reg_read(UC_SPARC_REG_O4)
    o5 = mu.reg_read(UC_SPARC_REG_O5)
    o6 = mu.reg_read(UC_SPARC_REG_O6)
    o7 = mu.reg_read(UC_SPARC_REG_O7)

    l0 = mu.reg_read(UC_SPARC_REG_L0)
    l1 = mu.reg_read(UC_SPARC_REG_L1)
    l2 = mu.reg_read(UC_SPARC_REG_L2)
    l3 = mu.reg_read(UC_SPARC_REG_L3)
    l4 = mu.reg_read(UC_SPARC_REG_L4)
    l5 = mu.reg_read(UC_SPARC_REG_L5)
    l6 = mu.reg_read(UC_SPARC_REG_L6)
    l7 = mu.reg_read(UC_SPARC_REG_L7)

    i0 = mu.reg_read(UC_SPARC_REG_I0)
    i1 = mu.reg_read(UC_SPARC_REG_I1)
    i2 = mu.reg_read(UC_SPARC_REG_I2)
    i3 = mu.reg_read(UC_SPARC_REG_I3)
    i4 = mu.reg_read(UC_SPARC_REG_I4)
    i5 = mu.reg_read(UC_SPARC_REG_I5)
    i6 = mu.reg_read(UC_SPARC_REG_I6)
    i7 = mu.reg_read(UC_SPARC_REG_I7)

    pc = mu.reg_read(UC_SPARC_REG_PC)
    sp = mu.reg_read(UC_SPARC_REG_SP)
    fp = mu.reg_read(UC_SPARC_REG_FP)
    print("   G0  = %d" % g0)
    print("   G1  = %d" % g1)
    print("   G2  = %d" % g2)
    print("   G3  = %d" % g3)
    print("   G4  = %d" % g4)
    print("   G5  = %d" % g5)
    print("   G6  = %d" % g6)
    print("   G7  = %d" % g7)
    print("")
    print("   O0  = %d" % o0)
    print("   O1  = %d" % o1)
    print("   O2  = %d" % o2)
    print("   O3  = %d" % o3)
    print("   O4  = %d" % o4)
    print("   O5  = %d" % o5)
    print("   O6  = %d" % o6)
    print("   O7  = %d" % o7)
    print("")
    print("   L0  = %d" % l0)
    print("   L1  = %d" % l1)
    print("   L2  = %d" % l2)
    print("   L3  = %d" % l3)
    print("   L4  = %d" % l4)
    print("   L5  = %d" % l5)
    print("   L6  = %d" % l6)
    print("   L7  = %d" % l7)
    print("")
    print("   I0  = %d" % i0)
    print("   I1  = %d" % i1)
    print("   I2  = %d" % i2)
    print("   I3  = %d" % i3)
    print("   I4  = %d" % i4)
    print("   I5  = %d" % i5)
    print("   I6  = %d" % i6)
    print("   I7  = %d" % i7)
    print("")
    print("   PC  = %d" % pc)
    print("   SP  = %d" % sp)
    print("   FP  = %d" % fp)
    print("")

print_registers(uc)

assert uc.reg_read(UC_SPARC_REG_PC) == 132  # make sure we executed all instructions
assert uc.reg_read(UC_SPARC_REG_SP) == 101
assert uc.reg_read(UC_SPARC_REG_FP) == 201

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
