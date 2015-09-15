#!/usr/bin/python

from unicorn import *
from unicorn.sparc_const import *

PAGE_SIZE = 1 * 1024 * 1024

uc = Uc(UC_ARCH_SPARC, UC_MODE_32)
uc.reg_write(UC_SPARC_REG_SP, 100)
uc.reg_write(UC_SPARC_REG_FP, 200)
uc.reg_write(UC_SPARC_REG_G0, 300)
uc.reg_write(UC_SPARC_REG_O0, 400)
uc.reg_write(UC_SPARC_REG_L0, 500)
uc.reg_write(UC_SPARC_REG_I0, 600)

  # 0x0:	\x80\x00\x20\x01	inc	%g0
  # 0x4:	\x90\x02\x20\x01	inc	%o0
  # 0x8:	\xA0\x04\x20\x01	inc	%l0
  # 0xc:	\xB0\x06\x20\x01	inc	%i0
CODE =  "\x80\x00\x20\x01" \
		"\x90\x02\x20\x01" \
		"\xA0\x04\x20\x01" \
		"\xB0\x06\x20\x01"

  # 0x0:	\x80\x00\x20\x01	add	%g0, 1, %g0
  # 0x4:	\x90\x02\x20\x01	add	%o0, 1, %o0
  # 0x8:	\xA0\x04\x20\x01	add	%l0, 1, %l0
  # 0xc:	\xB0\x06\x20\x01	add	%i0, 1, %i0
CODE2 =  "\x80\x00\x20\x01" \
		"\x90\x02\x20\x01" \
		"\xA0\x04\x20\x01" \
		"\xB0\x06\x20\x01"


uc.mem_map(0, PAGE_SIZE)
uc.mem_write(0, CODE2)
uc.emu_start(0, len(CODE2), 0, 4)

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

assert uc.reg_read(UC_SPARC_REG_PC) == 16  # make sure we executed all 4 instructions 
assert uc.reg_read(UC_SPARC_REG_SP) == 100
assert uc.reg_read(UC_SPARC_REG_FP) == 200

assert uc.reg_read(UC_SPARC_REG_G0) == 301
assert uc.reg_read(UC_SPARC_REG_O0) == 401
assert uc.reg_read(UC_SPARC_REG_L0) == 501
assert uc.reg_read(UC_SPARC_REG_I0) == 601