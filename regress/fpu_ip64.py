#!/usr/bin/python
from unicorn import *
from unicorn.x86_const import *
from capstone import *

ESP = 0x2000
PAGE_SIZE = 2 * 1024 * 1024

#	mov [esp], DWORD 0x37f
#	fldcw [esp]
#	fnop
#	fnstenv [esp + 8]
#	pop ecx
CODE = "C704247F030000D92C24D9D0D974240859".decode('hex')

class SimpleEngine:
	def __init__(self):
		self.capmd = Cs(CS_ARCH_X86, CS_MODE_64)

	def disas_single(self, data):
		for i in self.capmd.disasm(data, 16):
			print("\t%s\t%s" % (i.mnemonic, i.op_str))
			break

disasm = SimpleEngine()

def hook_code(uc, addr, size, user_data):
	mem = uc.mem_read(addr, size)
	print("  0x%X:" % (addr)),
	disasm.disas_single(str(mem))

def mem_reader(addr, size):
	tmp = mu.mem_read(addr, size)

	for i in tmp:
		print(" 0x%x" % i),
	print("")


mu = Uc(UC_ARCH_X86, UC_MODE_64)

mu.mem_map(0x0, PAGE_SIZE)
mu.mem_write(0x4000, CODE)
mu.reg_write(UC_X86_REG_RSP, ESP)
mu.hook_add(UC_HOOK_CODE, hook_code)


mu.emu_start(0x4000, 0, 0, 5)
rsp = mu.reg_read(UC_X86_REG_RSP)
print("Value of FPIP: [0x%X]" % (rsp + 10))
mem_reader(rsp + 10, 8)
# EXPECTED OUTPUT:

#   0x4000: 	mov	dword ptr [rsp], 0x37f
#   0x4007: 	fldcw	word ptr [rsp]
#   0x400A: 	fnop	
#   0x400C: 	fnstenv	dword ptr [rsp + 8]
#   0x4010: 	pop	rcx
# Value of FPIP: [0x2012]
#  0x0  0x0  0xa  0x40  0x0  0x0  0x0  0x0 

# WHERE: the value of FPIP should be the address of fnop