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
CODE = b'\xc7\x04\x24\x7f\x03\x00\x00\xd9\x2c\x24\xd9\xd0\xd9\x74\x24\x08\x59'

class SimpleEngine:
	def __init__(self):
		self.capmd = Cs(CS_ARCH_X86, CS_MODE_32)

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


mu = Uc(UC_ARCH_X86, UC_MODE_32)

mu.mem_map(0x0, PAGE_SIZE)
mu.mem_write(0x4000, CODE)
mu.reg_write(UC_X86_REG_ESP, ESP)
mu.hook_add(UC_HOOK_CODE, hook_code)


mu.emu_start(0x4000, 0, 0, 5)
esp = mu.reg_read(UC_X86_REG_ESP)
print("value at ESP [0x%X - 4]: " % esp)
mem_reader(esp +  14, 4)

# EXPECTED OUTPUT:
#   0x4000: 	mov	dword ptr [esp], 0x37f
#   0x4007: 	fldcw	word ptr [esp]
#   0x400A: 	fnop	
#   0x400C: 	fnstenv	dword ptr [esp + 8]
#   0x4010: 	pop	ecx
# value at ESP [0x2004 - 4]: 
#  0x0  0x0  0xa  0x40 
#  ^ this value should match the fnop instuction addr