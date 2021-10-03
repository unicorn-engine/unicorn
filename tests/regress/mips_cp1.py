from unicorn import *
from unicorn.mips_const import *



# .text:00416CB0                 cfc1    $v1, FCSR
shellcode = [0x44, 0x43, 0xF8, 0x00]
base = 0x416CB0

uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)
uc.mem_map(0x416000, 0x1000)
uc.mem_write(base, bytes(shellcode))
uc.emu_start(base, base + len(shellcode))