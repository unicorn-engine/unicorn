from unicorn import *
from unicorn.arm_const import *

# ADD R0, R10, R0;
# B L0;
# L0:
#   ADD R0, R10, R0; <--- we stop at here, the first instruction of the next TB.

code = b'\x00\x00\x8a\xe0\xff\xff\xff\xea\x00\x00\x8a\xe0'
address = 0x1000

mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(address, 0x1000)
mu.mem_write(address, code)
mu.emu_start(address, address + len(code) - 4)