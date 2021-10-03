from unicorn import *
from unicorn.x86_const import *

count = 0

def cb(uc, addr, sz, data):
    global count
    count += 1
    print(f"addr: {hex(addr)} count: {count}")
    if count == 5:
        uc.emu_stop()
    else:
        uc.reg_write(UC_X86_REG_RIP, 0x2000)

mu = Uc(UC_ARCH_X86, UC_MODE_64)

mu.mem_map(0x1000, 0x4000)
mu.mem_write(0x1000, b"\x90" * 5)
mu.mem_write(0x2000, b"\x90" * 5)
mu.hook_add(UC_HOOK_CODE, cb)
mu.emu_start(0x1000, 0x2000+1, 0, 0)
