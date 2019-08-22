#!/usr/bin/python
from unicorn import *
from unicorn.x86_const import *
import regress

PAGE_SIZE = 4 * 1024
ACCESS_ADDR = 0x1000

# mov eax, [0x1000]
# mov eax, [0x1000]
CODE = b'\xA1\x00\x10\x00\x00\xA1\x00\x10\x00\x00'

def hook_mem_read(uc, access, address, size, value, data):
    print("Reading at " + str(address))
    uc.mem_write(address, CODE);

class REP(regress.RegressTest):

    def test_rep(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        mu.mem_map(0, PAGE_SIZE)
        mu.mem_write(0, CODE)
        mu.mem_map(ACCESS_ADDR, PAGE_SIZE, UC_PROT_READ);
        mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read, begin = ACCESS_ADDR, end = ACCESS_ADDR + PAGE_SIZE)

        mu.emu_start(0, len(CODE))

if __name__ == '__main__':
    regress.main()
