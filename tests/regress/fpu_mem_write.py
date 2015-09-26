#!/usr/bin/python
from unicorn import *
from unicorn.x86_const import *

import regress

ESP = 0x2000
PAGE_SIZE = 1 * 1024 * 1024

#   wait
#   fnstcw  word ptr [esp]
#   pop ecx
CODE = b'\x9B\xD9\x3C\x24\x59'

def hook_mem_write(uc, access, address, size, value, user_data):
    print("mem WRITE: 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
    return True

class FpuWrite(regress.RegressTest):

    def mem_reader(self, mu, addr, size, expected):
        tmp = mu.mem_read(addr, size)
        for i, e in zip(tmp, expected):
            self.assertEquals(e, i)

    def runTest(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu.mem_map(0, PAGE_SIZE)
        mu.mem_write(0, CODE)
        mu.reg_write(UC_X86_REG_ESP, ESP)

        mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
        mu.emu_start(0x0, 5, 0, 2)
        esp = mu.reg_read(UC_X86_REG_ESP)
        self.mem_reader(mu, esp, 10, [0] * 10)

if __name__ == '__main__':
    regress.main()
