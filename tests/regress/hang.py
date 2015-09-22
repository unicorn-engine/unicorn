#!/usr/bin/python

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *

import regress

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    tmp = uc.mem_read(address, size)
    print("[0x%x] =" %(address), end="")
    for i in tmp:
        print(" %02x" %i, end="")
    print("")

# callback for tracing Linux interrupt
def hook_intr(uc, intno, user_data):
    # only handle Linux syscall
    rip = uc.reg_read(UC_X86_REG_RIP)
    if intno != 0x80:
        print("=== 0x%x: got interrupt %x, quit" %(rip, intno));
        uc.emu_stop()
        return

    eax = uc.reg_read(UC_X86_REG_EAX)
    print(">>> 0x%x: interrupt 0x%x, EAX = 0x%x" %(rip, intno, eax))

class Hang(regress.RegressTest):

    def runTest(self):
        binary1 = b'\xeb\x1c\x5a\x89\xd6\x8b\x02\x66\x3d\xca\x7d\x75\x06\x66\x05\x03\x03\x89\x02\xfe\xc2\x3d\x41\x41\x41\x41\x75\xe9\xff\xe6\xe8\xdf\xff\xff\xff\x31\xd2\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xca\x7d\x41\x41\x41\x41\x41\x41\x41\x41'

        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        mu.mem_map(0, 2 * 1024 * 1024)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # handle interrupt ourself
        mu.hook_add(UC_HOOK_INTR, hook_intr)

        # setup stack
        mu.reg_write(UC_X86_REG_RSP, 1024 * 1024)

        # fill in memory with 0xCC (software breakpoint int 3)
        for i in xrange(1 * 1024):
            mu.mem_write(0 + i, b'\xcc')

        # write machine code to be emulated to memory
        mu.mem_write(0, binary1)

        self.assertEqual(mu.emu_start(0, len(binary1)), None)

if __name__ == '__main__':
    regress.main()
