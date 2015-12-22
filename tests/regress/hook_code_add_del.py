#!/usr/bin/python

'''https://github.com/unicorn-engine/unicorn/issues/334'''

from __future__ import print_function
import regress

from unicorn import *
from unicorn.x86_const import *

ADDRESS = 0x8048000
STACK_ADDRESS = 0xffff000
STACK_SIZE = 4096
'''
31 DB           xor ebx, ebx
53              push ebx
43              inc ebx
53              push ebx
6A 02           push 2
6A 66           push 66h
58              pop eax
89 E1           mov ecx, esp
CD 80           int 80h
'''
CODE = "\x31\xDB\x53\x43\x53\x6A\x02\x6A\x66\x58\x89\xE1\xCD\x80"
EP = ADDRESS + 0x54

def hook_code(mu, address, size, user_data):
        print(">>> Tracing instruction at 0x%x, instruction size = %u" %(address, size))
        
class HookCodeAddDelTest(regress.RegressTest):
        def runTest(self):
                emu = Uc(UC_ARCH_X86, UC_MODE_32)
                emu.mem_map(ADDRESS, 0x1000)
                emu.mem_write(EP, CODE)

                emu.mem_map(STACK_ADDRESS, STACK_SIZE)
                emu.reg_write(UC_X86_REG_ESP, STACK_ADDRESS + STACK_SIZE)
                
                # UC_HOOK_CODE hook will work even after deletion
                i = emu.hook_add(UC_HOOK_CODE, hook_code, None)
                emu.hook_del(i)
                
                emu.emu_start(EP, EP + len(CODE), count = 3)
                print("EIP: 0x%x" % emu.reg_read(UC_X86_REG_EIP))
                
if __name__ == '__main__':
        regress.main()
