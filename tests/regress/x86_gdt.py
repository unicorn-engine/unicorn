#!/usr/bin/env python
from unicorn import *
from unicorn.x86_const import *
from struct import pack

import regress

F_GRANULARITY = 0x8
F_PROT_32 = 0x4
F_LONG = 0x2
F_AVAILABLE = 0x1 

A_PRESENT = 0x80

A_PRIV_3 = 0x60
A_PRIV_2 = 0x40
A_PRIV_1 = 0x20
A_PRIV_0 = 0x0

A_CODE = 0x10
A_DATA = 0x10
A_TSS = 0x0
A_GATE = 0x0

A_DATA_WRITABLE = 0x2
A_CODE_READABLE = 0x2

A_DIR_CON_BIT = 0x4

S_GDT = 0x0
S_LDT = 0x4
S_PRIV_3 = 0x3
S_PRIV_2 = 0x2
S_PRIV_1 = 0x1
S_PRIV_0 = 0x0

CODE = '65330d18000000'.decode('hex') # xor ecx, dword ptr gs:[0x18]

def create_selector(idx, flags):
    to_ret = flags
    to_ret |= idx << 3
    return to_ret

def create_gdt_entry(base, limit, access, flags):

    to_ret = limit & 0xffff;
    to_ret |= (base & 0xffffff) << 16;
    to_ret |= (access & 0xff) << 40;
    to_ret |= ((limit >> 16) & 0xf) << 48;
    to_ret |= (flags & 0xff) << 52;
    to_ret |= ((base >> 24) & 0xff) << 56;
    return pack('<Q',to_ret)

def hook_mem_read(uc, type, addr,*args):
    print(hex(addr))
    return False

CODE_ADDR = 0x40000
CODE_SIZE = 0x1000

GDT_ADDR = 0x3000
GDT_LIMIT = 0x1000
GDT_ENTRY_SIZE = 0x8

SEGMENT_ADDR = 0x5000
SEGMENT_SIZE = 0x1000

class GdtRead(regress.RegressTest):

    def test_gdt(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read)

        uc.mem_map(GDT_ADDR, GDT_LIMIT)
        uc.mem_map(SEGMENT_ADDR, SEGMENT_SIZE)
        uc.mem_map(CODE_ADDR, CODE_SIZE)

        uc.mem_write(CODE_ADDR, CODE)
        uc.mem_write(SEGMENT_ADDR+0x18, 'AAAA')

        gdt_entry = create_gdt_entry(SEGMENT_ADDR, SEGMENT_SIZE, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)
        uc.mem_write(GDT_ADDR + 8, gdt_entry)

        uc.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, GDT_LIMIT, 0x0))

        selector = create_selector(1, S_GDT | S_PRIV_3)
        uc.reg_write(UC_X86_REG_GS, selector)

        uc.emu_start(CODE_ADDR, CODE_ADDR+len(CODE))

        self.assertEqual(uc.reg_read(UC_X86_REG_ECX), 0x41414141)

if __name__ == '__main__':
    regress.main()
