#!/usr/bin/python

import binascii
import regress

from unicorn import *
from unicorn.x86_const import *


CODE = binascii.unhexlify((
    "8B 74 01 28"       # mov esi, dword ptr [ecx + eax + 0x28]  mapped: 0x1000
    "03 F0"             # add esi, eax                                   0x1004
    "8D 45 FC"          # lea eax, dword ptr [ebp - 4]                   0x1006
    "50"                # push eax                                       0x1009
    "6A 40"             # push 0x40                                      0x100A
    "6A 10"             # push 0x10                                      0x100C
    "56"                # push esi                                       0x100E
).replace(' ', ''))

BASE = 0x1000
STACK = 0x4000


class HookCodeStopEmuTest(regress.RegressTest):
    def test_hook_code_stop_emu(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # base of CODE
        mu.mem_map(BASE, 0x1000)
        mu.mem_write(BASE, CODE)

        # base of STACK
        mu.mem_map(STACK, 0x1000)
        mu.mem_write(STACK, b"\x00" * 0x1000)

        mu.reg_write(UC_X86_REG_EIP, BASE)
        mu.reg_write(UC_X86_REG_ESP, STACK + 0x1000 - 8)
        mu.reg_write(UC_X86_REG_EBP, STACK + 0x1000 - 8)
        mu.reg_write(UC_X86_REG_ECX, 0x0)
        mu.reg_write(UC_X86_REG_EAX, 0x0)

        # we only expect the following instruction to execute,
        #  and it will fail, because it accesses unmapped memory.
        # mov esi, dword ptr [ecx + eax + 0x28]    mapped: 0x1000

        with self.assertRaises(UcError) as ex:
            mu.emu_start(BASE, BASE + len(CODE), count=1)

        self.assertEqual(UC_ERR_READ_UNMAPPED, ex.exception.errno)

        regress.logger.debug("pc: %#x", mu.reg_read(UC_X86_REG_EIP))

        # now, we want to reuse the emulator, and keep executing
        #  from the next instruction

        # we expect the following instructions to execute
        #   add esi, eax                                   0x1004
        #   lea eax, dword ptr [ebp - 4]                   0x1006
        #   push eax                                       0x1009
        #   push 0x40                                      0x100A
        #   push 0x10                                      0x100C
        #   push esi                                       0x100E
        mu.emu_start(BASE + 0x4, BASE + len(CODE))

        regress.logger.debug("pc: %#x", mu.reg_read(UC_X86_REG_EIP))


if __name__ == '__main__':
    regress.main()
