#!/usr/bin/python

from __future__ import print_function
import binascii
import regress

from unicorn import *
from unicorn.x86_const import *


CODE = binascii.unhexlify(b"".join([
    b"8B 74 01 28",       # mov esi, dword ptr [ecx + eax + 0x28]  mapped: 0x1000
    b"03 F0",             # add esi, eax                                   0x1004
    b"8D 45 FC",          # lea eax, dword ptr [ebp - 4]                   0x1006
    b"50",                # push eax                                       0x1009
    b"6A 40",             # push 0x40                                      0x100A
    b"6A 10",             # push 0x10                                      0x100C
    b"56",                # push esi                                       0x100E
    b"FF 15 20 20 00 10"  # call some address                              0x100F
  ]).replace(" ", ""))


def showpc(mu):
    pc = mu.reg_read(UC_X86_REG_EIP)
    print("pc: 0x%x" % (pc))


class HookCodeStopEmuTest(regress.RegressTest):
    def test_hook_code_stop_emu(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # base of CODE
        mu.mem_map(0x1000, 0x1000)
        mu.mem_write(0x1000, CODE)
        mu.reg_write(UC_X86_REG_EIP, 0x1000)

        # base of STACK
        mu.mem_map(0x4000, 0x4000)
        mu.mem_write(0x4000, "\x00" * 0x4000)
        mu.reg_write(UC_X86_REG_ESP, 0x6000)
        mu.reg_write(UC_X86_REG_EBP, 0x6000)

        mu.reg_write(UC_X86_REG_ECX, 0x0)
        mu.reg_write(UC_X86_REG_EAX, 0x0)

        def _hook(_, access, address, length, value, context):
            pc = mu.reg_read(UC_X86_REG_EIP)
            print("mem unmapped: pc: %x access: %x address: %x length: %x value: %x" % (
                pc, access, address, length, value))
            mu.emu_stop()
            return True

        mu.hook_add(UC_HOOK_MEM_UNMAPPED, _hook)

        # we only expect the following instruction to execute,
        #  and it will fail, because it accesses unmapped memory.
        # mov esi, dword ptr [ecx + eax + 0x28]    mapped: 0x1000
        mu.emu_start(0x1000, 0x100F)
        showpc(mu)

        # now, we want to reuse the emulator, and keep executing
        #  from the next instruction
        mu.reg_write(UC_X86_REG_EIP, 0x1004)
        self.assertEqual(0x1004, mu.reg_read(UC_X86_REG_EIP))

        # we expect the following instructions to execute
        #   add esi, eax                                   0x1004
        #   lea eax, dword ptr [ebp - 4]                   0x1006
        #   push eax                                       0x1009
        #   push 0x40                                      0x100A
        #   push 0x10                                      0x100C
        #   push esi                                       0x100E
        #
        # currently, a UC_ERR_READ_UNMAPPED exception is raised here
        mu.emu_start(0x1004, 0x100F)
        showpc(mu)


if __name__ == '__main__':
    regress.main()
