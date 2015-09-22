#!/usr/bin/python

from unicorn import *
from unicorn.x86_const import *

import regress

binary1 = b'\xb8\x02\x00\x00\x00'    # mov eax, 2
binary2 = b'\xb8\x01\x00\x00\x00'    # mov eax, 1

class WrongRIP(regress.RegressTest):

    def test_step(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(0, 2 * 1024 * 1024)
        # write machine code to be emulated to memory
        mu.mem_write(0, binary1 + binary2)
        # emu for maximum 1 instruction.
        mu.emu_start(0, 5, 0, 1)

        self.assertEqual(0x2, mu.reg_read(UC_X86_REG_RAX))
        self.assertEqual(0x5, mu.reg_read(UC_X86_REG_RIP))

        mu.emu_start(5, 10, 0, 1)
        self.assertEqual(0xa, mu.reg_read(UC_X86_REG_RIP))
        self.assertEqual(0x1, mu.reg_read(UC_X86_REG_RAX))

    def test_step2(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(0, 2 * 1024 * 1024)
        # write machine code to be emulated to memory
        mu.mem_write(0, binary1 + binary2)
        # emu for maximum 1 instruction.
        mu.emu_start(0, 10, 0, 1)
        self.assertEqual(0x2, mu.reg_read(UC_X86_REG_RAX))
        self.assertEqual(0x5, mu.reg_read(UC_X86_REG_RIP))

        mu.emu_start(5, 10, 0, 1)
        self.assertEqual(0x1, mu.reg_read(UC_X86_REG_RAX))
        self.assertEqual(0xa, mu.reg_read(UC_X86_REG_RIP))

    def test_step3(self):
        bin3 = b'\x40\x01\xc1\x31\xf6' # inc eax; add ecx, eax; xor esi, esi
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu.mem_map(0, 2 * 1024 * 1024)
        # write machine code to be emulated to memory
        mu.mem_write(0, bin3)
        # emu for maximum 1 instruction.
        mu.emu_start(0, 10, 0, 1)
        self.assertEqual(0x1, mu.reg_read(UC_X86_REG_EAX))
        self.assertEqual(0x1, mu.reg_read(UC_X86_REG_EIP))

    def test_step_then_fin(self):
        bin4 = b'\x40\x01\xc1\x31\xf6\x90\x90\x90' # inc eax; add ecx, eax; xor esi, esi
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu.mem_map(0, 2 * 1024 * 1024)
        # write machine code to be emulated to memory
        mu.mem_write(0, bin4)
        # emu for maximum 1 instruction.
        mu.emu_start(0, len(binary1), 0, 1)

        self.assertEqual(0x1, mu.reg_read(UC_X86_REG_EAX))
        self.assertEqual(0x1, mu.reg_read(UC_X86_REG_EIP))
        # emu to the end
        mu.emu_start(1, len(bin4))
        self.assertEqual(0x1, mu.reg_read(UC_X86_REG_EAX))
        self.assertEqual(len(bin4), mu.reg_read(UC_X86_REG_EIP))

if __name__ == '__main__':
    regress.main()

