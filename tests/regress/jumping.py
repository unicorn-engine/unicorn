#!/usr/bin/env python
# Mariano Graziano

import binascii
import regress

from unicorn import *
from unicorn.x86_const import *


# set rdx to either 0xbabe or 0xc0ca, based on a comparison.
# rdx would never be set to 0xbabe unless we set zf to 1
CODE = (
    b"\x48\x31\xc0"                                 #       xor       rax, rax
    b"\x48\xb8\x04\x00\x00\x00\x00\x00\x00\x00"     #  03:  movabs    rax, 0x4
    b"\x48\x3d\x05\x00\x00\x00"                     #  0d:  cmp       rax, 0x5      <-- never true, zf is cleared
    b"\x74\x05"                                     #  13:  je        0x1a
    b"\xe9\x0f\x00\x00\x00"                         #       jmp       0x29
    b"\x48\xba\xbe\xba\x00\x00\x00\x00\x00\x00"     #  1a:  movabs    rdx, 0xbabe   <-- never reached unless we set zf
    b"\xe9\x0f\x00\x00\x00"                         #       jmp       0x38
    b"\x48\xba\xca\xc0\x00\x00\x00\x00\x00\x00"     #  29:  movabs    rdx, 0xc0ca
    b"\xe9\x00\x00\x00\x00"                         #       jmp       0x38
    b"\xf4"                                         #  38:  hlt
)

BASE = 0x1000000


class Jumping(regress.RegressTest):
    def clear_zf(self):
        eflags = self.uc.reg_read(UC_X86_REG_EFLAGS)

        if (eflags >> 6) & 0b1 == 0b1:
            eflags &= ~(0b1 << 6)

            regress.logger.debug("[clear_zf] clearing zero flag")
            self.uc.reg_write(UC_X86_REG_EFLAGS, eflags)

        else:
            regress.logger.debug("[clear_zf] no change needed")

    def set_zf(self):
        eflags = self.uc.reg_read(UC_X86_REG_EFLAGS)

        if (eflags >> 6) & 0b1 == 0b0:
            eflags |= (0b1 << 6)

            regress.logger.debug("[set_zf] setting zero flag")
            self.uc.reg_write(UC_X86_REG_EFLAGS, eflags)

        else:
            regress.logger.debug("[set_zf] no change needed")

    def multipath(self):
        regress.logger.debug("[multipath] - handling ZF (%s) - default", self.fixed_zf)

        if self.fixed_zf:
            self.set_zf()
        else:
            self.clear_zf()

        # BUG: eflags changes do not get reflected unless re-writing eip

    # callback for tracing basic blocks
    def hook_block(self, uc, address, size, _):
        regress.logger.debug("Reached a new basic block at %#x (%d bytes in size)", address, size)

    # callback for tracing instructions
    def hook_code(self, uc, address, size, _):
        insn = uc.mem_read(address, size)
        regress.logger.debug(">>> Tracing instruction at %#x : %s", address, binascii.hexlify(insn))

        regs = uc.reg_read_batch((
            UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
            UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
            UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
            UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
            UC_X86_REG_EFLAGS
        ))

        zf = (regs[16] >> 6) & 0b1

        regress.logger.debug("    RAX = %08x, R8  = %08x", regs[0], regs[ 8])
        regress.logger.debug("    RBX = %08x, R9  = %08x", regs[1], regs[ 9])
        regress.logger.debug("    RCX = %08x, R10 = %08x", regs[2], regs[10])
        regress.logger.debug("    RDX = %08x, R11 = %08x", regs[3], regs[11])
        regress.logger.debug("    RSI = %08x, R12 = %08x", regs[4], regs[12])
        regress.logger.debug("    RDI = %08x, R13 = %08x", regs[5], regs[13])
        regress.logger.debug("    RBP = %08x, R14 = %08x", regs[6], regs[14])
        regress.logger.debug("    RSP = %08x, R15 = %08x", regs[7], regs[15])
        regress.logger.debug("    EFLAGS = %08x (ZF = %d)", regs[16], zf)

        regress.logger.debug("-" * 32)
        self.multipath()
        regress.logger.debug("-" * 32)


    def setUp(self):
        # decide how to fixate zf value: 0 to clear, 1 to set
        self.fixed_zf = 1

        # Initialize emulator in X86-64bit mode
        uc = Uc(UC_ARCH_X86, UC_MODE_64)

        # map one page for this emulation
        uc.mem_map(BASE, 0x1000)

        # write machine code to be emulated to memory
        uc.mem_write(BASE, CODE)

        self.uc = uc

    def runTest(self):
        # tracing all basic blocks with customized callback
        self.uc.hook_add(UC_HOOK_BLOCK, self.hook_block)

        # tracing all instructions in range [ADDRESS, ADDRESS+0x60]
        self.uc.hook_add(UC_HOOK_CODE, self.hook_code, begin=BASE, end=BASE + 0x60)

        # emulate machine code in infinite time
        self.uc.emu_start(BASE, BASE + len(CODE))

        self.assertEqual(self.uc.reg_read(UC_X86_REG_RDX), 0xbabe, "rdx contains the wrong value. eflags modification failed")


if __name__ == '__main__':
    regress.main()
