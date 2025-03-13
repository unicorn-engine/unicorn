# By Mariano Graziano

import regress
import struct
import sys
import unittest
from unicorn import *
from unicorn.x86_const import *


class Emulator:
    def __init__(self, code, stack):
        def __page_aligned(address):
            return address & ~(0x1000 - 1)

        self.unicorn_code = code
        self.unicorn_stack = stack

        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.mu.ctl_set_tlb_mode(UC_TLB_VIRTUAL)

        regress.logger.debug("mapping code  : %#x", __page_aligned(code))
        regress.logger.debug("mapping stack : %#x", __page_aligned(stack))

        self.mu.mem_map(__page_aligned(code), 0x1000)
        self.mu.mem_map(__page_aligned(stack), 0x1000)

        self.mu.reg_write(UC_X86_REG_RSP, stack)
        self.mu.reg_write(UC_X86_REG_RIP, code)

        self.set_hooks()

    def set_hooks(self):
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self.hook_mem_access)
        self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_mem_invalid)
        self.mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self.hook_mem_fetch_unmapped)

    def hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        next_ip = self.unicorn_code + size

        self.write_reg(UC_X86_REG_RIP, next_ip)
        self.write_data(next_ip, b"\x90")
        # self.write_reg(UC_X86_REG_RIP, address)  # ???

        return True

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        regress.logger.debug("invalid mem access: access type = %d, to = %#x, size = %u, value = %#x", access, address,
                             size, value)

        return True

    def hook_mem_access(self, uc, access, address, size, value, user_data):
        return True

    def emu(self, steps):
        ip = self.mu.reg_read(UC_X86_REG_RIP)
        max_intel_insn_size = 15

        regress.logger.debug("starting at   : %#x", ip)
        self.mu.emu_start(ip, ip + max_intel_insn_size, count=steps)

    def write_data(self, address, content):
        self.mu.mem_write(address, content)

    def write_reg(self, reg, value):
        self.mu.reg_write(reg, value)


class TranslatorBuffer(regress.RegressTest):
    def init_unicorn(self, ip, sp, magic):
        emu = Emulator(ip, sp)

        emu.write_data(ip, b"\xf4" * 8)
        emu.write_data(sp, struct.pack("<Q", magic))

        emu.emu(1)

    @unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
    def runTest(self):
        ip_base = 0x000fffff816a0000  # was: 0xffffffff816a0000
        sp_base = 0x000f88001b800000  # was: 0xffff88001b800000
        mg_base = 0x000f880026f02000  # was: 0xffff880026f02000

        ips = range(0x9000, 0xf000, 8)
        sps = range(0x0000, 0x6000, 8)

        for i, (ip, sp) in enumerate(zip(ips, sps)):
            self.init_unicorn(ip_base + ip, sp_base + sp, mg_base + i * 8)


if __name__ == '__main__':
    regress.main()
