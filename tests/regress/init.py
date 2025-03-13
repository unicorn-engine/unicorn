# By Mariano Graziano

import platform
import regress
import struct
import sys
import unittest
from unicorn import *
from unicorn.x86_const import *


class Init(regress.RegressTest):

    def init_unicorn(self, ip, sp, counter):
        regress.logger.debug("[+] Emulating IP: %x SP: %x - Counter: %x" % (ip, sp, counter))
        self.emulator = Uc(UC_ARCH_X86, UC_MODE_64)
        self.emulator.ctl_set_tlb_mode(UC_TLB_VIRTUAL)
        self.emulator.mem_map(0x1000000, 2 * 1024 * 1024)
        self.emulator.mem_write(0x1000000, b"\x90")
        self.emulator.mem_map(0x8000000, 8 * 1024 * 1024)
        self.emulator.reg_write(UC_X86_REG_RSP, sp)
        content = self.generate_value(counter)
        self.emulator.mem_write(sp, content)
        self.set_hooks()

    def generate_value(self, counter):
        start = 0xffff880026f02000
        offset = counter * 8
        address = start + offset
        return struct.pack("<Q", address)

    def set_hooks(self):
        self.emulator.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_mem_invalid)
        self.emulator.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self.hook_mem_fetch_unmapped)

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        regress.logger.debug("[ HOOK_MEM_INVALID - Address: 0x%x ]", address)

        if access == UC_MEM_WRITE_UNMAPPED:
            regress.logger.debug(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x",
                                 address, size, value)

            address_page = address & 0xFFFFFFFFFFFFF000
            uc.mem_map(address_page, 2 * 1024 * 1024)
            uc.mem_write(address, str(value))

            return True
        return False

    def hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        regress.logger.debug("[ HOOK_MEM_FETCH - Address: 0x%x ]", address)
        regress.logger.debug("[ mem_fetch_unmapped: faulting address at 0x%x ]", address)

        uc.mem_write(0x1000003, b"\x90")
        uc.reg_write(UC_X86_REG_RIP, 0x1000001)
        return True

    @unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
    @unittest.skipIf(sys.platform == 'win32', 'TO BE CHECKED!')
    def runTest(self):
        ips = range(0x1000000, 0x1001000)
        sps = range(0x8000000, 0x8001000)

        for i, (ip, sp) in enumerate(zip(ips, sps)):
            self.init_unicorn(ip, sp, i)

            self.emulator.emu_start(0x1000000, 0x1000000 + 0x1)


if __name__ == '__main__':
    regress.main()
