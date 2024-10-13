#!/usr/bin/python
# By Mariano Graziano

import regress
import struct
import sys

from unicorn import *
from unicorn.x86_const import *


if sys.version_info.major == 2:
    range = xrange


mu = 0

class Init(regress.RegressTest):

    def init_unicorn(self, ip, sp, counter):
        global mu
        #print "[+] Emulating IP: %x SP: %x - Counter: %x" % (ip, sp, counter)
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(0x1000000, 2 * 1024 * 1024)
        mu.mem_write(0x1000000, b"\x90")
        mu.mem_map(0x8000000, 8 * 1024 * 1024)
        mu.reg_write(UC_X86_REG_RSP, sp)
        content = self.generate_value(counter)
        mu.mem_write(sp, content)
        self.set_hooks()

    def generate_value(self, counter):
        start = 0xffff880026f02000
        offset = counter * 8
        address = start + offset
        return struct.pack("<Q", address)

    def set_hooks(self):
        global mu
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_mem_invalid)
        mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self.hook_mem_fetch_unmapped)

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        global mu

        regress.logger.debug("[ HOOK_MEM_INVALID - Address: 0x%x ]", address)

        if access == UC_MEM_WRITE_UNMAPPED:
            regress.logger.debug(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x", address, size, value)

            address_page = address & 0xFFFFFFFFFFFFF000
            mu.mem_map(address_page, 2 * 1024 * 1024)
            mu.mem_write(address, str(value))

            return True
        else:
            return False

    def hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        global mu

        regress.logger.debug("[ HOOK_MEM_FETCH - Address: 0x%x ]", address)
        regress.logger.debug("[ mem_fetch_unmapped: faulting address at 0x%x ]", address)

        mu.mem_write(0x1000003, b"\x90") 
        mu.reg_write(UC_X86_REG_RIP, 0x1000001)
        return True

    def runTest(self):
        global mu

        ips = range(0x1000000, 0x1001000)
        sps = range(0x8000000, 0x8001000)

        for i, (ip, sp) in enumerate(zip(ips, sps)):
            self.init_unicorn(ip, sp, i)

            mu.emu_start(0x1000000, 0x1000000 + 0x1)


if __name__ == '__main__':
    regress.main()
