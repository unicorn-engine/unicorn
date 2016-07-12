#!/usr/bin/python
# By Mariano Graziano

from unicorn import *
from unicorn.x86_const import *

import regress, struct


class Emulator:
    def __init__(self, code, stack):
        self.mask = 0xFFFFFFFFFFFFF000
        self.unicorn_code = code
        self.unicorn_stack = stack
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        size = 1 * 4096
        self.mu.mem_map(code & self.mask, size)
        size = 1 * 4096
        self.mu.mem_map(stack & self.mask, size)
        self.set_hooks()

    def set_hooks(self):
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self.hook_mem_access)
        self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_mem_invalid)
        self.mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self.hook_mem_fetch_unmapped)

    def hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        next_ip = self.unicorn_code + size
        self.mu.reg_write(UC_X86_REG_RIP, next_ip)
        self.mu.mem_write(next_ip, "\x90")
        self.mu.reg_write(UC_X86_REG_RIP, address) 
        return True

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        return True
    
    def hook_mem_access(self, uc, access, address, size, value, user_data):
        return True

    def emu(self, size):
        ip = self.mu.reg_read(UC_X86_REG_RIP)
        try:
            self.mu.emu_start(ip, ip + size, timeout=10000, count=1)
        except UcError as e:
            print("Error %s" % e)

    def write_data(self, address, content):
        self.mu.mem_write(address, content)


class Init(regress.RegressTest):
    def init_unicorn(self, ip, sp, counter):
        #print "[+] Emulating IP: %x SP: %x - Counter: %x" % (ip, sp, counter)
        E = Emulator(ip, sp)
        E.write_data(ip, "\x90")
        E.write_data(sp, self.generate_value(counter))
        E.mu.reg_write(UC_X86_REG_RSP, sp)
        E.mu.reg_write(UC_X86_REG_RIP, ip)
        E.emu(1)
   
    def generate_value(self, counter):
        start = 0xffff880026f02000
        offset = counter * 8
        address = start + offset
        return struct.pack("<Q", address)
 
    def runTest(self):
        global mu
        ips = list(range(0xffffffff816a9000, 0xffffffff816af000, 0x1))
        sps = list(range(0xffff88001b800000, 0xffff88001b801000, 0x1))
        j = 0
        for i in ips:
            j += 1
            index = ips.index(i)
            self.init_unicorn(i, sps[index], j)

if __name__ == '__main__':
    regress.main()
