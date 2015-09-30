#!/usr/bin/env python

"""See https://github.com/unicorn-engine/unicorn/issues/98"""

import unicorn
import regress

ADDR = 0xffaabbcc

def hook_mem_invalid(mu, access, address, size, value, user_data):
    print ">>> Access type: %u, expected value: 0x%x, actual value: 0x%x" % (access, ADDR, address)
    assert(address == ADDR)
    mu.mem_map(address & 0xfffff000, 4 * 1024)
    mu.mem_write(address, b'\xcc')
    return True

class RegWriteSignExt(regress.RegressTest):

    def runTest(self):
        mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        mu.reg_write(unicorn.x86_const.UC_X86_REG_EBX, ADDR)

        mu.mem_map(0x10000000, 1024 * 4)
        # jmp ebx
        mu.mem_write(0x10000000, b'\xff\xe3')

        mu.hook_add(unicorn.UC_HOOK_MEM_FETCH_UNMAPPED | unicorn.UC_HOOK_MEM_FETCH_PROT, hook_mem_invalid)
        mu.emu_start(0x10000000, 0x10000000 + 2, count=1)

if __name__ == '__main__':
    regress.main()
