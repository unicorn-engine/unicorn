#!/usr/bin/env python

"""See https://github.com/unicorn-engine/unicorn/issues/98"""

import regress

from unicorn import *

ADDR = 0xffaabbcc


def hook_mem_invalid(mu, access, address, size, value, user_data):
    regress.logger.debug(">>> Access type: %u, expected value: 0x%x, actual value: 0x%x", access, ADDR, address)

    assert(address == ADDR)

    mu.mem_map(address & 0xfffff000, 4 * 1024)
    mu.mem_write(address, b'\xcc')

    return True


class RegWriteSignExt(regress.RegressTest):

    def runTest(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu.reg_write(x86_const.UC_X86_REG_EBX, ADDR)

        mu.mem_map(0x10000000, 1024 * 4)
        # jmp ebx
        mu.mem_write(0x10000000, b'\xff\xe3')

        mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT, hook_mem_invalid)
        mu.emu_start(0x10000000, 0x10000000 + 2, count=1)


if __name__ == '__main__':
    regress.main()
