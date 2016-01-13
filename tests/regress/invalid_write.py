#!/usr/bin/env python
# Test callback that returns False to cancel emulation

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *

import regress

X86_CODE32_MEM_WRITE = b"\x89\x0D\xAA\xAA\xAA\xAA\x41\x4a" # mov [0xaaaaaaaa], ecx; INC ecx; DEC edx


# callback for tracing invalid memory access (READ or WRITE)
def hook_mem_invalid(uc, access, address, size, value, user_data):
    return False


class InvalidWrite(regress.RegressTest):
    def test(self):
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # memory address where emulation starts
        ADDRESS = 0x1000000

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE32_MEM_WRITE)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_ECX, 0x1234)
        mu.reg_write(UC_X86_REG_EDX, 0x7890)

        # intercept invalid memory events
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)

        try:
            # emulation should return with error UC_ERR_WRITE_UNMAPPED
            mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32_MEM_WRITE))
        except UcError as e:
            self.assertEqual(e.errno, UC_ERR_WRITE_UNMAPPED)


if __name__ == '__main__':
    regress.main()
