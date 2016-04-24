#!/usr/bin/env python

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *

import regress

X86_CODE64 = "\x90" # NOP


class WriteBeforeMap(regress.RegressTest):
    def runTest(self):
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # memory address where emulation starts
        ADDRESS = 0x1000000

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE64)


if __name__ == '__main__':
    regress.main()
