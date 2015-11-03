#!/usr/bin/env python

import platform
import resource

from unicorn import *

import regress

# OS X: OK with 2047 iterations.
# OS X: Crashes at 2048:th iteration ("qemu: qemu_thread_create: Resource temporarily unavailable").
# Linux: No crashes observed.
class ThreadCreateCrash(regress.RegressTest):
    def test(self):
        for i in xrange(2048):
            Uc(UC_ARCH_X86, UC_MODE_64)
        self.assertTrue(True, "If not reached, then we have a crashing bug.")

if __name__ == '__main__':
    regress.main()
