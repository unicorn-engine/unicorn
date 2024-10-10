#!/usr/bin/env python

"""https://github.com/unicorn-engine/unicorn/issues/165"""

import regress

from unicorn import *


def hook_mem_read_unmapped(mu, access, address, size, value, user_data):
    pass

class TestHook(regress.RegressTest):
    def test_excessive_hooks(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        for _ in range(1337):
            mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read_unmapped)


if __name__ == '__main__':
    regress.main()
