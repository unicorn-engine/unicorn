#!/usr/bin/env python

"""https://github.com/unicorn-engine/unicorn/issues/165"""

import unicorn

def hook_mem_read_unmapped(mu, access, address, size, value, user_data):
    pass

mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)

try:
    for x in range(0, 1000):
        mu.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read_unmapped, None)
except unicorn.UcError as e:
    print("ERROR: %s" % e)
