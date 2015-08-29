#!/usr/bin/env python

import unicorn

for i in range(20):
    #try:
    u = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    u.mem_map(i*0x1000, 5)
    u.mem_read(i*0x1000+6, 1)
    print hex(i*0x1000) + " succeeeded"
    #except unicorn.UcError as e:
    #   print hex(i*0x1000) + " failed:",e
