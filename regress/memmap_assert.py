#!/usr/bin/env python

import unicorn

u = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
u.mem_map(0x2000, 0)
u.mem_map(0x4000, 1)
print "I am never reached"
