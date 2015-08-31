#!/usr/bin/env python

"""See https://github.com/unicorn-engine/unicorn/issues/82"""

import unicorn
CODE_ADDR = 0x10101000
CODE = b'\xff\xe3'
mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
mu.mem_map(CODE_ADDR, 1024 * 4)
mu.mem_write(CODE_ADDR, CODE)
# If EBX is zero then an exception is raised, as expected
mu.reg_write(unicorn.x86_const.UC_X86_REG_EBX, 0x0)

try:
    mu.emu_start(CODE_ADDR, CODE_ADDR + 2, count=1)
except unicorn.UcError as e:
    assert(e.errno == unicorn.UC_ERR_CODE_INVALID)
else:
    assert(False)

mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
mu.mem_map(CODE_ADDR, 1024 * 4)
# If we write this address to EBX then the emulator hangs on emu_start
mu.reg_write(unicorn.x86_const.UC_X86_REG_EBX, 0xaa96a47f)
mu.mem_write(CODE_ADDR, CODE)
try:
    mu.emu_start(CODE_ADDR, CODE_ADDR + 2, count=1)
except unicorn.UcError as e:
    assert(e.errno == unicorn.UC_ERR_CODE_INVALID)
else:
    assert(False)

print "Success"
