"""See https://github.com/unicorn-engine/unicorn/issues/65"""

import unicorn
ADDR = 0x10101000
mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
mu.mem_map(ADDR, 1024 * 4)
mu.mem_write(ADDR, b'\x41')
mu.emu_start(ADDR, ADDR + 1, count=1)
# The following should not trigger a null pointer dereference
mu.emu_stop()

