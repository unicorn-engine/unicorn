import gc
import regress
import weakref
from unicorn import *
from unicorn.x86_const import *

ADDRESS = 0x8048000
STACK_ADDRESS = 0xffff000
STACK_SIZE = 0x1000

CODE = (
    b"\x31\xDB"     #  xor      ebx, ebx
    b"\x53"         #  push     ebx
    b"\x43"         #  inc      ebx
    b"\x53"         #  push     ebx
    b"\x6A\x02"     #  push     2
    b"\x6A\x66"     #  push     66h
    b"\x58"         #  pop      eax
    b"\x89\xE1"     #  mov      ecx, esp
    b"\xCD\x80"     #  int      80h
)

EP = ADDRESS + 0x54

# Dictionary to keep weak references to instances
instances = weakref.WeakValueDictionary()


def create_instance(key, *args, **kwargs):
    obj = Uc(*args, **kwargs)
    instances[key] = obj

    return obj


def hook_code(mu, address, size, user_data):
    regress.logger.debug(">>> Tracing instruction at %#x, instruction size = %u", address, size)


def emu_loop(key):
    emu = create_instance(key, UC_ARCH_X86, UC_MODE_32)
    emu.mem_map(ADDRESS, 0x1000)
    emu.mem_write(EP, CODE)

    emu.mem_map(STACK_ADDRESS, STACK_SIZE)
    emu.reg_write(UC_X86_REG_ESP, STACK_ADDRESS + STACK_SIZE)

    i = emu.hook_add(UC_HOOK_CODE, hook_code, None)
    emu.hook_del(i)

    emu.emu_start(EP, EP + len(CODE), count=3)
    regress.logger.debug("EIP: %#x", emu.reg_read(UC_X86_REG_EIP))



class EmuLoopReferenceTest(regress.RegressTest):
    def debug_mem(self):
        gc.collect()  # don't care about stuff that would be garbage collected properly

        self.assertEqual(len(instances), 0)

    def runTest(self):
        for i in range(5):
            emu_loop('obj%d' % i)

        self.debug_mem()


if __name__ == '__main__':
    regress.main()
