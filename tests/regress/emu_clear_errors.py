import regress
from unicorn import *
from unicorn.x86_const import *

CODE = (
    b'\x8B\x74\x01\x28'  # mov esi, dword ptr [ecx + eax + 0x28]  mapped: 0x1000
    b'\x03\xF0'          # add esi, eax                                   0x1004
    b'\x8D\x45\xFC'      # lea eax, dword ptr [ebp - 4]                   0x1006
    b'\x50'              # push eax                                       0x1009
    b'\x6A\x40'          # push 0x40                                      0x100A
    b'\x6A\x10'          # push 0x10                                      0x100C
    b'\x56'              # push esi                                       0x100E
)
BASE = 0x1000
STACK = 0x4000


class EmuClearErrorsTest(regress.RegressTest):

    def test_hook_code_stop_emu(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # base of CODE
        mu.mem_map(BASE, 0x1000)
        mu.mem_write(BASE, CODE)

        # base of STACK
        mu.mem_map(STACK, 0x1000)
        mu.mem_write(STACK, b"\x00" * 0x1000)

        mu.reg_write(UC_X86_REG_EIP, BASE)
        mu.reg_write(UC_X86_REG_ESP, STACK + 0x1000 - 8)
        mu.reg_write(UC_X86_REG_EBP, STACK + 0x1000 - 8)
        mu.reg_write(UC_X86_REG_ECX, 0x0)
        mu.reg_write(UC_X86_REG_EAX, 0x0)

        # we only expect the following instruction to execute,
        #  and it will fail, because it accesses unmapped memory.
        # mov esi, dword ptr [ecx + eax + 0x28]    mapped: 0x1000

        with self.assertRaises(UcError) as ex:
            mu.emu_start(BASE, BASE + len(CODE), count=1)

        self.assertEqual(UC_ERR_READ_UNMAPPED, ex.exception.errno)

        regress.logger.debug("pc: %#x", mu.reg_read(UC_X86_REG_EIP))

        # now, we want to reuse the emulator, and keep executing
        #  from the next instruction

        # we expect the following instructions to execute
        #   add esi, eax                                   0x1004
        #   lea eax, dword ptr [ebp - 4]                   0x1006
        #   push eax                                       0x1009
        #   push 0x40                                      0x100A
        #   push 0x10                                      0x100C
        #   push esi                                       0x100E
        mu.emu_start(BASE + 0x4, BASE + len(CODE))

        regress.logger.debug("pc: %#x", mu.reg_read(UC_X86_REG_EIP))


if __name__ == '__main__':
    regress.main()
