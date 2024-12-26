import regress
from unicorn import *
from unicorn.x86_const import *
from capstone import *

CODE = (
    b'\x48\x31\xc0'      # xor       rax,rax
    b'\x48\x0f\xc7\xf0'  # rdrand    rax
    b'\xf4'              # hlt
)

BASE = 0x100000
PAGE_SIZE = 0x1000

# max possible length of a x86 instruction
MAX_INSN_LEN = 15


def hook_invalid_insn(uc, ud):
    regress.logger.debug('entered invalid instruction handler')

    pc = uc.reg_read(UC_X86_REG_RIP)
    data = uc.mem_read(pc, MAX_INSN_LEN)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    insn = next(md.disasm(data, pc, 1))

    if insn.mnemonic == 'rdrand':
        # chosen by fair dice roll, guaranteed to be random
        rax = 4

        # set result to rax
        uc.reg_write(UC_X86_REG_RAX, rax)

        # resume emulation from next instruction
        uc.reg_write(UC_X86_REG_RIP, pc + insn.size)

        # signal uc we are ok
        return True

    # not handled, uc will crash
    return False


class TestHooks(regress.RegressTest):
    def test_invalid_insn_recover(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        mu.mem_map(BASE, PAGE_SIZE)
        mu.mem_write(BASE, CODE)

        mu.hook_add(UC_HOOK_INSN_INVALID, hook_invalid_insn)

        try:
            mu.emu_start(BASE, BASE + len(CODE))
        except UcError as ex:
            if ex.errno == UC_ERR_INSN_INVALID:
                self.fail('invalid instruction did not recover properly')

            # unexpected exception, re-raise
            raise

        self.assertNotEqual(0, mu.reg_read(UC_X86_REG_RAX))


if __name__ == '__main__':
    regress.main()
