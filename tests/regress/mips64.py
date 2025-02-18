import regress
from unicorn import *
from unicorn.mips_const import *

# Two instructions:
#   daddu  $gp, $gp, $ra    # a 64-bit instruction. This is important - it ensures the selected CPU model is 64-bit, otherwise it would crash
#   move   $t1, $v0

code = b"\x03\x9f\xe0\x2d" + b"\x00\x40\x48\x25"

def run():
    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS64 + UC_MODE_BIG_ENDIAN)
    # For MIPS64 to be able to reference addresses >= 0x80000000, you need to enable the virtual TLB
    # See https://github.com/unicorn-engine/unicorn/pull/2111 for more details
    uc.ctl_set_tlb_mode(UC_TLB_VIRTUAL)

    ADDRESS = 0x0120003000

    uc.reg_write(UC_MIPS_REG_PC, ADDRESS)
    uc.reg_write(UC_MIPS_REG_GP, 0x123)
    uc.reg_write(UC_MIPS_REG_RA, 0x456)

    uc.mem_map(ADDRESS, 4 * 1024)
    uc.mem_write(ADDRESS, code)

    # This will raise an exception if MIPS64 fails
    uc.emu_start(ADDRESS, 0, count=2)


class MipsSingleStep(regress.RegressTest):
    def runTest(self):
        run()


if __name__ == '__main__':
    regress.main()
