import platform
import regress
import sys
import unittest
from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *

# count down from maxint to zero
_VALID_CODE = (
    b'\x31\xc9'     #           xor     ecx, ecx
    b'\x49'         #  _top:    dec     ecx
    b'\xf3\x90'     #           pause
    b'\xe3\xfb'     #           jecxz   _top
    b'\xf4'         #  _end:    hlt
)

_INVALID_CODE = (
    b'\xff\xff'  # (invalid)
)

CODE = _VALID_CODE + _INVALID_CODE

BASE = 0x100000


class TestCtl(regress.RegressTest):

    def test_mode(self):
        uc = Uc(UC_ARCH_ARM, UC_MODE_BIG_ENDIAN)

        # changing cpu model to one that supports EB
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M0)

        # changing cpu model to one that does not support EB; this is expected to fail
        with self.assertRaises(UcError) as ex:
            uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A8)

        self.assertEqual(UC_ERR_ARG, ex.exception.errno)

        # make sure we stay with the configuration we set beforehand
        self.assertEqual(UC_ARCH_ARM, uc.ctl_get_arch())
        self.assertEqual(UC_MODE_BIG_ENDIAN, uc.ctl_get_mode())
        self.assertEqual(UC_CPU_ARM_CORTEX_M0, uc.ctl_get_cpu_model())

    @unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
    @unittest.skip('TO BE CHECKED!')
    def test_page_size(self):
        SIZE_4KB = 4 * 1024 ** 1
        SIZE_2MB = 2 * 1024 ** 2

        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # set page size to 2 MiB; this should work
        uc.ctl_set_page_size(SIZE_2MB)

        # was it set properly?
        self.assertEqual(SIZE_2MB, uc.ctl_get_page_size())

        # set a page size which is not a power of 2
        with self.assertRaises(UcError) as ex:
            uc.ctl_set_page_size(SIZE_2MB + 0xbad)

        self.assertEqual(UC_ERR_ARG, ex.exception.errno)

        # are we still with the valid value?
        self.assertEqual(SIZE_2MB, uc.ctl_get_page_size())

        # force uc to complete its initialization by triggering a random api
        uc.ctl_flush_tb()

        # set a page size after uc has completed its initialization
        with self.assertRaises(UcError) as ex:
            uc.ctl_set_page_size(SIZE_4KB)

        self.assertEqual(UC_ERR_ARG, ex.exception.errno)

        # are we still with the valid value?
        self.assertEqual(SIZE_2MB, uc.ctl_get_page_size())

    def test_timeout(self):
        MILLIS_1S = 1000

        uc = Uc(UC_ARCH_X86, UC_MODE_32)

        uc.mem_map(BASE, 0x1000)
        uc.mem_write(BASE, CODE)

        # start a long emulation bound by timeout
        uc.emu_start(BASE, BASE + len(CODE), timeout=MILLIS_1S)

        # was timeout set properly? uc returns timeout in nanoseconds
        self.assertEqual(MILLIS_1S * 1000, uc.ctl_get_timeout())

        # no way we made it all the way down to zero
        self.assertNotEqual(0, uc.reg_read(UC_X86_REG_ECX))

    def test_exits(self):
        WRONG_EXIT = BASE + len(CODE)
        GOOD_EXIT = BASE + len(_VALID_CODE)

        uc = Uc(UC_ARCH_X86, UC_MODE_32)

        uc.mem_map(BASE, 0x1000)
        uc.mem_write(BASE, CODE)

        def __hook_code(uc, *args):
            ecx = uc.reg_read(UC_X86_REG_ECX)

            # 16 down to the count
            if ecx == 0xfffffff0:
                # fast-forward the counter and let it run for another 16 iterations
                uc.reg_write(UC_X86_REG_ECX, 0x10)

        uc.hook_add(UC_HOOK_CODE, __hook_code)

        # enable exits
        uc.ctl_exits_enabled(True)

        # fix the exit point so we don't reach invalid code
        uc.ctl_set_exits([GOOD_EXIT])

        # start emulation, setting a wrong stopping point that will get us to invalid code
        # since we enabled exits, the stopping point should be ignored
        uc.emu_start(BASE, WRONG_EXIT, count=1)

        # only one exit point was set
        self.assertEqual(1, uc.ctl_get_exits_cnt())

        # only one exit point, and it is the wrong one
        self.assertSequenceEqual([GOOD_EXIT], uc.ctl_get_exits(), int)

        # resume execution; rely on code hook to fast-forward the emulation
        # stopping point is ignored due to enabled exits
        uc.emu_start(BASE, WRONG_EXIT)

        # did we exit on the right place?
        # not failing on an invalid instruction is another good indication for that
        self.assertEqual(GOOD_EXIT, uc.reg_read(UC_X86_REG_EIP))

    @unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
    def test_tlb_mode(self):
        MAPPING_LO = 0x0000000001000000
        MAPPING_HI = 0x0010000000000000
        NOPSLED = b'\x90' * 8

        uc = Uc(UC_ARCH_X86, UC_MODE_64)

        uc.mem_map(MAPPING_LO, 0x1000)
        uc.mem_write(MAPPING_LO, NOPSLED)

        uc.emu_start(MAPPING_LO, MAPPING_LO + len(NOPSLED))

        # # we should be fine here
        # uc.emu_start(BASE, BASE + len(_VALID_CODE), count=1)

        uc.mem_map(MAPPING_HI, 0x1000)
        uc.mem_write(MAPPING_HI, NOPSLED)

        # this should prevent us from mapping to high addresses
        uc.ctl_set_tlb_mode(UC_TLB_CPU)

        # this should fail
        with self.assertRaises(UcError) as ex:
            uc.emu_start(MAPPING_HI, MAPPING_HI + len(NOPSLED))

        self.assertEqual(UC_ERR_FETCH_UNMAPPED, ex.exception.errno)

        # ------------------------------------------------------

        # this should allow us mapping to high addresses
        uc.ctl_set_tlb_mode(UC_TLB_VIRTUAL)

        # this should ok now
        uc.emu_start(MAPPING_HI, MAPPING_HI + len(NOPSLED))


if __name__ == '__main__':
    regress.main()
