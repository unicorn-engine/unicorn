import regress
import sys
import unittest
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64
from unicorn.unicorn_const import UC_TLB_VIRTUAL, UC_TLB_CPU, UC_ERR_FETCH_UNMAPPED

MAX_INTEL_INSN_SIZE = 15


class TestMem(regress.RegressTest):

    # 0x0008fffffffff000  : mappings till this point work ok
    # 0x0010000000000000  : mappings beyond this point will fail if tlb is not set to virtual

    def setUp(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)

    def map_code_page(self, address, payload):
        regress.logger.debug('attempting to map code at %#018x', address)

        self.uc.mem_map(address, 0x1000)
        self.uc.mem_write(address, payload)

    @unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
    def test_virt_high_mapping(self):
        """
        Mapping memory at high addresses should work when TLB mode
        is set to VIRTUAL.
        """

        base = 0x0010000000000000

        self.uc.ctl_set_tlb_mode(UC_TLB_VIRTUAL)

        for i in range(12):
            code = base << i

            self.map_code_page(code, b'\xf4')

            try:
                self.uc.emu_start(code, code + MAX_INTEL_INSN_SIZE, count=1)
            except UcError:
                self.fail('high mapping failed at %#018x' % code)

    @unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
    def test_cpu_high_mapping(self):
        """
        Mapping memory at high addresses should work fail TLB mode
        is set to CPU (default).
        """

        base = 0x0010000000000000

        self.uc.ctl_set_tlb_mode(UC_TLB_CPU)

        for i in range(12):
            code = base << i

            self.map_code_page(code, b'\xf4')

            with self.assertRaises(UcError) as ex:
                self.uc.emu_start(code, code + MAX_INTEL_INSN_SIZE, count=1)

            self.assertEqual(UC_ERR_FETCH_UNMAPPED, ex.exception.errno)


if __name__ == '__main__':
    regress.main()
