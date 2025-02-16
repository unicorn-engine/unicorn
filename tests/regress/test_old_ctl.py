import regress
import sys
import unittest
from unicorn import *
from unicorn.x86_const import *


# Very basic testing to ensure the old api exists
@unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
class OldCtl(regress.RegressTest):
    def runTest(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu.ctl_tlb_mode(UC_TLB_CPU)
        mu.ctl_set_tlb_mode(UC_TLB_VIRTUAL)


if __name__ == '__main__':
    regress.main()
