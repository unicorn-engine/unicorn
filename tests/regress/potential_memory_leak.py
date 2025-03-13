import platform
import regress
import sys
import unittest
from unicorn import *

try:
    # Only available on Unix: https://docs.python.org/3/library/resource.html
    import resource
except:
    pass

ITERATIONS = 10000


class MemoryLeak(regress.RegressTest):

    @unittest.skipIf(sys.platform == 'win32', reason='Test for Unix only')
    def test(self):
        if platform.system() == "Darwin":
            rusage_multiplier = 1
        elif platform.system() == "Linux":
            rusage_multiplier = 1024
        else:
            # resource.getrusage(...) is platform dependent. Only tested under OS X and Linux.
            self.skipTest('not OSx neither Linux')

        max_rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * rusage_multiplier

        for _ in range(ITERATIONS):
            mu = Uc(UC_ARCH_X86, UC_MODE_64)
            mu.mem_map(0, 0x1000)
            mu.emu_start(0, 0)

        max_rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * rusage_multiplier
        rss_increase_per_iteration = (max_rss_after - max_rss_before) / ITERATIONS

        self.assertLess(rss_increase_per_iteration, 8000.0)


if __name__ == '__main__':
    regress.main()
