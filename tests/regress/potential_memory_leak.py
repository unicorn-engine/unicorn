#!/usr/bin/env python

import platform
import resource

from unicorn import *

import regress

class MemoryLeak(regress.RegressTest):
    def test(self):
        if platform.system() == "Darwin":
            rusage_multiplier = 1
        elif platform.system() == "Linux":
            rusage_multiplier = 1024
        else:
            # resource.getrusage(...) is platform dependent. Only tested under OS X and Linux.
            return
        max_rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * rusage_multiplier
        for i in xrange(10000):
            mu = Uc(UC_ARCH_X86, UC_MODE_64)
            mu.mem_map(0, 4096)
            mu.emu_start(0, 0)
        max_rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * rusage_multiplier
        rss_increase_per_iteration = (max_rss_after - max_rss_before) / i
        self.assertLess(rss_increase_per_iteration, 8000)

if __name__ == '__main__':
    regress.main()
