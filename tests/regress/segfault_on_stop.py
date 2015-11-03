#!/usr/bin/env python

import regress
import unicorn


class SegfaultOnStop(regress.RegressTest):
    def test(self):
        unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64).emu_stop()
        self.assertTrue(True, "If not reached, then we have a crashing bug.")

if __name__ == '__main__':
    regress.main()
