""" https://github.com/unicorn-engine/unicorn/issues/165 """

import regress
from unicorn import *


class TestHook(regress.RegressTest):
    def test_excessive_hooks(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        for _ in range(1337):
            mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, lambda *args, **kwargs: None)


if __name__ == '__main__':
    regress.main()
