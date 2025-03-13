import regress
from unicorn import *


# OS X: OK with 2047 iterations.
# OS X: Crashes at 2048:th iteration ("qemu: qemu_thread_create: Resource temporarily unavailable").
# Linux: No crashes observed.

class ThreadCreateCrash(regress.RegressTest):
    def test(self):
        for _ in range(2048):
            Uc(UC_ARCH_X86, UC_MODE_64)


if __name__ == '__main__':
    regress.main()
