import regress
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE

CODE = b"\x90" * 3
CODE_ADDR = 0x1000


class HookCounter(object):
    """Counts number of hook calls."""
    
    def __init__(self):
        self.hook_calls = 0

    def bad_code_hook(self, uc, address, size, data):
        self.hook_calls += 1
        raise ValueError("Something went wrong")

    def good_code_hook(self, uc, address, size, data):
        self.hook_calls += 1


class TestExceptionInHook(regress.RegressTest):

    def test_exception_in_hook(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(CODE_ADDR, 0x1000)
        uc.mem_write(CODE_ADDR, CODE)

        counter = HookCounter()
        uc.hook_add(UC_HOOK_CODE, counter.bad_code_hook, begin=CODE_ADDR, end=CODE_ADDR + len(CODE))
        uc.hook_add(UC_HOOK_CODE, counter.good_code_hook, begin=CODE_ADDR, end=CODE_ADDR + len(CODE))

        self.assertRaises(ValueError, uc.emu_start, CODE_ADDR, CODE_ADDR + len(CODE))
        # Make sure hooks calls finish before raising (hook_calls == 2)
        self.assertEqual(counter.hook_calls, 2)


if __name__ == "__main__":
    regress.main()
