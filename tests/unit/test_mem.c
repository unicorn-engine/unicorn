#include "unicorn_test.h"

static void test_map_correct() {
    uc_engine* uc;

    OK(uc_open (UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map (uc, 0x40000, 0x1000 * 16, UC_PROT_ALL));

    OK(uc_close(uc));
}

static void test_map_wrapping() {
    uc_engine* uc;

    OK(uc_open (UC_ARCH_X86, UC_MODE_64, &uc));
    uc_assert_err(UC_ERR_ARG, uc_mem_map (uc, (~0ll - 0x4000) & ~0xfff, 0x8000, UC_PROT_ALL));

    OK(uc_close(uc));
}

TEST_LIST = {
    { "test_map_correct", test_map_correct },
    { "test_map_wrapping", test_map_wrapping },
    { NULL, NULL }
};
