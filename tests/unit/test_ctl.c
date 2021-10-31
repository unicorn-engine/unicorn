#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

#define GEN_SIMPLE_READ_TEST(field, ctl_type, arg_type, expected)              \
    static void test_uc_ctl_##field()                                          \
    {                                                                          \
        uc_engine *uc;                                                         \
        arg_type arg;                                                          \
        OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));                             \
        OK(uc_ctl(uc, UC_CTL_READ(ctl_type, 1), &arg));                        \
        TEST_CHECK(arg == expected);                                           \
    }

GEN_SIMPLE_READ_TEST(mode, UC_CTL_UC_MODE, int, 4)
GEN_SIMPLE_READ_TEST(arch, UC_CTL_UC_ARCH, int, 4)
GEN_SIMPLE_READ_TEST(page_size, UC_CTL_UC_PAGE_SIZE, uint32_t, 4096)
GEN_SIMPLE_READ_TEST(time_out, UC_CTL_UC_TIMEOUT, uint64_t, 0)

TEST_LIST = {{"test_uc_ctl_mode", test_uc_ctl_mode},
             {"test_uc_ctl_page_size", test_uc_ctl_page_size},
             {"test_uc_ctl_arch", test_uc_ctl_arch},
             {"test_uc_ctl_time_out", test_uc_ctl_time_out},
             {NULL, NULL}};