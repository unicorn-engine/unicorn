#include "unicorn_test.h"

const uint64_t code_start = 0x10000;
const uint64_t code_len = 0x4000;

static void test_sro_ld_h(void)
{
    uc_engine *uc;
    // ld.h d15, [a2]0x2  (SRO); EA = a2 + 2*off4 = code_start+4 -> 0x8123
    char code[] = "\x8c\x22\x00\x00\x23\x81";
    uint32_t d15, a2 = code_start;

    OK(uc_open(UC_ARCH_TRICORE, UC_MODE_LITTLE_ENDIAN, &uc));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_TRICORE_REG_A2, &a2));

    OK(uc_emu_start(uc, code_start, code_start + 2, 0, 0));

    OK(uc_reg_read(uc, UC_TRICORE_REG_D15, &d15));
    TEST_CHECK(d15 == 0xffff8123);

    OK(uc_close(uc));
}

TEST_LIST = {{"test_sro_ld_h", test_sro_ld_h}, {NULL, NULL}};
