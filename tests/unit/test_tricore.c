#include "unicorn_test.h"

const uint64_t code_start = 0x80000000;
const uint64_t code_len = 0x8000;

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static void test_ld_bu_preinc(void)
{
    uc_engine *uc;
    char code[] = "\x09\x2f\x41\x04"; // ld.bu d15, [+a2]1
    uint32_t a2 = code_start + 0x4000;
    uint32_t d15;
    uint8_t data = 0xbc;

    uc_common_setup(&uc, UC_ARCH_TRICORE, UC_MODE_LITTLE_ENDIAN, code,
                    sizeof(code) - 1);
    OK(uc_mem_write(uc, a2 + 1, &data, 1));
    OK(uc_reg_write(uc, UC_TRICORE_REG_A2, &a2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_TRICORE_REG_D15, &d15));
    OK(uc_reg_read(uc, UC_TRICORE_REG_A2, &a2));

    TEST_CHECK(d15 == 0xbc);
    TEST_CHECK(a2 == code_start + 0x4001);

    OK(uc_close(uc));
}

TEST_LIST = {{"test_ld_bu_preinc", test_ld_bu_preinc}, {NULL, NULL}};
