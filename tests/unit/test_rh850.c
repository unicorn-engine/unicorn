#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static void test_rh850_add(void)
{
    char code[] = "\x01\x0e\x06\x00\xc1\x11"; 
    uint32_t r1 = 0x1234;
    uint32_t r2 = 0x7777;
    uint32_t pc;
    uc_engine *uc;

    uc_common_setup(&uc, UC_ARCH_RH850, UC_MODE_LITTLE_ENDIAN, code,
                    sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_RH850_REG_R1, &r1));
    OK(uc_reg_write(uc, UC_RH850_REG_R2, &r2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RH850_REG_R1, &r1));
    OK(uc_reg_read(uc, UC_RH850_REG_R2, &r2));
    OK(uc_reg_read(uc, UC_RH850_REG_PC, &pc));

    TEST_CHECK(r1 == 0x1234 + 6);
    TEST_CHECK(r2 == 0x89b1);
    TEST_CHECK(pc == code_start + sizeof(code) - 1);

    //OK(uc_close(uc));
}

TEST_LIST = {{"test_rh850_add", test_rh850_add}, {NULL, NULL}};