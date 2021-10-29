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

static void test_ppc32_add()
{
    uc_engine *uc;
    char code[] = "\x7f\x46\x1a\x14"; // ADD 26, 6, 3
    int reg;

    uc_common_setup(&uc, UC_ARCH_PPC, UC_MODE_32 | UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1);

    reg = 42;
    OK(uc_reg_write(uc, UC_PPC_REG_3, &reg));
    reg = 1337;
    OK(uc_reg_write(uc, UC_PPC_REG_6, &reg));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_PPC_REG_26, &reg));

    TEST_CHECK(reg == 1379);

    OK(uc_close(uc));
}

TEST_LIST = {{"test_ppc32_add", test_ppc32_add}, {NULL, NULL}};