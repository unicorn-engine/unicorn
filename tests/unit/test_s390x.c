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

static void test_s390x_lr(void)
{
    char code[] = "\x18\x23"; // lr %r2, %r3
    uint64_t r_pc, r_r2, r_r3 = 0x114514;
    uc_engine *uc;

    uc_common_setup(&uc, UC_ARCH_S390X, UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1);

    OK(uc_reg_write(uc, UC_S390X_REG_R3, &r_r3));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_S390X_REG_R2, &r_r2));
    OK(uc_reg_read(uc, UC_S390X_REG_PC, &r_pc));

    TEST_CHECK(r_r2 == 0x114514);
    TEST_CHECK(r_pc == code_start + sizeof(code) - 1);

    OK(uc_close(uc));
}

TEST_LIST = {{"test_s390x_lr", test_s390x_lr}, {NULL, NULL}};
