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

static void test_ppc32_add(void)
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

// https://www.ibm.com/docs/en/aix/7.2?topic=set-fadd-fa-floating-add-instruction
static void test_ppc32_fadd(void)
{
    uc_engine *uc;
    char code[] = "\xfc\xc4\x28\x2a"; // fadd 6, 4, 5
    uint32_t r_msr;
    uint64_t r_fpr4, r_fpr5, r_fpr6;

    uc_common_setup(&uc, UC_ARCH_PPC, UC_MODE_32 | UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1);

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &r_msr));
    r_msr |= (1 << 13);                           // Big endian
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &r_msr)); // enable FP

    r_fpr4 = 0xC053400000000000ul;
    r_fpr5 = 0x400C000000000000ul;
    OK(uc_reg_write(uc, UC_PPC_REG_FPR4, &r_fpr4));
    OK(uc_reg_write(uc, UC_PPC_REG_FPR5, &r_fpr5));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_PPC_REG_FPR6, &r_fpr6));

    TEST_CHECK(r_fpr6 == 0xC052600000000000ul);

    OK(uc_close(uc));
}

static void test_ppc32_sc_cb(uc_engine *uc, uint32_t intno, void *data)
{
    uc_emu_stop(uc);
    return;
}

static void test_ppc32_sc(void)
{
    uc_engine *uc;
    char code[] = "\x44\x00\x00\x02"; // sc
    uint32_t r_pc;
    uc_hook h;

    uc_common_setup(&uc, UC_ARCH_PPC, UC_MODE_32 | UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1);

    OK(uc_hook_add(uc, &h, UC_HOOK_INTR, test_ppc32_sc_cb, NULL, 1, 0));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_PPC_REG_PC, &r_pc));

    TEST_CHECK(r_pc == code_start + 4);

    OK(uc_close(uc));
}

static void test_ppc32_cr(void)
{
    uc_engine *uc;
    uint32_t r_cr = 0x12345678;

    uc_common_setup(&uc, UC_ARCH_PPC, UC_MODE_32 | UC_MODE_BIG_ENDIAN, NULL, 0);

    OK(uc_reg_write(uc, UC_PPC_REG_CR, &r_cr));
    r_cr = 0;
    OK(uc_reg_read(uc, UC_PPC_REG_CR, &r_cr));

    TEST_CHECK(r_cr == 0x12345678);

    OK(uc_close(uc));
}

static void test_ppc32_spr_time(void)
{
    char code[] = ("\x7c\x76\x02\xa6" // mfspr r3, DEC
                   "\x7c\x6d\x42\xa6" // mfspr r3, TBUr
    );

    uc_engine *uc;
    uc_common_setup(&uc, UC_ARCH_PPC, UC_MODE_32 | UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_close(uc));
}

TEST_LIST = {{"test_ppc32_add", test_ppc32_add},
             {"test_ppc32_fadd", test_ppc32_fadd},
             {"test_ppc32_sc", test_ppc32_sc},
             {"test_ppc32_cr", test_ppc32_cr},
             {"test_ppc32_spr_time", test_ppc32_spr_time},
             {NULL, NULL}};