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

// ===== PPC64 tests =====

static void test_ppc64_add(void)
{
    uc_engine *uc;
    char code[] = "\x7f\x46\x1a\x14"; // ADD r26, r6, r3
    uint64_t reg;

    uc_common_setup(&uc, UC_ARCH_PPC, UC_MODE_PPC64 | UC_MODE_BIG_ENDIAN,
                    code, sizeof(code) - 1);

    reg = 42;
    OK(uc_reg_write(uc, UC_PPC_REG_3, &reg));
    reg = 1337;
    OK(uc_reg_write(uc, UC_PPC_REG_6, &reg));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_PPC_REG_26, &reg));

    TEST_CHECK(reg == 1379);

    OK(uc_close(uc));
}

static void test_ppc64_add_large(void)
{
    uc_engine *uc;
    char code[] = "\x7f\x46\x1a\x14"; // ADD r26, r6, r3
    uint64_t reg;

    uc_common_setup(&uc, UC_ARCH_PPC, UC_MODE_PPC64 | UC_MODE_BIG_ENDIAN,
                    code, sizeof(code) - 1);

    reg = 0x100000000ULL;
    OK(uc_reg_write(uc, UC_PPC_REG_3, &reg));
    reg = 0x200000000ULL;
    OK(uc_reg_write(uc, UC_PPC_REG_6, &reg));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_PPC_REG_26, &reg));

    TEST_CHECK(reg == 0x300000000ULL);

    OK(uc_close(uc));
}

static void test_ppc64_fadd(void)
{
    uc_engine *uc;
    char code[] = "\xfc\xc4\x28\x2a"; // fadd f6, f4, f5
    uint64_t r_msr;
    uint64_t r_fpr4, r_fpr5, r_fpr6;

    uc_common_setup(&uc, UC_ARCH_PPC, UC_MODE_PPC64 | UC_MODE_BIG_ENDIAN,
                    code, sizeof(code) - 1);

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &r_msr));
    r_msr |= (1 << 13);                           // enable FP
    r_msr |= (1ULL << 63);                         // SF bit for 64-bit mode
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &r_msr));

    r_fpr4 = 0xC053400000000000ULL;
    r_fpr5 = 0x400C000000000000ULL;
    OK(uc_reg_write(uc, UC_PPC_REG_FPR4, &r_fpr4));
    OK(uc_reg_write(uc, UC_PPC_REG_FPR5, &r_fpr5));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_PPC_REG_FPR6, &r_fpr6));

    TEST_CHECK(r_fpr6 == 0xC052600000000000ULL);

    OK(uc_close(uc));
}

static void test_ppc64_sc_cb(uc_engine *uc, uint32_t intno, void *data)
{
    uc_emu_stop(uc);
    return;
}

static void test_ppc64_sc(void)
{
    uc_engine *uc;
    char code[] = "\x44\x00\x00\x02"; // sc
    uint64_t r_pc;
    uc_hook h;

    uc_common_setup(&uc, UC_ARCH_PPC, UC_MODE_PPC64 | UC_MODE_BIG_ENDIAN,
                    code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &h, UC_HOOK_INTR, test_ppc64_sc_cb, NULL, 1, 0));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_PPC_REG_PC, &r_pc));

    TEST_CHECK(r_pc == code_start + 4);

    OK(uc_close(uc));
}

static void test_ppc64_cr(void)
{
    uc_engine *uc;
    uint32_t r_cr = 0x12345678;

    uc_common_setup(&uc, UC_ARCH_PPC, UC_MODE_PPC64 | UC_MODE_BIG_ENDIAN,
                    NULL, 0);

    OK(uc_reg_write(uc, UC_PPC_REG_CR, &r_cr));
    r_cr = 0;
    OK(uc_reg_read(uc, UC_PPC_REG_CR, &r_cr));

    TEST_CHECK(r_cr == 0x12345678);

    OK(uc_close(uc));
}

static void test_ppc64_ld(void)
{
    uc_engine *uc;
    char code[] = "\xe8\x64\x00\x00"; // ld r3, 0(r4)
    uint64_t reg;
    // Data in big-endian: 0x123456789ABCDEF0
    char data[] = "\x12\x34\x56\x78\x9A\xBC\xDE\xF0";
    uint64_t data_addr = 0x2000;

    uc_common_setup(&uc, UC_ARCH_PPC, UC_MODE_PPC64 | UC_MODE_BIG_ENDIAN,
                    code, sizeof(code) - 1);

    OK(uc_mem_write(uc, data_addr, data, sizeof(data) - 1));

    reg = data_addr;
    OK(uc_reg_write(uc, UC_PPC_REG_4, &reg));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_PPC_REG_3, &reg));

    TEST_CHECK(reg == 0x123456789ABCDEF0ULL);

    OK(uc_close(uc));
}

static void test_ppc64_std(void)
{
    uc_engine *uc;
    char code[] = "\xf8\x64\x00\x00"; // std r3, 0(r4)
    uint64_t reg;
    uint64_t data_addr = 0x2000;
    uint8_t buf[8];

    uc_common_setup(&uc, UC_ARCH_PPC, UC_MODE_PPC64 | UC_MODE_BIG_ENDIAN,
                    code, sizeof(code) - 1);

    reg = 0xAABBCCDD11223344ULL;
    OK(uc_reg_write(uc, UC_PPC_REG_3, &reg));
    reg = data_addr;
    OK(uc_reg_write(uc, UC_PPC_REG_4, &reg));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, data_addr, buf, 8));

    // Big-endian: first byte should be 0xAA
    TEST_CHECK(buf[0] == 0xAA);
    TEST_CHECK(buf[1] == 0xBB);
    TEST_CHECK(buf[2] == 0xCC);
    TEST_CHECK(buf[3] == 0xDD);
    TEST_CHECK(buf[4] == 0x11);
    TEST_CHECK(buf[5] == 0x22);
    TEST_CHECK(buf[6] == 0x33);
    TEST_CHECK(buf[7] == 0x44);

    OK(uc_close(uc));
}

static void test_ppc64_spr_time(void)
{
    char code[] = ("\x7c\x76\x02\xa6" // mfspr r3, DEC
                   "\x7c\x6c\x42\xa6" // mfspr r3, TBL
    );

    uc_engine *uc;
    uc_common_setup(&uc, UC_ARCH_PPC, UC_MODE_PPC64 | UC_MODE_BIG_ENDIAN,
                    code, sizeof(code) - 1);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_close(uc));
}

TEST_LIST = {{"test_ppc32_add", test_ppc32_add},
             {"test_ppc32_fadd", test_ppc32_fadd},
             {"test_ppc32_sc", test_ppc32_sc},
             {"test_ppc32_cr", test_ppc32_cr},
             {"test_ppc32_spr_time", test_ppc32_spr_time},
             {"test_ppc64_add", test_ppc64_add},
             {"test_ppc64_add_large", test_ppc64_add_large},
             {"test_ppc64_fadd", test_ppc64_fadd},
             {"test_ppc64_sc", test_ppc64_sc},
             {"test_ppc64_cr", test_ppc64_cr},
             {"test_ppc64_ld", test_ppc64_ld},
             {"test_ppc64_std", test_ppc64_std},
             {"test_ppc64_spr_time", test_ppc64_spr_time},
             {NULL, NULL}};