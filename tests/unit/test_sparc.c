#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

static void test_virtual_read(void)
{
    uc_engine *uc;
    uint8_t u8 = 8;

    OK(uc_open(UC_ARCH_SPARC, UC_MODE_SPARC32|UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));

    uc_assert_err(UC_ERR_ARG, uc_vmem_read(uc, code_start, UC_PROT_READ, &u8, sizeof(u8)));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_vmem_read(uc, code_start, UC_PROT_READ, &u8, sizeof(u8)));
}

static void test_sparc32_psr(void)
{
    uc_engine *uc;
    uint32_t psr;

    OK(uc_open(UC_ARCH_SPARC, UC_MODE_SPARC32 | UC_MODE_BIG_ENDIAN, &uc));

    // read before anything has been emulated
    OK(uc_reg_read(uc, UC_SPARC_REG_PSR, &psr));

    // icc = N|C, S, PS, ET and CWP = 3; the implementation and version bits are the CPU's
    psr = 0x009000e3;
    OK(uc_reg_write(uc, UC_SPARC_REG_PSR, &psr));
    OK(uc_reg_read(uc, UC_SPARC_REG_PSR, &psr));
    TEST_CHECK((psr & 0x00ffffff) == 0x009000e3);

    OK(uc_close(uc));
}

static void test_sparc32_y(void)
{
    uc_engine *uc;
    char code[] = "\x86\x70\x40\x02"  // udiv %g1, %g2, %g3
                  "\x86\x50\x40\x02"; // umul %g1, %g2, %g3
    uint32_t reg;

    OK(uc_open(UC_ARCH_SPARC, UC_MODE_SPARC32 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    reg = 0x12345678;
    OK(uc_reg_write(uc, UC_SPARC_REG_Y, &reg));
    reg = 0;
    OK(uc_reg_read(uc, UC_SPARC_REG_Y, &reg));
    TEST_CHECK(reg == 0x12345678);

    // Y:g1 / g2 = 0x100000000 / 2
    reg = 1;
    OK(uc_reg_write(uc, UC_SPARC_REG_Y, &reg));
    reg = 0;
    OK(uc_reg_write(uc, UC_SPARC_REG_G1, &reg));
    reg = 2;
    OK(uc_reg_write(uc, UC_SPARC_REG_G2, &reg));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));
    OK(uc_reg_read(uc, UC_SPARC_REG_G3, &reg));
    TEST_CHECK(reg == 0x80000000);

    // the high word of 0x80000000 * 4 goes to Y
    reg = 0x80000000;
    OK(uc_reg_write(uc, UC_SPARC_REG_G1, &reg));
    reg = 4;
    OK(uc_reg_write(uc, UC_SPARC_REG_G2, &reg));
    OK(uc_emu_start(uc, code_start + 4, code_start + 8, 0, 0));
    OK(uc_reg_read(uc, UC_SPARC_REG_G3, &reg));
    TEST_CHECK(reg == 0);
    OK(uc_reg_read(uc, UC_SPARC_REG_Y, &reg));
    TEST_CHECK(reg == 2);

    OK(uc_close(uc));
}

TEST_LIST = {
        {"test_virtual_read", test_virtual_read},
        {"test_sparc32_psr", test_sparc32_psr},
        {"test_sparc32_y", test_sparc32_y},
        {NULL, NULL}
};
