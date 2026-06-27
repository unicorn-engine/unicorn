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

    OK(uc_close(uc));
}

static void test_sparc32_public_registers(void)
{
    uc_engine *uc;
    uint32_t f0 = 0x11223344;
    uint32_t f1 = 0x55667788;
    uint32_t f31 = 0xaabbccdd;
    uint32_t fcc0 = 3;
    uint32_t icc = 0xb;
    uint32_t y = 0xcafebabe;
    uint32_t psr;
    uint32_t got;

    OK(uc_open(UC_ARCH_SPARC, UC_MODE_SPARC32 | UC_MODE_BIG_ENDIAN, &uc));

    OK(uc_reg_write(uc, UC_SPARC_REG_F0, &f0));
    OK(uc_reg_write(uc, UC_SPARC_REG_F1, &f1));
    OK(uc_reg_write(uc, UC_SPARC_REG_F31, &f31));
    OK(uc_reg_write(uc, UC_SPARC_REG_FCC0, &fcc0));
    OK(uc_reg_write(uc, UC_SPARC_REG_ICC, &icc));
    OK(uc_reg_write(uc, UC_SPARC_REG_Y, &y));

    OK(uc_reg_read(uc, UC_SPARC_REG_F0, &got));
    TEST_CHECK(got == f0);
    OK(uc_reg_read(uc, UC_SPARC_REG_F1, &got));
    TEST_CHECK(got == f1);
    OK(uc_reg_read(uc, UC_SPARC_REG_F31, &got));
    TEST_CHECK(got == f31);
    OK(uc_reg_read(uc, UC_SPARC_REG_FCC0, &got));
    TEST_CHECK(got == fcc0);
    OK(uc_reg_read(uc, UC_SPARC_REG_ICC, &got));
    TEST_CHECK(got == icc);
    OK(uc_reg_read(uc, UC_SPARC_REG_Y, &got));
    TEST_CHECK(got == y);
    OK(uc_reg_read(uc, UC_SPARC_REG_PSR, &psr));
    TEST_CHECK(((psr >> 20) & 0xf) == icc);

    OK(uc_close(uc));
}

static void test_sparc64_public_registers(void)
{
    uc_engine *uc;
    uint64_t f32 = 0x1122334455667788ull;
    uint64_t f62 = 0x8877665544332211ull;
    uint64_t y = 0x123456789abcdef0ull;
    uint64_t got64;
    uint32_t f0 = 0xa1b2c3d4;
    uint32_t f31 = 0x0badf00d;
    uint32_t fcc0 = 1;
    uint32_t fcc1 = 2;
    uint32_t fcc2 = 3;
    uint32_t fcc3 = 0;
    uint32_t icc = 5;
    uint32_t xcc = 0xa;
    uint32_t got32;

    OK(uc_open(UC_ARCH_SPARC, UC_MODE_SPARC64 | UC_MODE_BIG_ENDIAN, &uc));

    OK(uc_reg_write(uc, UC_SPARC_REG_F0, &f0));
    OK(uc_reg_write(uc, UC_SPARC_REG_F31, &f31));
    OK(uc_reg_write(uc, UC_SPARC_REG_F32, &f32));
    OK(uc_reg_write(uc, UC_SPARC_REG_F62, &f62));
    OK(uc_reg_write(uc, UC_SPARC_REG_FCC0, &fcc0));
    OK(uc_reg_write(uc, UC_SPARC_REG_FCC1, &fcc1));
    OK(uc_reg_write(uc, UC_SPARC_REG_FCC2, &fcc2));
    OK(uc_reg_write(uc, UC_SPARC_REG_FCC3, &fcc3));
    OK(uc_reg_write(uc, UC_SPARC_REG_ICC, &icc));
    OK(uc_reg_write(uc, UC_SPARC_REG_XCC, &xcc));
    OK(uc_reg_write(uc, UC_SPARC_REG_Y, &y));

    OK(uc_reg_read(uc, UC_SPARC_REG_F0, &got32));
    TEST_CHECK(got32 == f0);
    OK(uc_reg_read(uc, UC_SPARC_REG_F31, &got32));
    TEST_CHECK(got32 == f31);
    OK(uc_reg_read(uc, UC_SPARC_REG_F32, &got64));
    TEST_CHECK(got64 == f32);
    OK(uc_reg_read(uc, UC_SPARC_REG_F62, &got64));
    TEST_CHECK(got64 == f62);
    OK(uc_reg_read(uc, UC_SPARC_REG_FCC0, &got32));
    TEST_CHECK(got32 == fcc0);
    OK(uc_reg_read(uc, UC_SPARC_REG_FCC1, &got32));
    TEST_CHECK(got32 == fcc1);
    OK(uc_reg_read(uc, UC_SPARC_REG_FCC2, &got32));
    TEST_CHECK(got32 == fcc2);
    OK(uc_reg_read(uc, UC_SPARC_REG_FCC3, &got32));
    TEST_CHECK(got32 == fcc3);
    OK(uc_reg_read(uc, UC_SPARC_REG_ICC, &got32));
    TEST_CHECK(got32 == icc);
    OK(uc_reg_read(uc, UC_SPARC_REG_XCC, &got32));
    TEST_CHECK(got32 == xcc);
    OK(uc_reg_read(uc, UC_SPARC_REG_Y, &got64));
    TEST_CHECK(got64 == y);

    OK(uc_close(uc));
}

TEST_LIST = {
        {"test_virtual_read", test_virtual_read},
        {"test_sparc32_public_registers", test_sparc32_public_registers},
        {"test_sparc64_public_registers", test_sparc64_public_registers},
        {NULL, NULL}
};
