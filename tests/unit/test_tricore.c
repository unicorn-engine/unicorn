#include "unicorn_test.h"

const uint64_t code_start = 0x10000;
const uint64_t code_len = 0x4000;

static void uc_map_code(uc_engine *uc, const uint8_t *code, size_t size)
{
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, size));
}

static void uc_common_setup(uc_engine **uc, const uint8_t *code, size_t size)
{
    OK(uc_open(UC_ARCH_TRICORE, UC_MODE_LITTLE_ENDIAN, uc));
    uc_map_code(*uc, code, size);
}

static void test_tricore_mov_dreg(void)
{
    const uint8_t code[] = {
        0x82, 0x11,
        0xbb, 0x00, 0x00, 0x08,
    };
    uc_engine *uc;
    uint32_t d0 = 0;
    uint32_t d1 = 0;
    uint32_t pc = 0;

    uc_common_setup(&uc, code, sizeof(code));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_TRICORE_REG_D0, &d0));
    OK(uc_reg_read(uc, UC_TRICORE_REG_D1, &d1));
    OK(uc_reg_read(uc, UC_TRICORE_REG_PC, &pc));
    TEST_CHECK_(d0 == 0x8000, "d0 = 0x%08x", d0);
    TEST_CHECK_(d1 == 1, "d1 = 0x%08x", d1);
    TEST_CHECK(pc == code_start + sizeof(code));

    OK(uc_close(uc));
}

static void test_tricore_reg_roundtrip_one(uc_engine *uc, int reg,
                                           uint32_t value)
{
    uint32_t out = 0;

    OK(uc_reg_write(uc, reg, &value));
    OK(uc_reg_read(uc, reg, &out));
    TEST_CHECK(out == value);
}

static void test_tricore_csfr_reg_roundtrip(void)
{
    uc_engine *uc;
    uint32_t code = 0;

    uc_common_setup(&uc, (const uint8_t *)&code, sizeof(code));

    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_DPR0_U, 0x11112222);
    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_DPR3_L, 0x33334444);
    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_CPR0_U, 0x55556666);
    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_CPR3_L, 0x77778888);
    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_DPM2, 0x10203040);
    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_CPM3, 0x50607080);
    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_MMU_CON, 0xaabbccdd);
    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_MMU_TFA, 0x01020304);
    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_BMACON, 0x11223344);
    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_CCPIER, 0x55667788);
    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_DBGSR, 0x00000001);
    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_TR1EVT, 0x13579bdf);
    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_CCTRL, 0x2468ace0);
    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_M3CNT, 0xdeadbeef);
    test_tricore_reg_roundtrip_one(uc, UC_TRICORE_REG_PSW, 0xf8000123);

    OK(uc_close(uc));
}

static void test_tricore_cpu_model(void)
{
    uc_engine *uc;

    OK(uc_open(UC_ARCH_TRICORE, UC_MODE_LITTLE_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_TRICORE_TC1796));
    TEST_CHECK(uc_ctl_set_cpu_model(uc, UC_CPU_TRICORE_ENDING) ==
               UC_ERR_ARG);
    OK(uc_close(uc));
}

TEST_LIST = {
    {"test_tricore_mov_dreg", test_tricore_mov_dreg},
    {"test_tricore_csfr_reg_roundtrip", test_tricore_csfr_reg_roundtrip},
    {"test_tricore_cpu_model", test_tricore_cpu_model},
    {NULL, NULL},
};
