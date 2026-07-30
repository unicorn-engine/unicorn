#include "unicorn_test.h"
#include <string.h>

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size, uc_cpu_arm cpu)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_ctl_set_cpu_model(*uc, cpu));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

typedef struct _WFI_HOOK_INSN_RESULT {
    bool called;
} WFI_HOOK_INSN_RESULT;

static void test_arm_emit32(uint8_t *code, int offset, uint32_t insn)
{
    code[offset] = (uint8_t)insn;
    code[offset + 1] = (uint8_t)(insn >> 8);
    code[offset + 2] = (uint8_t)(insn >> 16);
    code[offset + 3] = (uint8_t)(insn >> 24);
}

static void test_arm_enable_vfp(uc_engine *uc)
{
    uint32_t cpacr = 0xfU << 20;
    uint32_t fpexc = 1U << 30;

    OK(uc_reg_write(uc, UC_ARM_REG_C1_C0_2, &cpacr));
    OK(uc_reg_write(uc, UC_ARM_REG_FPEXC, &fpexc));
}

static uint32_t test_arm_id_isar6_read(uc_engine *uc)
{
    uc_arm_cp_reg reg = {
        .cp = 15,
        .is64 = 0,
        .sec = 0,
        .crn = 0,
        .crm = 2,
        .opc1 = 0,
        .opc2 = 7,
        .val = 0,
    };

    OK(uc_reg_read(uc, UC_ARM_REG_CP_REG, &reg));
    return (uint32_t)reg.val;
}

static void test_arm_i8mm_q_run(uint32_t insn, const uint8_t *initial,
                                const uint8_t *n, const uint8_t *m,
                                const uint8_t *expected)
{
    uc_engine *uc;
    uint8_t code[4];
    uint64_t q0[2];
    uint64_t q1[2];
    uint64_t q2[2];
    const uint8_t *got = (const uint8_t *)q0;
    size_t i;

    test_arm_emit32(code, 0, insn);
    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM_MAX);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, n, 16);
    memcpy(q2, m, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_Q2, q2));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got[i] == expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm_i8mm_expect_exception(uint32_t insn, uc_cpu_arm cpu)
{
    uc_engine *uc;
    uint8_t code[4];

    test_arm_emit32(code, 0, insn);
    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, (const char *)code,
                    sizeof(code), cpu);
    test_arm_enable_vfp(uc);
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0) ==
               UC_ERR_INSN_INVALID);
    OK(uc_close(uc));
}

static void test_arm_i8mm(void)
{
    uc_engine *uc;
    const uint32_t id_isar6_i8mm = 0xfU << 24;
    const uint8_t initial[16] = {
        0x10, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff,
        0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff,
    };
    const uint8_t n[16] = {
        0x01, 0x7f, 0x80, 0xff, 0x10, 0xf0, 0x22, 0xdd,
        0x40, 0xc0, 0x55, 0xaa, 0x7e, 0x82, 0x01, 0xff,
    };
    const uint8_t m[16] = {
        0x02, 0xfe, 0x03, 0xfd, 0x80, 0x7f, 0x04, 0xfc,
        0x11, 0xef, 0x66, 0x99, 0x08, 0xf8, 0x01, 0xff,
    };
    const uint8_t exp_usdot[16] = {
        0x97, 0xfd, 0xff, 0xff, 0x14, 0x6c, 0x00, 0x00,
        0x78, 0xd5, 0xff, 0xff, 0x61, 0xfe, 0xff, 0xff,
    };
    const uint8_t exp_usdot_idx[16] = {
        0x95, 0x3c, 0x00, 0x00, 0x14, 0x6c, 0x00, 0x00,
        0x6c, 0x3e, 0x00, 0x00, 0x05, 0xfd, 0xff, 0xff,
    };
    const uint8_t exp_sudot_idx[16] = {
        0x95, 0x3c, 0x00, 0x00, 0x14, 0xde, 0xff, 0xff,
        0x6c, 0xad, 0xff, 0xff, 0x05, 0xff, 0xff, 0xff,
    };
    const uint8_t exp_smmla[16] = {
        0xbb, 0xee, 0xff, 0xff, 0x3e, 0xc6, 0xff, 0xff,
        0x07, 0x86, 0xff, 0xff, 0x59, 0x54, 0x00, 0x00,
    };
    const uint8_t exp_ummla[16] = {
        0xbb, 0xd4, 0x02, 0x00, 0x3e, 0x07, 0x03, 0x00,
        0x07, 0xe3, 0x02, 0x00, 0x59, 0xbe, 0x02, 0x00,
    };
    const uint8_t exp_usmmla[16] = {
        0xbb, 0x69, 0x00, 0x00, 0x3e, 0xbc, 0xff, 0xff,
        0x07, 0xfc, 0xff, 0xff, 0x59, 0xd3, 0xff, 0xff,
    };

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, "\x00\xf0\x20\xe3", 4,
                    UC_CPU_ARM_MAX);
    TEST_CHECK(((test_arm_id_isar6_read(uc) & id_isar6_i8mm) >> 24) == 1);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, "\x00\xf0\x20\xe3", 4,
                    UC_CPU_ARM_CORTEX_A15);
    TEST_CHECK((test_arm_id_isar6_read(uc) & id_isar6_i8mm) == 0);
    OK(uc_close(uc));

    test_arm_i8mm_q_run(0xfca20d44, initial, n, m, exp_usdot);
    test_arm_i8mm_q_run(0xfe820d64, initial, n, m, exp_usdot_idx);
    test_arm_i8mm_q_run(0xfe820d74, initial, n, m, exp_sudot_idx);
    test_arm_i8mm_q_run(0xfc220c44, initial, n, m, exp_smmla);
    test_arm_i8mm_q_run(0xfc220c54, initial, n, m, exp_ummla);
    test_arm_i8mm_q_run(0xfca20c44, initial, n, m, exp_usmmla);

    test_arm_i8mm_expect_exception(0xfca20d44, UC_CPU_ARM_CORTEX_A15);
}

static void test_arm_bf16_scalar_convert(void)
{
    uc_engine *uc;
    uint8_t code[4];
    uint32_t s0 = 0;
    uint32_t s1 = 0x3fc00000u;

    test_arm_emit32(code, 0, 0xeeb30960);
    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM_MAX);
    test_arm_enable_vfp(uc);
    OK(uc_reg_write(uc, UC_ARM_REG_S0, &s0));
    OK(uc_reg_write(uc, UC_ARM_REG_S1, &s1));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_S0, &s0));
    TEST_CHECK(s0 == 0x00003fc0u);
    OK(uc_close(uc));
}

static void test_arm_bf16_vector_convert_run(uint32_t insn,
                                             const uint16_t *initial,
                                             const uint32_t *source,
                                             const uint16_t *expected)
{
    uc_engine *uc;
    uint8_t code[4];
    uint64_t q0[2];
    uint64_t q1[2];
    const uint16_t *got = (const uint16_t *)q0;
    size_t i;

    test_arm_emit32(code, 0, insn);
    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM_MAX);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, source, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(got[i] == expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm_bf16_q_run(uint32_t insn, const uint32_t *initial,
                                const uint16_t *n, const uint16_t *m,
                                const uint32_t *expected)
{
    uc_engine *uc;
    uint8_t code[4];
    uint64_t q0[2];
    uint64_t q1[2];
    uint64_t q2[2];
    const uint32_t *got = (const uint32_t *)q0;
    size_t i;

    test_arm_emit32(code, 0, insn);
    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM_MAX);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, n, 16);
    memcpy(q2, m, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_Q2, q2));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(got[i] == expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm_bf16(void)
{
    uc_engine *uc;
    const uint32_t id_isar6_bf16 = 0xfU << 20;
    const uint16_t init_h[8] = {
        0x1111, 0x2222, 0x3333, 0x4444,
        0xaaaa, 0xbbbb, 0xcccc, 0xdddd,
    };
    const uint32_t fp32_source[4] = {
        0x3f800000u, 0xc0000000u, 0x40400000u, 0x40800000u,
    };
    const uint16_t exp_bfcvt[8] = {
        0x3f80, 0xc000, 0x4040, 0x4080,
        0xaaaa, 0xbbbb, 0xcccc, 0xdddd,
    };
    const uint32_t init_s[4] = {
        0x41200000u, 0x41a00000u, 0x41f00000u, 0x42200000u,
    };
    const uint16_t n_pair[8] = {
        0x3f80, 0x4000, 0x4040, 0x4080,
        0x3f80, 0x3f80, 0x4000, 0x4000,
    };
    const uint16_t m_pair[8] = {
        0x40a0, 0x40c0, 0x40e0, 0x4100,
        0x4000, 0x4040, 0x4080, 0x40a0,
    };
    const uint32_t exp_bfdot[4] = {
        0x41d80000u, 0x42920000u, 0x420c0000u, 0x42680000u,
    };
    const uint32_t exp_bfdot_idx[4] = {
        0x41d80000u, 0x426c0000u, 0x42240000u, 0x42780000u,
    };
    const uint16_t n_mmla[8] = {
        0x3f80, 0x4000, 0x4040, 0x4080,
        0x40a0, 0x40c0, 0x40e0, 0x4100,
    };
    const uint16_t m_mmla[8] = {
        0x3f80, 0x3f80, 0x4000, 0x4000,
        0x4040, 0x4040, 0x4080, 0x4080,
    };
    const uint32_t exp_bfmmla[4] = {
        0x41d80000u, 0x42640000u, 0x428e0000u, 0x43050000u,
    };
    const uint16_t n_long[8] = {
        0x3f80, 0x4000, 0x4040, 0x4080,
        0x40a0, 0x40c0, 0x40e0, 0x4100,
    };
    const uint16_t m_long[8] = {
        0x4000, 0x4040, 0x4080, 0x40a0,
        0x40c0, 0x40e0, 0x4100, 0x4110,
    };
    const uint32_t exp_bfmlalb[4] = {
        0x41400000u, 0x42000000u, 0x42700000u, 0x42c00000u,
    };
    const uint32_t exp_bfmlalt[4] = {
        0x41800000u, 0x42200000u, 0x42900000u, 0x42e00000u,
    };
    const uint32_t exp_bfmlalb_idx[4] = {
        0x41400000u, 0x41d00000u, 0x42200000u, 0x42580000u,
    };
    const uint32_t exp_bfmlalt_idx[4] = {
        0x41600000u, 0x41e00000u, 0x42280000u, 0x42600000u,
    };

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, "\x00\xf0\x20\xe3", 4,
                    UC_CPU_ARM_MAX);
    TEST_CHECK(((test_arm_id_isar6_read(uc) & id_isar6_bf16) >> 20) == 1);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, "\x00\xf0\x20\xe3", 4,
                    UC_CPU_ARM_CORTEX_A15);
    TEST_CHECK((test_arm_id_isar6_read(uc) & id_isar6_bf16) == 0);
    OK(uc_close(uc));

    test_arm_bf16_scalar_convert();
    test_arm_bf16_vector_convert_run(0xf3b60642, init_h, fp32_source,
                                     exp_bfcvt);
    test_arm_bf16_q_run(0xfc020d44, init_s, n_pair, m_pair, exp_bfdot);
    test_arm_bf16_q_run(0xfe020d44, init_s, n_pair, m_pair, exp_bfdot_idx);
    test_arm_bf16_q_run(0xfc020c44, init_s, n_mmla, m_mmla, exp_bfmmla);
    test_arm_bf16_q_run(0xfc320814, init_s, n_long, m_long, exp_bfmlalb);
    test_arm_bf16_q_run(0xfc320854, init_s, n_long, m_long, exp_bfmlalt);
    test_arm_bf16_q_run(0xfe320814, init_s, n_long, m_long,
                        exp_bfmlalb_idx);
    test_arm_bf16_q_run(0xfe320854, init_s, n_long, m_long,
                        exp_bfmlalt_idx);

    test_arm_i8mm_expect_exception(0xeeb30960, UC_CPU_ARM_CORTEX_A15);
    test_arm_i8mm_expect_exception(0xfc020d44, UC_CPU_ARM_CORTEX_A15);
    test_arm_i8mm_expect_exception(0xfc030c44, UC_CPU_ARM_MAX);
}

static void test_arm_nop(void)
{
    uc_engine *uc;
    char code[] = "\x00\xf0\x20\xe3"; // nop
    int r_r0 = 0x1234;
    int r_r2 = 0x6789;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &r_r0));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r_r2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));
    OK(uc_reg_read(uc, UC_ARM_REG_R2, &r_r2));
    TEST_CHECK(r_r0 == 0x1234);
    TEST_CHECK(r_r2 == 0x6789);

    OK(uc_close(uc));
}

static void test_arm_thumb_sub(void)
{
    uc_engine *uc;
    char code[] = "\x83\xb0"; // sub    sp, #0xc
    int r_sp = 0x1234;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_SP, &r_sp));
    TEST_CHECK(r_sp == 0x1228);

    OK(uc_close(uc));
}

static void test_armeb_sub(void)
{
    uc_engine *uc;
    char code[] =
        "\xe3\xa0\x00\x37\xe0\x42\x10\x03"; // mov r0, #0x37; sub r1, r2, r3
    int r_r0 = 0x1234;
    int r_r2 = 0x6789;
    int r_r3 = 0x3333;
    int r_r1;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1, UC_CPU_ARM_1176);
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &r_r0));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r_r2));
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &r_r3));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r_r1));
    OK(uc_reg_read(uc, UC_ARM_REG_R2, &r_r2));
    OK(uc_reg_read(uc, UC_ARM_REG_R3, &r_r3));

    TEST_CHECK(r_r0 == 0x37);
    TEST_CHECK(r_r2 == 0x6789);
    TEST_CHECK(r_r3 == 0x3333);
    TEST_CHECK(r_r1 == 0x3456);

    OK(uc_close(uc));
}

static void test_armeb_be8_sub(void)
{
    uc_engine *uc;
    char code[] =
        "\x37\x00\xa0\xe3\x03\x10\x42\xe0"; // mov r0, #0x37; sub r1, r2, r3
    int r_r0 = 0x1234;
    int r_r2 = 0x6789;
    int r_r3 = 0x3333;
    int r_r1;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_ARMBE8, code,
                    sizeof(code) - 1, UC_CPU_ARM_CORTEX_A15);
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &r_r0));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r_r2));
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &r_r3));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r_r1));
    OK(uc_reg_read(uc, UC_ARM_REG_R2, &r_r2));
    OK(uc_reg_read(uc, UC_ARM_REG_R3, &r_r3));

    TEST_CHECK(r_r0 == 0x37);
    TEST_CHECK(r_r2 == 0x6789);
    TEST_CHECK(r_r3 == 0x3333);
    TEST_CHECK(r_r1 == 0x3456);

    OK(uc_close(uc));
}

static void test_arm_thumbeb_sub(void)
{
    uc_engine *uc;
    char code[] = "\xb0\x83"; // sub    sp, #0xc
    int r_sp = 0x1234;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1, UC_CPU_ARM_1176);
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_SP, &r_sp));
    TEST_CHECK(r_sp == 0x1228);

    OK(uc_close(uc));
}

static void test_arm_thumb_ite_count_callback(uc_engine *uc, uint64_t address,
                                              uint32_t size, void *user_data)
{
    uint64_t *count = (uint64_t *)user_data;

    (*count) += 1;
}

static void test_arm_thumb_ite(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] =
        "\x9a\x42\x15\xbf\x00\x9a\x01\x9a\x78\x23\x15\x23"; // cmp r2, r3; itete
                                                            // ne; ldrne r2,
                                                            // [sp]; ldreq r2,
                                                            // [sp,#4]; movne
                                                            // r3, #0x78; moveq
                                                            // r3, #0x15
    int r_sp = 0x8000;
    int r_r2 = 0;
    int r_r3 = 1;
    int r_pc = 0;
    uint64_t count = 0;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r_r2));
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &r_r3));

    OK(uc_mem_map(uc, r_sp, 0x1000, UC_PROT_ALL));
    r_r2 = LEINT32(0x68);
    OK(uc_mem_write(uc, r_sp, &r_r2, 4));
    r_r2 = LEINT32(0x4d);
    OK(uc_mem_write(uc, r_sp + 4, &r_r2, 4));

    OK(uc_hook_add(uc, &hook, UC_HOOK_CODE, test_arm_thumb_ite_count_callback,
                   &count, 1, 0));

    // Execute four instructions at a time.
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R2, &r_r2));
    OK(uc_reg_read(uc, UC_ARM_REG_R3, &r_r3));
    TEST_CHECK(r_r2 == 0x68);
    TEST_CHECK(count == 4);

    r_pc = code_start;
    r_r2 = 0;
    count = 0;
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r_r2));
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &r_r3));
    for (int i = 0; i < 6 && r_pc < code_start + sizeof(code) - 1; i++) {
        // Execute one instruction at a time.
        OK(uc_emu_start(uc, r_pc | 1, code_start + sizeof(code) - 1, 0, 1));

        OK(uc_reg_read(uc, UC_ARM_REG_PC, &r_pc));
    }
    OK(uc_reg_read(uc, UC_ARM_REG_R2, &r_r2));

    TEST_CHECK(r_r2 == 0x68);
    TEST_CHECK(r_r3 == 0x78);
    TEST_CHECK(count == 4);

    OK(uc_close(uc));
}

static void test_arm_m_thumb_mrs(void)
{
    uc_engine *uc;
    char code[] =
        "\xef\xf3\x14\x80\xef\xf3\x00\x81"; // mrs r0, control; mrs r1, apsr
    uint32_t r_control = 0b10;
    uint32_t r_apsr = (0b10101 << 27);
    uint32_t r_r0, r_r1;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS, code,
                    sizeof(code) - 1, UC_CPU_ARM_CORTEX_A15);

    OK(uc_reg_write(uc, UC_ARM_REG_CONTROL, &r_control));
    OK(uc_reg_write(uc, UC_ARM_REG_APSR_NZCVQ, &r_apsr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r_r1));

    TEST_CHECK(r_r0 == 0b10);
    TEST_CHECK(r_r1 == (0b10101 << 27));

    OK(uc_close(uc));
}

static void test_arm_m_control(void)
{
    uc_engine *uc;
    int r_control, r_msp, r_psp;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS, &uc));

    r_control = 0; // Make sure we are using MSP.
    OK(uc_reg_write(uc, UC_ARM_REG_CONTROL, &r_control));

    r_msp = 0x1000;
    OK(uc_reg_write(uc, UC_ARM_REG_R13, &r_msp));

    r_control = 0b10; // Make the switch.
    OK(uc_reg_write(uc, UC_ARM_REG_CONTROL, &r_control));

    OK(uc_reg_read(uc, UC_ARM_REG_R13, &r_psp));
    TEST_CHECK(r_psp != r_msp);

    r_psp = 0x2000;
    OK(uc_reg_write(uc, UC_ARM_REG_R13, &r_psp));

    r_control = 0; // Switch again
    OK(uc_reg_write(uc, UC_ARM_REG_CONTROL, &r_control));

    OK(uc_reg_read(uc, UC_ARM_REG_R13, &r_msp));
    TEST_CHECK(r_psp != r_msp);
    TEST_CHECK(r_msp == 0x1000);

    OK(uc_close(uc));
}

static void test_arm_m55_mve_id(void)
{
    uc_engine *uc;
    uint32_t mvfr0, mvfr1, mvfr2;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_M55));

    OK(uc_reg_read(uc, UC_ARM_REG_MVFR0, &mvfr0));
    OK(uc_reg_read(uc, UC_ARM_REG_MVFR1, &mvfr1));
    OK(uc_reg_read(uc, UC_ARM_REG_MVFR2, &mvfr2));

    TEST_CHECK(mvfr0 == 0x10110221);
    TEST_CHECK(mvfr1 == 0x12100211);
    TEST_CHECK(mvfr2 == 0x00000040);
    TEST_CHECK(((mvfr1 >> 8) & 0xf) == 2);
    TEST_CHECK(((mvfr1 >> 20) & 0xf) == 1);

    OK(uc_close(uc));

    OK(uc_open(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_M33));

    OK(uc_reg_read(uc, UC_ARM_REG_MVFR1, &mvfr1));
    TEST_CHECK(((mvfr1 >> 8) & 0xf) == 0);
    TEST_CHECK(((mvfr1 >> 20) & 0xf) == 0);

    OK(uc_close(uc));
}

static void test_arm_m55_vpr_public_reg(void)
{
    uc_engine *uc;
    uc_context *ctx;
    uint32_t vpr = 0x00abcdef;
    uint32_t read_vpr = 0;
    uint32_t changed_vpr = 0x00123456;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_M55));

    OK(uc_reg_write(uc, UC_ARM_REG_VPR, &vpr));
    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &read_vpr));
    TEST_CHECK(read_vpr == vpr);

    OK(uc_context_alloc(uc, &ctx));
    OK(uc_context_save(uc, ctx));
    OK(uc_context_reg_read(ctx, UC_ARM_REG_VPR, &read_vpr));
    TEST_CHECK(read_vpr == vpr);

    OK(uc_reg_write(uc, UC_ARM_REG_VPR, &changed_vpr));
    OK(uc_context_restore(uc, ctx));
    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &read_vpr));
    TEST_CHECK(read_vpr == vpr);

    OK(uc_context_free(ctx));
    OK(uc_close(uc));
}

static void test_arm_m55_vpr_sysreg(void)
{
    uc_engine *uc;
    uint8_t code[16];
    uint32_t vpr = 0x00abcdef;
    uint32_t p0 = 0x1357;
    uint32_t r1 = 0;
    uint32_t r3 = 0;
    uint32_t read_vpr = 0;
    uc_err err;

    test_arm_emit32(code, 0, 0x0a10eeec);  /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, 0x1a10eefc);  /* vmrs r1,vpr */
    test_arm_emit32(code, 8, 0x2a10eeed);  /* vmsr p0,r2 */
    test_arm_emit32(code, 12, 0x3a10eefd); /* vmrs r3,p0 */

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &p0));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r1));
    OK(uc_reg_read(uc, UC_ARM_REG_R3, &r3));
    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &read_vpr));
    TEST_CHECK(r1 == vpr);
    TEST_CHECK(r3 == p0);
    TEST_CHECK(read_vpr == ((vpr & 0x00ff0000) | p0));
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, 4, UC_CPU_ARM_CORTEX_M33);
    test_arm_enable_vfp(uc);
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    err = uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0);
    TEST_CHECK_(err == UC_ERR_INSN_INVALID, "err=%u", (unsigned)err);
    OK(uc_close(uc));
}

static void test_arm_m55_fpscr_ltpsize(void)
{
    const uint32_t ltpsize_shift = 16;
    const uint32_t ltpsize_mask = 7U << ltpsize_shift;
    uc_engine *uc;
    uint8_t code[8];
    uint32_t fpscr = 5U << ltpsize_shift;
    uint32_t read_fpscr = 0;
    uint32_t r1 = 0;

    test_arm_emit32(code, 0, 0x0a10eee1); /* vmsr fpscr,r0 */
    test_arm_emit32(code, 4, 0x1a10eef1); /* vmrs r1,fpscr */

    OK(uc_open(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_M55));
    OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));
    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &read_fpscr));
    TEST_CHECK((read_fpscr & ltpsize_mask) == fpscr);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    fpscr = 6U << ltpsize_shift;
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &fpscr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r1));
    TEST_CHECK((r1 & ltpsize_mask) == fpscr);
    OK(uc_close(uc));

    OK(uc_open(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_M33));
    fpscr = 3U << ltpsize_shift;
    OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));
    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &read_fpscr));
    TEST_CHECK((read_fpscr & ltpsize_mask) == 0);
    OK(uc_close(uc));
}

static void test_arm_m55_fpscr_nzcvqc_sysreg(void)
{
    const uint32_t fpcr_ahp = 1U << 26;
    const uint32_t fpcr_qc = 1U << 27;
    const uint32_t fpcr_v = 1U << 28;
    const uint32_t fpcr_c = 1U << 29;
    const uint32_t fpcr_z = 1U << 30;
    const uint32_t fpcr_n = 1U << 31;
    const uint32_t nzcvqc_mask =
        fpcr_n | fpcr_z | fpcr_c | fpcr_v | fpcr_qc;
    const uint32_t preserved = fpcr_ahp | (5U << 16);
    const uint32_t set_qc = fpcr_n | fpcr_c | fpcr_qc | 0x0000ffff;
    const uint32_t clear_qc = fpcr_z | fpcr_v | 0x0000ffff;
    const uint32_t expected_final =
        preserved | (clear_qc & (fpcr_n | fpcr_z | fpcr_c | fpcr_v));
    uc_engine *uc;
    uint8_t code[24];
    uint32_t r1 = 0;
    uint32_t r3 = 0;
    uint32_t r5 = 0;
    uc_err err;

    test_arm_emit32(code, 0, 0x4a10eee1);  /* vmsr fpscr,r4 */
    test_arm_emit32(code, 4, 0x0a10eee2);  /* vmsr fpscr_nzcvqc,r0 */
    test_arm_emit32(code, 8, 0x1a10eef2);  /* vmrs r1,fpscr_nzcvqc */
    test_arm_emit32(code, 12, 0x2a10eee2); /* vmsr fpscr_nzcvqc,r2 */
    test_arm_emit32(code, 16, 0x3a10eef2); /* vmrs r3,fpscr_nzcvqc */
    test_arm_emit32(code, 20, 0x5a10eef1); /* vmrs r5,fpscr */

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &set_qc));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &clear_qc));
    OK(uc_reg_write(uc, UC_ARM_REG_R4, &preserved));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r1));
    OK(uc_reg_read(uc, UC_ARM_REG_R3, &r3));
    OK(uc_reg_read(uc, UC_ARM_REG_R5, &r5));
    TEST_CHECK(r1 == (set_qc & nzcvqc_mask));
    TEST_CHECK(r3 == (clear_qc & nzcvqc_mask));
    TEST_CHECK_((r5 & (nzcvqc_mask | fpcr_ahp | (7U << 16))) ==
                expected_final, "fpscr=0x%08x expected=0x%08x", r5,
                expected_final);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)(code + 4), 4, UC_CPU_ARM_CORTEX_M33);
    test_arm_enable_vfp(uc);
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &set_qc));
    err = uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0);
    TEST_CHECK_(err == UC_ERR_INSN_INVALID, "err=%u", (unsigned)err);
    OK(uc_close(uc));
}

static void test_arm_m55_vctp(void)
{
    uc_engine *uc;
    uint8_t code[4];
    uint32_t r0 = 3;
    uint32_t vpr = 0;
    uc_err err;

    test_arm_emit32(code, 0, 0xe801f020); /* vctp.32 r0 */

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &r0));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &vpr));
    TEST_CHECK_(vpr == 0x00000fff, "vpr=0x%08x", vpr);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M33);
    test_arm_enable_vfp(uc);
    err = uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0);
    TEST_CHECK_(err == UC_ERR_INSN_INVALID, "err=%u", (unsigned)err);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_eci(void)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t eci_reserved = 3U << 12;
    uc_engine *uc;
    uint8_t code[4];
    uint32_t r0 = 3;
    uint32_t epsr;
    uint32_t vpr = 0;
    uc_err err;

    test_arm_emit32(code, 0, 0xe801f020); /* vctp.32 r0 */

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    epsr = xpsr_t | eci_a0a1;
    OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &r0));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &vpr));
    OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
    TEST_CHECK_(vpr == 0x00000f00, "vpr=0x%08x", vpr);
    TEST_CHECK_((epsr & (0xfc00 | (3U << 25))) == 0,
                "epsr=0x%08x", epsr);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    epsr = xpsr_t | eci_reserved;
    OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
    err = uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0);
    TEST_CHECK_(err == UC_ERR_EXCEPTION, "err=%u", (unsigned)err);
    OK(uc_close(uc));
}

static void test_arm_m55_vpst_vpnot(void)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    uc_engine *uc;
    uint8_t code[8];
    uint32_t epsr;
    uint32_t vpr;
    uc_err err;

    test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, 0x6f4dfe71); /* vpst 0xb */

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    vpr = 0x00001357;
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &vpr));
    TEST_CHECK_(vpr == 0x00bb1357, "vpr=0x%08x", vpr);
    OK(uc_close(uc));

    test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, 0xcf4dfe31); /* vpst 0x6 */

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    vpr = 0x00001357;
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
    epsr = xpsr_t | eci_a0a1;
    OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
    OK(uc_emu_start(uc, (code_start + 4) | 1, code_start + sizeof(code), 0,
                    0));
    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &vpr));
    OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
    TEST_CHECK_(vpr == 0x00601357, "vpr=0x%08x", vpr);
    TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                "epsr=0x%08x", epsr);
    OK(uc_close(uc));

    test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, 0x0f4dfe31); /* vpnot */

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    vpr = 0x0000a55a;
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &vpr));
    TEST_CHECK_(vpr == 0x00005aa5, "vpr=0x%08x", vpr);
    OK(uc_close(uc));

    test_arm_emit32(code, 0, 0x0f4dfe31); /* vpnot */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, 4,
                    UC_CPU_ARM_CORTEX_M33);
    test_arm_enable_vfp(uc);
    err = uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0);
    TEST_CHECK_(err == UC_ERR_EXCEPTION, "err=%u", (unsigned)err);
    OK(uc_close(uc));

    test_arm_emit32(code, 0, 0x6f4dfe71); /* vpst 0xb */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, 4,
                    UC_CPU_ARM_CORTEX_M33);
    test_arm_enable_vfp(uc);
    err = uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0);
    TEST_CHECK_(err == UC_ERR_EXCEPTION, "err=%u", (unsigned)err);
    OK(uc_close(uc));
}

static uint32_t test_arm_load_le(const uint8_t *data, unsigned size)
{
    uint32_t ret = 0;
    unsigned i;

    for (i = 0; i < size; i++) {
        ret |= (uint32_t)data[i] << (i * 8);
    }

    return ret;
}

static void test_arm_store_le(uint8_t *data, unsigned size, uint32_t value)
{
    unsigned i;

    for (i = 0; i < size; i++) {
        data[i] = (uint8_t)(value >> (i * 8));
    }
}

static uint64_t test_arm_load_le64(const uint8_t *data)
{
    uint64_t ret = 0;
    unsigned i;

    for (i = 0; i < 8; i++) {
        ret |= (uint64_t)data[i] << (i * 8);
    }

    return ret;
}

static void test_arm_store_le64(uint8_t *data, uint64_t value)
{
    unsigned i;

    for (i = 0; i < 8; i++) {
        data[i] = (uint8_t)(value >> (i * 8));
    }
}

static void test_arm_m_profile_activate_fp_context(uc_engine *uc)
{
    uint32_t control = (1U << 2) | (1U << 3);

    OK(uc_reg_write(uc, UC_ARM_REG_CONTROL, &control));
}

typedef struct {
    uint32_t count;
    uint32_t intno;
} ArmIntrCapture;

static void test_arm_intr_capture_cb(uc_engine *uc, uint32_t intno,
                                     void *data)
{
    ArmIntrCapture *capture = (ArmIntrCapture *)data;

    capture->count++;
    capture->intno = intno;
    OK(uc_emu_stop(uc));
}

static void test_arm_m55_vlstm_lazy_preserve(void)
{
    const uint32_t frame_addr = code_start + 0x2000;
    const uint32_t initial_s0 = 0x11223344;
    const uint32_t initial_fpscr = 0xa8000010;
    const uint32_t initial_vpr = 0x00ab1357;
    const uint32_t replacement_vpr = 0x0055cafe;
    ArmIntrCapture capture = { 0 };
    uc_engine *uc;
    uc_hook hook;
    uint8_t code[8];
    uint8_t frame[0x48] = { 0 };
    uint32_t vpr;
    uc_err err;

    test_arm_emit32(code, 0, 0x0a80ec20); /* vlstm r0 */
    test_arm_emit32(code, 4, 0x1a10eeec); /* vmsr vpr,r1 */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    test_arm_m_profile_activate_fp_context(uc);
    OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_arm_intr_capture_cb,
                   &capture, 1, 0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &frame_addr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &replacement_vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_S0, &initial_s0));
    OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &initial_fpscr));
    OK(uc_reg_write(uc, UC_ARM_REG_VPR, &initial_vpr));

    err = uc_emu_start(uc, code_start | 1,
                       code_start + sizeof(code), 0, 0);
    OK(uc_mem_read(uc, frame_addr, frame, sizeof(frame)));
    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &vpr));

    TEST_CHECK_(err == UC_ERR_OK, "err=%u count=%u intno=%u",
                (unsigned)err, capture.count, capture.intno);
    TEST_CHECK_(capture.count == 0, "count=%u intno=%u",
                capture.count, capture.intno);
    TEST_CHECK(test_arm_load_le(frame, 4) == initial_s0);
    TEST_CHECK(test_arm_load_le(frame + 0x40, 4) == initial_fpscr);
    TEST_CHECK(test_arm_load_le(frame + 0x44, 4) == initial_vpr);
    TEST_CHECK_(vpr == replacement_vpr,
                "vpr=0x%08x expected=0x%08x",
                vpr, replacement_vpr);
    OK(uc_close(uc));
}

static void test_arm_m55_vlstm_lazy_fault(void)
{
    const uint32_t frame_addr = 0x800000;
    const uint32_t initial_vpr = 0x00ab1357;
    const uint32_t replacement_vpr = 0x0055cafe;
    ArmIntrCapture capture = { 0 };
    uc_engine *uc;
    uc_hook hook;
    uint8_t code[8];
    uint32_t vpr;

    test_arm_emit32(code, 0, 0x0a80ec20); /* vlstm r0 */
    test_arm_emit32(code, 4, 0x1a10eeec); /* vmsr vpr,r1 */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    test_arm_m_profile_activate_fp_context(uc);
    OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_arm_intr_capture_cb,
                   &capture, 1, 0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &frame_addr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &replacement_vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_VPR, &initial_vpr));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &vpr));

    TEST_CHECK_(capture.count == 1, "count=%u intno=%u",
                capture.count, capture.intno);
    TEST_CHECK_(capture.intno == 20, "intno=%u", capture.intno);
    TEST_CHECK(vpr == initial_vpr);
    OK(uc_close(uc));
}

static void test_arm_m55_sysreg_mem(void)
{
    const uint32_t fpcr_ahp = 1U << 26;
    const uint32_t fpcr_qc = 1U << 27;
    const uint32_t fpcr_v = 1U << 28;
    const uint32_t fpcr_c = 1U << 29;
    const uint32_t fpcr_z = 1U << 30;
    const uint32_t fpcr_n = 1U << 31;
    const uint32_t ltpsize_mask = 7U << 16;
    const uint32_t nzcvqc_mask =
        fpcr_n | fpcr_z | fpcr_c | fpcr_v | fpcr_qc;
    const uint64_t data_addr = code_start + 0x1000;
    const uint32_t initial_vpr = 0x00ab1357;
    const uint32_t p0_load = 0x0000a55a;
    const uint32_t loaded_vpr = 0x00cd2468;
    const uint32_t preserved = fpcr_ahp | (5U << 16);
    const uint32_t fpscr_initial =
        preserved | fpcr_n | fpcr_c | fpcr_qc | 0x1234;
    const uint32_t fpscr_load = fpcr_z | fpcr_v | 0xffff;
    const uint32_t fpscr_expected = preserved | fpcr_z | fpcr_v;
    uc_engine *uc;
    uint8_t code[44];
    uint8_t mem[32] = { 0 };
    uint32_t r1 = (uint32_t)data_addr;
    uint32_t r2 = (uint32_t)data_addr + 16;
    uint32_t r3 = 0;
    uint32_t r4 = 0;
    uint32_t r6 = 0;
    uint32_t read_vpr = 0;
    uc_err err;

    test_arm_emit32(code, 0, 0x0a10eeec);  /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, 0xaf80edc1);  /* vstr p0,[r1,#0] */
    test_arm_emit32(code, 8, 0x8f81edc1);  /* vstr vpr,[r1,#4] */
    test_arm_emit32(code, 12, 0xaf82edd1); /* vldr p0,[r1,#8] */
    test_arm_emit32(code, 16, 0x3a10eefc); /* vmrs r3,vpr */
    test_arm_emit32(code, 20, 0x8f81ecf2); /* vldr vpr,[r2],#4 */
    test_arm_emit32(code, 24, 0x4a10eefc); /* vmrs r4,vpr */
    test_arm_emit32(code, 28, 0x5a10eee1); /* vmsr fpscr,r5 */
    test_arm_emit32(code, 32, 0x4f85ed81); /* vstr fpscr_nzcvqc,[r1,#20] */
    test_arm_emit32(code, 36, 0x4f86ed91); /* vldr fpscr_nzcvqc,[r1,#24] */
    test_arm_emit32(code, 40, 0x6a10eef1); /* vmrs r6,fpscr */

    test_arm_store_le(mem + 8, 4, p0_load);
    test_arm_store_le(mem + 16, 4, loaded_vpr);
    test_arm_store_le(mem + 24, 4, fpscr_load);

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &initial_vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r1));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r2));
    OK(uc_reg_write(uc, UC_ARM_REG_R5, &fpscr_initial));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));

    memset(mem, 0, sizeof(mem));
    OK(uc_mem_read(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_read(uc, UC_ARM_REG_R2, &r2));
    OK(uc_reg_read(uc, UC_ARM_REG_R3, &r3));
    OK(uc_reg_read(uc, UC_ARM_REG_R4, &r4));
    OK(uc_reg_read(uc, UC_ARM_REG_R6, &r6));
    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &read_vpr));

    TEST_CHECK(test_arm_load_le(mem, 4) == (initial_vpr & 0xffff));
    TEST_CHECK(test_arm_load_le(mem + 4, 4) == initial_vpr);
    TEST_CHECK(test_arm_load_le(mem + 20, 4) ==
               (fpscr_initial & nzcvqc_mask));
    TEST_CHECK(r2 == (uint32_t)data_addr + 20);
    TEST_CHECK(r3 == ((initial_vpr & 0x00ff0000) |
                      (p0_load & 0xffff)));
    TEST_CHECK(r4 == loaded_vpr);
    TEST_CHECK(read_vpr == loaded_vpr);
    TEST_CHECK((r6 & (fpcr_ahp | ltpsize_mask | nzcvqc_mask)) ==
               fpscr_expected);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code + 4, 4, UC_CPU_ARM_CORTEX_M33);
    test_arm_enable_vfp(uc);
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r1));
    err = uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0);
    TEST_CHECK_(err == UC_ERR_EXCEPTION, "err=%u", (unsigned)err);
    OK(uc_close(uc));
}

static void test_arm_m55_vscclrm(void)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint32_t active_vpr = 0x00abcdef;
    const uint32_t inactive_vpr = 0x00123456;
    uc_engine *uc;
    uint8_t code[8];
    uint32_t s0 = 0x11111111;
    uint32_t s1 = 0x22222222;
    uint32_t s2 = 0x33333333;
    uint32_t s3 = 0x44444444;
    uint32_t s4 = 0x55555555;
    uint32_t vpr;
    uint32_t epsr;
    uc_err err;

    test_arm_emit32(code, 0, 0x0a01ec9f); /* vscclrm s0,#1 */
    test_arm_emit32(code, 4, 0x1b02ec9f); /* vscclrm d1,#1 */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    test_arm_m_profile_activate_fp_context(uc);
    OK(uc_reg_write(uc, UC_ARM_REG_S0, &s0));
    OK(uc_reg_write(uc, UC_ARM_REG_S1, &s1));
    OK(uc_reg_write(uc, UC_ARM_REG_S2, &s2));
    OK(uc_reg_write(uc, UC_ARM_REG_S3, &s3));
    OK(uc_reg_write(uc, UC_ARM_REG_S4, &s4));
    OK(uc_reg_write(uc, UC_ARM_REG_VPR, &active_vpr));
    epsr = xpsr_t | eci_a0a1;
    OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_S0, &s0));
    OK(uc_reg_read(uc, UC_ARM_REG_S1, &s1));
    OK(uc_reg_read(uc, UC_ARM_REG_S2, &s2));
    OK(uc_reg_read(uc, UC_ARM_REG_S3, &s3));
    OK(uc_reg_read(uc, UC_ARM_REG_S4, &s4));
    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &vpr));
    OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
    TEST_CHECK(s0 == 0);
    TEST_CHECK(s1 == 0x22222222);
    TEST_CHECK(s2 == 0);
    TEST_CHECK(s3 == 0);
    TEST_CHECK(s4 == 0x55555555);
    TEST_CHECK(vpr == 0);
    TEST_CHECK_((epsr & epsr_condexec_mask) == 0, "epsr=0x%08x", epsr);
    OK(uc_close(uc));

    s0 = 0x77777777;
    test_arm_emit32(code, 0, 0x0a01ec9f); /* vscclrm s0,#1 */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, 4, UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    OK(uc_reg_write(uc, UC_ARM_REG_S0, &s0));
    OK(uc_reg_write(uc, UC_ARM_REG_VPR, &inactive_vpr));
    OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_S0, &s0));
    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &vpr));
    TEST_CHECK(s0 == 0x77777777);
    TEST_CHECK(vpr == inactive_vpr);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, 4, UC_CPU_ARM_CORTEX_M33);
    test_arm_enable_vfp(uc);
    err = uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0);
    TEST_CHECK_(err == UC_ERR_INSN_INVALID, "err=%u", (unsigned)err);
    OK(uc_close(uc));
}

static void test_arm_mve_expected_logic(uint8_t *expected,
                                        const uint8_t *initial,
                                        const uint8_t *n, const uint8_t *m,
                                        char op, uint16_t mask)
{
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i++) {
        uint8_t value;

        switch (op) {
        case '&':
            value = n[i] & m[i];
            break;
        case 'b':
            value = n[i] & ~m[i];
            break;
        case '|':
            value = n[i] | m[i];
            break;
        case 'o':
            value = n[i] | ~m[i];
            break;
        case '^':
            value = n[i] ^ m[i];
            break;
        default:
            value = 0;
            break;
        }
        if (mask & (1U << i)) {
            expected[i] = value;
        }
    }
}

static void test_arm_mve_expected_addsub(uint8_t *expected,
                                         const uint8_t *initial,
                                         const uint8_t *n,
                                         const uint8_t *m,
                                         unsigned esize, bool sub,
                                         uint16_t mask)
{
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += esize) {
        uint32_t lhs = test_arm_load_le(n + i, esize);
        uint32_t rhs = test_arm_load_le(m + i, esize);
        uint32_t value = sub ? lhs - rhs : lhs + rhs;
        uint8_t lane[4];
        unsigned b;

        test_arm_store_le(lane, esize, value);
        for (b = 0; b < esize; b++) {
            if (mask & (1U << (i + b))) {
                expected[i + b] = lane[b];
            }
        }
    }
}

static void test_arm_mve_expected_mul(uint8_t *expected,
                                      const uint8_t *initial,
                                      const uint8_t *n, const uint8_t *m,
                                      unsigned esize, uint16_t mask)
{
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += esize) {
        uint32_t lhs = test_arm_load_le(n + i, esize);
        uint32_t rhs = test_arm_load_le(m + i, esize);
        uint32_t value = lhs * rhs;
        uint8_t lane[4];
        unsigned b;

        test_arm_store_le(lane, esize, value);
        for (b = 0; b < esize; b++) {
            if (mask & (1U << (i + b))) {
                expected[i + b] = lane[b];
            }
        }
    }
}

static void test_arm_mve_expected_scalar_2op(uint8_t *expected,
                                             const uint8_t *initial,
                                             const uint8_t *n,
                                             uint32_t scalar,
                                             unsigned esize, char op,
                                             uint16_t mask)
{
    uint32_t smask = esize == 4 ? UINT32_MAX : ((1U << (esize * 8)) - 1);
    uint32_t rhs = scalar & smask;
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += esize) {
        uint32_t lhs = test_arm_load_le(n + i, esize);
        uint32_t value;
        uint8_t lane[4];
        unsigned b;

        switch (op) {
        case '+':
            value = lhs + rhs;
            break;
        case '-':
            value = lhs - rhs;
            break;
        case '*':
            value = lhs * rhs;
            break;
        default:
            value = 0;
            break;
        }

        test_arm_store_le(lane, esize, value);
        for (b = 0; b < esize; b++) {
            if (mask & (1U << (i + b))) {
                expected[i + b] = lane[b];
            }
        }
    }
}

static uint32_t test_arm_reverse_bits(uint32_t value, unsigned bits)
{
    uint32_t result = 0;
    unsigned bit;

    for (bit = 0; bit < bits; bit++) {
        result <<= 1;
        result |= (value >> bit) & 1U;
    }

    return result;
}

static int64_t test_arm_sign_extend(uint32_t value, unsigned bits)
{
    uint64_t sign = 1ULL << (bits - 1);
    uint64_t mask = bits == 32 ? UINT32_MAX : ((1ULL << bits) - 1);

    value &= (uint32_t)mask;
    return (int64_t)((value ^ sign) - sign);
}

static void test_arm_mve_expected_mulh(uint8_t *expected,
                                       const uint8_t *initial,
                                       const uint8_t *n,
                                       const uint8_t *m,
                                       unsigned esize, bool is_signed,
                                       bool rounded, uint16_t mask)
{
    unsigned bits = esize * 8;
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += esize) {
        uint32_t lhs = test_arm_load_le(n + i, esize);
        uint32_t rhs = test_arm_load_le(m + i, esize);
        uint32_t result;
        unsigned b;

        if (is_signed) {
            int64_t slhs = test_arm_sign_extend(lhs, bits);
            int64_t srhs = test_arm_sign_extend(rhs, bits);
            int64_t sresult = slhs * srhs;

            if (rounded) {
                sresult += (int64_t)(1ULL << (bits - 1));
            }
            result = (uint32_t)(sresult >> bits);
        } else {
            uint64_t uresult = (uint64_t)lhs * rhs;

            if (rounded) {
                uresult += 1ULL << (bits - 1);
            }
            result = (uint32_t)(uresult >> bits);
        }

        for (b = 0; b < esize; b++) {
            if (mask & (1U << (i + b))) {
                expected[i + b] = (uint8_t)(result >> (b * 8));
            }
        }
    }
}

static void test_arm_mve_store_masked(uint8_t *expected, size_t offset,
                                      unsigned size, uint64_t value,
                                      uint16_t mask)
{
    uint8_t lane[8];
    unsigned b;

    if (size == 8) {
        test_arm_store_le64(lane, value);
    } else {
        test_arm_store_le(lane, size, (uint32_t)value);
    }
    for (b = 0; b < size; b++) {
        if (mask & (1U << (offset + b))) {
            expected[offset + b] = lane[b];
        }
    }
}

static void test_arm_mve_expected_vbrsr(uint8_t *expected,
                                        const uint8_t *initial,
                                        const uint8_t *n, uint32_t scalar,
                                        unsigned esize, uint16_t mask)
{
    unsigned bits = esize * 8;
    uint32_t count = scalar & 0xff;
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += esize) {
        uint32_t value = 0;

        if (count != 0) {
            value = test_arm_reverse_bits(test_arm_load_le(n + i, esize),
                                          bits);
            if (count < bits) {
                value >>= bits - count;
            }
        }
        test_arm_mve_store_masked(expected, i, esize, value, mask);
    }
}

static void test_arm_mve_expected_scalar_acc(uint8_t *expected,
                                             const uint8_t *initial,
                                             const uint8_t *n,
                                             uint32_t scalar, unsigned esize,
                                             bool sub, uint16_t mask)
{
    uint64_t smask = esize == 4 ? UINT32_MAX : ((1ULL << (esize * 8)) - 1);
    uint64_t m = scalar & smask;
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += esize) {
        uint64_t d = test_arm_load_le(initial + i, esize);
        uint64_t value = test_arm_load_le(n + i, esize);
        uint64_t result = sub ? value * d + m : value * m + d;

        test_arm_mve_store_masked(expected, i, esize, result, mask);
    }
}

static void test_arm_mve_expected_vmull(uint8_t *expected,
                                        const uint8_t *initial,
                                        const uint8_t *n,
                                        const uint8_t *m,
                                        unsigned esize, bool top,
                                        bool is_signed, uint16_t mask)
{
    unsigned bits = esize * 8;
    unsigned lesize = esize * 2;
    size_t le;

    memcpy(expected, initial, 16);
    for (le = 0; le < 16 / lesize; le++) {
        size_t src = le * 2 + (top ? 1 : 0);
        size_t dst = le * lesize;
        uint32_t lhs = test_arm_load_le(n + src * esize, esize);
        uint32_t rhs = test_arm_load_le(m + src * esize, esize);
        uint64_t result;

        if (is_signed) {
            int64_t slhs = test_arm_sign_extend(lhs, bits);
            int64_t srhs = test_arm_sign_extend(rhs, bits);

            result = (uint64_t)(slhs * srhs);
        } else {
            result = (uint64_t)lhs * rhs;
        }
        test_arm_mve_store_masked(expected, dst, lesize, result, mask);
    }
}

static uint64_t test_arm_mve_poly_mul(uint32_t lhs, uint32_t rhs,
                                      unsigned bits)
{
    uint64_t result = 0;
    unsigned bit;

    for (bit = 0; bit < bits; bit++) {
        if (lhs & (1U << bit)) {
            result ^= (uint64_t)rhs << bit;
        }
    }

    return result;
}

static void test_arm_mve_expected_vmullp(uint8_t *expected,
                                         const uint8_t *initial,
                                         const uint8_t *n,
                                         const uint8_t *m,
                                         unsigned bits, bool top,
                                         uint16_t mask)
{
    unsigned esize = bits / 8;
    unsigned lesize = esize * 2;
    size_t le;

    memcpy(expected, initial, 16);
    for (le = 0; le < 16 / lesize; le++) {
        size_t src = le * 2 + (top ? 1 : 0);
        size_t dst = le * lesize;
        uint32_t lhs = test_arm_load_le(n + src * esize, esize);
        uint32_t rhs = test_arm_load_le(m + src * esize, esize);
        uint64_t result = test_arm_mve_poly_mul(lhs, rhs, bits);

        test_arm_mve_store_masked(expected, dst, lesize, result, mask);
    }
}

static void test_arm_mve_expected_qdmull(uint8_t *expected,
                                         const uint8_t *initial,
                                         const uint8_t *n,
                                         const uint8_t *m,
                                         unsigned esize, bool top,
                                         uint16_t mask, bool *qc)
{
    const int64_t int64_min = -0x7fffffffffffffffLL - 1;
    const int64_t int64_max = 0x7fffffffffffffffLL;
    unsigned bits = esize * 8;
    unsigned lesize = esize * 2;
    unsigned satmask = esize == 2 ? (top ? (1U << 2) : 1U) :
        ((1U << 4) | 1U);
    int64_t min = lesize == 8 ? int64_min : -(1LL << (lesize * 8 - 1));
    int64_t max = lesize == 8 ? int64_max : (1LL << (lesize * 8 - 1)) - 1;
    size_t le;

    memcpy(expected, initial, 16);
    *qc = false;
    for (le = 0; le < 16 / lesize; le++) {
        size_t src = le * 2 + (top ? 1 : 0);
        size_t dst = le * lesize;
        int64_t lhs = test_arm_sign_extend(test_arm_load_le(n + src * esize,
                                                            esize), bits);
        int64_t rhs = test_arm_sign_extend(test_arm_load_le(m + src * esize,
                                                            esize), bits);
        int64_t product = lhs * rhs;
        int64_t result;
        bool saturated = false;

        if (esize == 4) {
            if (product > int64_max / 2) {
                result = int64_max;
                saturated = true;
            } else if (product < int64_min / 2) {
                result = int64_min;
                saturated = true;
            } else {
                result = product * 2;
            }
        } else {
            result = product * 2;
            if (result > max) {
                result = max;
                saturated = true;
            } else if (result < min) {
                result = min;
                saturated = true;
            }
        }

        if (saturated && ((mask >> dst) & satmask)) {
            *qc = true;
        }
        test_arm_mve_store_masked(expected, dst, lesize, (uint64_t)result,
                                  mask);
    }
}

static void test_arm_mve_expected_qdmlah(uint8_t *expected,
                                         const uint8_t *initial,
                                         const uint8_t *n, uint32_t scalar,
                                         unsigned esize, bool sub,
                                         bool rounded, uint16_t mask,
                                         bool *qc)
{
    const int64_t int64_min = -0x7fffffffffffffffLL - 1;
    const int64_t int64_max = 0x7fffffffffffffffLL;
    unsigned bits = esize * 8;
    int64_t min = bits == 32 ? int64_min : -(1LL << (bits * 2 - 1));
    int64_t max = bits == 32 ? int64_max : (1LL << (bits * 2 - 1)) - 1;
    int64_t m = test_arm_sign_extend(scalar, bits);
    size_t i;

    memcpy(expected, initial, 16);
    *qc = false;
    for (i = 0; i < 16; i += esize) {
        int64_t d = test_arm_sign_extend(test_arm_load_le(initial + i, esize),
                                         bits);
        int64_t value = test_arm_sign_extend(test_arm_load_le(n + i, esize),
                                             bits);
        int64_t product_lhs = value;
        int64_t product_rhs = sub ? d : m;
        int64_t addend = sub ? m : d;
        int64_t result = product_lhs * product_rhs * 2;
        bool saturated = false;

        result += addend * (1LL << bits);
        if (rounded) {
            result += 1LL << (bits - 1);
        }
        if (result > max) {
            result = max;
            saturated = true;
        } else if (result < min) {
            result = min;
            saturated = true;
        }
        result >>= bits;
        if (saturated && (mask & (1U << i))) {
            *qc = true;
        }
        test_arm_mve_store_masked(expected, i, esize, (uint64_t)result, mask);
    }
}

static void test_arm_mve_expected_minmax(uint8_t *expected,
                                         const uint8_t *initial,
                                         const uint8_t *n,
                                         const uint8_t *m,
                                         unsigned esize, bool is_signed,
                                         bool is_min, uint16_t mask)
{
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += esize) {
        uint32_t lhs = test_arm_load_le(n + i, esize);
        uint32_t rhs = test_arm_load_le(m + i, esize);
        uint32_t result;
        unsigned b;

        if (is_signed) {
            int64_t slhs = test_arm_sign_extend(lhs, esize * 8);
            int64_t srhs = test_arm_sign_extend(rhs, esize * 8);
            int64_t sresult = is_min ?
                (slhs <= srhs ? slhs : srhs) :
                (slhs >= srhs ? slhs : srhs);

            result = (uint32_t)sresult;
        } else {
            result = is_min ?
                (lhs <= rhs ? lhs : rhs) :
                (lhs >= rhs ? lhs : rhs);
        }

        for (b = 0; b < esize; b++) {
            if (mask & (1U << (i + b))) {
                expected[i + b] = (uint8_t)(result >> (b * 8));
            }
        }
    }
}

static void test_arm_mve_expected_abd(uint8_t *expected,
                                      const uint8_t *initial,
                                      const uint8_t *n,
                                      const uint8_t *m,
                                      unsigned esize, bool is_signed,
                                      uint16_t mask)
{
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += esize) {
        uint32_t lhs = test_arm_load_le(n + i, esize);
        uint32_t rhs = test_arm_load_le(m + i, esize);
        uint32_t result;
        unsigned b;

        if (is_signed) {
            int64_t slhs = test_arm_sign_extend(lhs, esize * 8);
            int64_t srhs = test_arm_sign_extend(rhs, esize * 8);
            uint64_t diff = slhs >= srhs ? slhs - srhs : srhs - slhs;

            result = (uint32_t)diff;
        } else {
            result = lhs >= rhs ? lhs - rhs : rhs - lhs;
        }

        for (b = 0; b < esize; b++) {
            if (mask & (1U << (i + b))) {
                expected[i + b] = (uint8_t)(result >> (b * 8));
            }
        }
    }
}

static void test_arm_mve_expected_halving(uint8_t *expected,
                                          const uint8_t *initial,
                                          const uint8_t *n,
                                          const uint8_t *m,
                                          unsigned esize, bool is_signed,
                                          bool sub, bool rounded,
                                          uint16_t mask)
{
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += esize) {
        uint32_t lhs = test_arm_load_le(n + i, esize);
        uint32_t rhs = test_arm_load_le(m + i, esize);
        uint32_t result;
        unsigned b;

        if (is_signed) {
            int64_t slhs = test_arm_sign_extend(lhs, esize * 8);
            int64_t srhs = test_arm_sign_extend(rhs, esize * 8);
            int64_t sresult = sub ? slhs - srhs : slhs + srhs;

            if (rounded) {
                sresult++;
            }
            sresult >>= 1;
            result = (uint32_t)sresult;
        } else {
            uint64_t uresult = sub ? (uint64_t)lhs - rhs :
                (uint64_t)lhs + rhs;

            if (rounded) {
                uresult++;
            }
            uresult >>= 1;
            result = (uint32_t)uresult;
        }

        for (b = 0; b < esize; b++) {
            if (mask & (1U << (i + b))) {
                expected[i + b] = (uint8_t)(result >> (b * 8));
            }
        }
    }
}

static void test_arm_mve_expected_cadd(uint8_t *expected,
                                       const uint8_t *initial,
                                       const uint8_t *n,
                                       const uint8_t *m,
                                       unsigned esize, bool rot270,
                                       bool halving, uint16_t mask)
{
    unsigned bits = esize * 8;
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += esize * 2) {
        int64_t n0 = test_arm_sign_extend(test_arm_load_le(n + i, esize),
                                          bits);
        int64_t n1 = test_arm_sign_extend(test_arm_load_le(n + i + esize,
                                                           esize), bits);
        int64_t m0 = test_arm_sign_extend(test_arm_load_le(m + i, esize),
                                          bits);
        int64_t m1 = test_arm_sign_extend(test_arm_load_le(m + i + esize,
                                                           esize), bits);
        int64_t r0 = rot270 ? n0 + m1 : n0 - m1;
        int64_t r1 = rot270 ? n1 - m0 : n1 + m0;

        if (halving) {
            r0 >>= 1;
            r1 >>= 1;
        }
        test_arm_mve_store_masked(expected, i, esize, (uint64_t)r0, mask);
        test_arm_mve_store_masked(expected, i + esize, esize,
                                  (uint64_t)r1, mask);
    }
}

static void test_arm_mve_expected_qaddsub(uint8_t *expected,
                                          const uint8_t *initial,
                                          const uint8_t *n,
                                          const uint8_t *m,
                                          unsigned esize, bool is_signed,
                                          bool sub, uint16_t mask, bool *qc)
{
    unsigned bits = esize * 8;
    size_t i;

    memcpy(expected, initial, 16);
    *qc = false;
    for (i = 0; i < 16; i += esize) {
        uint32_t lhs = test_arm_load_le(n + i, esize);
        uint32_t rhs = test_arm_load_le(m + i, esize);
        uint32_t result;
        bool saturated = false;
        unsigned b;

        if (is_signed) {
            int64_t min = -(1LL << (bits - 1));
            int64_t max = (1LL << (bits - 1)) - 1;
            int64_t slhs = test_arm_sign_extend(lhs, bits);
            int64_t srhs = test_arm_sign_extend(rhs, bits);
            int64_t sresult = sub ? slhs - srhs : slhs + srhs;

            if (sresult > max) {
                sresult = max;
                saturated = true;
            } else if (sresult < min) {
                sresult = min;
                saturated = true;
            }
            result = (uint32_t)sresult;
        } else {
            uint64_t max = bits == 32 ? UINT32_MAX : ((1ULL << bits) - 1);
            uint64_t uresult;

            if (sub && lhs < rhs) {
                uresult = 0;
                saturated = true;
            } else {
                uresult = sub ? (uint64_t)lhs - rhs : (uint64_t)lhs + rhs;
                if (uresult > max) {
                    uresult = max;
                    saturated = true;
                }
            }
            result = (uint32_t)uresult;
        }

        if (saturated && (mask & (1U << i))) {
            *qc = true;
        }
        for (b = 0; b < esize; b++) {
            if (mask & (1U << (i + b))) {
                expected[i + b] = (uint8_t)(result >> (b * 8));
            }
        }
    }
}

static void test_arm_mve_expected_shift(uint8_t *expected,
                                        const uint8_t *initial,
                                        const uint8_t *values,
                                        const uint8_t *shifts,
                                        unsigned esize, bool is_signed,
                                        bool rounded, uint16_t mask)
{
    unsigned bits = esize * 8;
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += esize) {
        uint32_t value = test_arm_load_le(values + i, esize);
        int8_t shift = (int8_t)test_arm_load_le(shifts + i, esize);
        uint32_t result;
        unsigned b;

        if (is_signed) {
            int64_t svalue = test_arm_sign_extend(value, bits);
            int64_t sresult;

            if (shift <= -(int)bits) {
                sresult = rounded ? 0 : (svalue < 0 ? -1 : 0);
            } else if (shift < 0) {
                if (rounded) {
                    svalue >>= -shift - 1;
                    sresult = (svalue >> 1) + (svalue & 1);
                } else {
                    sresult = svalue >> -shift;
                }
            } else if (shift < (int)bits) {
                sresult = (uint32_t)value << shift;
            } else {
                sresult = 0;
            }
            result = (uint32_t)sresult;
        } else {
            uint64_t uvalue = value;
            uint64_t uresult;

            if (shift <= -((int)bits + rounded)) {
                uresult = 0;
            } else if (shift < 0) {
                if (rounded) {
                    uvalue >>= -shift - 1;
                    uresult = (uvalue >> 1) + (uvalue & 1);
                } else {
                    uresult = uvalue >> -shift;
                }
            } else if (shift < (int)bits) {
                uresult = uvalue << shift;
            } else {
                uresult = 0;
            }
            result = (uint32_t)uresult;
        }

        for (b = 0; b < esize; b++) {
            if (mask & (1U << (i + b))) {
                expected[i + b] = (uint8_t)(result >> (b * 8));
            }
        }
    }
}

static uint32_t test_arm_mve_expected_qshift_scalar_lane(uint32_t src,
                                                        unsigned bits,
                                                        int8_t shift,
                                                        bool is_signed,
                                                        bool rounded,
                                                        bool *saturated);

static void test_arm_mve_expected_qshift(uint8_t *expected,
                                         const uint8_t *initial,
                                         const uint8_t *values,
                                         const uint8_t *shifts,
                                         unsigned esize, bool is_signed,
                                         bool rounded, uint16_t pred,
                                         bool *qc);

static void test_arm_mve_fill_scalar_shift(uint8_t *shifts, unsigned esize,
                                           uint32_t rm)
{
    size_t i;

    for (i = 0; i < 16; i += esize) {
        test_arm_store_le(shifts + i, esize, rm);
    }
}

static void test_arm_mve_expected_qdmulh(uint8_t *expected,
                                          const uint8_t *initial,
                                          const uint8_t *n,
                                          const uint8_t *m,
                                          unsigned esize, bool rounded,
                                         uint16_t mask, bool *qc)
{
    unsigned bits = esize * 8;
    int64_t min = -(1LL << (bits - 1));
    int64_t max = (1LL << (bits - 1)) - 1;
    size_t i;

    memcpy(expected, initial, 16);
    *qc = false;
    for (i = 0; i < 16; i += esize) {
        int64_t lhs = test_arm_sign_extend(test_arm_load_le(n + i, esize),
                                           bits);
        int64_t rhs = test_arm_sign_extend(test_arm_load_le(m + i, esize),
                                           bits);
        int64_t result = lhs * rhs;
        bool saturated = false;
        unsigned b;

        if (rounded) {
            result += 1LL << (bits - 2);
        }
        result >>= bits - 1;
        if (result > max) {
            result = max;
            saturated = true;
        } else if (result < min) {
            result = min;
            saturated = true;
        }
        if (saturated && (mask & (1U << i))) {
            *qc = true;
        }
        for (b = 0; b < esize; b++) {
            if (mask & (1U << (i + b))) {
                expected[i + b] = (uint8_t)((uint64_t)result >> (b * 8));
            }
        }
    }
}

static bool test_arm_sadd64_overflow(int64_t lhs, int64_t rhs, int64_t *ret)
{
    uint64_t ulhs = (uint64_t)lhs;
    uint64_t urhs = (uint64_t)rhs;
    uint64_t ures = ulhs + urhs;

    *ret = (int64_t)ures;
    return ((~(ulhs ^ urhs) & (ulhs ^ ures)) >> 63) != 0;
}

static bool test_arm_ssub64_overflow(int64_t lhs, int64_t rhs, int64_t *ret)
{
    uint64_t ulhs = (uint64_t)lhs;
    uint64_t urhs = (uint64_t)rhs;
    uint64_t ures = ulhs - urhs;

    *ret = (int64_t)ures;
    return (((ulhs ^ urhs) & (ulhs ^ ures)) >> 63) != 0;
}

static int32_t test_arm_mve_expected_qdmladh_lane(
    int64_t a, int64_t b, int64_t c, int64_t d, unsigned esize,
    bool subtract, bool rounded, bool *saturated)
{
    unsigned bits = esize * 8;

    *saturated = false;
    if (esize == 4) {
        int64_t m1 = a * b;
        int64_t m2 = c * d;
        int64_t result;

        if ((subtract ? test_arm_ssub64_overflow(m1, m2, &result) :
             test_arm_sadd64_overflow(m1, m2, &result)) ||
            test_arm_sadd64_overflow(result,
                                     (int64_t)rounded << 30, &result) ||
            test_arm_sadd64_overflow(result, result, &result)) {
            *saturated = true;
            return result < 0 ? INT32_MAX : INT32_MIN;
        }
        return (int32_t)(result >> 32);
    } else {
        int64_t min = -(1LL << (bits * 2 - 1));
        int64_t max = (1LL << (bits * 2 - 1)) - 1;
        int64_t result = subtract ? a * b - c * d : a * b + c * d;

        result = result * 2 + ((int64_t)rounded << (bits - 1));
        if (result > max) {
            result = max;
            *saturated = true;
        } else if (result < min) {
            result = min;
            *saturated = true;
        }
        return (int32_t)(result >> bits);
    }
}

static void test_arm_mve_expected_qdmladh(uint8_t *expected,
                                          const uint8_t *initial,
                                          const uint8_t *n,
                                          const uint8_t *m,
                                          unsigned esize, bool subtract,
                                          bool exchange, bool rounded,
                                          uint16_t mask, bool *qc)
{
    unsigned bits = esize * 8;
    size_t e;

    memcpy(expected, initial, 16);
    *qc = false;
    for (e = 0; e < 16 / esize; e++) {
        size_t off = e * esize;
        bool saturated;
        int64_t a;
        int64_t b;
        int64_t c;
        int64_t d;
        int32_t result;

        if ((e & 1) != exchange) {
            continue;
        }
        a = test_arm_sign_extend(test_arm_load_le(n + off, esize), bits);
        b = test_arm_sign_extend(
            test_arm_load_le(m + (e - exchange) * esize, esize), bits);
        c = test_arm_sign_extend(
            test_arm_load_le(n + (e + (1 - 2 * exchange)) * esize, esize),
            bits);
        d = test_arm_sign_extend(
            test_arm_load_le(m + (e + (1 - exchange)) * esize, esize),
            bits);
        result = test_arm_mve_expected_qdmladh_lane(
            a, b, c, d, esize, subtract, rounded, &saturated);
        test_arm_mve_store_masked(expected, off, esize, (uint64_t)result,
                                  mask);
        if (saturated && (mask & (1U << off))) {
            *qc = true;
        }
    }
}

static void test_arm_m55_mve_2op_run(uint32_t insn, const uint8_t *initial,
                                     const uint8_t *n, const uint8_t *m,
                                     const uint8_t *expected, bool eci)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    uint64_t q1[2];
    uint64_t q2[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    uint32_t vpr = 0;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, insn);

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, n, 16);
    memcpy(q2, m, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_Q2, q2));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                    insn, (unsigned)i, got[i], expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm_m55_mve_2op_run_qc(uint32_t insn,
                                        const uint8_t *initial,
                                        const uint8_t *n, const uint8_t *m,
                                        const uint8_t *expected, bool eci,
                                        bool expected_qc)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint32_t fpscr_qc = 1U << 27;
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    uint64_t q1[2];
    uint64_t q2[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    uint32_t fpscr = 0;
    uint32_t vpr = 0;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, n, 16);
    memcpy(q2, m, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_Q2, q2));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                    insn, (unsigned)i, got[i], expected[i]);
    }
    TEST_CHECK_(((fpscr & fpscr_qc) != 0) == expected_qc,
                "fpscr=0x%08x expected_qc=%d",
                fpscr, expected_qc);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_2op_expect_error(uint32_t insn, uc_cpu_arm cpu,
                                              uc_err expected)
{
    uc_engine *uc;
    uint8_t code[4];
    uc_err err;

    test_arm_emit32(code, 0, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code), cpu);
    test_arm_enable_vfp(uc);
    err = uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0);
    TEST_CHECK_(err == expected,
                "insn=0x%08x cpu=%d err=%u expected=%u",
                insn, (int)cpu, (unsigned)err, (unsigned)expected);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_scalar_2op_run(uint32_t insn,
                                            const uint8_t *initial,
                                            const uint8_t *n, uint32_t rm,
                                            const uint8_t *expected,
                                            bool eci)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    uint64_t q1[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    uint32_t vpr = 0;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, n, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &rm));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                    insn, (unsigned)i, got[i], expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm_m55_mve_scalar_2op_run_qc(uint32_t insn,
                                               const uint8_t *initial,
                                               const uint8_t *n, uint32_t rm,
                                               uint32_t vpr,
                                               const uint8_t *expected,
                                               bool eci, bool initial_qc,
                                               bool expected_qc)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint32_t fpscr_qc = 1U << 27;
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    uint64_t q1[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    uint32_t fpscr = 0;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, n, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &rm));
    OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));

    if (eci || initial_qc) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        if (initial_qc) {
            OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
            fpscr |= fpscr_qc;
            OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));
        }
        epsr = xpsr_t | eci_a0a1;
        if (eci) {
            OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        }
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        if (eci) {
            OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
            TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                        "epsr=0x%08x", epsr);
        }
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                    insn, (unsigned)i, got[i], expected[i]);
    }
    TEST_CHECK_(((fpscr & fpscr_qc) != 0) == expected_qc,
                "fpscr=0x%08x expected_qc=%d",
                fpscr, expected_qc);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_ldst_expect_error(uint32_t insn,
                                               uc_cpu_arm cpu,
                                               uc_err expected)
{
    uc_engine *uc;
    uint8_t code[4];
    uc_err err;

    test_arm_emit32(code, 0, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code), cpu);
    test_arm_enable_vfp(uc);
    err = uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0);
    TEST_CHECK_(err == expected, "err=%u", (unsigned)err);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_logic(void)
{
    const uint8_t initial[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const uint8_t n[16] = {
        0xf0, 0x0f, 0xaa, 0x55, 0x33, 0xcc, 0x80, 0x7f,
        0x01, 0xfe, 0x5a, 0xa5, 0x3c, 0xc3, 0x99, 0x66,
    };
    const uint8_t m[16] = {
        0x0f, 0x33, 0x55, 0xaa, 0xf0, 0x0f, 0x7f, 0x80,
        0xff, 0x10, 0xa5, 0x5a, 0xc3, 0x3c, 0x66, 0x99,
    };
    uint8_t expected[16];

    test_arm_mve_expected_logic(expected, initial, n, m, '&', 0xffff);
    test_arm_m55_mve_2op_run(0x0154ef02, initial, n, m, expected, false);

    test_arm_mve_expected_logic(expected, initial, n, m, 'b', 0xffff);
    test_arm_m55_mve_2op_run(0x0154ef12, initial, n, m, expected, false);

    test_arm_mve_expected_logic(expected, initial, n, m, '|', 0xffff);
    test_arm_m55_mve_2op_run(0x0154ef22, initial, n, m, expected, false);

    test_arm_mve_expected_logic(expected, initial, n, m, 'o', 0xffff);
    test_arm_m55_mve_2op_run(0x0154ef32, initial, n, m, expected, false);

    test_arm_mve_expected_logic(expected, initial, n, m, '^', 0xffff);
    test_arm_m55_mve_2op_run(0x0154ff02, initial, n, m, expected, false);

    test_arm_mve_expected_logic(expected, initial, n, m, '^', 0xff00);
    test_arm_m55_mve_2op_run(0x0154ff02, initial, n, m, expected, true);

    test_arm_m55_mve_2op_expect_error(0x0154ef42, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0154ef02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_INSN_INVALID);
}

static void test_arm_m55_mve_add_sub(void)
{
    const uint8_t initial[16] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    };
    const uint8_t n[16] = {
        0xff, 0x00, 0x7f, 0x80, 0x34, 0x12, 0x78, 0x56,
        0xef, 0xcd, 0xab, 0x89, 0x01, 0x00, 0x00, 0x80,
    };
    const uint8_t m[16] = {
        0x02, 0x03, 0x81, 0x80, 0x02, 0x01, 0x08, 0x07,
        0x11, 0x22, 0x33, 0x44, 0xff, 0xff, 0xff, 0x7f,
    };
    uint8_t expected[16];

    test_arm_mve_expected_addsub(expected, initial, n, m, 1, false, 0xffff);
    test_arm_m55_mve_2op_run(0x0844ef02, initial, n, m, expected, false);

    test_arm_mve_expected_addsub(expected, initial, n, m, 2, false, 0xffff);
    test_arm_m55_mve_2op_run(0x0844ef12, initial, n, m, expected, false);

    test_arm_mve_expected_addsub(expected, initial, n, m, 4, false, 0xffff);
    test_arm_m55_mve_2op_run(0x0844ef22, initial, n, m, expected, false);

    test_arm_mve_expected_addsub(expected, initial, n, m, 1, true, 0xffff);
    test_arm_m55_mve_2op_run(0x0844ff02, initial, n, m, expected, false);

    test_arm_mve_expected_addsub(expected, initial, n, m, 2, true, 0xffff);
    test_arm_m55_mve_2op_run(0x0844ff12, initial, n, m, expected, false);

    test_arm_mve_expected_addsub(expected, initial, n, m, 4, true, 0xffff);
    test_arm_m55_mve_2op_run(0x0844ff22, initial, n, m, expected, false);

    test_arm_mve_expected_mul(expected, initial, n, m, 1, 0xffff);
    test_arm_m55_mve_2op_run(0x0954ef02, initial, n, m, expected, false);

    test_arm_mve_expected_mul(expected, initial, n, m, 2, 0xffff);
    test_arm_m55_mve_2op_run(0x0954ef12, initial, n, m, expected, false);

    test_arm_mve_expected_mul(expected, initial, n, m, 4, 0xffff);
    test_arm_m55_mve_2op_run(0x0954ef22, initial, n, m, expected, false);

    test_arm_mve_expected_addsub(expected, initial, n, m, 4, false, 0xff00);
    test_arm_m55_mve_2op_run(0x0844ef22, initial, n, m, expected, true);

    test_arm_m55_mve_2op_expect_error(0x0844ef62, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0954ef32, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0954ef02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0844ef02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_INSN_INVALID);
}

static void test_arm_m55_mve_scalar_2op(void)
{
    const uint8_t initial[16] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    };
    const uint8_t n[16] = {
        0xff, 0x00, 0x7f, 0x80, 0x34, 0x12, 0x78, 0x56,
        0xef, 0xcd, 0xab, 0x89, 0x01, 0x00, 0x00, 0x80,
    };
    const uint32_t scalar = 0x80010203;
    uint8_t expected[16];

    test_arm_mve_expected_scalar_2op(expected, initial, n, scalar, 1, '+',
                                     0xffff);
    test_arm_m55_mve_scalar_2op_run(0x0f43ee03, initial, n, scalar,
                                    expected, false);

    test_arm_mve_expected_scalar_2op(expected, initial, n, scalar, 2, '+',
                                     0xffff);
    test_arm_m55_mve_scalar_2op_run(0x0f43ee13, initial, n, scalar,
                                    expected, false);

    test_arm_mve_expected_scalar_2op(expected, initial, n, scalar, 4, '-',
                                     0xffff);
    test_arm_m55_mve_scalar_2op_run(0x1f43ee23, initial, n, scalar,
                                    expected, false);

    test_arm_mve_expected_scalar_2op(expected, initial, n, scalar, 1, '*',
                                     0xffff);
    test_arm_m55_mve_scalar_2op_run(0x1e63ee03, initial, n, scalar,
                                    expected, false);

    test_arm_mve_expected_scalar_2op(expected, initial, n, scalar, 2, '*',
                                     0xffff);
    test_arm_m55_mve_scalar_2op_run(0x1e63ee13, initial, n, scalar,
                                    expected, false);

    test_arm_mve_expected_scalar_2op(expected, initial, n, scalar, 4, '*',
                                     0xffff);
    test_arm_m55_mve_scalar_2op_run(0x1e63ee23, initial, n, scalar,
                                    expected, false);

    test_arm_mve_expected_scalar_2op(expected, initial, n, scalar, 4, '+',
                                     0xff00);
    test_arm_m55_mve_scalar_2op_run(0x0f43ee23, initial, n, scalar,
                                    expected, true);

    test_arm_m55_mve_2op_expect_error(0x0f43ee43, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f4dee03, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f4fee03, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f43ee03, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_vbrsr(void)
{
    static const uint32_t vbrsr_insns[] = {
        0x1e63fe03, 0x1e63fe13, 0x1e63fe23,
    };
    const uint8_t initial[16] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    };
    const uint8_t n[16] = {
        0x80, 0x01, 0x55, 0xaa, 0x34, 0x12, 0xef, 0xcd,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    };
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    size_t ncase;

    for (ncase = 0; ncase < 3; ncase++) {
        unsigned esize = esizes[ncase];
        unsigned bits = esize * 8;

        test_arm_mve_expected_vbrsr(expected, initial, n, bits - 1, esize,
                                    0xffff);
        test_arm_m55_mve_scalar_2op_run(vbrsr_insns[ncase], initial, n,
                                        bits - 1, expected, false);

        test_arm_mve_expected_vbrsr(expected, initial, n, bits, esize,
                                    0xffff);
        test_arm_m55_mve_scalar_2op_run(vbrsr_insns[ncase], initial, n,
                                        bits, expected, false);

        test_arm_mve_expected_vbrsr(expected, initial, n, bits + 1, esize,
                                    0xffff);
        test_arm_m55_mve_scalar_2op_run(vbrsr_insns[ncase], initial, n,
                                        bits + 1, expected, false);
    }

    test_arm_mve_expected_vbrsr(expected, initial, n, 0, 1, 0xffff);
    test_arm_m55_mve_scalar_2op_run(vbrsr_insns[0], initial, n, 0,
                                    expected, false);

    test_arm_mve_expected_vbrsr(expected, initial, n, 0x100, 2, 0xffff);
    test_arm_m55_mve_scalar_2op_run(vbrsr_insns[1], initial, n, 0x100,
                                    expected, false);

    test_arm_mve_expected_vbrsr(expected, initial, n, 5, 4, 0x00f0);
    test_arm_m55_mve_scalar_2op_run_qc(vbrsr_insns[2], initial, n, 5,
                                       0x001100f0, expected, false, false,
                                       false);

    test_arm_mve_expected_vbrsr(expected, initial, n, 5, 4, 0xff00);
    test_arm_m55_mve_scalar_2op_run(vbrsr_insns[2], initial, n, 5,
                                    expected, true);

    test_arm_m55_mve_2op_expect_error(0x1e63fe43, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x1e6dfe03, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x1e6ffe03, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(vbrsr_insns[0],
                                      UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_scalar_halving_sat(void)
{
    static const uint32_t vhadds_insns[] = {
        0x0f43ee02, 0x0f43ee12, 0x0f43ee22,
    };
    static const uint32_t vhaddu_insns[] = {
        0x0f43fe02, 0x0f43fe12, 0x0f43fe22,
    };
    static const uint32_t vhsubs_insns[] = {
        0x1f43ee02, 0x1f43ee12, 0x1f43ee22,
    };
    static const uint32_t vhsubu_insns[] = {
        0x1f43fe02, 0x1f43fe12, 0x1f43fe22,
    };
    static const uint32_t vqadds_insns[] = {
        0x0f63ee02, 0x0f63ee12, 0x0f63ee22,
    };
    static const uint32_t vqaddu_insns[] = {
        0x0f63fe02, 0x0f63fe12, 0x0f63fe22,
    };
    static const uint32_t vqsubs_insns[] = {
        0x1f63ee02, 0x1f63ee12, 0x1f63ee22,
    };
    static const uint32_t vqsubu_insns[] = {
        0x1f63fe02, 0x1f63fe12, 0x1f63fe22,
    };
    static const uint32_t vqdmulh_insns[] = {
        0x0e63ee03, 0x0e63ee13, 0x0e63ee23,
    };
    static const uint32_t vqrdmulh_insns[] = {
        0x0e63fe03, 0x0e63fe13, 0x0e63fe23,
    };
    const uint8_t initial[16] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    };
    const uint8_t n[16] = {
        0x81, 0x7f, 0x12, 0xf0, 0x55, 0xaa, 0x01, 0x80,
        0xfe, 0x10, 0x33, 0xcc, 0x00, 0x00, 0x00, 0x80,
    };
    const uint32_t scalar = 0x8001807f;
    const uint32_t sat_scalar = 0x80008080;
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t scalar_lanes[16];
    uint8_t expected[16];
    bool qc;
    size_t ncase;

    for (ncase = 0; ncase < 3; ncase++) {
        unsigned esize = esizes[ncase];

        test_arm_mve_fill_scalar_shift(scalar_lanes, esize, scalar);
        test_arm_mve_expected_halving(expected, initial, n, scalar_lanes,
                                      esize, true, false, false, 0xffff);
        test_arm_m55_mve_scalar_2op_run(vhadds_insns[ncase], initial, n,
                                        scalar, expected, false);

        test_arm_mve_expected_halving(expected, initial, n, scalar_lanes,
                                      esize, false, false, false, 0xffff);
        test_arm_m55_mve_scalar_2op_run(vhaddu_insns[ncase], initial, n,
                                        scalar, expected, false);

        test_arm_mve_expected_halving(expected, initial, n, scalar_lanes,
                                      esize, true, true, false, 0xffff);
        test_arm_m55_mve_scalar_2op_run(vhsubs_insns[ncase], initial, n,
                                        scalar, expected, false);

        test_arm_mve_expected_halving(expected, initial, n, scalar_lanes,
                                      esize, false, true, false, 0xffff);
        test_arm_m55_mve_scalar_2op_run(vhsubu_insns[ncase], initial, n,
                                        scalar, expected, false);

        test_arm_mve_fill_scalar_shift(scalar_lanes, esize, sat_scalar);
        test_arm_mve_expected_qaddsub(expected, initial, n, scalar_lanes,
                                      esize, true, false, 0xffff, &qc);
        test_arm_m55_mve_scalar_2op_run_qc(vqadds_insns[ncase], initial, n,
                                           sat_scalar, 0, expected, false,
                                           false, qc);

        test_arm_mve_expected_qaddsub(expected, initial, n, scalar_lanes,
                                      esize, false, false, 0xffff, &qc);
        test_arm_m55_mve_scalar_2op_run_qc(vqaddu_insns[ncase], initial, n,
                                           sat_scalar, 0, expected, false,
                                           false, qc);

        test_arm_mve_expected_qaddsub(expected, initial, n, scalar_lanes,
                                      esize, true, true, 0xffff, &qc);
        test_arm_m55_mve_scalar_2op_run_qc(vqsubs_insns[ncase], initial, n,
                                           sat_scalar, 0, expected, false,
                                           false, qc);

        test_arm_mve_expected_qaddsub(expected, initial, n, scalar_lanes,
                                      esize, false, true, 0xffff, &qc);
        test_arm_m55_mve_scalar_2op_run_qc(vqsubu_insns[ncase], initial, n,
                                           sat_scalar, 0, expected, false,
                                           false, qc);

        test_arm_mve_expected_qdmulh(expected, initial, n, scalar_lanes,
                                     esize, false, 0xffff, &qc);
        test_arm_m55_mve_scalar_2op_run_qc(vqdmulh_insns[ncase], initial, n,
                                           sat_scalar, 0, expected, false,
                                           false, qc);

        test_arm_mve_expected_qdmulh(expected, initial, n, scalar_lanes,
                                     esize, true, 0xffff, &qc);
        test_arm_m55_mve_scalar_2op_run_qc(vqrdmulh_insns[ncase], initial, n,
                                           sat_scalar, 0, expected, false,
                                           false, qc);
    }

    test_arm_mve_fill_scalar_shift(scalar_lanes, 4, sat_scalar);
    test_arm_mve_expected_qaddsub(expected, initial, n, scalar_lanes, 4,
                                  true, false, 0xff00, &qc);
    test_arm_m55_mve_scalar_2op_run_qc(0x0f63ee22, initial, n, sat_scalar,
                                       0, expected, true, false, qc);

    test_arm_mve_expected_qaddsub(expected, initial, n, scalar_lanes, 4,
                                  true, false, 0xffff, &qc);
    test_arm_m55_mve_scalar_2op_run_qc(0x0f63ee22, initial, n, sat_scalar,
                                       0, expected, false, true, true);

    test_arm_m55_mve_2op_expect_error(0x0f43ee42, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f4dee02, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f4fee02, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f43ee02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_mulh(void)
{
    static const uint32_t vmulhs_insns[] = {
        0x0e05ee03, 0x0e05ee13, 0x0e05ee23,
    };
    static const uint32_t vmulhu_insns[] = {
        0x0e05fe03, 0x0e05fe13, 0x0e05fe23,
    };
    static const uint32_t vrmulhs_insns[] = {
        0x1e05ee03, 0x1e05ee13, 0x1e05ee23,
    };
    static const uint32_t vrmulhu_insns[] = {
        0x1e05fe03, 0x1e05fe13, 0x1e05fe23,
    };
    const uint8_t initial[16] = {
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    };
    const uint8_t n[16] = {
        0x80, 0x7f, 0xff, 0x00, 0x34, 0x12, 0x00, 0x80,
        0xfe, 0xff, 0x00, 0x40, 0x01, 0x00, 0xff, 0x7f,
    };
    const uint8_t m[16] = {
        0x7f, 0x80, 0x01, 0xff, 0x35, 0x12, 0xff, 0x7f,
        0x02, 0x00, 0xff, 0xbf, 0x00, 0x80, 0x00, 0x80,
    };
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    size_t ncase;

    for (ncase = 0; ncase < 3; ncase++) {
        test_arm_mve_expected_mulh(expected, initial, n, m, esizes[ncase],
                                   true, false, 0xffff);
        test_arm_m55_mve_2op_run(vmulhs_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_mulh(expected, initial, n, m, esizes[ncase],
                                   false, false, 0xffff);
        test_arm_m55_mve_2op_run(vmulhu_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_mulh(expected, initial, n, m, esizes[ncase],
                                   true, true, 0xffff);
        test_arm_m55_mve_2op_run(vrmulhs_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_mulh(expected, initial, n, m, esizes[ncase],
                                   false, true, 0xffff);
        test_arm_m55_mve_2op_run(vrmulhu_insns[ncase], initial, n, m,
                                 expected, false);
    }

    test_arm_mve_expected_mulh(expected, initial, n, m, 4, true, true,
                               0xff00);
    test_arm_m55_mve_2op_run(0x1e05ee23, initial, n, m, expected, true);

    test_arm_m55_mve_2op_expect_error(0x0e05ee43, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0e05ee03, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_vmull(void)
{
    static const uint32_t vmullbs_insns[] = {
        0x0e04ee03, 0x0e04ee13, 0x0e04ee23,
    };
    static const uint32_t vmullbu_insns[] = {
        0x0e04fe03, 0x0e04fe13, 0x0e04fe23,
    };
    static const uint32_t vmullts_insns[] = {
        0x1e04ee03, 0x1e04ee13, 0x1e04ee23,
    };
    static const uint32_t vmulltu_insns[] = {
        0x1e04fe03, 0x1e04fe13, 0x1e04fe23,
    };
    const uint8_t initial[16] = {
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    };
    const uint8_t n[16] = {
        0x80, 0x7f, 0xff, 0x00, 0x34, 0x12, 0x00, 0x80,
        0xfe, 0xff, 0x00, 0x40, 0x01, 0x00, 0xff, 0x7f,
    };
    const uint8_t m[16] = {
        0x7f, 0x80, 0x01, 0xff, 0x35, 0x12, 0xff, 0x7f,
        0x02, 0x00, 0xff, 0xbf, 0x00, 0x80, 0x00, 0x80,
    };
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    size_t ncase;

    for (ncase = 0; ncase < 3; ncase++) {
        test_arm_mve_expected_vmull(expected, initial, n, m, esizes[ncase],
                                    false, true, 0xffff);
        test_arm_m55_mve_2op_run(vmullbs_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_vmull(expected, initial, n, m, esizes[ncase],
                                    false, false, 0xffff);
        test_arm_m55_mve_2op_run(vmullbu_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_vmull(expected, initial, n, m, esizes[ncase],
                                    true, true, 0xffff);
        test_arm_m55_mve_2op_run(vmullts_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_vmull(expected, initial, n, m, esizes[ncase],
                                    true, false, 0xffff);
        test_arm_m55_mve_2op_run(vmulltu_insns[ncase], initial, n, m,
                                 expected, false);
    }

    test_arm_mve_expected_vmullp(expected, initial, n, m, 8, false, 0xffff);
    test_arm_m55_mve_2op_run(0x0e04ee33, initial, n, m, expected, false);

    test_arm_mve_expected_vmullp(expected, initial, n, m, 16, false, 0xffff);
    test_arm_m55_mve_2op_run(0x0e04fe33, initial, n, m, expected, false);

    test_arm_mve_expected_vmullp(expected, initial, n, m, 8, true, 0xffff);
    test_arm_m55_mve_2op_run(0x1e04ee33, initial, n, m, expected, false);

    test_arm_mve_expected_vmullp(expected, initial, n, m, 16, true, 0xffff);
    test_arm_m55_mve_2op_run(0x1e04fe33, initial, n, m, expected, false);

    test_arm_mve_expected_vmull(expected, initial, n, m, 4, true, true,
                                0xff00);
    test_arm_m55_mve_2op_run(0x1e04ee23, initial, n, m, expected, true);

    test_arm_mve_expected_vmull(expected, initial, initial, m, 1, false,
                                true, 0xffff);
    test_arm_m55_mve_2op_run(0x0e04ee01, initial, n, m, expected, false);

    test_arm_mve_expected_vmull(expected, initial, n, initial, 1, false,
                                true, 0xffff);
    test_arm_m55_mve_2op_run(0x0e00ee03, initial, n, m, expected, false);

    test_arm_m55_mve_2op_expect_error(0x0e04ee43, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0e04ee03, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_minmax(void)
{
    static const uint32_t vmaxs_insns[] = {
        0x0644ef02, 0x0644ef12, 0x0644ef22,
    };
    static const uint32_t vmaxu_insns[] = {
        0x0644ff02, 0x0644ff12, 0x0644ff22,
    };
    static const uint32_t vmins_insns[] = {
        0x0654ef02, 0x0654ef12, 0x0654ef22,
    };
    static const uint32_t vminu_insns[] = {
        0x0654ff02, 0x0654ff12, 0x0654ff22,
    };
    const uint8_t initial[16] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    };
    const uint8_t n[16] = {
        0x80, 0x7f, 0xff, 0x00, 0x34, 0x12, 0x00, 0x80,
        0xfe, 0xff, 0x00, 0x40, 0x01, 0x00, 0xff, 0x7f,
    };
    const uint8_t m[16] = {
        0x7f, 0x80, 0x01, 0xff, 0x35, 0x12, 0xff, 0x7f,
        0x02, 0x00, 0xff, 0xbf, 0x00, 0x80, 0x00, 0x80,
    };
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    size_t ncase;

    for (ncase = 0; ncase < 3; ncase++) {
        test_arm_mve_expected_minmax(expected, initial, n, m,
                                     esizes[ncase], true, false, 0xffff);
        test_arm_m55_mve_2op_run(vmaxs_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_minmax(expected, initial, n, m,
                                     esizes[ncase], false, false, 0xffff);
        test_arm_m55_mve_2op_run(vmaxu_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_minmax(expected, initial, n, m,
                                     esizes[ncase], true, true, 0xffff);
        test_arm_m55_mve_2op_run(vmins_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_minmax(expected, initial, n, m,
                                     esizes[ncase], false, true, 0xffff);
        test_arm_m55_mve_2op_run(vminu_insns[ncase], initial, n, m,
                                 expected, false);
    }

    test_arm_mve_expected_minmax(expected, initial, n, m, 4, false, false,
                                 0xff00);
    test_arm_m55_mve_2op_run(0x0644ff22, initial, n, m, expected, true);

    test_arm_m55_mve_2op_expect_error(0x0644ef32, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0644ef42, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0644ef02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_INSN_INVALID);
}

static void test_arm_m55_mve_vabd(void)
{
    static const uint32_t vabds_insns[] = {
        0x0744ef02, 0x0744ef12, 0x0744ef22,
    };
    static const uint32_t vabdu_insns[] = {
        0x0744ff02, 0x0744ff12, 0x0744ff22,
    };
    const uint8_t initial[16] = {
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    const uint8_t n[16] = {
        0x80, 0x7f, 0xff, 0x00, 0x34, 0x12, 0x00, 0x80,
        0xfe, 0xff, 0x00, 0x40, 0x01, 0x00, 0xff, 0x7f,
    };
    const uint8_t m[16] = {
        0x7f, 0x80, 0x01, 0xff, 0x35, 0x12, 0xff, 0x7f,
        0x02, 0x00, 0xff, 0xbf, 0x00, 0x80, 0x00, 0x80,
    };
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    size_t ncase;

    for (ncase = 0; ncase < 3; ncase++) {
        test_arm_mve_expected_abd(expected, initial, n, m, esizes[ncase],
                                  true, 0xffff);
        test_arm_m55_mve_2op_run(vabds_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_abd(expected, initial, n, m, esizes[ncase],
                                  false, 0xffff);
        test_arm_m55_mve_2op_run(vabdu_insns[ncase], initial, n, m,
                                 expected, false);
    }

    test_arm_mve_expected_abd(expected, initial, n, m, 4, true, 0xff00);
    test_arm_m55_mve_2op_run(0x0744ef22, initial, n, m, expected, true);

    test_arm_m55_mve_2op_expect_error(0x0744ef32, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0744ef42, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0744ef02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_INSN_INVALID);
}

static void test_arm_m55_mve_halving(void)
{
    static const uint32_t vhadds_insns[] = {
        0x0044ef02, 0x0044ef12, 0x0044ef22,
    };
    static const uint32_t vhaddu_insns[] = {
        0x0044ff02, 0x0044ff12, 0x0044ff22,
    };
    static const uint32_t vrhadds_insns[] = {
        0x0144ef02, 0x0144ef12, 0x0144ef22,
    };
    static const uint32_t vrhaddu_insns[] = {
        0x0144ff02, 0x0144ff12, 0x0144ff22,
    };
    static const uint32_t vhsubs_insns[] = {
        0x0244ef02, 0x0244ef12, 0x0244ef22,
    };
    static const uint32_t vhsubu_insns[] = {
        0x0244ff02, 0x0244ff12, 0x0244ff22,
    };
    const uint8_t initial[16] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };
    const uint8_t n[16] = {
        0x80, 0x7f, 0xff, 0x00, 0x34, 0x12, 0x00, 0x80,
        0xfe, 0xff, 0x00, 0x40, 0x01, 0x00, 0xff, 0x7f,
    };
    const uint8_t m[16] = {
        0x7f, 0x80, 0x01, 0xff, 0x35, 0x12, 0xff, 0x7f,
        0x02, 0x00, 0xff, 0xbf, 0x00, 0x80, 0x00, 0x80,
    };
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    size_t ncase;

    for (ncase = 0; ncase < 3; ncase++) {
        test_arm_mve_expected_halving(expected, initial, n, m,
                                      esizes[ncase], true, false, false,
                                      0xffff);
        test_arm_m55_mve_2op_run(vhadds_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_halving(expected, initial, n, m,
                                      esizes[ncase], false, false, false,
                                      0xffff);
        test_arm_m55_mve_2op_run(vhaddu_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_halving(expected, initial, n, m,
                                      esizes[ncase], true, false, true,
                                      0xffff);
        test_arm_m55_mve_2op_run(vrhadds_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_halving(expected, initial, n, m,
                                      esizes[ncase], false, false, true,
                                      0xffff);
        test_arm_m55_mve_2op_run(vrhaddu_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_halving(expected, initial, n, m,
                                      esizes[ncase], true, true, false,
                                      0xffff);
        test_arm_m55_mve_2op_run(vhsubs_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_halving(expected, initial, n, m,
                                      esizes[ncase], false, true, false,
                                      0xffff);
        test_arm_m55_mve_2op_run(vhsubu_insns[ncase], initial, n, m,
                                 expected, false);
    }

    test_arm_mve_expected_halving(expected, initial, n, m, 4, false, true,
                                  false, 0xff00);
    test_arm_m55_mve_2op_run(0x0244ff22, initial, n, m, expected, true);

    test_arm_mve_expected_halving(expected, initial, n, m, 4, true, false,
                                  true, 0xff00);
    test_arm_m55_mve_2op_run(0x0144ef22, initial, n, m, expected, true);

    test_arm_m55_mve_2op_expect_error(0x0044ef32, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0144ef32, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0044ef42, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0144ef42, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0044ef02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0144ef02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_INSN_INVALID);
}

static void test_arm_m55_mve_qaddsub(void)
{
    static const uint32_t vqadds_insns[] = {
        0x0054ef02, 0x0054ef12, 0x0054ef22,
    };
    static const uint32_t vqaddu_insns[] = {
        0x0054ff02, 0x0054ff12, 0x0054ff22,
    };
    static const uint32_t vqsubs_insns[] = {
        0x0254ef02, 0x0254ef12, 0x0254ef22,
    };
    static const uint32_t vqsubu_insns[] = {
        0x0254ff02, 0x0254ff12, 0x0254ff22,
    };
    const uint8_t initial[16] = {
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    };
    const uint8_t n[16] = {
        0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    };
    const uint8_t m[16] = {
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00,
    };
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    bool qc;
    size_t ncase;

    for (ncase = 0; ncase < 3; ncase++) {
        test_arm_mve_expected_qaddsub(expected, initial, n, m,
                                      esizes[ncase], true, false, 0xffff,
                                      &qc);
        test_arm_m55_mve_2op_run_qc(vqadds_insns[ncase], initial, n, m,
                                    expected, false, qc);

        test_arm_mve_expected_qaddsub(expected, initial, n, m,
                                      esizes[ncase], false, false, 0xffff,
                                      &qc);
        test_arm_m55_mve_2op_run_qc(vqaddu_insns[ncase], initial, n, m,
                                    expected, false, qc);

        test_arm_mve_expected_qaddsub(expected, initial, n, m,
                                      esizes[ncase], true, true, 0xffff,
                                      &qc);
        test_arm_m55_mve_2op_run_qc(vqsubs_insns[ncase], initial, n, m,
                                    expected, false, qc);

        test_arm_mve_expected_qaddsub(expected, initial, n, m,
                                      esizes[ncase], false, true, 0xffff,
                                      &qc);
        test_arm_m55_mve_2op_run_qc(vqsubu_insns[ncase], initial, n, m,
                                    expected, false, qc);
    }

    test_arm_mve_expected_qaddsub(expected, initial, n, m, 4, true, false,
                                  0xff00, &qc);
    test_arm_m55_mve_2op_run_qc(0x0054ef22, initial, n, m, expected, true,
                                qc);

    test_arm_m55_mve_2op_expect_error(0x0054ef32, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0054ef42, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0054ef02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_INSN_INVALID);
}

static void test_arm_m55_mve_shift(void)
{
    static const uint32_t vshls_insns[] = {
        0x0444ef02, 0x0444ef12, 0x0444ef22,
    };
    static const uint32_t vshlu_insns[] = {
        0x0444ff02, 0x0444ff12, 0x0444ff22,
    };
    static const uint32_t vrshls_insns[] = {
        0x0544ef02, 0x0544ef12, 0x0544ef22,
    };
    static const uint32_t vrshlu_insns[] = {
        0x0544ff02, 0x0544ff12, 0x0544ff22,
    };
    static const uint32_t vqshls_insns[] = {
        0x0454ef02, 0x0454ef12, 0x0454ef22,
    };
    static const uint32_t vqshlu_insns[] = {
        0x0454ff02, 0x0454ff12, 0x0454ff22,
    };
    static const uint32_t vqrshls_insns[] = {
        0x0554ef02, 0x0554ef12, 0x0554ef22,
    };
    static const uint32_t vqrshlu_insns[] = {
        0x0554ff02, 0x0554ff12, 0x0554ff22,
    };
    const uint8_t initial[16] = {
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    };
    const uint8_t values[16] = {
        0x81, 0x7f, 0x40, 0x03, 0xff, 0x80, 0x55, 0xaa,
        0x34, 0x12, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x80,
    };
    const uint8_t shifts[16] = {
        0x01, 0xff, 0xfe, 0x08, 0xf8, 0x00, 0x03, 0xfd,
        0x10, 0xf0, 0x04, 0xfc, 0x20, 0xe0, 0x07, 0xf9,
    };
    const uint8_t skip_values[16] = {
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0xc0,
        0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    };
    const uint8_t skip_shifts[16] = {
        0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    };
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    bool qc;
    size_t ncase;

    for (ncase = 0; ncase < 3; ncase++) {
        test_arm_mve_expected_shift(expected, initial, values, shifts,
                                    esizes[ncase], true, false, 0xffff);
        test_arm_m55_mve_2op_run(vshls_insns[ncase], initial, shifts,
                                 values, expected, false);

        test_arm_mve_expected_shift(expected, initial, values, shifts,
                                    esizes[ncase], false, false, 0xffff);
        test_arm_m55_mve_2op_run(vshlu_insns[ncase], initial, shifts,
                                 values, expected, false);

        test_arm_mve_expected_shift(expected, initial, values, shifts,
                                    esizes[ncase], true, true, 0xffff);
        test_arm_m55_mve_2op_run(vrshls_insns[ncase], initial, shifts,
                                 values, expected, false);

        test_arm_mve_expected_shift(expected, initial, values, shifts,
                                    esizes[ncase], false, true, 0xffff);
        test_arm_m55_mve_2op_run(vrshlu_insns[ncase], initial, shifts,
                                 values, expected, false);

        test_arm_mve_expected_qshift(expected, initial, values, shifts,
                                     esizes[ncase], true, false, 0xffff,
                                     &qc);
        test_arm_m55_mve_2op_run_qc(vqshls_insns[ncase], initial, shifts,
                                    values, expected, false, qc);

        test_arm_mve_expected_qshift(expected, initial, values, shifts,
                                     esizes[ncase], false, false, 0xffff,
                                     &qc);
        test_arm_m55_mve_2op_run_qc(vqshlu_insns[ncase], initial, shifts,
                                    values, expected, false, qc);

        test_arm_mve_expected_qshift(expected, initial, values, shifts,
                                     esizes[ncase], true, true, 0xffff,
                                     &qc);
        test_arm_m55_mve_2op_run_qc(vqrshls_insns[ncase], initial, shifts,
                                    values, expected, false, qc);

        test_arm_mve_expected_qshift(expected, initial, values, shifts,
                                     esizes[ncase], false, true, 0xffff,
                                     &qc);
        test_arm_m55_mve_2op_run_qc(vqrshlu_insns[ncase], initial, shifts,
                                    values, expected, false, qc);
    }

    test_arm_mve_expected_shift(expected, initial, values, shifts, 4, false,
                                true, 0xff00);
    test_arm_m55_mve_2op_run(0x0544ff22, initial, shifts, values, expected,
                             true);

    test_arm_mve_expected_qshift(expected, initial, skip_values, skip_shifts,
                                 4, true, false, 0xff00, &qc);
    test_arm_m55_mve_2op_run_qc(0x0454ef22, initial, skip_shifts,
                                skip_values, expected, true, qc);

    test_arm_m55_mve_2op_expect_error(0x0444ef32, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0444ef42, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0444ef02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0454ef32, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0454ef42, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0454ef02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_INSN_INVALID);
}

static void test_arm_m55_mve_qdmulh(void)
{
    static const uint32_t vqdmulh_insns[] = {
        0x0b44ef02, 0x0b44ef12, 0x0b44ef22,
    };
    static const uint32_t vqrdmulh_insns[] = {
        0x0b44ff02, 0x0b44ff12, 0x0b44ff22,
    };
    const uint8_t initial[16] = {
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    };
    const uint8_t n[16] = {
        0x80, 0x7f, 0xff, 0x7f, 0x00, 0x80, 0x00, 0x40,
        0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x7f,
    };
    const uint8_t m[16] = {
        0x80, 0x7f, 0xff, 0x7f, 0x00, 0x80, 0x00, 0x40,
        0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x7f,
    };
    const uint8_t eci_n[16] = {
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x20,
    };
    const uint8_t eci_m[16] = {
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x20,
    };
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    bool qc;
    size_t ncase;

    for (ncase = 0; ncase < 3; ncase++) {
        test_arm_mve_expected_qdmulh(expected, initial, n, m,
                                     esizes[ncase], false, 0xffff, &qc);
        test_arm_m55_mve_2op_run_qc(vqdmulh_insns[ncase], initial, n, m,
                                    expected, false, qc);

        test_arm_mve_expected_qdmulh(expected, initial, n, m,
                                     esizes[ncase], true, 0xffff, &qc);
        test_arm_m55_mve_2op_run_qc(vqrdmulh_insns[ncase], initial, n, m,
                                    expected, false, qc);
    }

    test_arm_mve_expected_qdmulh(expected, initial, eci_n, eci_m, 4, false,
                                 0xff00, &qc);
    test_arm_m55_mve_2op_run_qc(0x0b44ef22, initial, eci_n, eci_m,
                                expected, true, qc);

    test_arm_m55_mve_2op_expect_error(0x0b44ef32, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0b44ef42, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0b44ef02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_INSN_INVALID);
}

static void test_arm_m55_mve_qdmladh(void)
{
    static const uint32_t vqdmladh_insns[] = {
        0x0e04ee02, 0x0e04ee12, 0x0e04ee22,
    };
    static const uint32_t vqdmladhx_insns[] = {
        0x1e04ee02, 0x1e04ee12, 0x1e04ee22,
    };
    static const uint32_t vqrdmladh_insns[] = {
        0x0e05ee02, 0x0e05ee12, 0x0e05ee22,
    };
    static const uint32_t vqrdmladhx_insns[] = {
        0x1e05ee02, 0x1e05ee12, 0x1e05ee22,
    };
    static const uint32_t vqdmlsdh_insns[] = {
        0x0e04fe02, 0x0e04fe12, 0x0e04fe22,
    };
    static const uint32_t vqdmlsdhx_insns[] = {
        0x1e04fe02, 0x1e04fe12, 0x1e04fe22,
    };
    static const uint32_t vqrdmlsdh_insns[] = {
        0x0e05fe02, 0x0e05fe12, 0x0e05fe22,
    };
    static const uint32_t vqrdmlsdhx_insns[] = {
        0x1e05fe02, 0x1e05fe12, 0x1e05fe22,
    };
    const uint8_t initial[16] = {
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    };
    const uint8_t n[16] = {
        0x7f, 0x7f, 0x08, 0x00, 0x80, 0x80, 0x02, 0x00,
        0x10, 0x00, 0x20, 0x00, 0xff, 0xff, 0x7f, 0x00,
    };
    const uint8_t m[16] = {
        0x7f, 0x7f, 0x08, 0x00, 0x80, 0x80, 0x02, 0x00,
        0x04, 0x00, 0x08, 0x00, 0xff, 0xff, 0x01, 0x00,
    };
    const uint8_t sat_n[16] = {
        0x7f, 0x7f, 0x7f, 0x7f, 0x00, 0x00, 0x00, 0x40,
        0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    };
    const uint8_t sat_m[16] = {
        0x7f, 0x7f, 0x7f, 0x7f, 0x00, 0x00, 0x00, 0x40,
        0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    };
    const uint8_t eci_n[16] = {
        0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0x7f,
        0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    };
    const uint8_t eci_m[16] = {
        0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0x7f,
        0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    };
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    bool qc;
    size_t ncase;

    for (ncase = 0; ncase < 3; ncase++) {
        unsigned esize = esizes[ncase];

        test_arm_mve_expected_qdmladh(expected, initial, n, m, esize,
                                      false, false, false, 0xffff, &qc);
        test_arm_m55_mve_2op_run_qc(vqdmladh_insns[ncase], initial, n, m,
                                    expected, false, qc);

        test_arm_mve_expected_qdmladh(expected, initial, n, m, esize,
                                      false, true, false, 0xffff, &qc);
        test_arm_m55_mve_2op_run_qc(vqdmladhx_insns[ncase], initial, n, m,
                                    expected, false, qc);

        test_arm_mve_expected_qdmladh(expected, initial, n, m, esize,
                                      false, false, true, 0xffff, &qc);
        test_arm_m55_mve_2op_run_qc(vqrdmladh_insns[ncase], initial, n, m,
                                    expected, false, qc);

        test_arm_mve_expected_qdmladh(expected, initial, n, m, esize,
                                      false, true, true, 0xffff, &qc);
        test_arm_m55_mve_2op_run_qc(vqrdmladhx_insns[ncase], initial, n, m,
                                    expected, false, qc);

        test_arm_mve_expected_qdmladh(expected, initial, n, m, esize,
                                      true, false, false, 0xffff, &qc);
        test_arm_m55_mve_2op_run_qc(vqdmlsdh_insns[ncase], initial, n, m,
                                    expected, false, qc);

        test_arm_mve_expected_qdmladh(expected, initial, n, m, esize,
                                      true, true, false, 0xffff, &qc);
        test_arm_m55_mve_2op_run_qc(vqdmlsdhx_insns[ncase], initial, n, m,
                                    expected, false, qc);

        test_arm_mve_expected_qdmladh(expected, initial, n, m, esize,
                                      true, false, true, 0xffff, &qc);
        test_arm_m55_mve_2op_run_qc(vqrdmlsdh_insns[ncase], initial, n, m,
                                    expected, false, qc);

        test_arm_mve_expected_qdmladh(expected, initial, n, m, esize,
                                      true, true, true, 0xffff, &qc);
        test_arm_m55_mve_2op_run_qc(vqrdmlsdhx_insns[ncase], initial, n, m,
                                    expected, false, qc);
    }

    test_arm_mve_expected_qdmladh(expected, initial, sat_n, sat_m, 1,
                                  false, false, false, 0xffff, &qc);
    test_arm_m55_mve_2op_run_qc(0x0e04ee02, initial, sat_n, sat_m,
                                expected, false, qc);

    test_arm_mve_expected_qdmladh(expected, initial, eci_n, eci_m, 4,
                                  false, false, false, 0xff00, &qc);
    test_arm_m55_mve_2op_run_qc(0x0e04ee22, initial, eci_n, eci_m,
                                expected, true, qc);

    test_arm_m55_mve_2op_expect_error(0x0e04ee42, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0e04ee02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_qdmull(void)
{
    static const uint32_t vqdmullb_insns[] = {
        0x0f05ee32, 0x0f05fe32,
    };
    static const uint32_t vqdmullt_insns[] = {
        0x1f05ee32, 0x1f05fe32,
    };
    const uint8_t initial[16] = {
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    };
    const uint8_t n[16] = {
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x80, 0x00, 0x40, 0xff, 0xff, 0xff, 0x7f,
    };
    const uint8_t m[16] = {
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x80, 0x00, 0x40, 0xff, 0xff, 0xff, 0x7f,
    };
    const uint8_t eci_n[16] = {
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x20,
    };
    const uint8_t eci_m[16] = {
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x20,
    };
    const unsigned esizes[] = { 2, 4 };
    uint8_t expected[16];
    bool qc;
    size_t ncase;

    for (ncase = 0; ncase < 2; ncase++) {
        test_arm_mve_expected_qdmull(expected, initial, n, m, esizes[ncase],
                                     false, 0xffff, &qc);
        test_arm_m55_mve_2op_run_qc(vqdmullb_insns[ncase], initial, n, m,
                                    expected, false, qc);

        test_arm_mve_expected_qdmull(expected, initial, n, m, esizes[ncase],
                                     true, 0xffff, &qc);
        test_arm_m55_mve_2op_run_qc(vqdmullt_insns[ncase], initial, n, m,
                                    expected, false, qc);
    }

    test_arm_mve_expected_qdmull(expected, initial, eci_n, eci_m, 4, false,
                                 0xff00, &qc);
    test_arm_m55_mve_2op_run_qc(0x0f05fe32, initial, eci_n, eci_m, expected,
                                true, qc);

    test_arm_mve_expected_qdmull(expected, initial, initial, m, 2, false,
                                 0xffff, &qc);
    test_arm_m55_mve_2op_run_qc(0x0f05ee30, initial, n, m, expected, false,
                                qc);

    test_arm_m55_mve_2op_expect_error(0x0f05ee72, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f05fe30, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f01fe32, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f05ee32, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_scalar_qdmull(void)
{
    static const uint32_t vqdmullb_insns[] = {
        0x0f63ee32, 0x0f63fe32,
    };
    static const uint32_t vqdmullt_insns[] = {
        0x1f63ee32, 0x1f63fe32,
    };
    const uint8_t initial[16] = {
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    };
    const uint8_t n[16] = {
        0x00, 0x80, 0x00, 0x80, 0xff, 0x7f, 0xff, 0x7f,
        0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x7f,
    };
    const uint32_t scalars[] = {
        0x80008000, 0x80000000,
    };
    const unsigned esizes[] = { 2, 4 };
    uint8_t scalar_lanes[16];
    uint8_t expected[16];
    bool qc;
    size_t ncase;

    for (ncase = 0; ncase < 2; ncase++) {
        unsigned esize = esizes[ncase];
        uint32_t scalar = scalars[ncase];

        test_arm_mve_fill_scalar_shift(scalar_lanes, esize, scalar);
        test_arm_mve_expected_qdmull(expected, initial, n, scalar_lanes,
                                     esize, false, 0xffff, &qc);
        test_arm_m55_mve_scalar_2op_run_qc(vqdmullb_insns[ncase], initial,
                                           n, scalar, 0, expected, false,
                                           false, qc);

        test_arm_mve_expected_qdmull(expected, initial, n, scalar_lanes,
                                     esize, true, 0xffff, &qc);
        test_arm_m55_mve_scalar_2op_run_qc(vqdmullt_insns[ncase], initial,
                                           n, scalar, 0, expected, false,
                                           false, qc);
    }

    test_arm_mve_fill_scalar_shift(scalar_lanes, 4, 0x80000000);
    test_arm_mve_expected_qdmull(expected, initial, n, scalar_lanes, 4,
                                 false, 0xff00, &qc);
    test_arm_m55_mve_scalar_2op_run_qc(0x0f63fe32, initial, n, 0x80000000,
                                       0, expected, true, false, qc);

    test_arm_mve_fill_scalar_shift(scalar_lanes, 2, 0x80008000);
    test_arm_mve_expected_qdmull(expected, initial, initial, scalar_lanes, 2,
                                 false, 0xffff, &qc);
    test_arm_m55_mve_scalar_2op_run_qc(0x0f63ee30, initial, n, 0x80008000,
                                       0, expected, false, false, qc);

    test_arm_m55_mve_2op_expect_error(0x0f6dee32, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f6fee32, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f63ee72, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0fe3ee30, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f63fe30, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f63ee32, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_scalar_acc(void)
{
    static const uint32_t vmla_insns[] = {
        0x0e43ee03, 0x0e43ee13, 0x0e43ee23,
    };
    static const uint32_t vmla_alias_insns[] = {
        0x0e43fe03, 0x0e43fe13, 0x0e43fe23,
    };
    static const uint32_t vmlas_insns[] = {
        0x1e43ee03, 0x1e43ee13, 0x1e43ee23,
    };
    static const uint32_t vmlas_alias_insns[] = {
        0x1e43fe03, 0x1e43fe13, 0x1e43fe23,
    };
    static const uint32_t vqdmlah_insns[] = {
        0x0e63ee02, 0x0e63ee12, 0x0e63ee22,
    };
    static const uint32_t vqrdmlah_insns[] = {
        0x0e43ee02, 0x0e43ee12, 0x0e43ee22,
    };
    static const uint32_t vqdmlash_insns[] = {
        0x1e63ee02, 0x1e63ee12, 0x1e63ee22,
    };
    static const uint32_t vqrdmlash_insns[] = {
        0x1e43ee02, 0x1e43ee12, 0x1e43ee22,
    };
    const uint8_t initial[16] = {
        0xf0, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13,
        0x20, 0x21, 0x22, 0x23, 0x30, 0x31, 0x32, 0x33,
    };
    const uint8_t n[16] = {
        0x7f, 0x80, 0x01, 0xff, 0x34, 0x12, 0x00, 0x80,
        0x02, 0x00, 0x00, 0x40, 0xff, 0xff, 0xff, 0x7f,
    };
    const uint8_t q_initial[16] = {
        0xff, 0x7f, 0x7f, 0x00, 0x02, 0x00, 0x03, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    };
    const uint8_t q_n[16] = {
        0x00, 0x80, 0x80, 0x01, 0x01, 0x00, 0x02, 0x00,
        0x01, 0x00, 0x00, 0x40, 0x02, 0x00, 0x00, 0x20,
    };
    const uint32_t scalar = 0x40004040;
    const uint32_t sat_scalar = 0x80008080;
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    bool qc;
    size_t ncase;

    for (ncase = 0; ncase < 3; ncase++) {
        unsigned esize = esizes[ncase];

        test_arm_mve_expected_scalar_acc(expected, initial, n, scalar,
                                         esize, false, 0xffff);
        test_arm_m55_mve_scalar_2op_run(vmla_insns[ncase], initial, n,
                                        scalar, expected, false);
        test_arm_m55_mve_scalar_2op_run(vmla_alias_insns[ncase], initial,
                                        n, scalar, expected, false);

        test_arm_mve_expected_scalar_acc(expected, initial, n, scalar,
                                         esize, true, 0xffff);
        test_arm_m55_mve_scalar_2op_run(vmlas_insns[ncase], initial, n,
                                        scalar, expected, false);
        test_arm_m55_mve_scalar_2op_run(vmlas_alias_insns[ncase], initial,
                                        n, scalar, expected, false);

        test_arm_mve_expected_qdmlah(expected, q_initial, q_n, sat_scalar,
                                     esize, false, false, 0xffff, &qc);
        test_arm_m55_mve_scalar_2op_run_qc(vqdmlah_insns[ncase], q_initial,
                                           q_n, sat_scalar, 0, expected,
                                           false, false, qc);

        test_arm_mve_expected_qdmlah(expected, q_initial, q_n, scalar,
                                     esize, false, true, 0xffff, &qc);
        test_arm_m55_mve_scalar_2op_run_qc(vqrdmlah_insns[ncase], q_initial,
                                           q_n, scalar, 0, expected, false,
                                           false, qc);

        test_arm_mve_expected_qdmlah(expected, q_initial, q_n, sat_scalar,
                                     esize, true, false, 0xffff, &qc);
        test_arm_m55_mve_scalar_2op_run_qc(vqdmlash_insns[ncase], q_initial,
                                           q_n, sat_scalar, 0, expected,
                                           false, false, qc);

        test_arm_mve_expected_qdmlah(expected, q_initial, q_n, scalar,
                                     esize, true, true, 0xffff, &qc);
        test_arm_m55_mve_scalar_2op_run_qc(vqrdmlash_insns[ncase],
                                           q_initial, q_n, scalar, 0,
                                           expected, false, false, qc);
    }

    test_arm_mve_expected_scalar_acc(expected, initial, n, scalar, 4,
                                     false, 0xff00);
    test_arm_m55_mve_scalar_2op_run(vmla_insns[2], initial, n, scalar,
                                    expected, true);

    test_arm_mve_expected_qdmlah(expected, q_initial, q_n, sat_scalar, 4,
                                 false, false, 0xff00, &qc);
    test_arm_m55_mve_scalar_2op_run_qc(vqdmlah_insns[2], q_initial, q_n,
                                       sat_scalar, 0, expected, true, false,
                                       qc);

    test_arm_mve_expected_qdmlah(expected, q_initial, q_n, scalar, 4,
                                 false, true, 0xffff, &qc);
    test_arm_m55_mve_scalar_2op_run_qc(vqrdmlah_insns[2], q_initial, q_n,
                                       scalar, 0, expected, false, true,
                                       true);

    test_arm_m55_mve_2op_expect_error(0x0e63ee32, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x1e63ee32, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0e43ee43, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0ec3ee01, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0e4dee03, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0e4fee03, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0e43ee03, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_cadd(void)
{
    static const uint32_t vhcadd90_insns[] = {
        0x0f04ee02, 0x0f04ee12, 0x0f04ee22,
    };
    static const uint32_t vhcadd270_insns[] = {
        0x1f04ee02, 0x1f04ee12, 0x1f04ee22,
    };
    static const uint32_t vcadd90_insns[] = {
        0x0f04fe02, 0x0f04fe12, 0x0f04fe22,
    };
    static const uint32_t vcadd270_insns[] = {
        0x1f04fe02, 0x1f04fe12, 0x1f04fe22,
    };
    const uint8_t initial[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const uint8_t n[16] = {
        0x80, 0x7f, 0x01, 0xff, 0x34, 0x12, 0x00, 0x80,
        0xfe, 0xff, 0x00, 0x40, 0x11, 0x22, 0xef, 0xdd,
    };
    const uint8_t m[16] = {
        0x7f, 0x80, 0x02, 0xfe, 0x35, 0x12, 0xff, 0x7f,
        0x02, 0x00, 0xff, 0xbf, 0x44, 0x33, 0xbc, 0xaa,
    };
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    size_t ncase;

    for (ncase = 0; ncase < 3; ncase++) {
        test_arm_mve_expected_cadd(expected, initial, n, m, esizes[ncase],
                                   false, true, 0xffff);
        test_arm_m55_mve_2op_run(vhcadd90_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_cadd(expected, initial, n, m, esizes[ncase],
                                   true, true, 0xffff);
        test_arm_m55_mve_2op_run(vhcadd270_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_cadd(expected, initial, n, m, esizes[ncase],
                                   false, false, 0xffff);
        test_arm_m55_mve_2op_run(vcadd90_insns[ncase], initial, n, m,
                                 expected, false);

        test_arm_mve_expected_cadd(expected, initial, n, m, esizes[ncase],
                                   true, false, 0xffff);
        test_arm_m55_mve_2op_run(vcadd270_insns[ncase], initial, n, m,
                                 expected, false);
    }

    test_arm_mve_expected_cadd(expected, initial, n, m, 4, true, true,
                               0xff00);
    test_arm_m55_mve_2op_run(0x1f04ee22, initial, n, m, expected, true);

    test_arm_mve_expected_cadd(expected, initial, n, initial, 4, false,
                               false, 0xffff);
    test_arm_m55_mve_2op_run(0x0f00fe22, initial, n, m, expected, false);

    test_arm_m55_mve_2op_expect_error(0x0f04fe42, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f04fe02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_EXCEPTION);
}

static void test_arm_mve_expected_vdup(uint8_t *expected,
                                       const uint8_t *initial,
                                       uint32_t value, unsigned esize,
                                       uint16_t mask)
{
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += esize) {
        test_arm_mve_store_masked(expected, i, esize, value, mask);
    }
}

static uint64_t test_arm_mve_dup_const32(uint32_t value)
{
    return ((uint64_t)value << 32) | value;
}

static uint64_t test_arm_mve_asimd_imm_const(uint32_t imm, unsigned cmode,
                                             bool op)
{
    switch (cmode) {
    case 0:
    case 1:
        break;
    case 2:
    case 3:
        imm <<= 8;
        break;
    case 4:
    case 5:
        imm <<= 16;
        break;
    case 6:
    case 7:
        imm <<= 24;
        break;
    case 8:
    case 9:
        imm |= imm << 16;
        break;
    case 10:
    case 11:
        imm = (imm << 8) | (imm << 24);
        break;
    case 12:
        imm = (imm << 8) | 0xff;
        break;
    case 13:
        imm = (imm << 16) | 0xffff;
        break;
    case 14:
        if (op) {
            uint64_t imm64 = 0;
            unsigned n;

            for (n = 0; n < 8; n++) {
                if (imm & (1U << n)) {
                    imm64 |= 0xffULL << (n * 8);
                }
            }
            return imm64;
        }
        imm |= (imm << 8) | (imm << 16) | (imm << 24);
        break;
    case 15:
        TEST_CHECK(!op);
        imm = ((imm & 0x80) << 24) | ((imm & 0x3f) << 19) |
              ((imm & 0x40) ? (0x1f << 25) : (1 << 30));
        break;
    default:
        TEST_CHECK(false);
        break;
    }
    if (op) {
        imm = ~imm;
    }
    return test_arm_mve_dup_const32(imm);
}

static uint32_t test_arm_mve_vimm_1r_insn(unsigned qd, uint32_t imm,
                                          unsigned cmode, bool op)
{
    uint32_t view = 0xef800050;

    view |= ((qd >> 3) & 1) << 22;
    view |= (qd & 7) << 13;
    view |= ((imm >> 7) & 1) << 28;
    view |= ((imm >> 4) & 7) << 16;
    view |= imm & 0xf;
    view |= (cmode & 0xf) << 8;
    if (op) {
        view |= 1U << 5;
    }
    return (view << 16) | (view >> 16);
}

static void test_arm_mve_expected_vimm(uint8_t *expected,
                                       const uint8_t *initial,
                                       uint64_t imm, char op,
                                       uint16_t mask)
{
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += 8) {
        uint64_t lhs = test_arm_load_le64(initial + i);
        uint64_t result;

        switch (op) {
        case 'm':
            result = imm;
            break;
        case '&':
            result = lhs & imm;
            break;
        case '|':
            result = lhs | imm;
            break;
        default:
            TEST_CHECK(false);
            result = 0;
            break;
        }
        test_arm_mve_store_masked(expected, i, 8, result, mask);
    }
}

static void test_arm_m55_mve_vimm_run(uint32_t insn, const uint8_t *initial,
                                      uint32_t vpr,
                                      const uint8_t *expected, bool eci)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                    insn, (unsigned)i, got[i], expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm_m55_mve_vimm(void)
{
    const uint8_t initial[16] = {
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
    };
    uint8_t expected[16];
    uint64_t imm;
    uint32_t insn;

    insn = test_arm_mve_vimm_1r_insn(0, 0x5a, 0, false);
    imm = test_arm_mve_asimd_imm_const(0x5a, 0, false);
    test_arm_mve_expected_vimm(expected, initial, imm, 'm', 0xffff);
    test_arm_m55_mve_vimm_run(insn, initial, 0, expected, false);

    insn = test_arm_mve_vimm_1r_insn(0, 0x24, 2, true);
    imm = test_arm_mve_asimd_imm_const(0x24, 2, true);
    test_arm_mve_expected_vimm(expected, initial, imm, 'm', 0xffff);
    test_arm_m55_mve_vimm_run(insn, initial, 0, expected, false);

    insn = test_arm_mve_vimm_1r_insn(0, 0x33, 1, false);
    imm = test_arm_mve_asimd_imm_const(0x33, 1, false);
    test_arm_mve_expected_vimm(expected, initial, imm, '|', 0xffff);
    test_arm_m55_mve_vimm_run(insn, initial, 0, expected, false);

    insn = test_arm_mve_vimm_1r_insn(0, 0x12, 3, true);
    imm = test_arm_mve_asimd_imm_const(0x12, 3, true);
    test_arm_mve_expected_vimm(expected, initial, imm, '&', 0xffff);
    test_arm_m55_mve_vimm_run(insn, initial, 0, expected, false);

    insn = test_arm_mve_vimm_1r_insn(0, 0x6c, 0, false);
    imm = test_arm_mve_asimd_imm_const(0x6c, 0, false);
    test_arm_mve_expected_vimm(expected, initial, imm, 'm', 0x00f0);
    test_arm_m55_mve_vimm_run(insn, initial, 0x001100f0, expected, false);

    insn = test_arm_mve_vimm_1r_insn(0, 0x77, 1, false);
    imm = test_arm_mve_asimd_imm_const(0x77, 1, false);
    test_arm_mve_expected_vimm(expected, initial, imm, '|', 0xff00);
    test_arm_m55_mve_vimm_run(insn, initial, 0, expected, true);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vimm_1r_insn(0, 0x01, 15, true),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vimm_1r_insn(8, 0x5a, 0, false),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vimm_1r_insn(0, 0x5a, 0, false),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_INSN_INVALID);
}

typedef enum test_arm_mve_shift_imm_kind {
    TEST_ARM_MVE_SHIFT_IMM_SHL,
    TEST_ARM_MVE_SHIFT_IMM_SHR_S,
    TEST_ARM_MVE_SHIFT_IMM_SHR_U,
    TEST_ARM_MVE_SHIFT_IMM_RSHR_S,
    TEST_ARM_MVE_SHIFT_IMM_RSHR_U,
    TEST_ARM_MVE_SHIFT_IMM_SRI,
    TEST_ARM_MVE_SHIFT_IMM_SLI,
    TEST_ARM_MVE_SHIFT_IMM_QSHL_S,
    TEST_ARM_MVE_SHIFT_IMM_QSHL_U,
    TEST_ARM_MVE_SHIFT_IMM_QSHL_SU,
} test_arm_mve_shift_imm_kind;

static uint32_t test_arm_mve_view_to_t32(uint32_t view)
{
    return (view << 16) | (view >> 16);
}

static uint32_t test_arm_mve_2op_insn(uint32_t base, unsigned qd,
                                      unsigned qn, unsigned qm)
{
    uint32_t view = base;

    view |= ((qd >> 3) & 1) << 22;
    view |= (qd & 7) << 13;
    view |= ((qn >> 3) & 1) << 7;
    view |= (qn & 7) << 17;
    view |= ((qm >> 3) & 1) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static void test_arm_mve_expected_carry(uint8_t *expected,
                                        const uint8_t *initial,
                                        const uint8_t *n, const uint8_t *m,
                                        bool subtract, uint32_t carry_in,
                                        uint16_t mask, uint32_t *carry_out)
{
    unsigned lane;

    memcpy(expected, initial, 16);
    for (lane = 0; lane < 4; lane++, mask >>= 4) {
        uint16_t lane_mask = mask & 0xf;
        uint64_t value = carry_in;
        unsigned byte;

        value += test_arm_load_le(n + lane * 4, 4);
        value += test_arm_load_le(m + lane * 4, 4) ^
            (subtract ? UINT32_MAX : 0);
        if (lane_mask & 1) {
            carry_in = (uint32_t)(value >> 32);
        }
        for (byte = 0; byte < 4; byte++) {
            if (lane_mask & (1U << byte)) {
                expected[lane * 4 + byte] =
                    (uint8_t)((uint32_t)value >> (byte * 8));
            }
        }
    }
    *carry_out = carry_in;
}

static void test_arm_m55_mve_carry_run(uint32_t insn,
                                       const uint8_t *initial,
                                       const uint8_t *n, const uint8_t *m,
                                       uint32_t fpscr_in, uint32_t vpr,
                                       const uint8_t *expected,
                                       uint32_t expected_c, bool eci)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint32_t fpscr_c = 1U << 29;
    const uint32_t fpscr_nzv = (1U << 31) | (1U << 30) | (1U << 28);
    uc_engine *uc;
    uint8_t code[8] = { 0 };
    uint64_t q0[2];
    uint64_t q1[2];
    uint64_t q2[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    uint32_t fpscr = fpscr_in;
    uint32_t target_offset = 0;
    bool seed_c = (fpscr_in & fpscr_c) != 0;
    size_t i;

    if (seed_c) {
        test_arm_emit32(code, 0, test_arm_mve_2op_insn(0xee301f00, 3, 1, 2));
        target_offset = 4;
    }
    test_arm_emit32(code, target_offset, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, n, 16);
    memcpy(q2, m, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_Q2, q2));
    if (seed_c) {
        uint32_t zero = 0;

        OK(uc_reg_write(uc, UC_ARM_REG_VPR, &zero));
        OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &zero));
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
    } else {
        OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));
    }
    OK(uc_reg_write(uc, UC_ARM_REG_VPR, &vpr));

    if (eci) {
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + target_offset) | 1,
                        code_start + target_offset + 4, 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, (code_start + target_offset) | 1,
                        code_start + target_offset + 4, 0, 0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                    insn, (unsigned)i, got[i], expected[i]);
    }
    TEST_CHECK((fpscr & fpscr_c) == (expected_c ? fpscr_c : 0));
    TEST_CHECK((fpscr & fpscr_nzv) == 0);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_carry(void)
{
    const uint32_t vadc_base = 0xee300f00;
    const uint32_t vadci_base = 0xee301f00;
    const uint32_t vsbc_base = 0xfe300f00;
    const uint32_t vsbci_base = 0xfe301f00;
    const uint32_t fpscr_c = 1U << 29;
    const uint32_t fpscr_nzv = (1U << 31) | (1U << 30) | (1U << 28);
    const uint8_t initial[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const uint8_t n[16] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x80,
    };
    const uint8_t m[16] = {
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
    };
    uint8_t expected[16];
    uint32_t carry_out;
    uint32_t insn;

    insn = test_arm_mve_2op_insn(vadc_base, 0, 1, 2);
    test_arm_mve_expected_carry(expected, initial, n, m, false, 1, 0xffff,
                                &carry_out);
    test_arm_m55_mve_carry_run(insn, initial, n, m, fpscr_nzv | fpscr_c, 0,
                               expected, carry_out, false);

    insn = test_arm_mve_2op_insn(vadci_base, 0, 1, 2);
    test_arm_mve_expected_carry(expected, initial, n, m, false, 0, 0xffff,
                                &carry_out);
    test_arm_m55_mve_carry_run(insn, initial, n, m, fpscr_nzv | fpscr_c, 0,
                               expected, carry_out, false);

    insn = test_arm_mve_2op_insn(vsbc_base, 0, 1, 2);
    test_arm_mve_expected_carry(expected, initial, n, m, true, 1, 0xffff,
                                &carry_out);
    test_arm_m55_mve_carry_run(insn, initial, n, m, fpscr_nzv | fpscr_c, 0,
                               expected, carry_out, false);

    insn = test_arm_mve_2op_insn(vsbci_base, 0, 1, 2);
    test_arm_mve_expected_carry(expected, initial, n, m, true, 1, 0xffff,
                                &carry_out);
    test_arm_m55_mve_carry_run(insn, initial, n, m, fpscr_nzv, 0, expected,
                               carry_out, false);

    insn = test_arm_mve_2op_insn(vadc_base, 0, 1, 2);
    test_arm_mve_expected_carry(expected, initial, n, m, false, 1, 0x00ff,
                                &carry_out);
    test_arm_m55_mve_carry_run(insn, initial, n, m, fpscr_nzv | fpscr_c,
                               0x00ff00ff, expected, carry_out, false);

    insn = test_arm_mve_2op_insn(vadci_base, 0, 1, 2);
    test_arm_mve_expected_carry(expected, initial, n, m, false, 1, 0xff00,
                                &carry_out);
    test_arm_m55_mve_carry_run(insn, initial, n, m, fpscr_nzv | fpscr_c, 0,
                               expected, carry_out, true);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_2op_insn(vadc_base, 8, 1, 2),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_2op_insn(vadc_base, 0, 1, 2),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
}

static uint32_t test_arm_mve_fp_scalar_insn(uint32_t base, bool fp16,
                                            unsigned qd, unsigned qn,
                                            unsigned rm)
{
    uint32_t view = base;

    if (fp16) {
        view |= 1U << 28;
    }
    view |= ((qd >> 3) & 1) << 22;
    view |= (qd & 7) << 13;
    view |= ((qn >> 3) & 1) << 7;
    view |= (qn & 7) << 17;
    view |= rm & 15;
    return test_arm_mve_view_to_t32(view);
}

static void test_arm_m55_mve_fp_scalar_run(uint32_t insn,
                                           const uint8_t *initial,
                                           const uint8_t *n, uint32_t rm,
                                           uint32_t vpr,
                                           const uint8_t *expected,
                                           bool eci, bool expected_ioc)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint32_t fpscr_ioc = 1U;
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    uint64_t q1[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    uint32_t fpscr = 0;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, n, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &rm));
    OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                    insn, (unsigned)i, got[i], expected[i]);
    }
    TEST_CHECK_(((fpscr & fpscr_ioc) != 0) == expected_ioc,
                "insn=0x%08x fpscr=0x%08x expected_ioc=%u",
                insn, fpscr, expected_ioc ? 1 : 0);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_fp_scalar(void)
{
    const uint32_t vadd_base = 0xee300f40;
    const uint32_t vsub_base = 0xee301f40;
    const uint32_t vmul_base = 0xee310e60;
    const uint32_t vfma_base = 0xee310e40;
    const uint32_t vfmas_base = 0xee311e40;
    const uint8_t initial_f32[16] = {
        0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x00, 0xc0,
        0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x80, 0xc0,
    };
    const uint8_t n_f32[16] = {
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x40,
        0x00, 0x00, 0xc0, 0xbf, 0x00, 0x00, 0x00, 0xbf,
    };
    const uint8_t vadd_f32[16] = {
        0x00, 0x00, 0x80, 0x40, 0x00, 0x00, 0xa0, 0x40,
        0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0xc0, 0x3f,
    };
    const uint8_t vsub_f32[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f,
        0x00, 0x00, 0x60, 0xc0, 0x00, 0x00, 0x20, 0xc0,
    };
    const uint8_t vmul_f32[16] = {
        0x00, 0x00, 0x80, 0x40, 0x00, 0x00, 0xc0, 0x40,
        0x00, 0x00, 0x40, 0xc0, 0x00, 0x00, 0x80, 0xbf,
    };
    const uint8_t vfma_f32[16] = {
        0x00, 0x00, 0xa0, 0x40, 0x00, 0x00, 0x80, 0x40,
        0x00, 0x00, 0x20, 0xc0, 0x00, 0x00, 0xa0, 0xc0,
    };
    const uint8_t vfmas_f32[16] = {
        0x00, 0x00, 0x80, 0x40, 0x00, 0x00, 0x80, 0xc0,
        0x00, 0x00, 0xa0, 0x3f, 0x00, 0x00, 0x80, 0x40,
    };
    const uint8_t vfma_f32_eci[16] = {
        0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x00, 0xc0,
        0x00, 0x00, 0x20, 0xc0, 0x00, 0x00, 0xa0, 0xc0,
    };
    const uint8_t initial_f16[16] = {
        0x00, 0x3c, 0x00, 0xc0, 0x00, 0x38, 0x00, 0xc4,
        0x00, 0x3e, 0x00, 0xbc, 0x00, 0x00, 0x00, 0x42,
    };
    const uint8_t n_f16[16] = {
        0x00, 0x40, 0x00, 0x42, 0x00, 0xbe, 0x00, 0xb8,
        0x00, 0x44, 0x00, 0xc2, 0x00, 0x3c, 0x00, 0x34,
    };
    const uint8_t vadd_f16[16] = {
        0x00, 0x44, 0x00, 0x45, 0x00, 0x38, 0x00, 0x3e,
        0x00, 0x46, 0x00, 0xbc, 0x00, 0x42, 0x80, 0x40,
    };
    const uint8_t vsub_f16[16] = {
        0x00, 0x00, 0x00, 0x3c, 0x00, 0xc3, 0x00, 0xc1,
        0x00, 0x40, 0x00, 0xc5, 0x00, 0xbc, 0x00, 0xbf,
    };
    const uint8_t vmul_f16[16] = {
        0x00, 0x44, 0x00, 0x46, 0x00, 0xc2, 0x00, 0xbc,
        0x00, 0x48, 0x00, 0xc6, 0x00, 0x40, 0x00, 0x38,
    };
    const uint8_t vfma_f16[16] = {
        0x00, 0x45, 0x00, 0x44, 0x00, 0xc1, 0x00, 0xc5,
        0xc0, 0x48, 0x00, 0xc7, 0x00, 0x40, 0x00, 0x43,
    };
    const uint8_t vfmas_f16[16] = {
        0x00, 0x44, 0x00, 0xc4, 0x00, 0x3d, 0x00, 0x44,
        0x00, 0x48, 0x00, 0x45, 0x00, 0x40, 0x80, 0x41,
    };
    const uint8_t vmul_f16_vpr[16] = {
        0x00, 0x3c, 0x00, 0xc0, 0x00, 0xc2, 0x00, 0xbc,
        0x00, 0x3e, 0x00, 0xbc, 0x00, 0x00, 0x00, 0x42,
    };
    const struct {
        uint32_t base;
        const uint8_t *expected_f32;
        const uint8_t *expected_f16;
    } cases[] = {
        { vadd_base, vadd_f32, vadd_f16 },
        { vsub_base, vsub_f32, vsub_f16 },
        { vmul_base, vmul_f32, vmul_f16 },
        { vfma_base, vfma_f32, vfma_f16 },
        { vfmas_base, vfmas_f32, vfmas_f16 },
    };
    uint32_t scalar_f32 = 0x40000000;
    uint32_t scalar_f16 = 0x4000;
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        test_arm_m55_mve_fp_scalar_run(
            test_arm_mve_fp_scalar_insn(cases[i].base, false, 0, 1, 3),
            initial_f32, n_f32, scalar_f32, 0, cases[i].expected_f32,
            false, false);
        test_arm_m55_mve_fp_scalar_run(
            test_arm_mve_fp_scalar_insn(cases[i].base, true, 0, 1, 3),
            initial_f16, n_f16, scalar_f16, 0, cases[i].expected_f16,
            false, false);
    }

    test_arm_m55_mve_fp_scalar_run(
        test_arm_mve_fp_scalar_insn(vmul_base, true, 0, 1, 3),
        initial_f16, n_f16, scalar_f16, 0x001100f0, vmul_f16_vpr,
        false, false);
    test_arm_m55_mve_fp_scalar_run(
        test_arm_mve_fp_scalar_insn(vfma_base, false, 0, 1, 3),
        initial_f32, n_f32, scalar_f32, 0, vfma_f32_eci, true, false);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_fp_scalar_insn(vadd_base, false, 0, 1, 13),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_fp_scalar_insn(vadd_base, false, 0, 1, 15),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_fp_scalar_insn(vadd_base, false, 8, 1, 3),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_fp_scalar_insn(vadd_base, false, 0, 8, 3),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_fp_scalar_insn(vadd_base, false, 0, 1, 3),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
}

static uint32_t test_arm_mve_vshift_imm_insn(unsigned qd, unsigned qm,
                                             uint32_t base, unsigned size,
                                             unsigned shift, bool right)
{
    unsigned bits = 8U << size;
    uint32_t encoded = right ? bits - shift : shift;
    uint32_t view = base;

    view |= ((qd >> 3) & 1) << 22;
    view |= (qd & 7) << 13;
    view |= ((qm >> 3) & 1) << 5;
    view |= (qm & 7) << 1;
    switch (size) {
    case 0:
        view |= 1U << 19;
        view |= (encoded & 7) << 16;
        break;
    case 1:
        view |= 1U << 20;
        view |= (encoded & 15) << 16;
        break;
    case 2:
        view |= 1U << 21;
        view |= (encoded & 31) << 16;
        break;
    default:
        TEST_CHECK(false);
        break;
    }
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_element_mask(unsigned bits)
{
    return bits == 32 ? UINT32_MAX : (1U << bits) - 1;
}

static uint32_t test_arm_mve_expected_shift_imm_lane(uint32_t dst,
                                                     uint32_t src,
                                                     unsigned bits,
                                                     unsigned shift,
                                                     test_arm_mve_shift_imm_kind kind)
{
    uint32_t mask = test_arm_mve_element_mask(bits);
    uint64_t wide;
    int64_t sval;
    int64_t stmp;
    uint32_t field_mask;

    src &= mask;
    dst &= mask;
    switch (kind) {
    case TEST_ARM_MVE_SHIFT_IMM_SHL:
        return (uint32_t)((uint64_t)src << shift) & mask;
    case TEST_ARM_MVE_SHIFT_IMM_SHR_S:
        sval = test_arm_sign_extend(src, bits);
        if (shift >= bits) {
            return sval < 0 ? mask : 0;
        }
        return (uint32_t)(sval >> shift) & mask;
    case TEST_ARM_MVE_SHIFT_IMM_SHR_U:
        return shift >= bits ? 0 : src >> shift;
    case TEST_ARM_MVE_SHIFT_IMM_RSHR_S:
        sval = test_arm_sign_extend(src, bits);
        stmp = sval >> (shift - 1);
        return (uint32_t)((stmp >> 1) + (stmp & 1)) & mask;
    case TEST_ARM_MVE_SHIFT_IMM_RSHR_U:
        wide = src + (1ULL << (shift - 1));
        return (uint32_t)(wide >> shift) & mask;
    case TEST_ARM_MVE_SHIFT_IMM_SRI:
        if (shift == bits) {
            return dst;
        }
        field_mask = mask >> shift;
        return ((src >> shift) & field_mask) | (dst & ~field_mask);
    case TEST_ARM_MVE_SHIFT_IMM_SLI:
        field_mask = (mask << shift) & mask;
        return (((uint32_t)((uint64_t)src << shift)) & field_mask) |
               (dst & ~field_mask);
    default:
        TEST_CHECK(false);
        return 0;
    }
}

static void test_arm_mve_expected_shift_imm(uint8_t *expected,
                                            const uint8_t *initial,
                                            const uint8_t *source,
                                            unsigned esize,
                                            unsigned shift,
                                            test_arm_mve_shift_imm_kind kind,
                                            uint16_t pred)
{
    unsigned bits = esize * 8;
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += esize) {
        uint32_t dst = test_arm_load_le(initial + i, esize);
        uint32_t src = test_arm_load_le(source + i, esize);
        uint32_t result;

        result = test_arm_mve_expected_shift_imm_lane(dst, src, bits,
                                                      shift, kind);
        test_arm_mve_store_masked(expected, i, esize, result, pred);
    }
}

static uint32_t test_arm_mve_sat_u(uint64_t value, unsigned bits,
                                   bool *saturated)
{
    uint64_t max = bits == 32 ? UINT32_MAX : (1ULL << bits) - 1;

    if (value > max) {
        *saturated = true;
        return (uint32_t)max;
    }
    return (uint32_t)value;
}

static uint32_t test_arm_mve_sat_s(int64_t value, unsigned bits,
                                   bool *saturated)
{
    int64_t min = -(1LL << (bits - 1));
    int64_t max = (1LL << (bits - 1)) - 1;

    if (value > max) {
        *saturated = true;
        return (uint32_t)max;
    } else if (value < min) {
        *saturated = true;
        return (uint32_t)min;
    }
    return (uint32_t)value;
}

static uint32_t test_arm_mve_expected_qshift_imm_lane(
    uint32_t src, unsigned bits, unsigned shift,
    test_arm_mve_shift_imm_kind kind, bool *saturated)
{
    uint32_t mask = test_arm_mve_element_mask(bits);
    int64_t sval;

    src &= mask;
    *saturated = false;
    switch (kind) {
    case TEST_ARM_MVE_SHIFT_IMM_QSHL_S:
        sval = test_arm_sign_extend(src, bits);
        return test_arm_mve_sat_s(sval * (1LL << shift), bits, saturated) &
               mask;
    case TEST_ARM_MVE_SHIFT_IMM_QSHL_U:
        return test_arm_mve_sat_u((uint64_t)src << shift, bits, saturated) &
               mask;
    case TEST_ARM_MVE_SHIFT_IMM_QSHL_SU:
        sval = test_arm_sign_extend(src, bits);
        if (sval < 0) {
            *saturated = true;
            return 0;
        }
        return test_arm_mve_sat_u((uint64_t)sval << shift, bits,
                                  saturated) & mask;
    default:
        TEST_CHECK(false);
        return 0;
    }
}

static void test_arm_mve_expected_qshift_imm(
    uint8_t *expected, const uint8_t *initial, const uint8_t *source,
    unsigned esize, unsigned shift, test_arm_mve_shift_imm_kind kind,
    uint16_t pred, bool *qc)
{
    unsigned bits = esize * 8;
    size_t i;

    memcpy(expected, initial, 16);
    *qc = false;
    for (i = 0; i < 16; i += esize) {
        uint32_t src = test_arm_load_le(source + i, esize);
        bool saturated;
        uint32_t result;

        result = test_arm_mve_expected_qshift_imm_lane(src, bits, shift,
                                                       kind, &saturated);
        test_arm_mve_store_masked(expected, i, esize, result, pred);
        if (saturated && (pred & (1U << i))) {
            *qc = true;
        }
    }
}

static void test_arm_m55_mve_shift_imm_run_qc_init(uint32_t insn,
                                                   const uint8_t *initial,
                                                   const uint8_t *source,
                                                   uint32_t vpr,
                                                   const uint8_t *expected,
                                                   bool eci,
                                                   bool initial_qc,
                                                   bool expected_qc)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint32_t fpscr_qc = 1U << 27;
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    uint64_t q1[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    uint32_t fpscr = 0;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, source, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));

    if (eci || initial_qc) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        if (initial_qc) {
            OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
            fpscr |= fpscr_qc;
            OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));
        }
        epsr = xpsr_t | eci_a0a1;
        if (eci) {
            OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        }
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        if (eci) {
            OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
            TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                        "epsr=0x%08x", epsr);
        }
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                    insn, (unsigned)i, got[i], expected[i]);
    }
    TEST_CHECK_(((fpscr & fpscr_qc) != 0) == expected_qc,
                "fpscr=0x%08x expected_qc=%d",
                fpscr, expected_qc);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_shift_imm_run_qc(uint32_t insn,
                                              const uint8_t *initial,
                                              const uint8_t *source,
                                              uint32_t vpr,
                                              const uint8_t *expected,
                                              bool eci,
                                              bool expected_qc)
{
    test_arm_m55_mve_shift_imm_run_qc_init(insn, initial, source, vpr,
                                           expected, eci, false,
                                           expected_qc);
}

static void test_arm_m55_mve_shift_imm_run(uint32_t insn,
                                           const uint8_t *initial,
                                           const uint8_t *source,
                                           uint32_t vpr,
                                           const uint8_t *expected,
                                           bool eci)
{
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, source, vpr, expected,
                                      eci, false);
}

static void test_arm_m55_mve_shift_imm(void)
{
    const uint8_t initial[16] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    };
    const uint8_t source[16] = {
        0x81, 0x7f, 0x12, 0xf0, 0x55, 0xaa, 0x01, 0x80,
        0xfe, 0x10, 0x33, 0xcc, 0x09, 0x90, 0x44, 0x22,
    };
    uint8_t expected[16];
    uint32_t insn;

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xef800550, 0, 3, false);
    test_arm_mve_expected_shift_imm(expected, initial, source, 1, 3,
                                    TEST_ARM_MVE_SHIFT_IMM_SHL, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xef800050, 1, 4, true);
    test_arm_mve_expected_shift_imm(expected, initial, source, 2, 4,
                                    TEST_ARM_MVE_SHIFT_IMM_SHR_S, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xff800050, 2, 8, true);
    test_arm_mve_expected_shift_imm(expected, initial, source, 4, 8,
                                    TEST_ARM_MVE_SHIFT_IMM_SHR_U, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xff800250, 0, 2, true);
    test_arm_mve_expected_shift_imm(expected, initial, source, 1, 2,
                                    TEST_ARM_MVE_SHIFT_IMM_RSHR_U,
                                    0x00f0);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0x001100f0,
                                   expected, false);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xef800250, 2, 8, true);
    test_arm_mve_expected_shift_imm(expected, initial, source, 4, 8,
                                    TEST_ARM_MVE_SHIFT_IMM_RSHR_S,
                                    0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xef800050, 0, 8, true);
    test_arm_mve_expected_shift_imm(expected, initial, source, 1, 8,
                                    TEST_ARM_MVE_SHIFT_IMM_SHR_S, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xff800050, 2, 32, true);
    test_arm_mve_expected_shift_imm(expected, initial, source, 4, 32,
                                    TEST_ARM_MVE_SHIFT_IMM_SHR_U, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xef800250, 1, 16, true);
    test_arm_mve_expected_shift_imm(expected, initial, source, 2, 16,
                                    TEST_ARM_MVE_SHIFT_IMM_RSHR_S,
                                    0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xff800250, 0, 8, true);
    test_arm_mve_expected_shift_imm(expected, initial, source, 1, 8,
                                    TEST_ARM_MVE_SHIFT_IMM_RSHR_U,
                                    0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xff800450, 1, 4, true);
    test_arm_mve_expected_shift_imm(expected, initial, source, 2, 4,
                                    TEST_ARM_MVE_SHIFT_IMM_SRI, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xff800550, 2, 8, false);
    test_arm_mve_expected_shift_imm(expected, initial, source, 4, 8,
                                    TEST_ARM_MVE_SHIFT_IMM_SLI, 0xff00);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   true);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshift_imm_insn(8, 1, 0xef800550, 0, 3, false),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshift_imm_insn(0, 1, 0xef800550, 0, 3, false),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_INSN_INVALID);
}

static void test_arm_m55_mve_qshift_imm(void)
{
    const uint8_t initial[16] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    };
    const uint8_t source[16] = {
        0x81, 0x7f, 0x12, 0xf0, 0x55, 0xaa, 0x01, 0x80,
        0xfe, 0x10, 0x33, 0xcc, 0x09, 0x90, 0x44, 0x22,
    };
    const uint8_t eci_source[16] = {
        0x7f, 0x80, 0x70, 0x90, 0x60, 0xa0, 0x50, 0xb0,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    uint8_t expected[16];
    uint32_t insn;
    bool qc;

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xef800750, 0, 2, false);
    test_arm_mve_expected_qshift_imm(expected, initial, source, 1, 2,
                                     TEST_ARM_MVE_SHIFT_IMM_QSHL_S,
                                     0xffff, &qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, source, 0, expected,
                                      false, qc);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xff800750, 1, 4, false);
    test_arm_mve_expected_qshift_imm(expected, initial, source, 2, 4,
                                     TEST_ARM_MVE_SHIFT_IMM_QSHL_U,
                                     0xffff, &qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, source, 0, expected,
                                      false, qc);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xff800650, 2, 8, false);
    test_arm_mve_expected_qshift_imm(expected, initial, source, 4, 8,
                                     TEST_ARM_MVE_SHIFT_IMM_QSHL_SU,
                                     0xffff, &qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, source, 0, expected,
                                      false, qc);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xff800750, 0, 7, false);
    test_arm_mve_expected_qshift_imm(expected, initial, source, 1, 7,
                                     TEST_ARM_MVE_SHIFT_IMM_QSHL_U,
                                     0x00f0, &qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, source, 0x001100f0,
                                      expected, false, qc);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xef800750, 0, 2, false);
    test_arm_mve_expected_qshift_imm(expected, initial, eci_source, 1, 2,
                                     TEST_ARM_MVE_SHIFT_IMM_QSHL_S,
                                     0xff00, &qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, eci_source, 0,
                                      expected, true, qc);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshift_imm_insn(8, 1, 0xef800750, 0, 2, false),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshift_imm_insn(0, 1, 0xef800750, 0, 2, false),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_INSN_INVALID);
}

static uint32_t test_arm_mve_vshift_scalar_insn(unsigned qd, uint32_t base,
                                                unsigned size, unsigned rm)
{
    uint32_t view = base;

    view |= ((qd >> 3) & 1) << 22;
    view |= (qd & 7) << 13;
    view |= (size & 3) << 18;
    view |= rm & 15;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_expected_qshift_scalar_lane(uint32_t src,
                                                        unsigned bits,
                                                        int8_t shift,
                                                        bool is_signed,
                                                        bool rounded,
                                                        bool *saturated)
{
    uint32_t mask = test_arm_mve_element_mask(bits);
    int64_t sval;
    int64_t sresult;
    uint64_t uvalue;
    uint64_t uresult;

    src &= mask;
    *saturated = false;
    if (is_signed) {
        sval = test_arm_sign_extend(src, bits);
        if (shift <= -(int)bits) {
            sresult = rounded ? 0 : (sval < 0 ? -1 : 0);
        } else if (shift < 0) {
            if (rounded) {
                sval >>= -shift - 1;
                sresult = (sval >> 1) + (sval & 1);
            } else {
                sresult = sval >> -shift;
            }
        } else if (shift < (int)bits) {
            return test_arm_mve_sat_s(sval * (1LL << shift), bits,
                                      saturated) & mask;
        } else if (sval == 0) {
            sresult = 0;
        } else {
            *saturated = true;
            return (sval < 0 ? 1U << (bits - 1) :
                    (1U << (bits - 1)) - 1) & mask;
        }
        return (uint32_t)sresult & mask;
    }

    uvalue = src;
    if (shift <= -((int)bits + rounded)) {
        uresult = 0;
    } else if (shift < 0) {
        if (rounded) {
            uvalue >>= -shift - 1;
            uresult = (uvalue >> 1) + (uvalue & 1);
        } else {
            uresult = uvalue >> -shift;
        }
    } else if (shift < (int)bits) {
        return test_arm_mve_sat_u(uvalue << shift, bits, saturated) & mask;
    } else if (uvalue == 0) {
        uresult = 0;
    } else {
        *saturated = true;
        return mask;
    }
    return (uint32_t)uresult & mask;
}

static void test_arm_mve_expected_qshift(uint8_t *expected,
                                         const uint8_t *initial,
                                         const uint8_t *values,
                                         const uint8_t *shifts,
                                         unsigned esize, bool is_signed,
                                         bool rounded, uint16_t pred,
                                         bool *qc)
{
    unsigned bits = esize * 8;
    size_t i;

    memcpy(expected, initial, 16);
    *qc = false;
    for (i = 0; i < 16; i += esize) {
        uint32_t src = test_arm_load_le(values + i, esize);
        int8_t shift = (int8_t)test_arm_load_le(shifts + i, esize);
        bool saturated;
        uint32_t result;

        result = test_arm_mve_expected_qshift_scalar_lane(src, bits, shift,
                                                          is_signed, rounded,
                                                          &saturated);
        test_arm_mve_store_masked(expected, i, esize, result, pred);
        if (saturated && (pred & (1U << i))) {
            *qc = true;
        }
    }
}

static void test_arm_mve_expected_qshift_scalar(uint8_t *expected,
                                                const uint8_t *initial,
                                                const uint8_t *source,
                                                unsigned esize, uint32_t rm,
                                                bool is_signed,
                                                bool rounded, uint16_t pred,
                                                bool *qc)
{
    unsigned bits = esize * 8;
    int8_t shift = (int8_t)rm;
    size_t i;

    memcpy(expected, initial, 16);
    *qc = false;
    for (i = 0; i < 16; i += esize) {
        uint32_t src = test_arm_load_le(source + i, esize);
        bool saturated;
        uint32_t result;

        result = test_arm_mve_expected_qshift_scalar_lane(src, bits, shift,
                                                          is_signed, rounded,
                                                          &saturated);
        test_arm_mve_store_masked(expected, i, esize, result, pred);
        if (saturated && (pred & (1U << i))) {
            *qc = true;
        }
    }
}

static void test_arm_m55_mve_scalar_shift_run_qc_init(uint32_t insn,
                                                      const uint8_t *initial,
                                                      uint32_t rm,
                                                      uint32_t vpr,
                                                      const uint8_t *expected,
                                                      bool eci,
                                                      bool initial_qc,
                                                      bool expected_qc)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint32_t fpscr_qc = 1U << 27;
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    uint32_t fpscr = 0;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &rm));
    OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));

    if (eci || initial_qc) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        if (initial_qc) {
            OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
            fpscr |= fpscr_qc;
            OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));
        }
        epsr = xpsr_t | eci_a0a1;
        if (eci) {
            OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        }
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        if (eci) {
            OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
            TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                        "epsr=0x%08x", epsr);
        }
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                    insn, (unsigned)i, got[i], expected[i]);
    }
    TEST_CHECK_(((fpscr & fpscr_qc) != 0) == expected_qc,
                "fpscr=0x%08x expected_qc=%d",
                fpscr, expected_qc);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_scalar_shift_run_qc(uint32_t insn,
                                                 const uint8_t *initial,
                                                 uint32_t rm, uint32_t vpr,
                                                 const uint8_t *expected,
                                                 bool eci, bool expected_qc)
{
    test_arm_m55_mve_scalar_shift_run_qc_init(insn, initial, rm, vpr,
                                              expected, eci, false,
                                              expected_qc);
}

static void test_arm_m55_mve_scalar_shift_run(uint32_t insn,
                                              const uint8_t *initial,
                                              uint32_t rm,
                                              const uint8_t *expected,
                                              bool eci)
{
    test_arm_m55_mve_scalar_shift_run_qc(insn, initial, rm, 0, expected,
                                         eci, false);
}

static void test_arm_m55_mve_scalar_shift(void)
{
    static const uint32_t vshls_base = 0xee311e60;
    static const uint32_t vshlu_base = 0xfe311e60;
    static const uint32_t vrshls_base = 0xee331e60;
    static const uint32_t vrshlu_base = 0xfe331e60;
    static const uint32_t vqshls_base = 0xee311ee0;
    static const uint32_t vqshlu_base = 0xfe311ee0;
    static const uint32_t vqrshls_base = 0xee331ee0;
    static const uint32_t vqrshlu_base = 0xfe331ee0;
    const uint8_t initial[16] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    };
    const uint8_t source[16] = {
        0x81, 0x7f, 0x12, 0xf0, 0x55, 0xaa, 0x01, 0x80,
        0xfe, 0x10, 0x33, 0xcc, 0x09, 0x90, 0x44, 0x22,
    };
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    uint8_t shifts[16];
    uint32_t insn;
    bool qc;
    size_t ncase;

    for (ncase = 0; ncase < 3; ncase++) {
        unsigned size = (unsigned)ncase;
        unsigned esize = esizes[ncase];

        insn = test_arm_mve_vshift_scalar_insn(0, vshls_base, size, 3);
        test_arm_mve_fill_scalar_shift(shifts, esize, (uint32_t)-1);
        test_arm_mve_expected_shift(expected, initial, source, shifts, esize,
                                    true, false, 0xffff);
        test_arm_m55_mve_scalar_shift_run(insn, source, (uint32_t)-1,
                                          expected, false);

        insn = test_arm_mve_vshift_scalar_insn(0, vshlu_base, size, 3);
        test_arm_mve_fill_scalar_shift(shifts, esize, 2);
        test_arm_mve_expected_shift(expected, initial, source, shifts, esize,
                                    false, false, 0xffff);
        test_arm_m55_mve_scalar_shift_run(insn, source, 2, expected, false);

        insn = test_arm_mve_vshift_scalar_insn(0, vrshls_base, size, 3);
        test_arm_mve_fill_scalar_shift(shifts, esize, (uint32_t)-2);
        test_arm_mve_expected_shift(expected, initial, source, shifts, esize,
                                    true, true, 0xffff);
        test_arm_m55_mve_scalar_shift_run(insn, source, (uint32_t)-2,
                                          expected, false);

        insn = test_arm_mve_vshift_scalar_insn(0, vrshlu_base, size, 3);
        test_arm_mve_fill_scalar_shift(shifts, esize, (uint32_t)-3);
        test_arm_mve_expected_shift(expected, initial, source, shifts, esize,
                                    false, true, 0xffff);
        test_arm_m55_mve_scalar_shift_run(insn, source, (uint32_t)-3,
                                          expected, false);

        insn = test_arm_mve_vshift_scalar_insn(0, vqshls_base, size, 3);
        test_arm_mve_expected_qshift_scalar(expected, source, source, esize,
                                            4, true, false, 0xffff, &qc);
        test_arm_m55_mve_scalar_shift_run_qc(insn, source, 4, 0, expected,
                                             false, qc);

        insn = test_arm_mve_vshift_scalar_insn(0, vqshlu_base, size, 3);
        test_arm_mve_expected_qshift_scalar(expected, source, source, esize,
                                            5, false, false, 0xffff, &qc);
        test_arm_m55_mve_scalar_shift_run_qc(insn, source, 5, 0, expected,
                                             false, qc);

        insn = test_arm_mve_vshift_scalar_insn(0, vqrshls_base, size, 3);
        test_arm_mve_expected_qshift_scalar(expected, source, source, esize,
                                            (uint32_t)-2, true, true, 0xffff,
                                            &qc);
        test_arm_m55_mve_scalar_shift_run_qc(insn, source, (uint32_t)-2, 0,
                                             expected, false, qc);

        insn = test_arm_mve_vshift_scalar_insn(0, vqrshlu_base, size, 3);
        test_arm_mve_expected_qshift_scalar(expected, source, source, esize,
                                            (uint32_t)-3, false, true,
                                            0xffff, &qc);
        test_arm_m55_mve_scalar_shift_run_qc(insn, source, (uint32_t)-3, 0,
                                             expected, false, qc);
    }

    insn = test_arm_mve_vshift_scalar_insn(0, vqrshlu_base, 2, 3);
    test_arm_mve_expected_qshift_scalar(expected, source, source, 4, 8,
                                        false, true, 0x00f0, &qc);
    test_arm_m55_mve_scalar_shift_run_qc(insn, source, 8, 0x001100f0,
                                         expected, false, qc);

    test_arm_mve_expected_qshift_scalar(expected, source, source, 4, 8,
                                        false, true, 0xff00, &qc);
    test_arm_m55_mve_scalar_shift_run_qc(insn, source, 8, 0, expected, true,
                                         qc);

    test_arm_mve_expected_qshift_scalar(expected, source, source, 1, 1,
                                        true, false, 0xffff, &qc);
    test_arm_m55_mve_scalar_shift_run_qc_init(
        test_arm_mve_vshift_scalar_insn(0, vqshls_base, 0, 3),
        source, 1, 0, expected, false, true, true);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshift_scalar_insn(0, vshls_base, 3, 3),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshift_scalar_insn(8, vshls_base, 0, 3),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshift_scalar_insn(0, vshls_base, 0, 13),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshift_scalar_insn(0, vshls_base, 0, 15),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshift_scalar_insn(0, vshls_base, 0, 3),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
}

static uint32_t test_arm_mve_gpr_shift_imm_insn(uint32_t base,
                                                unsigned rda,
                                                unsigned shift)
{
    uint32_t view = base;

    view |= (rda & 15) << 16;
    view |= ((shift >> 2) & 7) << 12;
    view |= (shift & 3) << 6;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_gpr_shift_long_imm_insn(uint32_t base,
                                                     unsigned rdalo,
                                                     unsigned rdahi,
                                                     unsigned shift)
{
    uint32_t view = base;

    view |= ((rdalo >> 1) & 7) << 17;
    view |= ((rdahi >> 1) & 7) << 9;
    view |= ((shift >> 2) & 7) << 12;
    view |= (shift & 3) << 6;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_gpr_shift_reg_insn(uint32_t base,
                                                unsigned rda,
                                                unsigned rm)
{
    uint32_t view = base;

    view |= (rda & 15) << 16;
    view |= (rm & 15) << 12;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_gpr_shift_long_reg_insn(uint32_t base,
                                                     unsigned rdalo,
                                                     unsigned rdahi,
                                                     unsigned rm)
{
    uint32_t view = base;

    view |= ((rdalo >> 1) & 7) << 17;
    view |= ((rdahi >> 1) & 7) << 9;
    view |= (rm & 15) << 12;
    return test_arm_mve_view_to_t32(view);
}

static void test_arm_m55_mve_gpr_shift32_run_qc(uint32_t insn,
                                                unsigned rda_reg,
                                                uint32_t initial_rda,
                                                unsigned rm_reg,
                                                uint32_t rm,
                                                uint32_t expected_rda,
                                                bool expected_qc)
{
    const uint32_t fpscr_qc = 1U << 27;
    uc_engine *uc;
    uint8_t code[4];
    uint32_t fpscr = 0;
    uint32_t got;

    test_arm_emit32(code, 0, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    OK(uc_reg_write(uc, UC_ARM_REG_R0 + rda_reg, &initial_rda));
    if (rm_reg < 13) {
        OK(uc_reg_write(uc, UC_ARM_REG_R0 + rm_reg, &rm));
    }
    OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0 + rda_reg, &got));
    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
    TEST_CHECK_(got == expected_rda,
                "insn=0x%08x r%u=0x%08x expected=0x%08x",
                insn, rda_reg, got, expected_rda);
    TEST_CHECK_(((fpscr & fpscr_qc) != 0) == expected_qc,
                "insn=0x%08x fpscr=0x%08x expected_qc=%d",
                insn, fpscr, expected_qc);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_gpr_shift64_run_qc(uint32_t insn,
                                                unsigned rdalo_reg,
                                                unsigned rdahi_reg,
                                                uint64_t initial_rda,
                                                unsigned rm_reg,
                                                uint32_t rm,
                                                uint64_t expected_rda,
                                                bool expected_qc)
{
    const uint32_t fpscr_qc = 1U << 27;
    uc_engine *uc;
    uint8_t code[4];
    uint32_t initlo = (uint32_t)initial_rda;
    uint32_t inithi = (uint32_t)(initial_rda >> 32);
    uint32_t gotlo;
    uint32_t gothi;
    uint32_t fpscr = 0;
    uint64_t got;

    test_arm_emit32(code, 0, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    OK(uc_reg_write(uc, UC_ARM_REG_R0 + rdalo_reg, &initlo));
    OK(uc_reg_write(uc, UC_ARM_REG_R0 + rdahi_reg, &inithi));
    if (rm_reg < 13) {
        OK(uc_reg_write(uc, UC_ARM_REG_R0 + rm_reg, &rm));
    }
    OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0 + rdalo_reg, &gotlo));
    OK(uc_reg_read(uc, UC_ARM_REG_R0 + rdahi_reg, &gothi));
    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
    got = ((uint64_t)gothi << 32) | gotlo;
    TEST_CHECK_(got == expected_rda,
                "insn=0x%08x got=0x%016llx expected=0x%016llx",
                insn, (unsigned long long)got,
                (unsigned long long)expected_rda);
    TEST_CHECK_(((fpscr & fpscr_qc) != 0) == expected_qc,
                "insn=0x%08x fpscr=0x%08x expected_qc=%d",
                insn, fpscr, expected_qc);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_gpr_shift(void)
{
    uint32_t insn;

    insn = test_arm_mve_gpr_shift_imm_insn(0xea500f0f, 2, 2);
    test_arm_m55_mve_gpr_shift32_run_qc(insn, 2, 0x40000000,
                                        16, 0, UINT32_MAX, true);

    insn = test_arm_mve_gpr_shift_imm_insn(0xea500f3f, 2, 3);
    test_arm_m55_mve_gpr_shift32_run_qc(insn, 2, 0x20000000,
                                        16, 0, 0x7fffffff, true);

    insn = test_arm_mve_gpr_shift_imm_insn(0xea500f1f, 2, 1);
    test_arm_m55_mve_gpr_shift32_run_qc(insn, 2, 0x80000001,
                                        16, 0, 0x40000001, false);

    insn = test_arm_mve_gpr_shift_imm_insn(0xea500f2f, 2, 1);
    test_arm_m55_mve_gpr_shift32_run_qc(insn, 2, 0x80000001,
                                        16, 0, 0xc0000001, false);

    insn = test_arm_mve_gpr_shift_imm_insn(0xea500f1f, 2, 0);
    test_arm_m55_mve_gpr_shift32_run_qc(insn, 2, 0x80000000,
                                        16, 0, 1, false);

    insn = test_arm_mve_gpr_shift_reg_insn(0xea500f0d, 2, 4);
    test_arm_m55_mve_gpr_shift32_run_qc(insn, 2, 3, 4,
                                        (uint32_t)-1, 2, false);

    insn = test_arm_mve_gpr_shift_reg_insn(0xea500f2d, 2, 4);
    test_arm_m55_mve_gpr_shift32_run_qc(insn, 2, 0x40000000, 4,
                                        (uint32_t)-2, 0x7fffffff, true);

    insn = test_arm_mve_gpr_shift_long_imm_insn(0xea50010f, 2, 3, 4);
    test_arm_m55_mve_gpr_shift64_run_qc(
        insn, 2, 3, 0x0000000100000001ULL, 16, 0,
        0x0000001000000010ULL, false);

    insn = test_arm_mve_gpr_shift_long_imm_insn(0xea50011f, 2, 3, 4);
    test_arm_m55_mve_gpr_shift64_run_qc(
        insn, 2, 3, 0x8000000000000000ULL, 16, 0,
        0x0800000000000000ULL, false);

    insn = test_arm_mve_gpr_shift_long_imm_insn(0xea50012f, 2, 3, 4);
    test_arm_m55_mve_gpr_shift64_run_qc(
        insn, 2, 3, 0x8000000000000000ULL, 16, 0,
        0xf800000000000000ULL, false);

    insn = test_arm_mve_gpr_shift_long_imm_insn(0xea51010f, 2, 3, 2);
    test_arm_m55_mve_gpr_shift64_run_qc(
        insn, 2, 3, 0x4000000000000000ULL, 16, 0,
        UINT64_MAX, true);

    insn = test_arm_mve_gpr_shift_long_imm_insn(0xea51013f, 2, 3, 3);
    test_arm_m55_mve_gpr_shift64_run_qc(
        insn, 2, 3, 0x2000000000000000ULL, 16, 0,
        INT64_MAX, true);

    insn = test_arm_mve_gpr_shift_long_imm_insn(0xea51011f, 2, 3, 1);
    test_arm_m55_mve_gpr_shift64_run_qc(
        insn, 2, 3, 0x8000000000000001ULL, 16, 0,
        0x4000000000000001ULL, false);

    insn = test_arm_mve_gpr_shift_long_imm_insn(0xea51012f, 2, 3, 1);
    test_arm_m55_mve_gpr_shift64_run_qc(
        insn, 2, 3, 0x8000000000000001ULL, 16, 0,
        0xc000000000000001ULL, false);

    insn = test_arm_mve_gpr_shift_long_reg_insn(0xea50010d, 2, 3, 4);
    test_arm_m55_mve_gpr_shift64_run_qc(
        insn, 2, 3, 8, 4, (uint32_t)-1, 4, false);

    insn = test_arm_mve_gpr_shift_long_reg_insn(0xea50012d, 2, 3, 4);
    test_arm_m55_mve_gpr_shift64_run_qc(
        insn, 2, 3, 0x8000000000000000ULL, 4, 4,
        0xf800000000000000ULL, false);

    insn = test_arm_mve_gpr_shift_long_reg_insn(0xea51010d, 2, 3, 4);
    test_arm_m55_mve_gpr_shift64_run_qc(
        insn, 2, 3, 0x4000000000000000ULL, 4, 2,
        UINT64_MAX, true);

    insn = test_arm_mve_gpr_shift_long_reg_insn(0xea51012d, 2, 3, 4);
    test_arm_m55_mve_gpr_shift64_run_qc(
        insn, 2, 3, 0x4000000000000000ULL, 4, (uint32_t)-2,
        INT64_MAX, true);

    insn = test_arm_mve_gpr_shift_long_reg_insn(0xea51018d, 2, 3, 4);
    test_arm_m55_mve_gpr_shift64_run_qc(
        insn, 2, 3, 0x0000800000000000ULL, 4, 1,
        0x0000ffffffffffffULL, true);

    insn = test_arm_mve_gpr_shift_long_reg_insn(0xea5101ad, 2, 3, 4);
    test_arm_m55_mve_gpr_shift64_run_qc(
        insn, 2, 3, 0x0000400000000000ULL, 4, (uint32_t)-2,
        0x00007fffffffffffULL, true);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_gpr_shift_imm_insn(0xea500f0f, 13, 2),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_gpr_shift_reg_insn(0xea500f0d, 2, 2),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_gpr_shift_long_imm_insn(0xea50010f, 2, 13, 4),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_gpr_shift_long_reg_insn(0xea50010d, 2, 3, 2),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_gpr_shift_imm_insn(0xea500f0f, 2, 2),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_FETCH_UNMAPPED);
}

static uint32_t test_arm_mve_vshll_insn(unsigned qd, unsigned qm,
                                        uint32_t base, unsigned size,
                                        unsigned shift, bool esize_shift)
{
    uint32_t view = base;

    view |= ((qd >> 3) & 1) << 22;
    view |= (qd & 7) << 13;
    view |= ((qm >> 3) & 1) << 5;
    view |= (qm & 7) << 1;
    if (esize_shift) {
        if (size == 1) {
            view |= 1U << 18;
        } else {
            TEST_CHECK(size == 0);
        }
    } else if (size == 0) {
        view |= 1U << 19;
        view |= (shift & 7) << 16;
    } else {
        TEST_CHECK(size == 1);
        view |= 1U << 20;
        view |= (shift & 15) << 16;
    }
    return test_arm_mve_view_to_t32(view);
}

static void test_arm_mve_expected_vshll(uint8_t *expected,
                                        const uint8_t *initial,
                                        const uint8_t *source,
                                        unsigned esize, unsigned shift,
                                        bool top, bool is_signed,
                                        uint16_t pred)
{
    unsigned bits = esize * 8;
    unsigned lesize = esize * 2;
    size_t le;

    memcpy(expected, initial, 16);
    for (le = 0; le < 16 / lesize; le++) {
        size_t src_off = (le * 2 + top) * esize;
        size_t dst_off = le * lesize;
        uint32_t src = test_arm_load_le(source + src_off, esize);
        uint64_t result;

        if (is_signed) {
            result = (uint64_t)(test_arm_sign_extend(src, bits) *
                                (1LL << shift));
        } else {
            result = (uint64_t)src << shift;
        }
        test_arm_mve_store_masked(expected, dst_off, lesize, result, pred);
    }
}

static void test_arm_m55_mve_vshll(void)
{
    const uint8_t initial[16] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    };
    const uint8_t source[16] = {
        0x81, 0x7f, 0x12, 0xf0, 0x55, 0xaa, 0x01, 0x80,
        0xfe, 0x10, 0x33, 0xcc, 0x09, 0x90, 0x44, 0x22,
    };
    uint8_t expected[16];
    uint32_t insn;

    insn = test_arm_mve_vshll_insn(0, 1, 0xeea00f40, 0, 3, false);
    test_arm_mve_expected_vshll(expected, initial, source, 1, 3, false,
                                true, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshll_insn(0, 1, 0xfea01f40, 1, 4, false);
    test_arm_mve_expected_vshll(expected, initial, source, 2, 4, true,
                                false, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshll_insn(0, 1, 0xfea00f40, 0, 0, false);
    test_arm_mve_expected_vshll(expected, initial, source, 1, 0, false,
                                false, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshll_insn(0, 1, 0xee310e01, 0, 8, true);
    test_arm_mve_expected_vshll(expected, initial, source, 1, 8, false,
                                true, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshll_insn(0, 1, 0xfe311e01, 1, 16, true);
    test_arm_mve_expected_vshll(expected, initial, source, 2, 16, true,
                                false, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshll_insn(0, 1, 0xeea01f40, 0, 2, false);
    test_arm_mve_expected_vshll(expected, initial, source, 1, 2, true,
                                true, 0xff00);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected, true);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshll_insn(8, 1, 0xeea00f40, 0, 3, false),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshll_insn(0, 1, 0xeea00f40, 0, 3, false),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
}

static uint64_t test_arm_mve_urshr(uint64_t value, unsigned shift)
{
    return (value >> shift) + ((value >> (shift - 1)) & 1);
}

static int64_t test_arm_mve_srshr(int64_t value, unsigned shift)
{
    return (value >> shift) + ((value >> (shift - 1)) & 1);
}

typedef enum test_arm_mve_qshrn_kind {
    TEST_ARM_MVE_QSHRN_S,
    TEST_ARM_MVE_QSHRN_U,
    TEST_ARM_MVE_QSHRUN,
    TEST_ARM_MVE_QRSHRN_S,
    TEST_ARM_MVE_QRSHRN_U,
    TEST_ARM_MVE_QRSHRUN,
} test_arm_mve_qshrn_kind;

static uint32_t test_arm_mve_expected_qshrn_lane(
    uint64_t src, unsigned src_bits, unsigned dst_bits, unsigned shift,
    test_arm_mve_qshrn_kind kind, bool *saturated)
{
    uint32_t dst_mask = test_arm_mve_element_mask(dst_bits);
    int64_t signed_src;
    int64_t signed_value;
    uint64_t unsigned_value;

    *saturated = false;
    switch (kind) {
    case TEST_ARM_MVE_QSHRN_S:
        signed_src = test_arm_sign_extend((uint32_t)src, src_bits);
        signed_value = signed_src >> shift;
        return test_arm_mve_sat_s(signed_value, dst_bits, saturated) &
               dst_mask;
    case TEST_ARM_MVE_QSHRN_U:
        unsigned_value = src >> shift;
        return test_arm_mve_sat_u(unsigned_value, dst_bits, saturated) &
               dst_mask;
    case TEST_ARM_MVE_QSHRUN:
        signed_src = test_arm_sign_extend((uint32_t)src, src_bits);
        signed_value = signed_src >> shift;
        break;
    case TEST_ARM_MVE_QRSHRN_S:
        signed_src = test_arm_sign_extend((uint32_t)src, src_bits);
        signed_value = test_arm_mve_srshr(signed_src, shift);
        return test_arm_mve_sat_s(signed_value, dst_bits, saturated) &
               dst_mask;
    case TEST_ARM_MVE_QRSHRN_U:
        unsigned_value = test_arm_mve_urshr(src, shift);
        return test_arm_mve_sat_u(unsigned_value, dst_bits, saturated) &
               dst_mask;
    case TEST_ARM_MVE_QRSHRUN:
        signed_src = test_arm_sign_extend((uint32_t)src, src_bits);
        signed_value = test_arm_mve_srshr(signed_src, shift);
        break;
    default:
        TEST_CHECK(false);
        return 0;
    }

    if (signed_value < 0) {
        *saturated = true;
        return 0;
    }
    return test_arm_mve_sat_u((uint64_t)signed_value, dst_bits,
                              saturated) & dst_mask;
}

static void test_arm_mve_expected_shrn(uint8_t *expected,
                                       const uint8_t *initial,
                                       const uint8_t *source,
                                       unsigned esize, unsigned shift,
                                       bool top, bool rounded,
                                       uint16_t pred)
{
    unsigned lesize = esize * 2;
    size_t le;

    memcpy(expected, initial, 16);
    for (le = 0; le < 16 / lesize; le++) {
        size_t src_off = le * lesize;
        size_t dst_off = (le * 2 + top) * esize;
        uint64_t src = test_arm_load_le(source + src_off, lesize);
        uint64_t result = rounded ? test_arm_mve_urshr(src, shift) :
            src >> shift;

        test_arm_mve_store_masked(expected, dst_off, esize, result, pred);
    }
}

static void test_arm_mve_expected_qshrn(uint8_t *expected,
                                        const uint8_t *initial,
                                        const uint8_t *source,
                                        unsigned esize, unsigned shift,
                                        bool top,
                                        test_arm_mve_qshrn_kind kind,
                                        uint16_t pred, bool *qc)
{
    unsigned dst_bits = esize * 8;
    unsigned lesize = esize * 2;
    unsigned src_bits = lesize * 8;
    size_t le;

    memcpy(expected, initial, 16);
    *qc = false;
    for (le = 0; le < 16 / lesize; le++) {
        size_t src_off = le * lesize;
        size_t dst_off = (le * 2 + top) * esize;
        uint64_t src = test_arm_load_le(source + src_off, lesize);
        bool saturated;
        uint32_t result;

        result = test_arm_mve_expected_qshrn_lane(src, src_bits, dst_bits,
                                                  shift, kind, &saturated);
        test_arm_mve_store_masked(expected, dst_off, esize, result, pred);
        if (saturated && (pred & (1U << dst_off))) {
            *qc = true;
        }
    }
}

static void test_arm_m55_mve_shrn_imm(void)
{
    const uint8_t initial[16] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    };
    const uint8_t source[16] = {
        0xff, 0x00, 0x80, 0x01, 0x7f, 0x80, 0x01, 0xff,
        0x34, 0x12, 0x78, 0x56, 0x88, 0x77, 0x66, 0x55,
    };
    uint8_t expected[16];
    uint32_t insn;

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xee800fc1, 0, 4, true);
    test_arm_mve_expected_shrn(expected, initial, source, 1, 4, false,
                               false, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xee801fc1, 1, 8, true);
    test_arm_mve_expected_shrn(expected, initial, source, 2, 8, true,
                               false, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xfe800fc1, 0, 8, true);
    test_arm_mve_expected_shrn(expected, initial, source, 1, 8, false,
                               true, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xfe801fc1, 1, 16, true);
    test_arm_mve_expected_shrn(expected, initial, source, 2, 16, true,
                               true, 0xffff);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected,
                                   false);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xee801fc1, 0, 4, true);
    test_arm_mve_expected_shrn(expected, initial, source, 1, 4, true,
                               false, 0xff00);
    test_arm_m55_mve_shift_imm_run(insn, initial, source, 0, expected, true);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshift_imm_insn(8, 1, 0xee800fc1, 0, 4, true),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshift_imm_insn(0, 1, 0xee800fc1, 0, 4, true),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_qshrn_imm(void)
{
    const uint8_t initial[16] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    };
    const uint8_t source[16] = {
        0xff, 0x00, 0x80, 0x01, 0x7f, 0x80, 0x01, 0xff,
        0xf8, 0x0f, 0x80, 0xff, 0x00, 0x80, 0xff, 0x7f,
    };
    const uint8_t eci_source[16] = {
        0x00, 0x80, 0xff, 0x7f, 0x00, 0x80, 0xff, 0x7f,
        0x10, 0x00, 0x20, 0x00, 0x30, 0x00, 0x40, 0x00,
    };
    const uint8_t pred_source[16] = {
        0x00, 0x80, 0xff, 0x7f, 0x10, 0x00, 0x20, 0x00,
        0x30, 0x00, 0x40, 0x00, 0x50, 0x00, 0x60, 0x00,
    };
    const uint8_t nonsat_source[16] = {
        0x10, 0x00, 0x20, 0x00, 0x30, 0x00, 0x40, 0x00,
        0x50, 0x00, 0x60, 0x00, 0x70, 0x00, 0x7f, 0x00,
    };
    uint8_t expected[16];
    uint32_t insn;
    bool qc;

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xee800f40, 0, 1, true);
    test_arm_mve_expected_qshrn(expected, initial, source, 1, 1, false,
                                TEST_ARM_MVE_QSHRN_S, 0xffff, &qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, source, 0, expected,
                                      false, qc);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xfe801f40, 1, 8, true);
    test_arm_mve_expected_qshrn(expected, initial, source, 2, 8, true,
                                TEST_ARM_MVE_QSHRN_U, 0xffff, &qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, source, 0, expected,
                                      false, qc);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xee800fc0, 0, 4, true);
    test_arm_mve_expected_qshrn(expected, initial, source, 1, 4, false,
                                TEST_ARM_MVE_QSHRUN, 0xffff, &qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, source, 0, expected,
                                      false, qc);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xee801f41, 0, 4, true);
    test_arm_mve_expected_qshrn(expected, initial, source, 1, 4, true,
                                TEST_ARM_MVE_QRSHRN_S, 0xffff, &qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, source, 0, expected,
                                      false, qc);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xfe800f41, 0, 8, true);
    test_arm_mve_expected_qshrn(expected, initial, source, 1, 8, false,
                                TEST_ARM_MVE_QRSHRN_U, 0xffff, &qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, source, 0, expected,
                                      false, qc);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xfe800fc0, 0, 4, true);
    test_arm_mve_expected_qshrn(expected, initial, eci_source, 1, 4, false,
                                TEST_ARM_MVE_QRSHRUN, 0xff00, &qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, eci_source, 0,
                                      expected, true, qc);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xee801fc0, 1, 8, true);
    test_arm_mve_expected_qshrn(expected, initial, source, 2, 8, true,
                                TEST_ARM_MVE_QSHRUN, 0xffff, &qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, source, 0, expected,
                                      false, qc);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xfe801fc0, 0, 4, true);
    test_arm_mve_expected_qshrn(expected, initial, source, 1, 4, true,
                                TEST_ARM_MVE_QRSHRUN, 0xffff, &qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, source, 0, expected,
                                      false, qc);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xee800f40, 0, 1, true);
    test_arm_mve_expected_qshrn(expected, initial, pred_source, 1, 1, false,
                                TEST_ARM_MVE_QSHRN_S, 0x00f0, &qc);
    TEST_CHECK(!qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, pred_source,
                                      0x001100f0, expected, false, qc);

    insn = test_arm_mve_vshift_imm_insn(0, 1, 0xee800f40, 0, 1, true);
    test_arm_mve_expected_qshrn(expected, initial, nonsat_source, 1, 1,
                                false, TEST_ARM_MVE_QSHRN_S, 0xffff, &qc);
    TEST_CHECK(!qc);
    test_arm_m55_mve_shift_imm_run_qc_init(insn, initial, nonsat_source, 0,
                                           expected, false, true, true);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshift_imm_insn(8, 1, 0xee800f40, 0, 1, true),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshift_imm_insn(0, 1, 0xee800f40, 0, 1, true),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
}

typedef enum test_arm_mve_movn_kind {
    TEST_ARM_MVE_MOVN,
    TEST_ARM_MVE_QMOVN_S,
    TEST_ARM_MVE_QMOVN_U,
    TEST_ARM_MVE_QMOVUN,
} test_arm_mve_movn_kind;

static uint32_t test_arm_mve_1op_insn(unsigned qd, unsigned qm,
                                      uint32_t base, unsigned size)
{
    uint32_t view = base;

    view |= ((qd >> 3) & 1) << 22;
    view |= (size & 3) << 18;
    view |= (qd & 7) << 13;
    view |= ((qm >> 3) & 1) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_vcvt_fixed_insn(unsigned qd, unsigned qm,
                                             uint32_t base, unsigned size,
                                             uint32_t shift)
{
    uint32_t view = base;
    uint32_t encoded;

    encoded = (size == 1) ? (16 - shift) : (32 - shift);
    view |= (encoded & ((1U << (size == 1 ? 4 : 5)) - 1)) << 16;
    view |= ((qd >> 3) & 1) << 22;
    view |= (qd & 7) << 13;
    view |= ((qm >> 3) & 1) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_movn_insn(unsigned qd, unsigned qm,
                                       uint32_t base, unsigned size)
{
    return test_arm_mve_1op_insn(qd, qm, base, size);
}

static uint32_t test_arm_mve_expected_movn_lane(
    uint64_t src, unsigned src_bits, unsigned dst_bits,
    test_arm_mve_movn_kind kind, bool *saturated)
{
    uint32_t dst_mask = test_arm_mve_element_mask(dst_bits);
    int64_t signed_src;

    *saturated = false;
    switch (kind) {
    case TEST_ARM_MVE_MOVN:
        return (uint32_t)src & dst_mask;
    case TEST_ARM_MVE_QMOVN_S:
        signed_src = test_arm_sign_extend((uint32_t)src, src_bits);
        return test_arm_mve_sat_s(signed_src, dst_bits, saturated) &
               dst_mask;
    case TEST_ARM_MVE_QMOVN_U:
        return test_arm_mve_sat_u(src, dst_bits, saturated) & dst_mask;
    case TEST_ARM_MVE_QMOVUN:
        signed_src = test_arm_sign_extend((uint32_t)src, src_bits);
        if (signed_src < 0) {
            *saturated = true;
            return 0;
        }
        return test_arm_mve_sat_u((uint64_t)signed_src, dst_bits,
                                  saturated) & dst_mask;
    default:
        TEST_CHECK(false);
        return 0;
    }
}

static void test_arm_mve_expected_movn(uint8_t *expected,
                                       const uint8_t *initial,
                                       const uint8_t *source,
                                       unsigned esize, bool top,
                                       test_arm_mve_movn_kind kind,
                                       uint16_t pred, bool *qc)
{
    unsigned dst_bits = esize * 8;
    unsigned lesize = esize * 2;
    unsigned src_bits = lesize * 8;
    size_t le;

    memcpy(expected, initial, 16);
    *qc = false;
    for (le = 0; le < 16 / lesize; le++) {
        size_t src_off = le * lesize;
        size_t dst_off = (le * 2 + top) * esize;
        uint64_t src = test_arm_load_le(source + src_off, lesize);
        bool saturated;
        uint32_t result;

        result = test_arm_mve_expected_movn_lane(src, src_bits, dst_bits,
                                                 kind, &saturated);
        test_arm_mve_store_masked(expected, dst_off, esize, result, pred);
        if (saturated && (pred & (1U << dst_off))) {
            *qc = true;
        }
    }
}

static void test_arm_m55_mve_movn(void)
{
    const uint8_t initial[16] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    };
    const uint8_t half_source[16] = {
        0x34, 0x12, 0x80, 0xff, 0xff, 0x00, 0x7f, 0x7f,
        0x00, 0x80, 0xff, 0x7f, 0x01, 0x00, 0x00, 0xff,
    };
    const uint8_t word_source[16] = {
        0x34, 0x12, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff,
        0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80,
    };
    const uint8_t pred_source[16] = {
        0x00, 0x80, 0xff, 0x7f, 0x10, 0x00, 0x20, 0x00,
        0x00, 0x80, 0xff, 0x7f, 0x00, 0x80, 0xff, 0x7f,
    };
    const uint8_t eci_source[16] = {
        0x00, 0x80, 0xff, 0x7f, 0x00, 0x80, 0xff, 0x7f,
        0x10, 0x00, 0x20, 0x00, 0x30, 0x00, 0x40, 0x00,
    };
    uint8_t expected[16];
    uint32_t insn;
    bool qc;

    insn = test_arm_mve_movn_insn(0, 1, 0xfe310e81, 0);
    test_arm_mve_expected_movn(expected, initial, half_source, 1, false,
                               TEST_ARM_MVE_MOVN, 0xffff, &qc);
    TEST_CHECK(!qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, half_source, 0,
                                      expected, false, qc);

    insn = test_arm_mve_movn_insn(0, 1, 0xfe311e81, 1);
    test_arm_mve_expected_movn(expected, initial, word_source, 2, true,
                               TEST_ARM_MVE_MOVN, 0xffff, &qc);
    TEST_CHECK(!qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, word_source, 0,
                                      expected, false, qc);

    insn = test_arm_mve_movn_insn(0, 1, 0xee330e01, 0);
    test_arm_mve_expected_movn(expected, initial, half_source, 1, false,
                               TEST_ARM_MVE_QMOVN_S, 0xffff, &qc);
    TEST_CHECK(qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, half_source, 0,
                                      expected, false, qc);

    insn = test_arm_mve_movn_insn(0, 1, 0xfe331e01, 1);
    test_arm_mve_expected_movn(expected, initial, word_source, 2, true,
                               TEST_ARM_MVE_QMOVN_U, 0xffff, &qc);
    TEST_CHECK(qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, word_source, 0,
                                      expected, false, qc);

    insn = test_arm_mve_movn_insn(0, 1, 0xee310e81, 0);
    test_arm_mve_expected_movn(expected, initial, half_source, 1, false,
                               TEST_ARM_MVE_QMOVUN, 0xffff, &qc);
    TEST_CHECK(qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, half_source, 0,
                                      expected, false, qc);

    insn = test_arm_mve_movn_insn(0, 1, 0xee311e81, 1);
    test_arm_mve_expected_movn(expected, initial, word_source, 2, true,
                               TEST_ARM_MVE_QMOVUN, 0xffff, &qc);
    TEST_CHECK(qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, word_source, 0,
                                      expected, false, qc);

    insn = test_arm_mve_movn_insn(0, 1, 0xee330e01, 0);
    test_arm_mve_expected_movn(expected, initial, pred_source, 1, false,
                               TEST_ARM_MVE_QMOVN_S, 0x00f0, &qc);
    TEST_CHECK(!qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, pred_source,
                                      0x001100f0, expected, false, qc);

    insn = test_arm_mve_movn_insn(0, 1, 0xee310e81, 0);
    test_arm_mve_expected_movn(expected, initial, eci_source, 1, false,
                               TEST_ARM_MVE_QMOVUN, 0xff00, &qc);
    TEST_CHECK(!qc);
    test_arm_m55_mve_shift_imm_run_qc(insn, initial, eci_source, 0,
                                      expected, true, qc);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_movn_insn(0, 1, 0xfe310e81, 2),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_movn_insn(8, 1, 0xfe310e81, 0),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_movn_insn(0, 1, 0xfe310e81, 0),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
}

static uint32_t test_arm_mve_vaddv_insn(unsigned qm, unsigned rda,
                                        bool is_unsigned, unsigned size,
                                        bool accum)
{
    uint32_t view = 0xeef10f00;

    view |= (is_unsigned ? 1U : 0U) << 28;
    view |= (size & 3) << 18;
    view |= ((rda >> 1) & 7) << 13;
    view |= (accum ? 1U : 0U) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

typedef enum test_arm_mve_reduce_minmax_kind {
    TEST_ARM_MVE_REDUCE_MAX_S,
    TEST_ARM_MVE_REDUCE_MAX_U,
    TEST_ARM_MVE_REDUCE_MAXA,
    TEST_ARM_MVE_REDUCE_MIN_S,
    TEST_ARM_MVE_REDUCE_MIN_U,
    TEST_ARM_MVE_REDUCE_MINA,
} test_arm_mve_reduce_minmax_kind;

typedef enum test_arm_mve_reduce_fp_kind {
    TEST_ARM_MVE_REDUCE_FMAXNMV_F32,
    TEST_ARM_MVE_REDUCE_FMAXNMV_F16,
    TEST_ARM_MVE_REDUCE_FMINNMV_F32,
    TEST_ARM_MVE_REDUCE_FMINNMV_F16,
    TEST_ARM_MVE_REDUCE_FMAXNMAV_F32,
    TEST_ARM_MVE_REDUCE_FMAXNMAV_F16,
    TEST_ARM_MVE_REDUCE_FMINNMAV_F32,
    TEST_ARM_MVE_REDUCE_FMINNMAV_F16,
} test_arm_mve_reduce_fp_kind;

static uint32_t
test_arm_mve_vmaxv_insn(unsigned qm, unsigned rda,
                        test_arm_mve_reduce_minmax_kind kind,
                        unsigned size)
{
    uint32_t view;

    switch (kind) {
    case TEST_ARM_MVE_REDUCE_MAX_S:
        view = 0xeee20f00;
        break;
    case TEST_ARM_MVE_REDUCE_MAX_U:
        view = 0xfee20f00;
        break;
    case TEST_ARM_MVE_REDUCE_MAXA:
        view = 0xeee00f00;
        break;
    case TEST_ARM_MVE_REDUCE_MIN_S:
        view = 0xeee20f80;
        break;
    case TEST_ARM_MVE_REDUCE_MIN_U:
        view = 0xfee20f80;
        break;
    case TEST_ARM_MVE_REDUCE_MINA:
        view = 0xeee00f80;
        break;
    default:
        TEST_ASSERT(false);
        view = 0;
        break;
    }

    view |= (size & 3) << 18;
    view |= (rda & 15) << 12;
    view |= ((qm >> 3) & 1) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_vmaxnmv_insn(unsigned qm, unsigned rda,
                                          test_arm_mve_reduce_fp_kind kind)
{
    uint32_t view;

    switch (kind) {
    case TEST_ARM_MVE_REDUCE_FMAXNMV_F32:
        view = 0xeeee0f00;
        break;
    case TEST_ARM_MVE_REDUCE_FMAXNMV_F16:
        view = 0xfeee0f00;
        break;
    case TEST_ARM_MVE_REDUCE_FMINNMV_F32:
        view = 0xeeee0f80;
        break;
    case TEST_ARM_MVE_REDUCE_FMINNMV_F16:
        view = 0xfeee0f80;
        break;
    case TEST_ARM_MVE_REDUCE_FMAXNMAV_F32:
        view = 0xeeec0f00;
        break;
    case TEST_ARM_MVE_REDUCE_FMAXNMAV_F16:
        view = 0xfeec0f00;
        break;
    case TEST_ARM_MVE_REDUCE_FMINNMAV_F32:
        view = 0xeeec0f80;
        break;
    case TEST_ARM_MVE_REDUCE_FMINNMAV_F16:
        view = 0xfeec0f80;
        break;
    default:
        TEST_ASSERT(false);
        view = 0;
        break;
    }

    view |= (rda & 15) << 12;
    view |= ((qm >> 3) & 1) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_vaddlv_insn(unsigned qm, unsigned rdalo,
                                         unsigned rdahi, bool is_unsigned,
                                         bool accum)
{
    uint32_t view = 0xee890f00;

    view |= (is_unsigned ? 1U : 0U) << 28;
    view |= ((rdahi >> 1) & 7) << 20;
    view |= ((rdalo >> 1) & 7) << 13;
    view |= (accum ? 1U : 0U) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_vabav_insn(unsigned qn, unsigned qm,
                                        unsigned rda, bool is_unsigned,
                                        unsigned size)
{
    uint32_t view = 0xee800f01;

    view |= (is_unsigned ? 1U : 0U) << 28;
    view |= (size & 3) << 20;
    view |= (qn & 7) << 17;
    view |= (rda & 15) << 12;
    view |= ((qn >> 3) & 1) << 7;
    view |= ((qm >> 3) & 1) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_expected_vaddv(const uint8_t *source,
                                            unsigned esize,
                                            bool is_unsigned,
                                            uint32_t accum,
                                            uint16_t pred)
{
    size_t i;

    for (i = 0; i < 16; i += esize) {
        uint32_t value = test_arm_load_le(source + i, esize);

        if (!(pred & (1U << i))) {
            continue;
        }
        if (is_unsigned) {
            accum += value;
        } else {
            accum += (uint32_t)test_arm_sign_extend(value, esize * 8);
        }
    }
    return accum;
}

static uint32_t
test_arm_mve_expected_vmaxv(const uint8_t *source, unsigned esize,
                            test_arm_mve_reduce_minmax_kind kind,
                            uint32_t accum, uint16_t pred)
{
    unsigned bits = esize * 8;
    uint64_t mask = bits == 32 ? UINT32_MAX : (1ULL << bits) - 1;
    int64_t saccum = test_arm_sign_extend(accum & (uint32_t)mask, bits);
    uint64_t uaccum = accum & (uint32_t)mask;
    size_t i;

    for (i = 0; i < 16; i += esize) {
        uint32_t value = test_arm_load_le(source + i, esize);
        int64_t svalue;
        uint64_t uvalue;

        if (!(pred & (1U << i))) {
            continue;
        }

        switch (kind) {
        case TEST_ARM_MVE_REDUCE_MAX_S:
            svalue = test_arm_sign_extend(value, bits);
            saccum = saccum >= svalue ? saccum : svalue;
            break;
        case TEST_ARM_MVE_REDUCE_MIN_S:
            svalue = test_arm_sign_extend(value, bits);
            saccum = saccum >= svalue ? svalue : saccum;
            break;
        case TEST_ARM_MVE_REDUCE_MAX_U:
            uvalue = value & mask;
            uaccum = uaccum >= uvalue ? uaccum : uvalue;
            break;
        case TEST_ARM_MVE_REDUCE_MIN_U:
            uvalue = value & mask;
            uaccum = uaccum >= uvalue ? uvalue : uaccum;
            break;
        case TEST_ARM_MVE_REDUCE_MAXA:
            svalue = test_arm_sign_extend(value, bits);
            uvalue = (uint64_t)(svalue < 0 ? -svalue : svalue);
            uaccum = uaccum >= uvalue ? uaccum : uvalue;
            break;
        case TEST_ARM_MVE_REDUCE_MINA:
            svalue = test_arm_sign_extend(value, bits);
            uvalue = (uint64_t)(svalue < 0 ? -svalue : svalue);
            uaccum = uaccum >= uvalue ? uvalue : uaccum;
            break;
        }
    }

    switch (kind) {
    case TEST_ARM_MVE_REDUCE_MAX_S:
    case TEST_ARM_MVE_REDUCE_MIN_S:
        return (uint32_t)saccum;
    default:
        return (uint32_t)uaccum;
    }
}

static uint64_t test_arm_mve_expected_vaddlv(const uint8_t *source,
                                             bool is_unsigned,
                                             uint64_t accum,
                                             uint16_t pred)
{
    size_t i;

    for (i = 0; i < 16; i += 4) {
        uint32_t value = test_arm_load_le(source + i, 4);

        if (!(pred & (1U << i))) {
            continue;
        }
        if (is_unsigned) {
            accum += value;
        } else {
            accum += (uint64_t)test_arm_sign_extend(value, 32);
        }
    }
    return accum;
}

static uint32_t test_arm_mve_expected_vabav(const uint8_t *n,
                                            const uint8_t *m,
                                            unsigned esize,
                                            bool is_unsigned,
                                            uint32_t accum,
                                            uint16_t pred)
{
    size_t i;

    for (i = 0; i < 16; i += esize) {
        uint32_t lhs = test_arm_load_le(n + i, esize);
        uint32_t rhs = test_arm_load_le(m + i, esize);
        int64_t slhs;
        int64_t srhs;
        uint64_t diff;

        if (!(pred & (1U << i))) {
            continue;
        }
        if (is_unsigned) {
            diff = lhs >= rhs ? lhs - rhs : rhs - lhs;
        } else {
            slhs = test_arm_sign_extend(lhs, esize * 8);
            srhs = test_arm_sign_extend(rhs, esize * 8);
            diff = slhs >= srhs ? slhs - srhs : srhs - slhs;
        }
        accum += (uint32_t)diff;
    }
    return accum;
}

static void test_arm_m55_mve_reduce32_run(uint32_t insn,
                                          const uint8_t *q1_data,
                                          const uint8_t *q2_data,
                                          unsigned rda_reg,
                                          uint32_t initial_rda,
                                          uint32_t vpr,
                                          uint32_t expected_rda,
                                          bool eci)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q1[2];
    uint64_t q2[2];
    uint32_t epsr;
    uint32_t got;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q1, q1_data, 16);
    memcpy(q2, q2_data, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_Q2, q2));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R0 + rda_reg, &initial_rda));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_R0 + rda_reg, &got));
    TEST_CHECK_(got == expected_rda,
                "insn=0x%08x r%u=0x%08x expected=0x%08x",
                insn, rda_reg, got, expected_rda);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_reduce_fp_run(uint32_t insn,
                                           const uint8_t *q1_data,
                                           unsigned rda_reg,
                                           uint32_t initial_rda,
                                           uint32_t vpr,
                                           uint32_t expected_rda,
                                           bool eci, bool expected_ioc)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint32_t fpscr_ioc = 1U;
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q1[2];
    uint32_t epsr;
    uint32_t fpscr;
    uint32_t got;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q1, q1_data, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R0 + rda_reg, &initial_rda));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_R0 + rda_reg, &got));
    TEST_CHECK_(got == expected_rda,
                "insn=0x%08x r%u=0x%08x expected=0x%08x",
                insn, rda_reg, got, expected_rda);

    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
    TEST_CHECK_(((fpscr & fpscr_ioc) != 0) == expected_ioc,
                "insn=0x%08x fpscr=0x%08x expected_ioc=%u",
                insn, fpscr, expected_ioc ? 1 : 0);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_reduce64_run(uint32_t insn,
                                          const uint8_t *source,
                                          unsigned rdalo_reg,
                                          unsigned rdahi_reg,
                                          uint64_t initial_rda,
                                          uint32_t vpr,
                                          uint64_t expected_rda,
                                          bool eci)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q1[2];
    uint32_t epsr;
    uint32_t gotlo;
    uint32_t gothi;
    uint32_t initlo = (uint32_t)initial_rda;
    uint32_t inithi = (uint32_t)(initial_rda >> 32);

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q1, source, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R0 + rdalo_reg, &initlo));
    OK(uc_reg_write(uc, UC_ARM_REG_R0 + rdahi_reg, &inithi));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_R0 + rdalo_reg, &gotlo));
    OK(uc_reg_read(uc, UC_ARM_REG_R0 + rdahi_reg, &gothi));
    TEST_CHECK_((((uint64_t)gothi << 32) | gotlo) == expected_rda,
                "insn=0x%08x got=0x%08x%08x expected=0x%016llx",
                insn, gothi, gotlo, (unsigned long long)expected_rda);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_reduce(void)
{
    const uint8_t source[16] = {
        0x01, 0xff, 0x7f, 0x80, 0x10, 0x00, 0xf0, 0xff,
        0x78, 0x56, 0x34, 0x12, 0x88, 0xa9, 0xcb, 0xed,
    };
    const uint8_t other[16] = {
        0x7f, 0x00, 0x80, 0xff, 0x20, 0x00, 0x10, 0x00,
        0x00, 0x80, 0xff, 0x7f, 0x78, 0x56, 0x34, 0x12,
    };
    const uint8_t fp32_source[16] = {
        0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0xa0, 0x40,
        0x00, 0x00, 0xe0, 0xc0, 0x00, 0x00, 0x40, 0x40,
    };
    const uint8_t fp32_snan_source[16] = {
        0x01, 0x00, 0x80, 0x7f, 0x00, 0x00, 0x00, 0xc0,
        0x00, 0x00, 0x80, 0xbf, 0x00, 0x00, 0x00, 0x40,
    };
    const uint8_t fp16_source[16] = {
        0x00, 0xc0, 0x00, 0x42, 0x00, 0x38, 0x00, 0xc4,
        0x00, 0x3e, 0x00, 0xb4, 0x00, 0x41, 0x00, 0xc6,
    };
    const uint8_t fp16_snan_source[16] = {
        0x00, 0x7d, 0x00, 0xc0, 0x00, 0xbc, 0x00, 0x40,
        0x00, 0x38, 0x00, 0xb8, 0x00, 0x3c, 0x00, 0xc2,
    };
    uint32_t insn;
    uint32_t expected32;
    uint64_t expected64;

    insn = test_arm_mve_vaddv_insn(1, 2, false, 0, false);
    expected32 = test_arm_mve_expected_vaddv(source, 1, false, 0, 0xffff);
    test_arm_m55_mve_reduce32_run(insn, source, other, 2, 0x11111111, 0,
                                  expected32, false);

    insn = test_arm_mve_vaddv_insn(1, 2, true, 1, true);
    expected32 = test_arm_mve_expected_vaddv(source, 2, true, 0x1000,
                                             0x00f0);
    test_arm_m55_mve_reduce32_run(insn, source, other, 2, 0x1000,
                                  0x001100f0, expected32, false);

    insn = test_arm_mve_vaddv_insn(1, 2, false, 2, false);
    expected32 = test_arm_mve_expected_vaddv(source, 4, false, 0x12345678,
                                             0xff00);
    test_arm_m55_mve_reduce32_run(insn, source, other, 2, 0x12345678, 0,
                                  expected32, true);

    insn = test_arm_mve_vmaxv_insn(1, 2, TEST_ARM_MVE_REDUCE_MAX_S, 0);
    expected32 = test_arm_mve_expected_vmaxv(
        source, 1, TEST_ARM_MVE_REDUCE_MAX_S, 0x00000081, 0xffff);
    test_arm_m55_mve_reduce32_run(insn, source, other, 2, 0x00000081, 0,
                                  expected32, false);

    insn = test_arm_mve_vmaxv_insn(1, 2, TEST_ARM_MVE_REDUCE_MIN_S, 1);
    expected32 = test_arm_mve_expected_vmaxv(
        source, 2, TEST_ARM_MVE_REDUCE_MIN_S, 0x00007fff, 0xffff);
    test_arm_m55_mve_reduce32_run(insn, source, other, 2, 0x00007fff, 0,
                                  expected32, false);

    insn = test_arm_mve_vmaxv_insn(1, 2, TEST_ARM_MVE_REDUCE_MAX_U, 2);
    expected32 = test_arm_mve_expected_vmaxv(
        source, 4, TEST_ARM_MVE_REDUCE_MAX_U, 0x00001000, 0x00f0);
    test_arm_m55_mve_reduce32_run(insn, source, other, 2, 0x00001000,
                                  0x001100f0, expected32, false);

    insn = test_arm_mve_vmaxv_insn(1, 2, TEST_ARM_MVE_REDUCE_MIN_U, 0);
    expected32 = test_arm_mve_expected_vmaxv(
        source, 1, TEST_ARM_MVE_REDUCE_MIN_U, 0x00000080, 0xffff);
    test_arm_m55_mve_reduce32_run(insn, source, other, 2, 0x00000080, 0,
                                  expected32, false);

    insn = test_arm_mve_vmaxv_insn(1, 2, TEST_ARM_MVE_REDUCE_MAXA, 0);
    expected32 = test_arm_mve_expected_vmaxv(
        source, 1, TEST_ARM_MVE_REDUCE_MAXA, 0x000000c8, 0xffff);
    test_arm_m55_mve_reduce32_run(insn, source, other, 2, 0x000000c8, 0,
                                  expected32, false);

    insn = test_arm_mve_vmaxv_insn(1, 2, TEST_ARM_MVE_REDUCE_MAXA, 0);
    expected32 = test_arm_mve_expected_vmaxv(
        source, 1, TEST_ARM_MVE_REDUCE_MAXA, 1, 0xff00);
    test_arm_m55_mve_reduce32_run(insn, source, other, 2, 1, 0,
                                  expected32, true);

    insn = test_arm_mve_vmaxv_insn(1, 2, TEST_ARM_MVE_REDUCE_MINA, 1);
    expected32 = test_arm_mve_expected_vmaxv(
        source, 2, TEST_ARM_MVE_REDUCE_MINA, 0x0000ffff, 0xffff);
    test_arm_m55_mve_reduce32_run(insn, source, other, 2, 0x0000ffff, 0,
                                  expected32, false);

    insn = test_arm_mve_vmaxnmv_insn(
        1, 2, TEST_ARM_MVE_REDUCE_FMAXNMV_F32);
    test_arm_m55_mve_reduce_fp_run(insn, fp32_source, 2, 0x3f800000, 0,
                                   0x40a00000, false, false);

    insn = test_arm_mve_vmaxnmv_insn(
        1, 2, TEST_ARM_MVE_REDUCE_FMINNMV_F32);
    test_arm_m55_mve_reduce_fp_run(insn, fp32_source, 2, 0x3f800000, 0,
                                   0xc0e00000, false, false);

    insn = test_arm_mve_vmaxnmv_insn(
        1, 2, TEST_ARM_MVE_REDUCE_FMAXNMV_F32);
    test_arm_m55_mve_reduce_fp_run(insn, fp32_source, 2, 0x00000000,
                                   0, 0x40400000, true, false);

    insn = test_arm_mve_vmaxnmv_insn(
        1, 2, TEST_ARM_MVE_REDUCE_FMAXNMV_F32);
    test_arm_m55_mve_reduce_fp_run(insn, fp32_source, 2, 0x3f800000,
                                   0x001100f0, 0x40a00000, false, false);

    insn = test_arm_mve_vmaxnmv_insn(
        1, 2, TEST_ARM_MVE_REDUCE_FMAXNMAV_F32);
    test_arm_m55_mve_reduce_fp_run(insn, fp32_source, 2, 0xbf800000, 0,
                                   0x40e00000, false, false);

    insn = test_arm_mve_vmaxnmv_insn(
        1, 2, TEST_ARM_MVE_REDUCE_FMINNMAV_F32);
    test_arm_m55_mve_reduce_fp_run(insn, fp32_source, 2, 0xc1200000, 0,
                                   0xc1200000, false, false);

    insn = test_arm_mve_vmaxnmv_insn(
        1, 2, TEST_ARM_MVE_REDUCE_FMAXNMV_F32);
    test_arm_m55_mve_reduce_fp_run(insn, fp32_snan_source, 2, 0x3f800000,
                                   0, 0x40000000, false, true);

    insn = test_arm_mve_vmaxnmv_insn(
        1, 2, TEST_ARM_MVE_REDUCE_FMAXNMV_F16);
    test_arm_m55_mve_reduce_fp_run(insn, fp16_source, 2, 0x00003c00, 0,
                                   0x00004200, false, false);

    insn = test_arm_mve_vmaxnmv_insn(
        1, 2, TEST_ARM_MVE_REDUCE_FMINNMV_F16);
    test_arm_m55_mve_reduce_fp_run(insn, fp16_source, 2, 0x00003c00, 0,
                                   0x0000c600, false, false);

    insn = test_arm_mve_vmaxnmv_insn(
        1, 2, TEST_ARM_MVE_REDUCE_FMAXNMAV_F16);
    test_arm_m55_mve_reduce_fp_run(insn, fp16_source, 2, 0x0000bc00, 0,
                                   0x00004600, false, false);

    insn = test_arm_mve_vmaxnmv_insn(
        1, 2, TEST_ARM_MVE_REDUCE_FMINNMAV_F16);
    test_arm_m55_mve_reduce_fp_run(insn, fp16_source, 2, 0x0000bc00, 0,
                                   0x0000bc00, false, false);

    insn = test_arm_mve_vmaxnmv_insn(
        1, 2, TEST_ARM_MVE_REDUCE_FMAXNMV_F16);
    test_arm_m55_mve_reduce_fp_run(insn, fp16_snan_source, 2, 0x00003c00,
                                   0, 0x00004000, false, true);

    insn = test_arm_mve_vaddlv_insn(1, 2, 3, false, false);
    expected64 = test_arm_mve_expected_vaddlv(source, false, 0, 0xffff);
    test_arm_m55_mve_reduce64_run(insn, source, 2, 3,
                                  0x2222222211111111ULL, 0, expected64,
                                  false);

    insn = test_arm_mve_vaddlv_insn(1, 2, 3, true, true);
    expected64 = test_arm_mve_expected_vaddlv(source, true,
                                             0x0000000100000010ULL,
                                             0x00f0);
    test_arm_m55_mve_reduce64_run(insn, source, 2, 3,
                                  0x0000000100000010ULL, 0x001100f0,
                                  expected64, false);

    insn = test_arm_mve_vaddlv_insn(1, 2, 3, false, false);
    expected64 = test_arm_mve_expected_vaddlv(source, false,
                                             0x1234567887654321ULL,
                                             0xff00);
    test_arm_m55_mve_reduce64_run(insn, source, 2, 3,
                                  0x1234567887654321ULL, 0, expected64,
                                  true);

    insn = test_arm_mve_vabav_insn(1, 2, 4, false, 0);
    expected32 = test_arm_mve_expected_vabav(source, other, 1, false, 5,
                                             0xffff);
    test_arm_m55_mve_reduce32_run(insn, source, other, 4, 5, 0,
                                  expected32, false);

    insn = test_arm_mve_vabav_insn(1, 2, 4, true, 1);
    expected32 = test_arm_mve_expected_vabav(source, other, 2, true, 0x100,
                                             0x00f0);
    test_arm_m55_mve_reduce32_run(insn, source, other, 4, 0x100,
                                  0x001100f0, expected32, false);

    insn = test_arm_mve_vabav_insn(1, 2, 4, false, 2);
    expected32 = test_arm_mve_expected_vabav(source, other, 4, false,
                                             0x76543210, 0xff00);
    test_arm_m55_mve_reduce32_run(insn, source, other, 4, 0x76543210, 0,
                                  expected32, true);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vaddv_insn(1, 2, false, 3, false),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vaddlv_insn(1, 2, 13, false, false),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vabav_insn(8, 2, 4, false, 0),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vabav_insn(1, 2, 13, false, 0),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vmaxv_insn(8, 2, TEST_ARM_MVE_REDUCE_MAX_S, 0),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vmaxv_insn(1, 13, TEST_ARM_MVE_REDUCE_MAX_U, 1),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vmaxv_insn(1, 15, TEST_ARM_MVE_REDUCE_MINA, 2),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vmaxnmv_insn(8, 2, TEST_ARM_MVE_REDUCE_FMAXNMV_F32),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vmaxnmv_insn(1, 13, TEST_ARM_MVE_REDUCE_FMAXNMV_F16),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vmaxnmv_insn(1, 15, TEST_ARM_MVE_REDUCE_FMINNMAV_F32),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vaddv_insn(1, 2, false, 0, false),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vmaxv_insn(1, 2, TEST_ARM_MVE_REDUCE_MIN_U, 0),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vmaxnmv_insn(1, 2, TEST_ARM_MVE_REDUCE_FMAXNMV_F32),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
}

typedef enum test_arm_mve_dualacc_kind {
    TEST_ARM_MVE_DUALACC_ADD_S,
    TEST_ARM_MVE_DUALACC_ADD_U,
    TEST_ARM_MVE_DUALACC_SUB_S,
} test_arm_mve_dualacc_kind;

static uint32_t test_arm_mve_vmladav_insn(unsigned qn, unsigned qm,
                                          unsigned rda,
                                          test_arm_mve_dualacc_kind kind,
                                          unsigned size, bool xchg,
                                          bool accum)
{
    uint32_t view;

    switch (kind) {
    case TEST_ARM_MVE_DUALACC_ADD_S:
        view = size == 0 ? 0xeef00f00 : 0xeef00e00;
        break;
    case TEST_ARM_MVE_DUALACC_ADD_U:
        view = size == 0 ? 0xfef00f00 : 0xfef00e00;
        break;
    case TEST_ARM_MVE_DUALACC_SUB_S:
    default:
        view = size == 0 ? 0xfef00e01 : 0xeef00e01;
        break;
    }
    if (size != 0) {
        view |= ((size - 1) & 1) << 16;
    }
    view |= ((qn >> 3) & 1) << 7;
    view |= (qn & 7) << 17;
    view |= ((rda >> 1) & 7) << 13;
    view |= (xchg ? 1U : 0U) << 12;
    view |= (accum ? 1U : 0U) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_set_view_bit(uint32_t insn, unsigned bit)
{
    uint32_t view = test_arm_mve_view_to_t32(insn);

    view |= 1U << bit;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_vmlaldav_insn(unsigned qn, unsigned qm,
                                           unsigned rdalo, unsigned rdahi,
                                           test_arm_mve_dualacc_kind kind,
                                           unsigned size, bool xchg,
                                           bool accum)
{
    uint32_t view;

    switch (kind) {
    case TEST_ARM_MVE_DUALACC_ADD_S:
        view = 0xee800e00;
        break;
    case TEST_ARM_MVE_DUALACC_ADD_U:
        view = 0xfe800e00;
        break;
    case TEST_ARM_MVE_DUALACC_SUB_S:
    default:
        view = 0xee800e01;
        break;
    }
    view |= ((size - 1) & 1) << 16;
    view |= ((rdahi >> 1) & 7) << 20;
    view |= ((rdalo >> 1) & 7) << 13;
    view |= ((qn >> 3) & 1) << 7;
    view |= (qn & 7) << 17;
    view |= (xchg ? 1U : 0U) << 12;
    view |= (accum ? 1U : 0U) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_vrmlaldavh_insn(unsigned qn, unsigned qm,
                                             unsigned rdalo, unsigned rdahi,
                                             test_arm_mve_dualacc_kind kind,
                                             bool xchg, bool accum)
{
    uint32_t view;

    switch (kind) {
    case TEST_ARM_MVE_DUALACC_ADD_S:
        view = 0xee800f00;
        break;
    case TEST_ARM_MVE_DUALACC_ADD_U:
        view = 0xfe800f00;
        break;
    case TEST_ARM_MVE_DUALACC_SUB_S:
    default:
        view = 0xfe800e01;
        break;
    }
    view |= ((rdahi >> 1) & 7) << 20;
    view |= ((rdalo >> 1) & 7) << 13;
    view |= ((qn >> 3) & 1) << 7;
    view |= (qn & 7) << 17;
    view |= (xchg ? 1U : 0U) << 12;
    view |= (accum ? 1U : 0U) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_expected_dualacc32(const uint8_t *n,
                                                const uint8_t *m,
                                                unsigned esize,
                                                test_arm_mve_dualacc_kind kind,
                                                bool xchg, uint32_t accum,
                                                uint16_t pred)
{
    size_t e;

    for (e = 0; e < 16 / esize; e++) {
        size_t ne = xchg ? (e ^ 1) : e;
        uint32_t nval = test_arm_load_le(n + ne * esize, esize);
        uint32_t mval = test_arm_load_le(m + e * esize, esize);
        uint32_t product;

        if (!(pred & (1U << (e * esize)))) {
            continue;
        }
        if (kind == TEST_ARM_MVE_DUALACC_ADD_U) {
            product = nval * mval;
        } else {
            int64_t sn = test_arm_sign_extend(nval, esize * 8);
            int64_t sm = test_arm_sign_extend(mval, esize * 8);

            product = (uint32_t)(sn * sm);
        }
        if (kind == TEST_ARM_MVE_DUALACC_SUB_S && (e & 1)) {
            accum -= product;
        } else {
            accum += product;
        }
    }
    return accum;
}

static uint64_t test_arm_mve_expected_dualacc64(const uint8_t *n,
                                                const uint8_t *m,
                                                unsigned esize,
                                                test_arm_mve_dualacc_kind kind,
                                                bool xchg, uint64_t accum,
                                                uint16_t pred)
{
    size_t e;

    for (e = 0; e < 16 / esize; e++) {
        size_t ne = xchg ? (e ^ 1) : e;
        uint32_t nval = test_arm_load_le(n + ne * esize, esize);
        uint32_t mval = test_arm_load_le(m + e * esize, esize);
        uint64_t product;

        if (!(pred & (1U << (e * esize)))) {
            continue;
        }
        if (kind == TEST_ARM_MVE_DUALACC_ADD_U) {
            product = (uint64_t)nval * mval;
        } else {
            int64_t sn = test_arm_sign_extend(nval, esize * 8);
            int64_t sm = test_arm_sign_extend(mval, esize * 8);

            product = (uint64_t)(sn * sm);
        }
        if (kind == TEST_ARM_MVE_DUALACC_SUB_S && (e & 1)) {
            accum -= product;
        } else {
            accum += product;
        }
    }
    return accum;
}

static uint64_t
test_arm_mve_expected_dualacc64_high(const uint8_t *n, const uint8_t *m,
                                     test_arm_mve_dualacc_kind kind,
                                     bool xchg, uint64_t accum,
                                     uint16_t pred)
{
    size_t e;

    for (e = 0; e < 4; e++) {
        size_t ne = xchg ? (e ^ 1) : e;
        uint32_t nval = test_arm_load_le(n + ne * 4, 4);
        uint32_t mval = test_arm_load_le(m + e * 4, 4);

        if (!(pred & (1U << (e * 4)))) {
            continue;
        }
        if (kind == TEST_ARM_MVE_DUALACC_ADD_U) {
            uint64_t product = (uint64_t)nval * mval;

            accum += (product >> 8) + ((product >> 7) & 1);
        } else {
            int64_t sn = test_arm_sign_extend(nval, 32);
            int64_t sm = test_arm_sign_extend(mval, 32);
            int64_t product = sn * sm;

            if (kind == TEST_ARM_MVE_DUALACC_SUB_S && (e & 1)) {
                product = -product;
            }
            accum += (uint64_t)((product >> 8) + ((product >> 7) & 1));
        }
    }
    return accum;
}

static void test_arm_m55_mve_dualacc64_run(uint32_t insn,
                                           const uint8_t *q1_data,
                                           const uint8_t *q2_data,
                                           unsigned rdalo_reg,
                                           unsigned rdahi_reg,
                                           uint64_t initial_rda,
                                           uint32_t vpr,
                                           uint64_t expected_rda,
                                           bool eci)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q1[2];
    uint64_t q2[2];
    uint32_t epsr;
    uint32_t gotlo;
    uint32_t gothi;
    uint32_t initlo = (uint32_t)initial_rda;
    uint32_t inithi = (uint32_t)(initial_rda >> 32);

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q1, q1_data, 16);
    memcpy(q2, q2_data, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_Q2, q2));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R0 + rdalo_reg, &initlo));
    OK(uc_reg_write(uc, UC_ARM_REG_R0 + rdahi_reg, &inithi));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_R0 + rdalo_reg, &gotlo));
    OK(uc_reg_read(uc, UC_ARM_REG_R0 + rdahi_reg, &gothi));
    TEST_CHECK_((((uint64_t)gothi << 32) | gotlo) == expected_rda,
                "insn=0x%08x got=0x%08x%08x expected=0x%016llx",
                insn, gothi, gotlo, (unsigned long long)expected_rda);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_dualacc(void)
{
    const uint8_t n[16] = {
        0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x05, 0xfb,
        0x06, 0xfa, 0x07, 0xf9, 0x08, 0xf8, 0x09, 0xf7,
    };
    const uint8_t m[16] = {
        0x01, 0x04, 0xff, 0x03, 0x02, 0xfe, 0x05, 0xfd,
        0x06, 0xfc, 0x07, 0xfb, 0x08, 0xfa, 0x09, 0xf9,
    };
    uint32_t insn;
    uint32_t expected32;
    uint64_t expected64;

    insn = test_arm_mve_vmladav_insn(1, 2, 4, TEST_ARM_MVE_DUALACC_ADD_S,
                                     0, false, false);
    expected32 = test_arm_mve_expected_dualacc32(n, m, 1,
                                                 TEST_ARM_MVE_DUALACC_ADD_S,
                                                 false, 0, 0xffff);
    test_arm_m55_mve_reduce32_run(insn, n, m, 4, 0x11111111, 0,
                                  expected32, false);

    insn = test_arm_mve_set_view_bit(insn, 0);
    test_arm_m55_mve_reduce32_run(insn, n, m, 4, 0x11111111, 0,
                                  expected32, false);

    insn = test_arm_mve_vmladav_insn(1, 2, 4, TEST_ARM_MVE_DUALACC_ADD_U,
                                     1, false, true);
    expected32 = test_arm_mve_expected_dualacc32(n, m, 2,
                                                 TEST_ARM_MVE_DUALACC_ADD_U,
                                                 false, 0x1000, 0x00f0);
    test_arm_m55_mve_reduce32_run(insn, n, m, 4, 0x1000, 0x001100f0,
                                  expected32, false);

    insn = test_arm_mve_vmladav_insn(1, 2, 4, TEST_ARM_MVE_DUALACC_SUB_S,
                                     2, true, false);
    expected32 = test_arm_mve_expected_dualacc32(n, m, 4,
                                                 TEST_ARM_MVE_DUALACC_SUB_S,
                                                 true, 0x76543210, 0xff00);
    test_arm_m55_mve_reduce32_run(insn, n, m, 4, 0x76543210, 0,
                                  expected32, true);

    insn = test_arm_mve_vmladav_insn(1, 2, 4, TEST_ARM_MVE_DUALACC_SUB_S,
                                     0, false, false);
    expected32 = test_arm_mve_expected_dualacc32(n, m, 1,
                                                 TEST_ARM_MVE_DUALACC_SUB_S,
                                                 false, 0, 0xffff);
    test_arm_m55_mve_reduce32_run(insn, n, m, 4, 0x11111111, 0,
                                  expected32, false);

    insn = test_arm_mve_vmlaldav_insn(1, 2, 2, 3,
                                      TEST_ARM_MVE_DUALACC_ADD_S, 1,
                                      false, false);
    expected64 = test_arm_mve_expected_dualacc64(n, m, 2,
                                                 TEST_ARM_MVE_DUALACC_ADD_S,
                                                 false, 0, 0xffff);
    test_arm_m55_mve_dualacc64_run(insn, n, m, 2, 3,
                                   0x2222222211111111ULL, 0,
                                   expected64, false);

    insn = test_arm_mve_vmlaldav_insn(1, 2, 2, 3,
                                      TEST_ARM_MVE_DUALACC_ADD_S, 1,
                                      true, true);
    expected64 = test_arm_mve_expected_dualacc64(n, m, 2,
                                                 TEST_ARM_MVE_DUALACC_ADD_S,
                                                 true,
                                                 0x0000000000000100ULL,
                                                 0xffff);
    test_arm_m55_mve_dualacc64_run(insn, n, m, 2, 3, 0x100, 0,
                                   expected64, false);

    insn = test_arm_mve_vmlaldav_insn(1, 2, 2, 3,
                                      TEST_ARM_MVE_DUALACC_ADD_U, 2,
                                      false, true);
    expected64 = test_arm_mve_expected_dualacc64(n, m, 4,
                                                 TEST_ARM_MVE_DUALACC_ADD_U,
                                                 false,
                                                 0x0000000100000010ULL,
                                                 0x00f0);
    test_arm_m55_mve_dualacc64_run(insn, n, m, 2, 3,
                                   0x0000000100000010ULL, 0x001100f0,
                                   expected64, false);

    insn = test_arm_mve_vmlaldav_insn(1, 2, 2, 3,
                                      TEST_ARM_MVE_DUALACC_SUB_S, 1,
                                      true, false);
    expected64 = test_arm_mve_expected_dualacc64(n, m, 2,
                                                 TEST_ARM_MVE_DUALACC_SUB_S,
                                                 true,
                                                 0x1234567887654321ULL,
                                                 0xff00);
    test_arm_m55_mve_dualacc64_run(insn, n, m, 2, 3,
                                   0x1234567887654321ULL, 0,
                                   expected64, true);

    insn = test_arm_mve_vrmlaldavh_insn(1, 2, 2, 3,
                                        TEST_ARM_MVE_DUALACC_ADD_S,
                                        false, false);
    expected64 = test_arm_mve_expected_dualacc64_high(
        n, m, TEST_ARM_MVE_DUALACC_ADD_S, false, 0, 0xffff);
    test_arm_m55_mve_dualacc64_run(insn, n, m, 2, 3,
                                   0x2222222211111111ULL, 0,
                                   expected64, false);

    insn = test_arm_mve_vrmlaldavh_insn(1, 2, 2, 3,
                                        TEST_ARM_MVE_DUALACC_ADD_S,
                                        true, true);
    expected64 = test_arm_mve_expected_dualacc64_high(
        n, m, TEST_ARM_MVE_DUALACC_ADD_S, true, 0x100, 0xffff);
    test_arm_m55_mve_dualacc64_run(insn, n, m, 2, 3, 0x100, 0,
                                   expected64, false);

    insn = test_arm_mve_vrmlaldavh_insn(1, 2, 2, 3,
                                        TEST_ARM_MVE_DUALACC_ADD_U,
                                        false, true);
    expected64 = test_arm_mve_expected_dualacc64_high(
        n, m, TEST_ARM_MVE_DUALACC_ADD_U, false,
        0x0000000100000010ULL, 0x00f0);
    test_arm_m55_mve_dualacc64_run(insn, n, m, 2, 3,
                                   0x0000000100000010ULL, 0x001100f0,
                                   expected64, false);

    insn = test_arm_mve_vrmlaldavh_insn(1, 2, 2, 3,
                                        TEST_ARM_MVE_DUALACC_SUB_S,
                                        false, true);
    expected64 = test_arm_mve_expected_dualacc64_high(
        n, m, TEST_ARM_MVE_DUALACC_SUB_S, false,
        0x0000000000000200ULL, 0xffff);
    test_arm_m55_mve_dualacc64_run(insn, n, m, 2, 3, 0x200, 0,
                                   expected64, false);

    insn = test_arm_mve_vrmlaldavh_insn(1, 2, 2, 3,
                                        TEST_ARM_MVE_DUALACC_SUB_S,
                                        true, false);
    expected64 = test_arm_mve_expected_dualacc64_high(
        n, m, TEST_ARM_MVE_DUALACC_SUB_S, true,
        0x1234567887654321ULL, 0xff00);
    test_arm_m55_mve_dualacc64_run(insn, n, m, 2, 3,
                                   0x1234567887654321ULL, 0,
                                   expected64, true);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vmladav_insn(1, 2, 4, TEST_ARM_MVE_DUALACC_ADD_U, 0,
                                  true, false),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vrmlaldavh_insn(1, 2, 2, 3,
                                     TEST_ARM_MVE_DUALACC_ADD_U, true,
                                     false),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vrmlaldavh_insn(8, 2, 2, 3,
                                     TEST_ARM_MVE_DUALACC_ADD_S, false,
                                     false),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vrmlaldavh_insn(1, 2, 2, 3,
                                     TEST_ARM_MVE_DUALACC_ADD_S, false,
                                     false),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vmladav_insn(8, 2, 4, TEST_ARM_MVE_DUALACC_ADD_S, 0,
                                  false, false),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vmlaldav_insn(1, 2, 2, 13,
                                   TEST_ARM_MVE_DUALACC_ADD_S, 1, false,
                                   false),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vmladav_insn(1, 2, 4, TEST_ARM_MVE_DUALACC_ADD_S, 0,
                                  false, false),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
}

static uint32_t test_arm_mve_vshlc_insn(unsigned qd, unsigned rdm,
                                        unsigned shift)
{
    uint32_t view = 0xeea00fc0;

    view |= ((qd >> 3) & 1) << 22;
    view |= (shift & 31) << 16;
    view |= (qd & 7) << 13;
    view |= rdm & 15;
    return test_arm_mve_view_to_t32(view);
}

static void test_arm_mve_expected_vshlc(uint8_t *expected,
                                        const uint8_t *initial,
                                        uint32_t rdm, unsigned shift,
                                        uint16_t pred,
                                        uint32_t *expected_rdm)
{
    size_t e;

    memcpy(expected, initial, 16);
    for (e = 0; e < 16 / 4; e++) {
        size_t off = e * 4;
        uint32_t lane = test_arm_load_le(initial + off, 4);
        uint32_t result;

        if (shift == 0) {
            result = rdm;
            if (pred & (1U << off)) {
                rdm = lane;
            }
        } else {
            uint32_t shiftmask = (uint32_t)((1ULL << shift) - 1);

            result = (lane << shift) | (rdm & shiftmask);
            if (pred & (1U << off)) {
                rdm = lane >> (32 - shift);
            }
        }
        test_arm_mve_store_masked(expected, off, 4, result, pred);
    }
    *expected_rdm = rdm;
}

static void test_arm_m55_mve_vshlc_run(uint32_t insn,
                                       const uint8_t *initial,
                                       uint32_t rdm,
                                       uint32_t vpr,
                                       const uint8_t *expected,
                                       uint32_t expected_rdm,
                                       bool eci)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &rdm));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &rdm));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                    insn, (unsigned)i, got[i], expected[i]);
    }
    TEST_CHECK_(rdm == expected_rdm, "rdm=0x%08x expected=0x%08x",
                rdm, expected_rdm);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_vshlc(void)
{
    const uint8_t initial[16] = {
        0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a,
        0xa9, 0xcb, 0xed, 0x0f, 0x21, 0x43, 0x65, 0x87,
    };
    uint8_t expected[16];
    uint32_t insn;
    uint32_t expected_rdm;
    uint32_t rdm;

    rdm = 0xf000000a;
    insn = test_arm_mve_vshlc_insn(0, 1, 4);
    test_arm_mve_expected_vshlc(expected, initial, rdm, 4, 0xffff,
                                &expected_rdm);
    test_arm_m55_mve_vshlc_run(insn, initial, rdm, 0, expected,
                               expected_rdm, false);

    rdm = 0x89abcdef;
    insn = test_arm_mve_vshlc_insn(0, 1, 0);
    test_arm_mve_expected_vshlc(expected, initial, rdm, 0, 0xffff,
                                &expected_rdm);
    test_arm_m55_mve_vshlc_run(insn, initial, rdm, 0, expected,
                               expected_rdm, false);

    rdm = 0x0000000b;
    insn = test_arm_mve_vshlc_insn(0, 1, 8);
    test_arm_mve_expected_vshlc(expected, initial, rdm, 8, 0x00f0,
                                &expected_rdm);
    test_arm_m55_mve_vshlc_run(insn, initial, rdm, 0x001100f0, expected,
                               expected_rdm, false);

    rdm = 0x0000000c;
    insn = test_arm_mve_vshlc_insn(0, 1, 4);
    test_arm_mve_expected_vshlc(expected, initial, rdm, 4, 0xff00,
                                &expected_rdm);
    test_arm_m55_mve_vshlc_run(insn, initial, rdm, 0, expected,
                               expected_rdm, true);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshlc_insn(8, 1, 4),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshlc_insn(0, 13, 4),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vshlc_insn(0, 1, 4),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_vdup_run(uint32_t insn, int source_reg,
                                      const uint8_t *initial,
                                      uint32_t value, uint32_t vpr,
                                      const uint8_t *expected, bool eci)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, source_reg, &value));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                    insn, (unsigned)i, got[i], expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm_m55_mve_vdup(void)
{
    const uint8_t initial[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    uint8_t expected[16];
    uint32_t value = 0x89abcdef;
    uint32_t vpr = 0;

    test_arm_mve_expected_vdup(expected, initial, value, 1, 0xffff);
    test_arm_m55_mve_vdup_run(0x1b10eee0, UC_ARM_REG_R1, initial, value,
                              vpr, expected, false);

    test_arm_mve_expected_vdup(expected, initial, value, 2, 0xffff);
    test_arm_m55_mve_vdup_run(0x1b30eea0, UC_ARM_REG_R1, initial, value,
                              vpr, expected, false);

    test_arm_mve_expected_vdup(expected, initial, value, 4, 0xffff);
    test_arm_m55_mve_vdup_run(0x1b10eea0, UC_ARM_REG_R1, initial, value,
                              vpr, expected, false);

    vpr = 0x001100f0;
    test_arm_mve_expected_vdup(expected, initial, value, 1, 0x00f0);
    test_arm_m55_mve_vdup_run(0x1b10eee0, UC_ARM_REG_R1, initial, value,
                              vpr, expected, false);

    vpr = 0;
    test_arm_mve_expected_vdup(expected, initial, value, 4, 0xff00);
    test_arm_m55_mve_vdup_run(0x1b10eea0, UC_ARM_REG_R1, initial, value,
                              vpr, expected, true);

    test_arm_mve_expected_vdup(expected, initial, value, 4, 0xffff);
    test_arm_m55_mve_vdup_run(0xeb10eea0, UC_ARM_REG_LR, initial, value,
                              vpr, expected, false);

    test_arm_m55_mve_2op_expect_error(0x1b90eee0, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0xdb10eee0, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0xfb10eee0, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x1b30eee0, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x1b10eee0, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_INSN_INVALID);
}

static void test_arm_m55_mve_vmov_2gp(void)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint8_t initial[16] = {
        0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55,
        0xcc, 0xbb, 0xaa, 0x99, 0x00, 0xff, 0xee, 0xdd,
    };
    uint8_t expected[16];
    uint8_t code[4];
    uint64_t q0[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t r1;
    uint32_t r2;
    uint32_t epsr;
    uc_engine *uc;
    size_t i;

    test_arm_emit32(code, 0, 0x0f01ec02);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    r1 = 0x11111111;
    r2 = 0x22222222;
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r1));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r2));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r1));
    OK(uc_reg_read(uc, UC_ARM_REG_R2, &r2));
    TEST_CHECK_(r1 == 0x11223344, "r1=0x%08x", r1);
    TEST_CHECK_(r2 == 0x99aabbcc, "r2=0x%08x", r2);
    OK(uc_close(uc));

    test_arm_emit32(code, 0, 0x0f11ec02);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    r1 = 0x11111111;
    r2 = 0x22222222;
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r1));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r2));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r1));
    OK(uc_reg_read(uc, UC_ARM_REG_R2, &r2));
    TEST_CHECK_(r1 == 0x55667788, "r1=0x%08x", r1);
    TEST_CHECK_(r2 == 0xddeeff00, "r2=0x%08x", r2);
    OK(uc_close(uc));

    test_arm_emit32(code, 0, 0x0f01ec02);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    r1 = 0x11111111;
    r2 = 0x22222222;
    epsr = xpsr_t | eci_a0a1;
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r1));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r2));
    OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r1));
    OK(uc_reg_read(uc, UC_ARM_REG_R2, &r2));
    OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
    TEST_CHECK_(r1 == 0x11111111, "eci r1=0x%08x", r1);
    TEST_CHECK_(r2 == 0x99aabbcc, "eci r2=0x%08x", r2);
    TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                "epsr=0x%08x", epsr);
    OK(uc_close(uc));

    test_arm_emit32(code, 0, 0x0f01ec12);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(expected, initial, 16);
    r1 = 0x01020304;
    r2 = 0xa1a2a3a4;
    test_arm_store_le(expected, 4, r1);
    test_arm_store_le(expected + 8, 4, r2);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r1));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r2));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "from idx0 i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got[i], expected[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 0, 0x0f11ec12);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(expected, initial, 16);
    r1 = 0x01020304;
    r2 = 0xa1a2a3a4;
    test_arm_store_le(expected + 4, 4, r1);
    test_arm_store_le(expected + 12, 4, r2);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r1));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r2));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "from idx1 i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got[i], expected[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 0, 0x0f11ec12);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(expected, initial, 16);
    r1 = 0x01020304;
    r2 = 0xa1a2a3a4;
    epsr = xpsr_t | eci_a0a1;
    test_arm_store_le(expected + 12, 4, r2);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r1));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r2));
    OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "from eci i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got[i], expected[i]);
    }
    TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                "epsr=0x%08x", epsr);
    OK(uc_close(uc));

    test_arm_emit32(code, 0, 0x0f01ec11);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(expected, initial, 16);
    r1 = 0x01020304;
    test_arm_store_le(expected, 4, r1);
    test_arm_store_le(expected + 8, 4, r1);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r1));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "from dup i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got[i], expected[i]);
    }
    OK(uc_close(uc));

    test_arm_m55_mve_2op_expect_error(0x0f01ec42, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f0dec02, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f01ec0f, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f01ec01, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f0dec12, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f01ec1f, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f01ec02, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_EXCEPTION);
}

static void test_arm_mve_expected_vidup(uint8_t *expected,
                                        const uint8_t *initial,
                                        uint32_t offset, uint32_t wrap,
                                        uint32_t imm, unsigned esize,
                                        bool wrapped, bool decrement,
                                        uint16_t mask,
                                        uint32_t *final_offset)
{
    size_t i;

    memcpy(expected, initial, 16);
    for (i = 0; i < 16; i += esize) {
        test_arm_mve_store_masked(expected, i, esize, offset, mask);
        if (wrapped) {
            if (decrement) {
                if (offset == 0) {
                    offset = wrap;
                }
                offset -= imm;
            } else {
                offset += imm;
                if (offset == wrap) {
                    offset = 0;
                }
            }
        } else if (decrement) {
            offset -= imm;
        } else {
            offset += imm;
        }
    }
    *final_offset = offset;
}

static void test_arm_m55_mve_vidup_run(uint32_t insn,
                                       const uint8_t *initial,
                                       uint32_t rn_value, uint32_t rm_value,
                                       uint32_t vpr,
                                       const uint8_t *expected,
                                       uint32_t expected_rn, bool eci)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &rn_value));
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &rm_value));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_R2, &rn_value));
    TEST_CHECK_(rn_value == expected_rn,
                "insn=0x%08x rn=0x%08x expected=0x%08x",
                insn, rn_value, expected_rn);
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                    insn, (unsigned)i, got[i], expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm_m55_mve_vidup(void)
{
    const uint8_t initial[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const uint32_t vidup_insns[] = {
        0x0f6eee03, 0x0f6eee13, 0x0f6eee23,
    };
    const uint32_t vddup_insns[] = {
        0x1f6eee03, 0x1f6eee13, 0x1f6eee23,
    };
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    uint32_t final_offset;
    uint32_t vpr = 0;
    size_t n;

    for (n = 0; n < 3; n++) {
        test_arm_mve_expected_vidup(expected, initial, 0x10, 0, 1,
                                    esizes[n], false, false, 0xffff,
                                    &final_offset);
        test_arm_m55_mve_vidup_run(vidup_insns[n], initial, 0x10, 0,
                                   vpr, expected, final_offset, false);

        test_arm_mve_expected_vidup(expected, initial, 0x20, 0, 1,
                                    esizes[n], false, true, 0xffff,
                                    &final_offset);
        test_arm_m55_mve_vidup_run(vddup_insns[n], initial, 0x20, 0,
                                   vpr, expected, final_offset, false);
    }

    test_arm_mve_expected_vidup(expected, initial, 2, 5, 1, 1, true,
                                false, 0xffff, &final_offset);
    test_arm_m55_mve_vidup_run(0x0f62ee03, initial, 2, 5, vpr, expected,
                               final_offset, false);

    test_arm_mve_expected_vidup(expected, initial, 0, 5, 1, 1, true,
                                true, 0xffff, &final_offset);
    test_arm_m55_mve_vidup_run(0x1f62ee03, initial, 0, 5, vpr, expected,
                               final_offset, false);

    vpr = 0x001100f0;
    test_arm_mve_expected_vidup(expected, initial, 0x40, 0, 1, 1, false,
                                false, 0x00f0, &final_offset);
    test_arm_m55_mve_vidup_run(0x0f6eee03, initial, 0x40, 0, vpr,
                               expected, final_offset, false);

    vpr = 0;
    test_arm_mve_expected_vidup(expected, initial, 0x100, 0, 1, 4, false,
                                false, 0xff00, &final_offset);
    test_arm_m55_mve_vidup_run(0x0f6eee23, initial, 0x100, 0, vpr,
                               expected, final_offset, true);

    test_arm_m55_mve_2op_expect_error(0x0f6eee33, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f6eee43, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f6cee03, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f6eee03, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_EXCEPTION);
}

enum test_arm_mve_1op_kind {
    TEST_ARM_MVE_CLS,
    TEST_ARM_MVE_CLZ,
    TEST_ARM_MVE_MVN,
    TEST_ARM_MVE_ABS,
    TEST_ARM_MVE_NEG,
    TEST_ARM_MVE_MAXA,
    TEST_ARM_MVE_MINA,
    TEST_ARM_MVE_QABS,
    TEST_ARM_MVE_QNEG,
};

static uint32_t test_arm_clz_bits(uint32_t value, unsigned bits)
{
    uint32_t bit;
    uint32_t count = 0;

    for (bit = 1U << (bits - 1); bit; bit >>= 1) {
        if (value & bit) {
            break;
        }
        count++;
    }

    return count;
}

static uint32_t test_arm_cls_bits(uint32_t value, unsigned bits)
{
    uint32_t sign = value & (1U << (bits - 1));
    uint32_t count = 0;
    int bit;

    for (bit = (int)bits - 2; bit >= 0; bit--) {
        bool set = (value & (1U << bit)) != 0;

        if (set != (sign != 0)) {
            break;
        }
        count++;
    }

    return count;
}

static void test_arm_mve_expected_1op(uint8_t *expected,
                                      const uint8_t *initial,
                                      const uint8_t *source,
                                      enum test_arm_mve_1op_kind kind,
                                      unsigned esize, uint16_t mask,
                                      bool *qc)
{
    unsigned bits = esize * 8;
    size_t i;

    memcpy(expected, initial, 16);
    *qc = false;
    for (i = 0; i < 16; i += esize, mask >>= esize) {
        uint32_t value = test_arm_load_le(source + i, esize);
        uint32_t result = 0;
        int64_t signed_value = test_arm_sign_extend(value, bits);

        switch (kind) {
        case TEST_ARM_MVE_CLS:
            result = test_arm_cls_bits(value, bits);
            break;
        case TEST_ARM_MVE_CLZ:
            result = test_arm_clz_bits(value, bits);
            break;
        case TEST_ARM_MVE_MVN:
            result = ~value;
            break;
        case TEST_ARM_MVE_ABS:
            result = (uint32_t)(signed_value < 0 ?
                                -signed_value : signed_value);
            break;
        case TEST_ARM_MVE_NEG:
            result = (uint32_t)-signed_value;
            break;
        case TEST_ARM_MVE_MAXA:
        case TEST_ARM_MVE_MINA: {
            uint32_t dst = test_arm_load_le(initial + i, esize);
            uint32_t abs_value = (uint32_t)(signed_value < 0 ?
                                           -signed_value : signed_value);

            if (kind == TEST_ARM_MVE_MAXA) {
                result = dst >= abs_value ? dst : abs_value;
            } else {
                result = dst >= abs_value ? abs_value : dst;
            }
            break;
        }
        case TEST_ARM_MVE_QABS:
        case TEST_ARM_MVE_QNEG: {
            int64_t min = -(1LL << (bits - 1));
            int64_t max = (1LL << (bits - 1)) - 1;
            int64_t signed_result = kind == TEST_ARM_MVE_QABS ?
                (signed_value < 0 ? -signed_value : signed_value) :
                -signed_value;

            if (signed_result > max) {
                signed_result = max;
                *qc |= (mask & 1) != 0;
            } else if (signed_result < min) {
                signed_result = min;
                *qc |= (mask & 1) != 0;
            }
            result = (uint32_t)signed_result;
            break;
        }
        default:
            break;
        }

        if (mask & 1) {
            test_arm_store_le(expected + i, esize, result);
        }
    }
}

static void test_arm_mve_expected_rev(uint8_t *expected,
                                      const uint8_t *source,
                                      unsigned group_size,
                                      unsigned elem_size)
{
    size_t group;

    for (group = 0; group < 16; group += group_size) {
        size_t e;
        size_t elems = group_size / elem_size;

        for (e = 0; e < elems; e++) {
            memcpy(expected + group + e * elem_size,
                   source + group + (elems - 1 - e) * elem_size,
                   elem_size);
        }
    }
}

static void test_arm_m55_mve_1op_run(uint32_t insn, const uint8_t *initial,
                                     const uint8_t *source,
                                     const uint8_t *expected,
                                     bool eci, bool expected_qc)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint32_t fpscr_qc = 1U << 27;
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    uint64_t q1[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    uint32_t fpscr = 0;
    uint32_t vpr = 0;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, source, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));
    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    }
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                    insn, (unsigned)i, got[i], expected[i]);
    }
    TEST_CHECK_(((fpscr & fpscr_qc) != 0) == expected_qc,
                "fpscr=0x%08x expected_qc=%d",
                fpscr, expected_qc);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_1op(void)
{
    static const uint32_t cls_insns[] = {
        0x0442ffb0, 0x0442ffb4, 0x0442ffb8,
    };
    static const uint32_t clz_insns[] = {
        0x04c2ffb0, 0x04c2ffb4, 0x04c2ffb8,
    };
    static const uint32_t abs_insns[] = {
        0x0342ffb1, 0x0342ffb5, 0x0342ffb9,
    };
    static const uint32_t neg_insns[] = {
        0x03c2ffb1, 0x03c2ffb5, 0x03c2ffb9,
    };
    static const uint32_t qabs_insns[] = {
        0x0742ffb0, 0x0742ffb4, 0x0742ffb8,
    };
    static const uint32_t qneg_insns[] = {
        0x07c2ffb0, 0x07c2ffb4, 0x07c2ffb8,
    };
    static const struct {
        uint32_t insn;
        unsigned group_size;
        unsigned elem_size;
    } rev_cases[] = {
        { 0x0142ffb0, 2, 1 },
        { 0x00c2ffb0, 4, 1 },
        { 0x00c2ffb4, 4, 2 },
        { 0x0042ffb0, 8, 1 },
        { 0x0042ffb4, 8, 2 },
        { 0x0042ffb8, 8, 4 },
    };
    const uint8_t initial[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const uint8_t source[16] = {
        0x00, 0x01, 0x7f, 0x80, 0xff, 0x55, 0xaa, 0x7f,
        0x80, 0x00, 0x34, 0x12, 0xcc, 0xdd, 0xee, 0xff,
    };
    const unsigned esizes[] = { 1, 2, 4 };
    uint8_t expected[16];
    bool qc;
    size_t n;

    for (n = 0; n < 3; n++) {
        test_arm_mve_expected_1op(expected, initial, source,
                                  TEST_ARM_MVE_CLS, esizes[n], 0xffff, &qc);
        test_arm_m55_mve_1op_run(cls_insns[n], initial, source, expected,
                                 false, false);

        test_arm_mve_expected_1op(expected, initial, source,
                                  TEST_ARM_MVE_CLZ, esizes[n], 0xffff, &qc);
        test_arm_m55_mve_1op_run(clz_insns[n], initial, source, expected,
                                 false, false);

        test_arm_mve_expected_1op(expected, initial, source,
                                  TEST_ARM_MVE_ABS, esizes[n], 0xffff, &qc);
        test_arm_m55_mve_1op_run(abs_insns[n], initial, source, expected,
                                 false, false);

        test_arm_mve_expected_1op(expected, initial, source,
                                  TEST_ARM_MVE_NEG, esizes[n], 0xffff, &qc);
        test_arm_m55_mve_1op_run(neg_insns[n], initial, source, expected,
                                 false, false);

        test_arm_mve_expected_1op(expected, initial, source,
                                  TEST_ARM_MVE_MAXA, esizes[n], 0xffff,
                                  &qc);
        test_arm_m55_mve_1op_run(
            test_arm_mve_1op_insn(0, 1, 0xee330e81, n), initial, source,
            expected, false, false);

        test_arm_mve_expected_1op(expected, initial, source,
                                  TEST_ARM_MVE_MINA, esizes[n], 0xffff,
                                  &qc);
        test_arm_m55_mve_1op_run(
            test_arm_mve_1op_insn(0, 1, 0xee331e81, n), initial, source,
            expected, false, false);

        test_arm_mve_expected_1op(expected, initial, source,
                                  TEST_ARM_MVE_QABS, esizes[n], 0xffff, &qc);
        test_arm_m55_mve_1op_run(qabs_insns[n], initial, source, expected,
                                 false, qc);

        test_arm_mve_expected_1op(expected, initial, source,
                                  TEST_ARM_MVE_QNEG, esizes[n], 0xffff, &qc);
        test_arm_m55_mve_1op_run(qneg_insns[n], initial, source, expected,
                                 false, qc);
    }

    for (n = 0; n < sizeof(rev_cases) / sizeof(rev_cases[0]); n++) {
        memcpy(expected, initial, 16);
        test_arm_mve_expected_rev(expected, source,
                                  rev_cases[n].group_size,
                                  rev_cases[n].elem_size);
        test_arm_m55_mve_1op_run(rev_cases[n].insn, initial, source,
                                 expected, false, false);
    }

    test_arm_mve_expected_1op(expected, initial, source, TEST_ARM_MVE_MVN,
                              1, 0xffff, &qc);
    test_arm_m55_mve_1op_run(0x05c2ffb0, initial, source, expected,
                             false, false);

    test_arm_mve_expected_1op(expected, initial, source, TEST_ARM_MVE_MVN,
                              1, 0xff00, &qc);
    test_arm_m55_mve_1op_run(0x05c2ffb0, initial, source, expected,
                             true, false);

    test_arm_mve_expected_1op(expected, initial, source, TEST_ARM_MVE_MAXA,
                              1, 0xff00, &qc);
    test_arm_m55_mve_1op_run(test_arm_mve_1op_insn(0, 1, 0xee330e81, 0),
                             initial, source, expected, true, false);

    test_arm_m55_mve_2op_expect_error(0x04c2ffbc, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x0142ffb4, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x05c2fff0, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(0x05c2ffb0, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_INSN_INVALID);
}

static uint32_t test_arm_mve_fp_2op_insn(uint32_t base, bool fp16,
                                         unsigned qd, unsigned qn,
                                         unsigned qm)
{
    uint32_t view = base;

    if (fp16) {
        view |= 1U << 20;
    }
    view |= ((qd >> 3) & 1) << 22;
    view |= (qd & 7) << 13;
    view |= ((qn >> 3) & 1) << 7;
    view |= (qn & 7) << 17;
    view |= ((qm >> 3) & 1) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_fp_2op_qdqn_insn(uint32_t base, unsigned qd,
                                              unsigned qm)
{
    uint32_t view = base;

    view |= ((qd >> 3) & 1) << 22;
    view |= (qd & 7) << 13;
    view |= ((qm >> 3) & 1) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_fp_2op_rev_insn(uint32_t base, bool fp32,
                                             unsigned qd, unsigned qn,
                                             unsigned qm)
{
    uint32_t view = base;

    if (fp32) {
        view |= 1U << 20;
    }
    view |= ((qd >> 3) & 1) << 22;
    view |= (qd & 7) << 13;
    view |= ((qn >> 3) & 1) << 7;
    view |= (qn & 7) << 17;
    view |= ((qm >> 3) & 1) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_fp_vcmul_insn(uint32_t base, bool fp32,
                                           unsigned qd, unsigned qn,
                                           unsigned qm)
{
    uint32_t view = base;

    if (fp32) {
        view |= 1U << 28;
    }
    view |= ((qd >> 3) & 1) << 22;
    view |= (qd & 7) << 13;
    view |= ((qn >> 3) & 1) << 7;
    view |= (qn & 7) << 17;
    view |= ((qm >> 3) & 1) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static void test_arm_m55_mve_fp_2op_run(uint32_t insn,
                                        const uint8_t *initial,
                                        const uint8_t *n, const uint8_t *m,
                                        uint32_t vpr,
                                        const uint8_t *expected,
                                        uint16_t expected_mask,
                                        bool eci, bool expected_ioc)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint32_t fpscr_ioc = 1U;
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    uint64_t q1[2];
    uint64_t q2[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    uint32_t fpscr = 0;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, n, 16);
    memcpy(q2, m, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_Q2, q2));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
    for (i = 0; i < 16; i++) {
        if (expected_mask & (1U << i)) {
            TEST_CHECK_(got[i] == expected[i],
                        "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                        insn, (unsigned)i, got[i], expected[i]);
        }
    }
    TEST_CHECK_(((fpscr & fpscr_ioc) != 0) == expected_ioc,
                "insn=0x%08x fpscr=0x%08x expected_ioc=%u",
                insn, fpscr, expected_ioc ? 1 : 0);
    OK(uc_close(uc));
}

static void test_arm_m55_mve_fp_1op_run(uint32_t insn,
                                        const uint8_t *initial,
                                        const uint8_t *source,
                                        uint32_t vpr,
                                        const uint8_t *expected,
                                        uint16_t expected_mask,
                                        bool eci, bool expected_ioc)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint32_t fpscr_ioc = 1U;
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    uint64_t q1[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    uint32_t fpscr = 0;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, source, 16);
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
    for (i = 0; i < 16; i++) {
        if (expected_mask & (1U << i)) {
            TEST_CHECK_(got[i] == expected[i],
                        "insn=0x%08x i=%u got=0x%02x expected=0x%02x",
                        insn, (unsigned)i, got[i], expected[i]);
        }
    }
    TEST_CHECK_(((fpscr & fpscr_ioc) != 0) == expected_ioc,
                "insn=0x%08x fpscr=0x%08x expected_ioc=%u",
                insn, fpscr, expected_ioc ? 1 : 0);
    OK(uc_close(uc));
}

static void test_arm_store_le16_vector(uint8_t *dst, const uint16_t *values,
                                       size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        test_arm_store_le(dst + i * 2, 2, values[i]);
    }
}

static void test_arm_store_le32_vector(uint8_t *dst, const uint32_t *values,
                                       size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        test_arm_store_le(dst + i * 4, 4, values[i]);
    }
}

static void test_arm_m55_mve_fp_convert_round(void)
{
    const uint32_t vcvt_sf_base = 0xffb30640;
    const uint32_t vcvt_uf_base = 0xffb306c0;
    const uint32_t vcvt_fs_base = 0xffb30740;
    const uint32_t vcvt_fu_base = 0xffb307c0;
    const uint32_t vcvt_sh_fixed_base = 0xefb00c50;
    const uint32_t vcvt_uh_fixed_base = 0xffb00c50;
    const uint32_t vcvt_hs_fixed_base = 0xefb00d50;
    const uint32_t vcvt_hu_fixed_base = 0xffb00d50;
    const uint32_t vcvt_sf_fixed_base = 0xefa00e50;
    const uint32_t vcvt_uf_fixed_base = 0xffa00e50;
    const uint32_t vcvt_fs_fixed_base = 0xefa00f50;
    const uint32_t vcvt_fu_fixed_base = 0xffa00f50;
    const uint32_t vcvtb_sh_base = 0xee3f0e01;
    const uint32_t vcvtt_sh_base = 0xee3f1e01;
    const uint32_t vcvtb_hs_base = 0xfe3f0e01;
    const uint32_t vcvtt_hs_base = 0xfe3f1e01;
    const uint32_t vcvtas_base = 0xffb30040;
    const uint32_t vcvtau_base = 0xffb300c0;
    const uint32_t vcvtns_base = 0xffb30140;
    const uint32_t vcvtnu_base = 0xffb301c0;
    const uint32_t vcvtps_base = 0xffb30240;
    const uint32_t vcvtpu_base = 0xffb302c0;
    const uint32_t vcvtms_base = 0xffb30340;
    const uint32_t vcvtmu_base = 0xffb303c0;
    const uint32_t vrintn_base = 0xffb20440;
    const uint32_t vrintx_base = 0xffb204c0;
    const uint32_t vrinta_base = 0xffb20540;
    const uint32_t vrintz_base = 0xffb205c0;
    const uint32_t vrintm_base = 0xffb206c0;
    const uint32_t vrintp_base = 0xffb207c0;
    const uint8_t initial[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    uint8_t source[16];
    uint8_t expected[16];
    uint32_t insn;

    const uint32_t s32_values[] = {
        1, 0xfffffffe, 3, 0xfffffffc,
    };
    const uint32_t f32_from_s32[] = {
        0x3f800000, 0xc0000000, 0x40400000, 0xc0800000,
    };
    const uint16_t u16_values[] = {
        0, 1, 2, 3, 4, 8, 16, 32,
    };
    const uint16_t f16_from_u16[] = {
        0x0000, 0x3c00, 0x4000, 0x4200,
        0x4400, 0x4800, 0x4c00, 0x5000,
    };
    const uint32_t f32_to_s32[] = {
        0x3fe00000, 0xc0200000, 0x7f800001, 0xbf400000,
    };
    const uint32_t s32_from_f32[] = {
        1, 0xfffffffe, 0, 0,
    };
    const uint16_t f16_to_u16[] = {
        0x3e00, 0x4000, 0x4300, 0x4400,
        0x4500, 0x0000, 0x4800, 0x4c00,
    };
    const uint16_t u16_from_f16[] = {
        1, 2, 3, 4, 5, 0, 8, 16,
    };
    const uint16_t s16_fixed_values[] = {
        4, 0xfff8, 16, 0xffe0, 0, 2, 0xfffe, 32,
    };
    const uint16_t f16_from_s16_fixed[] = {
        0x3c00, 0xc000, 0x4400, 0xc800,
        0x0000, 0x3800, 0xb800, 0x4800,
    };
    const uint16_t u16_fixed_values[] = {
        0, 4, 8, 16, 32, 64, 128, 256,
    };
    const uint16_t f16_from_u16_fixed[] = {
        0x0000, 0x3800, 0x3c00, 0x4000,
        0x4400, 0x4800, 0x4c00, 0x5000,
    };
    const uint16_t f16_to_s16_fixed[] = {
        0x3d00, 0xbc00, 0x3800, 0xc100,
        0x4200, 0xb800, 0x0000, 0x4400,
    };
    const uint16_t s16_from_f16_fixed[] = {
        5, 0xfffc, 2, 0xfff6, 12, 0xfffe, 0, 16,
    };
    const uint16_t f16_to_u16_fixed[] = {
        0x3d00, 0x3800, 0x4000, 0x4200,
        0x4400, 0x0000, 0x4800, 0x4c00,
    };
    const uint16_t u16_from_f16_fixed[] = {
        5, 2, 8, 12, 16, 0, 32, 64,
    };
    const uint32_t s32_fixed_to_f32[] = {
        16, 0xffffffe0, 64, 0xffffff80,
    };
    const uint32_t f32_from_s32_fixed[] = {
        0x3f800000, 0xc0000000, 0x40800000, 0xc1000000,
    };
    const uint32_t u32_fixed_to_f32[] = {
        0, 8, 16, 32,
    };
    const uint32_t f32_from_u32_fixed[] = {
        0x00000000, 0x3f000000, 0x3f800000, 0x40000000,
    };
    const uint32_t f32_fixed_values[] = {
        0x3fa00000, 0xbfc00000, 0x40000000, 0xc0300000,
    };
    const uint32_t s32_from_f32_fixed[] = {
        10, 0xfffffff4, 16, 0xffffffea,
    };
    const uint32_t f32_to_u32_fixed[] = {
        0x3fa00000, 0xbf800000, 0x7f800000, 0x7fc00000,
    };
    const uint32_t u32_from_f32_fixed[] = {
        5, 0, 0xffffffff, 0,
    };
    const uint16_t f16_from_f32_lanes[] = {
        0x3c00, 0xc000, 0x4200, 0xc400,
    };
    const uint16_t f16_hs_values[] = {
        0x3c00, 0x4000, 0xc000, 0x4200,
        0x4400, 0xc400, 0x3800, 0xb800,
    };
    const uint32_t f32_from_f16_bottom[] = {
        0x3f800000, 0xc0000000, 0x40800000, 0x3f000000,
    };
    const uint32_t f32_from_f16_top[] = {
        0x40000000, 0x40400000, 0xc0800000, 0xbf000000,
    };
    const uint32_t f32_tie_away[] = {
        0x3fc00000, 0xbfc00000, 0x40100000, 0xc0100000,
    };
    const uint32_t s32_tie_away[] = {
        2, 0xfffffffe, 2, 0xfffffffe,
    };
    const uint16_t f16_tie_away_u[] = {
        0x3e00, 0x4100, 0xbe00, 0xb800,
        0x7c00, 0x7e00, 0x0000, 0x3c00,
    };
    const uint16_t u16_tie_away[] = {
        2, 3, 0, 0, 0xffff, 0, 0, 1,
    };
    const uint32_t f32_tie_even_s[] = {
        0x3fc00000, 0x40200000, 0xbfc00000, 0xc0200000,
    };
    const uint32_t s32_tie_even[] = {
        2, 2, 0xfffffffe, 0xfffffffe,
    };
    const uint32_t f32_tie_even_u[] = {
        0x40200000, 0x40600000, 0x40900000, 0x40b00000,
    };
    const uint32_t u32_tie_even[] = {
        2, 4, 4, 6,
    };
    const uint32_t f32_ceil_s[] = {
        0x3fa00000, 0xbfa00000, 0x4f000000, 0x7fc00000,
    };
    const uint32_t s32_ceil[] = {
        2, 0xffffffff, 0x7fffffff, 0,
    };
    const uint32_t f32_ceil_u[] = {
        0x3fa00000, 0xbfa00000, 0x4f800000, 0x7fc00000,
    };
    const uint32_t u32_ceil[] = {
        2, 0, 0xffffffff, 0,
    };
    const uint16_t f16_floor[] = {
        0x3e00, 0xbe00, 0x4100, 0xc100,
        0x4200, 0xc200, 0x0000, 0xb800,
    };
    const uint16_t s16_floor[] = {
        1, 0xfffe, 2, 0xfffd, 3, 0xfffd, 0, 0xffff,
    };
    const uint16_t f16_floor_u[] = {
        0x3e00, 0x4100, 0xbe00, 0xb800,
        0x7c00, 0x7e00, 0x0000, 0x3c00,
    };
    const uint16_t u16_floor[] = {
        1, 2, 0, 0, 0xffff, 0, 0, 1,
    };
    const uint32_t f32_round_ties[] = {
        0x40200000, 0x40600000, 0xc0200000, 0xc0600000,
    };
    const uint32_t f32_round_ties_expected[] = {
        0x40000000, 0x40800000, 0xc0000000, 0xc0800000,
    };
    const uint16_t f16_round_away[] = {
        0x3e00, 0xbe00, 0x4100, 0xc100,
        0x4200, 0xc200, 0x3800, 0xb800,
    };
    const uint16_t f16_round_away_expected[] = {
        0x4000, 0xc000, 0x4200, 0xc200,
        0x4200, 0xc200, 0x3c00, 0xbc00,
    };
    const uint16_t f16_round_ties_expected[] = {
        0x4000, 0xc000, 0x4000, 0xc000,
        0x4200, 0xc200, 0x0000, 0x8000,
    };
    const uint32_t f32_round_frac[] = {
        0x3fe00000, 0xbfe00000, 0x40000000, 0xc0000000,
    };
    const uint32_t f32_round_zero_expected[] = {
        0x3f800000, 0xbf800000, 0x40000000, 0xc0000000,
    };
    const uint32_t f32_round_floor_expected[] = {
        0x3f800000, 0xc0000000, 0x40000000, 0xc0000000,
    };
    const uint32_t f32_round_ceil_expected[] = {
        0x40000000, 0xbf800000, 0x40000000, 0xc0000000,
    };

    test_arm_store_le32_vector(source, s32_values, 4);
    test_arm_store_le32_vector(expected, f32_from_s32, 4);
    insn = test_arm_mve_1op_insn(0, 1, vcvt_sf_base, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    memcpy(expected, initial, sizeof(expected));
    test_arm_store_le32_vector(expected, f32_from_s32, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0x00ff00ff,
                                expected, 0xffff, false, false);

    memcpy(expected, initial, sizeof(expected));
    test_arm_store_le32_vector(expected + 8, f32_from_s32 + 2, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, true, false);

    test_arm_store_le16_vector(source, u16_values, 8);
    test_arm_store_le16_vector(expected, f16_from_u16, 8);
    insn = test_arm_mve_1op_insn(0, 1, vcvt_uf_base, 1);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le32_vector(source, f32_to_s32, 4);
    test_arm_store_le32_vector(expected, s32_from_f32, 4);
    insn = test_arm_mve_1op_insn(0, 1, vcvt_fs_base, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, true);

    test_arm_store_le16_vector(source, f16_to_u16, 8);
    test_arm_store_le16_vector(expected, u16_from_f16, 8);
    insn = test_arm_mve_1op_insn(0, 1, vcvt_fu_base, 1);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le16_vector(source, s16_fixed_values, 8);
    test_arm_store_le16_vector(expected, f16_from_s16_fixed, 8);
    insn = test_arm_mve_vcvt_fixed_insn(0, 1, vcvt_sh_fixed_base, 1, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le16_vector(source, u16_fixed_values, 8);
    test_arm_store_le16_vector(expected, f16_from_u16_fixed, 8);
    insn = test_arm_mve_vcvt_fixed_insn(0, 1, vcvt_uh_fixed_base, 1, 3);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le16_vector(source, f16_to_s16_fixed, 8);
    test_arm_store_le16_vector(expected, s16_from_f16_fixed, 8);
    insn = test_arm_mve_vcvt_fixed_insn(0, 1, vcvt_hs_fixed_base, 1, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le16_vector(source, f16_to_u16_fixed, 8);
    test_arm_store_le16_vector(expected, u16_from_f16_fixed, 8);
    insn = test_arm_mve_vcvt_fixed_insn(0, 1, vcvt_hu_fixed_base, 1, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le32_vector(source, s32_fixed_to_f32, 4);
    test_arm_store_le32_vector(expected, f32_from_s32_fixed, 4);
    insn = test_arm_mve_vcvt_fixed_insn(0, 1, vcvt_sf_fixed_base, 2, 4);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le32_vector(source, u32_fixed_to_f32, 4);
    test_arm_store_le32_vector(expected, f32_from_u32_fixed, 4);
    insn = test_arm_mve_vcvt_fixed_insn(0, 1, vcvt_uf_fixed_base, 2, 4);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le32_vector(source, f32_fixed_values, 4);
    test_arm_store_le32_vector(expected, s32_from_f32_fixed, 4);
    insn = test_arm_mve_vcvt_fixed_insn(0, 1, vcvt_fs_fixed_base, 2, 3);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le32_vector(source, f32_to_u32_fixed, 4);
    test_arm_store_le32_vector(expected, u32_from_f32_fixed, 4);
    insn = test_arm_mve_vcvt_fixed_insn(0, 1, vcvt_fu_fixed_base, 2, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, true);

    test_arm_store_le32_vector(source, f32_from_s32, 4);
    memcpy(expected, initial, sizeof(expected));
    test_arm_store_le(expected + 0, 2, f16_from_f32_lanes[0]);
    test_arm_store_le(expected + 4, 2, f16_from_f32_lanes[1]);
    test_arm_store_le(expected + 8, 2, f16_from_f32_lanes[2]);
    test_arm_store_le(expected + 12, 2, f16_from_f32_lanes[3]);
    insn = test_arm_mve_1op_insn(0, 1, vcvtb_sh_base, 0);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    memcpy(expected, initial, sizeof(expected));
    test_arm_store_le(expected + 2, 2, f16_from_f32_lanes[0]);
    test_arm_store_le(expected + 6, 2, f16_from_f32_lanes[1]);
    test_arm_store_le(expected + 10, 2, f16_from_f32_lanes[2]);
    test_arm_store_le(expected + 14, 2, f16_from_f32_lanes[3]);
    insn = test_arm_mve_1op_insn(0, 1, vcvtt_sh_base, 0);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le16_vector(source, f16_hs_values, 8);
    test_arm_store_le32_vector(expected, f32_from_f16_bottom, 4);
    insn = test_arm_mve_1op_insn(0, 1, vcvtb_hs_base, 0);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le32_vector(expected, f32_from_f16_top, 4);
    insn = test_arm_mve_1op_insn(0, 1, vcvtt_hs_base, 0);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le32_vector(source, f32_tie_away, 4);
    test_arm_store_le32_vector(expected, s32_tie_away, 4);
    insn = test_arm_mve_1op_insn(0, 1, vcvtas_base, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le16_vector(source, f16_tie_away_u, 8);
    test_arm_store_le16_vector(expected, u16_tie_away, 8);
    insn = test_arm_mve_1op_insn(0, 1, vcvtau_base, 1);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, true);

    test_arm_store_le32_vector(source, f32_tie_even_s, 4);
    test_arm_store_le32_vector(expected, s32_tie_even, 4);
    insn = test_arm_mve_1op_insn(0, 1, vcvtns_base, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le32_vector(source, f32_tie_even_u, 4);
    test_arm_store_le32_vector(expected, u32_tie_even, 4);
    insn = test_arm_mve_1op_insn(0, 1, vcvtnu_base, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le32_vector(source, f32_ceil_s, 4);
    test_arm_store_le32_vector(expected, s32_ceil, 4);
    insn = test_arm_mve_1op_insn(0, 1, vcvtps_base, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, true);

    test_arm_store_le32_vector(source, f32_ceil_u, 4);
    test_arm_store_le32_vector(expected, u32_ceil, 4);
    insn = test_arm_mve_1op_insn(0, 1, vcvtpu_base, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, true);

    test_arm_store_le16_vector(source, f16_floor, 8);
    test_arm_store_le16_vector(expected, s16_floor, 8);
    insn = test_arm_mve_1op_insn(0, 1, vcvtms_base, 1);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le16_vector(source, f16_floor_u, 8);
    test_arm_store_le16_vector(expected, u16_floor, 8);
    insn = test_arm_mve_1op_insn(0, 1, vcvtmu_base, 1);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, true);

    test_arm_store_le32_vector(source, f32_round_ties, 4);
    test_arm_store_le32_vector(expected, f32_round_ties_expected, 4);
    insn = test_arm_mve_1op_insn(0, 1, vrintn_base, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le16_vector(source, f16_round_away, 8);
    test_arm_store_le16_vector(expected, f16_round_away_expected, 8);
    insn = test_arm_mve_1op_insn(0, 1, vrinta_base, 1);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le32_vector(source, f32_round_frac, 4);
    test_arm_store_le32_vector(expected, f32_round_zero_expected, 4);
    insn = test_arm_mve_1op_insn(0, 1, vrintz_base, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le32_vector(expected, f32_round_floor_expected, 4);
    insn = test_arm_mve_1op_insn(0, 1, vrintm_base, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le32_vector(expected, f32_round_ceil_expected, 4);
    insn = test_arm_mve_1op_insn(0, 1, vrintp_base, 2);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_store_le16_vector(source, f16_round_away, 8);
    test_arm_store_le16_vector(expected, f16_round_ties_expected, 8);
    insn = test_arm_mve_1op_insn(0, 1, vrintx_base, 1);
    test_arm_m55_mve_fp_1op_run(insn, initial, source, 0, expected,
                                0xffff, false, false);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_1op_insn(0, 1, vcvt_sf_base, 0),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_1op_insn(8, 1, vcvt_sf_base, 2),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vcvt_fixed_insn(0, 1, vcvt_sh_fixed_base, 1, 2),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_1op_insn(0, 1, vrintn_base, 2),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_INSN_INVALID);
}

static void test_arm_m55_mve_fp_vector(void)
{
    const uint32_t vabs_base = 0xffb10740;
    const uint32_t vneg_base = 0xffb107c0;
    const uint32_t vadd_base = 0xef000d40;
    const uint32_t vsub_base = 0xef200d40;
    const uint32_t vmul_base = 0xff000d50;
    const uint32_t vabd_base = 0xff200d40;
    const uint32_t vmaxnm_base = 0xff000f50;
    const uint32_t vminnm_base = 0xff200f50;
    const uint32_t vmaxnma_f32_base = 0xee3f0e41;
    const uint32_t vminnma_f16_base = 0xfe3f1e41;
    const uint32_t vfma_base = 0xef000c50;
    const uint32_t vfms_base = 0xef200c50;
    const uint32_t vfcadd90_base = 0xfc800840;
    const uint32_t vfcadd270_base = 0xfd800840;
    const uint32_t vcmul0_base = 0xee300e00;
    const uint32_t vcmul90_base = 0xee300e01;
    const uint32_t vcmul180_base = 0xee301e00;
    const uint32_t vcmul270_base = 0xee301e01;
    const uint32_t vcmla0_base = 0xfc200840;
    const uint32_t vcmla90_base = 0xfca00840;
    const uint32_t vcmla180_base = 0xfd200840;
    const uint32_t vcmla270_base = 0xfda00840;
    const uint8_t initial[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    uint8_t n[16];
    uint8_t m[16];
    uint8_t expected[16];
    uint8_t fma_initial[16];
    uint8_t fms_initial[16];
    uint32_t insn;
    size_t i;

    const uint16_t h_values[] = {
        0xbc00, 0x4000, 0xfc00, 0x7e00,
        0x8000, 0x3c00, 0xc000, 0x0000,
    };
    const uint32_t s_values[] = {
        0xbf800000, 0x40000000, 0xff800000, 0x7fc00000,
    };
    const uint32_t s_add_n[] = {
        0x3f800000, 0x40000000, 0xc0800000, 0x80000000,
    };
    const uint32_t s_add_m[] = {
        0x40400000, 0xbf800000, 0x3fc00000, 0x00000000,
    };
    const uint32_t s_add_expected[] = {
        0x40800000, 0x3f800000, 0xc0200000, 0x00000000,
    };
    const uint16_t h_sub_n[] = {
        0x4200, 0xc000, 0x3c00, 0x3800,
        0x4000, 0xbc00, 0x0000, 0x4400,
    };
    const uint16_t h_sub_m[] = {
        0x3c00, 0x4000, 0xc200, 0x3400,
        0x3c00, 0xbc00, 0x8000, 0x4000,
    };
    const uint16_t h_sub_expected[] = {
        0x4000, 0xc400, 0x4400, 0x3400,
        0x3c00, 0x0000, 0x0000, 0x4000,
    };
    const uint32_t s_mul_n[] = {
        0x3f800000, 0x7f800001, 0x40000000, 0xc0000000,
    };
    const uint32_t s_mul_m[] = {
        0x40000000, 0x3f800000, 0x40400000, 0xbf800000,
    };
    const uint32_t s_mul_expected[] = {
        0x40000000, 0, 0x40c00000, 0x40000000,
    };
    const uint32_t s_abd_n[] = {
        0x40a00000, 0x3f800000, 0xc0000000, 0x00000000,
    };
    const uint32_t s_abd_m[] = {
        0x40000000, 0x40600000, 0xc0a00000, 0x80000000,
    };
    const uint32_t s_abd_expected[] = {
        0x40400000, 0x40200000, 0x40400000, 0x00000000,
    };
    const uint16_t h_nm_n[] = {
        0x3c00, 0xc000, 0x4400, 0xbc00,
        0x3800, 0xc400, 0x4200, 0xbe00,
    };
    const uint16_t h_nm_m[] = {
        0x4000, 0xc200, 0x3c00, 0xc000,
        0x3c00, 0xc000, 0xc500, 0xbc00,
    };
    const uint16_t h_maxnm_expected[] = {
        0x4000, 0xc000, 0x4400, 0xbc00,
        0x3c00, 0xc000, 0x4200, 0xbc00,
    };
    const uint16_t h_minnm_expected[] = {
        0x3c00, 0xc200, 0x3c00, 0xc000,
        0x3800, 0xc400, 0xc500, 0xbe00,
    };
    const uint32_t s_nma_n[] = {
        0xbf800000, 0x40000000, 0xc0800000, 0xbf400000,
    };
    const uint32_t s_nma_m[] = {
        0x40400000, 0xbfc00000, 0x40000000, 0xc0000000,
    };
    const uint32_t s_maxnma_expected[] = {
        0x40400000, 0x40000000, 0x40800000, 0x40000000,
    };
    const uint16_t h_nma_n[] = {
        0xc000, 0x3c00, 0xc400, 0x3800,
        0x4200, 0x8000, 0xbe00, 0x4400,
    };
    const uint16_t h_nma_m[] = {
        0x3c00, 0xc200, 0x4000, 0xb400,
        0x4400, 0x0000, 0xc000, 0xb800,
    };
    const uint16_t h_minnma_expected[] = {
        0x3c00, 0x3c00, 0x4000, 0x3400,
        0x4200, 0x0000, 0x3e00, 0x3800,
    };
    const uint32_t s_fma_initial[] = {
        0x3f800000, 0xc0000000, 0x3f000000, 0xbf800000,
    };
    const uint32_t s_fma_n[] = {
        0x40000000, 0xc0400000, 0x40800000, 0xc0000000,
    };
    const uint32_t s_fma_nan_n[] = {
        0x40000000, 0x7f800001, 0x40800000, 0xc0000000,
    };
    const uint32_t s_fma_m[] = {
        0x40400000, 0x3f000000, 0xc0000000, 0xbf800000,
    };
    const uint32_t s_fma_expected[] = {
        0x40e00000, 0xc0600000, 0xc0f00000, 0x3f800000,
    };
    const uint16_t h_fms_initial[] = {
        0x3c00, 0x4000, 0xc400, 0x3800,
        0xbc00, 0x0000, 0x4400, 0xc000,
    };
    const uint16_t h_fms_n[] = {
        0x4000, 0xc200, 0x3c00, 0xc000,
        0x3800, 0xbc00, 0x4400, 0x8000,
    };
    const uint16_t h_fms_m[] = {
        0x4200, 0x3c00, 0xc000, 0xbc00,
        0x4000, 0x4400, 0xb800, 0x3c00,
    };
    const uint16_t h_fms_expected[] = {
        0xc500, 0x4500, 0xc000, 0xbe00,
        0xc000, 0x4400, 0x4600, 0xc000,
    };
    const uint32_t s_fcadd_n[] = {
        0x41200000, 0x41a00000, 0xc0a00000, 0x41000000,
    };
    const uint32_t s_fcadd_m[] = {
        0x3f800000, 0x40000000, 0x40400000, 0xc0800000,
    };
    const uint32_t s_fcadd90_expected[] = {
        0x41000000, 0x41a80000, 0xbf800000, 0x41300000,
    };
    const uint16_t h_fcadd_n[] = {
        0x3c00, 0x4000, 0xc200, 0x4400,
        0x3800, 0xbc00, 0xc000, 0xc400,
    };
    const uint16_t h_fcadd_m[] = {
        0x3800, 0x3c00, 0x4000, 0xbc00,
        0xc000, 0x4200, 0xb800, 0xc200,
    };
    const uint16_t h_fcadd270_expected[] = {
        0x4000, 0x3e00, 0xc400, 0x4000,
        0x4300, 0x3c00, 0xc500, 0xc300,
    };
    const uint32_t s_cmul_n[] = {
        0x40000000, 0x40400000, 0xc0000000, 0x3fc00000,
    };
    const uint32_t s_cmul_m[] = {
        0x40800000, 0x40a00000, 0x40400000, 0xc0800000,
    };
    const uint32_t s_cmul0_expected[] = {
        0x41000000, 0x41200000, 0xc0c00000, 0x41000000,
    };
    const uint32_t s_cmul90_expected[] = {
        0xc1700000, 0x41400000, 0x40c00000, 0x40900000,
    };
    const uint16_t h_cmul_n[] = {
        0x4000, 0x4200, 0xc000, 0x3c00,
        0x3800, 0xbc00, 0xc400, 0xc500,
    };
    const uint16_t h_cmul_m[] = {
        0x4400, 0x4500, 0x4200, 0xc400,
        0xc000, 0x4200, 0xb800, 0xc200,
    };
    const uint16_t h_cmul180_expected[] = {
        0xc800, 0xc900, 0x4600, 0xc800,
        0x3c00, 0xbe00, 0xc000, 0xca00,
    };
    const uint16_t h_cmul270_expected[] = {
        0x4b80, 0xca00, 0xc400, 0xc200,
        0xc200, 0xc000, 0x4b80, 0xc100,
    };
    const uint32_t s_cmla0_expected[] = {
        0x41100000, 0x41000000, 0xc0b00000, 0x40e00000,
    };
    const uint32_t s_cmla90_expected[] = {
        0xc1600000, 0x41200000, 0x40d00000, 0x40600000,
    };
    const uint16_t h_cmla180_expected[] = {
        0xc700, 0xc800, 0x4000, 0xc780,
        0x0000, 0xbe00, 0x4000, 0xcb00,
    };
    const uint16_t h_cmla270_expected[] = {
        0x4c00, 0xc900, 0xc800, 0xc100,
        0xc400, 0xc000, 0x4cc0, 0xc480,
    };

    memcpy(n, initial, sizeof(n));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 8; i++) {
        test_arm_store_le(n + i * 2, 2, h_values[i]);
        test_arm_store_le(expected + i * 2, 2, h_values[i] & 0x7fff);
    }
    insn = test_arm_mve_1op_insn(0, 1, vabs_base, 1);
    test_arm_m55_mve_1op_run(insn, initial, n, expected, false, false);

    memcpy(n, initial, sizeof(n));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 4; i++) {
        test_arm_store_le(n + i * 4, 4, s_values[i]);
        test_arm_store_le(expected + i * 4, 4, s_values[i] ^ 0x80000000);
    }
    insn = test_arm_mve_1op_insn(0, 1, vneg_base, 2);
    test_arm_m55_mve_1op_run(insn, initial, n, expected, false, false);

    memcpy(n, initial, sizeof(n));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 8; i++) {
        test_arm_store_le(n + i * 2, 2, h_values[i]);
    }
    for (i = 4; i < 8; i++) {
        test_arm_store_le(expected + i * 2, 2, h_values[i] ^ 0x8000);
    }
    insn = test_arm_mve_1op_insn(0, 1, vneg_base, 1);
    test_arm_m55_mve_1op_run(insn, initial, n, expected, true, false);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 4; i++) {
        test_arm_store_le(n + i * 4, 4, s_add_n[i]);
        test_arm_store_le(m + i * 4, 4, s_add_m[i]);
        test_arm_store_le(expected + i * 4, 4, s_add_expected[i]);
    }
    insn = test_arm_mve_fp_2op_insn(vadd_base, false, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 8; i++) {
        test_arm_store_le(n + i * 2, 2, h_sub_n[i]);
        test_arm_store_le(m + i * 2, 2, h_sub_m[i]);
        test_arm_store_le(expected + i * 2, 2, h_sub_expected[i]);
    }
    insn = test_arm_mve_fp_2op_insn(vsub_base, true, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 4; i++) {
        test_arm_store_le(n + i * 4, 4, s_add_n[i]);
        test_arm_store_le(m + i * 4, 4, s_add_m[i]);
    }
    for (i = 2; i < 4; i++) {
        test_arm_store_le(expected + i * 4, 4, s_add_expected[i]);
    }
    insn = test_arm_mve_fp_2op_insn(vadd_base, false, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, initial, n, m, 0x00000055,
                                expected, 0xffff, true, false);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 4; i++) {
        test_arm_store_le(n + i * 4, 4, s_mul_n[i]);
        test_arm_store_le(m + i * 4, 4, s_mul_m[i]);
        test_arm_store_le(expected + i * 4, 4, s_mul_expected[i]);
    }
    insn = test_arm_mve_fp_2op_insn(vmul_base, false, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, initial, n, m, 0, expected,
                                0xff0f, false, true);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 4; i++) {
        test_arm_store_le(n + i * 4, 4, s_abd_n[i]);
        test_arm_store_le(m + i * 4, 4, s_abd_m[i]);
        test_arm_store_le(expected + i * 4, 4, s_abd_expected[i]);
    }
    insn = test_arm_mve_fp_2op_insn(vabd_base, false, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 8; i++) {
        test_arm_store_le(n + i * 2, 2, h_nm_n[i]);
        test_arm_store_le(m + i * 2, 2, h_nm_m[i]);
        test_arm_store_le(expected + i * 2, 2, h_maxnm_expected[i]);
    }
    insn = test_arm_mve_fp_2op_insn(vmaxnm_base, true, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 8; i++) {
        test_arm_store_le(expected + i * 2, 2, h_minnm_expected[i]);
    }
    insn = test_arm_mve_fp_2op_insn(vminnm_base, true, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 4; i++) {
        test_arm_store_le(n + i * 4, 4, s_nma_n[i]);
        test_arm_store_le(m + i * 4, 4, s_nma_m[i]);
        test_arm_store_le(expected + i * 4, 4, s_maxnma_expected[i]);
    }
    insn = test_arm_mve_fp_2op_qdqn_insn(vmaxnma_f32_base, 0, 2);
    test_arm_m55_mve_fp_2op_run(insn, n, initial, m, 0, expected,
                                0xffff, false, false);

    memcpy(expected, n, sizeof(expected));
    for (i = 2; i < 4; i++) {
        test_arm_store_le(expected + i * 4, 4, s_maxnma_expected[i]);
    }
    test_arm_m55_mve_fp_2op_run(insn, n, initial, m, 0x00000055,
                                expected, 0xffff, true, false);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 8; i++) {
        test_arm_store_le(n + i * 2, 2, h_nma_n[i]);
        test_arm_store_le(m + i * 2, 2, h_nma_m[i]);
        test_arm_store_le(expected + i * 2, 2, h_minnma_expected[i]);
    }
    insn = test_arm_mve_fp_2op_qdqn_insn(vminnma_f16_base, 0, 2);
    test_arm_m55_mve_fp_2op_run(insn, n, initial, m, 0, expected,
                                0xffff, false, false);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 4; i++) {
        test_arm_store_le(fma_initial + i * 4, 4, s_fma_initial[i]);
        test_arm_store_le(n + i * 4, 4, s_fma_n[i]);
        test_arm_store_le(m + i * 4, 4, s_fma_m[i]);
        test_arm_store_le(expected + i * 4, 4, s_fma_expected[i]);
    }
    insn = test_arm_mve_fp_2op_insn(vfma_base, false, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, fma_initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(expected, fma_initial, sizeof(expected));
    for (i = 2; i < 4; i++) {
        test_arm_store_le(expected + i * 4, 4, s_fma_expected[i]);
    }
    insn = test_arm_mve_fp_2op_insn(vfma_base, false, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, fma_initial, n, m, 0x00000055,
                                expected, 0xffff, true, false);

    for (i = 0; i < 4; i++) {
        test_arm_store_le(n + i * 4, 4, s_fma_nan_n[i]);
    }
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 4; i++) {
        test_arm_store_le(expected + i * 4, 4, s_fma_expected[i]);
    }
    insn = test_arm_mve_fp_2op_insn(vfma_base, false, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, fma_initial, n, m, 0, expected,
                                0xff0f, false, true);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 8; i++) {
        test_arm_store_le(fms_initial + i * 2, 2, h_fms_initial[i]);
        test_arm_store_le(n + i * 2, 2, h_fms_n[i]);
        test_arm_store_le(m + i * 2, 2, h_fms_m[i]);
        test_arm_store_le(expected + i * 2, 2, h_fms_expected[i]);
    }
    insn = test_arm_mve_fp_2op_insn(vfms_base, true, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, fms_initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 4; i++) {
        test_arm_store_le(n + i * 4, 4, s_fcadd_n[i]);
        test_arm_store_le(m + i * 4, 4, s_fcadd_m[i]);
        test_arm_store_le(expected + i * 4, 4, s_fcadd90_expected[i]);
    }
    insn = test_arm_mve_fp_2op_rev_insn(vfcadd90_base, true, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 8; i++) {
        test_arm_store_le(n + i * 2, 2, h_fcadd_n[i]);
        test_arm_store_le(m + i * 2, 2, h_fcadd_m[i]);
        test_arm_store_le(expected + i * 2, 2, h_fcadd270_expected[i]);
    }
    insn = test_arm_mve_fp_2op_rev_insn(vfcadd270_base, false, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 4; i++) {
        test_arm_store_le(n + i * 4, 4, s_cmul_n[i]);
        test_arm_store_le(m + i * 4, 4, s_cmul_m[i]);
        test_arm_store_le(expected + i * 4, 4, s_cmul0_expected[i]);
    }
    insn = test_arm_mve_fp_vcmul_insn(vcmul0_base, true, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 4; i++) {
        test_arm_store_le(expected + i * 4, 4, s_cmul90_expected[i]);
    }
    insn = test_arm_mve_fp_vcmul_insn(vcmul90_base, true, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 8; i++) {
        test_arm_store_le(n + i * 2, 2, h_cmul_n[i]);
        test_arm_store_le(m + i * 2, 2, h_cmul_m[i]);
        test_arm_store_le(expected + i * 2, 2, h_cmul180_expected[i]);
    }
    insn = test_arm_mve_fp_vcmul_insn(vcmul180_base, false, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 8; i++) {
        test_arm_store_le(expected + i * 2, 2, h_cmul270_expected[i]);
    }
    insn = test_arm_mve_fp_vcmul_insn(vcmul270_base, false, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    for (i = 0; i < 4; i++) {
        test_arm_store_le(n + i * 4, 4, s_cmul_n[i]);
        test_arm_store_le(m + i * 4, 4, s_cmul_m[i]);
    }
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 4; i++) {
        test_arm_store_le(expected + i * 4, 4, s_cmla0_expected[i]);
    }
    insn = test_arm_mve_fp_2op_rev_insn(vcmla0_base, true, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, fma_initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 4; i++) {
        test_arm_store_le(expected + i * 4, 4, s_cmla90_expected[i]);
    }
    insn = test_arm_mve_fp_2op_rev_insn(vcmla90_base, true, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, fma_initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(n, initial, sizeof(n));
    memcpy(m, initial, sizeof(m));
    for (i = 0; i < 8; i++) {
        test_arm_store_le(n + i * 2, 2, h_cmul_n[i]);
        test_arm_store_le(m + i * 2, 2, h_cmul_m[i]);
    }
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 8; i++) {
        test_arm_store_le(expected + i * 2, 2, h_cmla180_expected[i]);
    }
    insn = test_arm_mve_fp_2op_rev_insn(vcmla180_base, false, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, fms_initial, n, m, 0, expected,
                                0xffff, false, false);

    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < 8; i++) {
        test_arm_store_le(expected + i * 2, 2, h_cmla270_expected[i]);
    }
    insn = test_arm_mve_fp_2op_rev_insn(vcmla270_base, false, 0, 1, 2);
    test_arm_m55_mve_fp_2op_run(insn, fms_initial, n, m, 0, expected,
                                0xffff, false, false);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_1op_insn(0, 1, vabs_base, 0),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_1op_insn(8, 1, vabs_base, 1),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_fp_2op_insn(vadd_base, false, 8, 1, 2),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_fp_2op_insn(vfma_base, false, 8, 1, 2),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_fp_2op_qdqn_insn(vmaxnma_f32_base, 8, 2),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_fp_2op_qdqn_insn(vmaxnma_f32_base, 0, 8),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_fp_2op_rev_insn(vfcadd90_base, true, 8, 1, 2),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_fp_vcmul_insn(vcmul0_base, true, 8, 1, 2),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_fp_2op_rev_insn(vcmla0_base, true, 8, 1, 2),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_fp_2op_insn(vadd_base, false, 0, 1, 2),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_INSN_INVALID);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_fp_2op_qdqn_insn(vmaxnma_f32_base, 0, 2),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_vldrw_vstrw(void)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint64_t data_addr = code_start + 0x2000;
    const uint8_t initial[16] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    };
    const uint8_t mem[32] = {
        0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55,
        0xcc, 0xbb, 0xaa, 0x99, 0x00, 0xff, 0xee, 0xdd,
        0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05,
        0x0c, 0x0b, 0x0a, 0x09, 0x10, 0x0f, 0x0e, 0x0d,
    };
    const uint8_t qbytes[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    uint8_t expected[32];
    uint8_t got_mem[32];
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t base;
    uint32_t epsr;
    uint32_t vpr;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, 0x1f00ed91); /* vldrw.32 q0,[r1,#0] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == mem[i], "load i=%u got=0x%02x",
                    (unsigned)i, got[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1f04ed81); /* vstrw.32 q0,[r1,#16] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memset(got_mem, 0xee, sizeof(got_mem));
    memcpy(q0, qbytes, 16);
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, got_mem, sizeof(got_mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, data_addr, got_mem, sizeof(got_mem)));
    memset(expected, 0xee, sizeof(expected));
    memcpy(expected + 16, qbytes, 16);
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK_(got_mem[i] == expected[i], "store i=%u got=0x%02x",
                    (unsigned)i, got_mem[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1f00ed91); /* vldrw.32 q0,[r1,#0] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    base = (uint32_t)data_addr;
    vpr = 0x001100f0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    memset(expected, 0, 16);
    memcpy(expected + 4, mem + 4, 4);
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i], "pred load i=%u got=0x%02x",
                    (unsigned)i, got[i]);
    }
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
    epsr = xpsr_t | eci_a0a1;
    OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
    OK(uc_emu_start(uc, (code_start + 4) | 1,
                    code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
    memcpy(expected, initial, 8);
    memcpy(expected + 8, mem + 8, 8);
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i], "eci load i=%u got=0x%02x",
                    (unsigned)i, got[i]);
    }
    TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                "epsr=0x%08x", epsr);
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1f00ed81); /* vstrw.32 q0,[r1,#0] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memset(got_mem, 0xee, sizeof(got_mem));
    memcpy(q0, qbytes, 16);
    base = (uint32_t)data_addr;
    vpr = 0x001100f0;
    OK(uc_mem_write(uc, data_addr, got_mem, sizeof(got_mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, data_addr, got_mem, sizeof(got_mem)));
    memset(expected, 0xee, sizeof(expected));
    memcpy(expected + 4, qbytes + 4, 4);
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK_(got_mem[i] == expected[i], "pred store i=%u got=0x%02x",
                    (unsigned)i, got_mem[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1f04ecb1); /* vldrw.32 q0,[r1],#16 */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &base));
    TEST_CHECK_(base == (uint32_t)(data_addr + 16), "base=0x%08x", base);
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == mem[i], "post load i=%u got=0x%02x",
                    (unsigned)i, got[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1f04ed21); /* vstrw.32 q0,[r1,#-16]! */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memset(got_mem, 0xee, sizeof(got_mem));
    memcpy(q0, qbytes, 16);
    base = (uint32_t)(data_addr + 16);
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, got_mem, sizeof(got_mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &base));
    OK(uc_mem_read(uc, data_addr, got_mem, sizeof(got_mem)));
    TEST_CHECK_(base == (uint32_t)data_addr, "base=0x%08x", base);
    memset(expected, 0xee, sizeof(expected));
    memcpy(expected, qbytes, 16);
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK_(got_mem[i] == expected[i], "pre store i=%u got=0x%02x",
                    (unsigned)i, got_mem[i]);
    }
    OK(uc_close(uc));

    test_arm_m55_mve_ldst_expect_error(0x1f00edd1, UC_CPU_ARM_CORTEX_M55,
                                       UC_ERR_EXCEPTION);
    test_arm_m55_mve_ldst_expect_error(0x1f00ed91, UC_CPU_ARM_CORTEX_M33,
                                       UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_vldrbh_vstrbh(void)
{
    const uint64_t data_addr = code_start + 0x2000;
    const uint8_t initial[16] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    };
    const uint8_t mem[16] = {
        0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55,
        0xcc, 0xbb, 0xaa, 0x99, 0x00, 0xff, 0xee, 0xdd,
    };
    const uint8_t qbytes[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const uint32_t load_insns[] = {
        0x1e00ed91, /* vldrb.8 q0,[r1,#0] */
        0x1e80ed91, /* vldrh.16 q0,[r1,#0] */
    };
    const uint32_t store_insns[] = {
        0x1e00ed81, /* vstrb.8 q0,[r1,#0] */
        0x1e80ed81, /* vstrh.16 q0,[r1,#0] */
    };
    uint8_t expected[16];
    uint8_t got_mem[16];
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t base;
    uint32_t vpr;
    size_t i;
    size_t n;

    for (n = 0; n < sizeof(load_insns) / sizeof(load_insns[0]); n++) {
        test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
        test_arm_emit32(code, 4, load_insns[n]);
        uc_common_setup(&uc, UC_ARCH_ARM,
                        UC_MODE_THUMB | UC_MODE_MCLASS,
                        (const char *)code, sizeof(code),
                        UC_CPU_ARM_CORTEX_M55);
        test_arm_enable_vfp(uc);
        memcpy(q0, initial, 16);
        base = (uint32_t)data_addr;
        vpr = 0;
        OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
        OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
        OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
        OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
        OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
        for (i = 0; i < 16; i++) {
            TEST_CHECK_(got[i] == mem[i], "load n=%u i=%u got=0x%02x",
                        (unsigned)n, (unsigned)i, got[i]);
        }
        OK(uc_close(uc));
    }

    for (n = 0; n < sizeof(store_insns) / sizeof(store_insns[0]); n++) {
        test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
        test_arm_emit32(code, 4, store_insns[n]);
        uc_common_setup(&uc, UC_ARCH_ARM,
                        UC_MODE_THUMB | UC_MODE_MCLASS,
                        (const char *)code, sizeof(code),
                        UC_CPU_ARM_CORTEX_M55);
        test_arm_enable_vfp(uc);
        memset(got_mem, 0xee, sizeof(got_mem));
        memcpy(q0, qbytes, 16);
        base = (uint32_t)data_addr;
        vpr = 0;
        OK(uc_mem_write(uc, data_addr, got_mem, sizeof(got_mem)));
        OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
        OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
        OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
        OK(uc_mem_read(uc, data_addr, got_mem, sizeof(got_mem)));
        for (i = 0; i < 16; i++) {
            TEST_CHECK_(got_mem[i] == qbytes[i],
                        "store n=%u i=%u got=0x%02x",
                        (unsigned)n, (unsigned)i, got_mem[i]);
        }
        OK(uc_close(uc));
    }

    test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, 0x1e00ed91); /* vldrb.8 q0,[r1,#0] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    base = (uint32_t)data_addr;
    vpr = 0x001100f0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    memset(expected, 0, sizeof(expected));
    memcpy(expected + 4, mem + 4, 4);
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i], "pred b load i=%u got=0x%02x",
                    (unsigned)i, got[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1e80ed81); /* vstrh.16 q0,[r1,#0] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memset(got_mem, 0xee, sizeof(got_mem));
    memcpy(q0, qbytes, 16);
    base = (uint32_t)data_addr;
    vpr = 0x001100f0;
    OK(uc_mem_write(uc, data_addr, got_mem, sizeof(got_mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, data_addr, got_mem, sizeof(got_mem)));
    memset(expected, 0xee, sizeof(expected));
    memcpy(expected + 4, qbytes + 4, 4);
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got_mem[i] == expected[i],
                    "pred h store i=%u got=0x%02x",
                    (unsigned)i, got_mem[i]);
    }
    OK(uc_close(uc));
}

static void test_arm_m55_mve_vldst_widen_narrow(void)
{
    const uint64_t data_addr = code_start + 0x2000;
    const uint8_t mem[16] = {
        0x80, 0x7f, 0x01, 0xff, 0x34, 0x12, 0x01, 0x80,
        0xfe, 0xff, 0x00, 0x40, 0x55, 0xaa, 0x10, 0xf0,
    };
    const uint8_t qbytes[16] = {
        0x81, 0x10, 0x82, 0x20, 0x83, 0x30, 0x84, 0x40,
        0x85, 0x50, 0x86, 0x60, 0x87, 0x70, 0x88, 0x80,
    };
    const struct {
        uint32_t insn;
        unsigned mem_size;
        unsigned elem_size;
        bool is_signed;
    } load_cases[] = {
        { 0x0e80ed91, 1, 2, true },  /* vldrb.s16 q0,[r1,#0] */
        { 0x0e80fd91, 1, 2, false }, /* vldrb.u16 q0,[r1,#0] */
        { 0x0f00ed91, 1, 4, true },  /* vldrb.s32 q0,[r1,#0] */
        { 0x0f00fd91, 1, 4, false }, /* vldrb.u32 q0,[r1,#0] */
        { 0x0f00ed99, 2, 4, true },  /* vldrh.s32 q0,[r1,#0] */
        { 0x0f00fd99, 2, 4, false }, /* vldrh.u32 q0,[r1,#0] */
    };
    const struct {
        uint32_t insn;
        unsigned mem_size;
        unsigned elem_size;
    } store_cases[] = {
        { 0x0e80ed81, 1, 2 }, /* vstrb.16 q0,[r1,#0] */
        { 0x0f00ed81, 1, 4 }, /* vstrb.32 q0,[r1,#0] */
        { 0x0f00ed89, 2, 4 }, /* vstrh.32 q0,[r1,#0] */
    };
    uint8_t expected[16];
    uint8_t got_mem[16];
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t base;
    uint32_t vpr;
    size_t i;
    size_t n;

    for (n = 0; n < sizeof(load_cases) / sizeof(load_cases[0]); n++) {
        test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
        test_arm_emit32(code, 4, load_cases[n].insn);
        uc_common_setup(&uc, UC_ARCH_ARM,
                        UC_MODE_THUMB | UC_MODE_MCLASS,
                        (const char *)code, sizeof(code),
                        UC_CPU_ARM_CORTEX_M55);
        test_arm_enable_vfp(uc);
        memset(q0, 0xee, sizeof(q0));
        memset(expected, 0, sizeof(expected));
        base = (uint32_t)data_addr;
        vpr = 0;
        OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
        OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
        OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
        OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
        OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
        for (i = 0; i < 16 / load_cases[n].elem_size; i++) {
            uint32_t value = test_arm_load_le(mem + i * load_cases[n].mem_size,
                                              load_cases[n].mem_size);

            if (load_cases[n].is_signed) {
                if (load_cases[n].mem_size == 1 && (value & 0x80)) {
                    value |= 0xffffff00;
                } else if (load_cases[n].mem_size == 2 &&
                           (value & 0x8000)) {
                    value |= 0xffff0000;
                }
            }
            test_arm_store_le(expected + i * load_cases[n].elem_size,
                              load_cases[n].elem_size, value);
        }
        for (i = 0; i < 16; i++) {
            TEST_CHECK_(got[i] == expected[i],
                        "wide load n=%u i=%u got=0x%02x expected=0x%02x",
                        (unsigned)n, (unsigned)i, got[i], expected[i]);
        }
        OK(uc_close(uc));
    }

    for (n = 0; n < sizeof(store_cases) / sizeof(store_cases[0]); n++) {
        test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
        test_arm_emit32(code, 4, store_cases[n].insn);
        uc_common_setup(&uc, UC_ARCH_ARM,
                        UC_MODE_THUMB | UC_MODE_MCLASS,
                        (const char *)code, sizeof(code),
                        UC_CPU_ARM_CORTEX_M55);
        test_arm_enable_vfp(uc);
        memset(got_mem, 0xee, sizeof(got_mem));
        memcpy(q0, qbytes, 16);
        memset(expected, 0xee, sizeof(expected));
        base = (uint32_t)data_addr;
        vpr = 0;
        OK(uc_mem_write(uc, data_addr, got_mem, sizeof(got_mem)));
        OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
        OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
        OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
        OK(uc_mem_read(uc, data_addr, got_mem, sizeof(got_mem)));
        for (i = 0; i < 16 / store_cases[n].elem_size; i++) {
            uint32_t value = test_arm_load_le(qbytes + i *
                                              store_cases[n].elem_size,
                                              store_cases[n].mem_size);

            test_arm_store_le(expected + i * store_cases[n].mem_size,
                              store_cases[n].mem_size, value);
        }
        for (i = 0; i < 16; i++) {
            TEST_CHECK_(got_mem[i] == expected[i],
                        "narrow store n=%u i=%u got=0x%02x expected=0x%02x",
                        (unsigned)n, (unsigned)i, got_mem[i], expected[i]);
        }
        OK(uc_close(uc));
    }

    test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, 0x0e80ed91); /* vldrb.s16 q0,[r1,#0] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memset(q0, 0xee, sizeof(q0));
    memset(expected, 0, sizeof(expected));
    base = (uint32_t)data_addr;
    vpr = 0x001100f0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    test_arm_store_le(expected + 4, 2, test_arm_load_le(mem + 2, 1));
    test_arm_store_le(expected + 6, 2, 0xffffffff);
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "pred wide load i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got[i], expected[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x0f00ed89); /* vstrh.32 q0,[r1,#0] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memset(got_mem, 0xee, sizeof(got_mem));
    memcpy(q0, qbytes, 16);
    memset(expected, 0xee, sizeof(expected));
    base = (uint32_t)data_addr;
    vpr = 0x001100f0;
    OK(uc_mem_write(uc, data_addr, got_mem, sizeof(got_mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, data_addr, got_mem, sizeof(got_mem)));
    memcpy(expected + 2, qbytes + 4, 2);
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got_mem[i] == expected[i],
                    "pred narrow store i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got_mem[i], expected[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x0e84ecb1); /* vldrb.s16 q0,[r1],#4 */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memset(q0, 0xee, sizeof(q0));
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &base));
    TEST_CHECK_(base == (uint32_t)(data_addr + 4), "base=0x%08x", base);
    OK(uc_close(uc));

    test_arm_m55_mve_ldst_expect_error(0x0e80fd81, UC_CPU_ARM_CORTEX_M55,
                                       UC_ERR_EXCEPTION);
    test_arm_m55_mve_ldst_expect_error(0x0e80ed91, UC_CPU_ARM_CORTEX_M33,
                                       UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_sg(void)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint64_t data_addr = code_start + 0x2000;
    const uint8_t initial[16] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    };
    const uint8_t mem[32] = {
        0x10, 0x81, 0x22, 0x7f, 0xfe, 0x35, 0xc0, 0x49,
        0x08, 0x09, 0xaa, 0x0b, 0x0c, 0xdd, 0x0e, 0x0f,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0, 0x12,
    };
    const uint8_t qbytes[16] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    };
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    uint64_t q1[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint8_t expected[32];
    uint8_t got_mem[32];
    uint32_t base;
    uint32_t epsr;
    uint32_t vpr;
    size_t i;

    test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, 0x0e02fc91); /* vldrb.u8 q0,[r1,q1] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memset(q1, 0, sizeof(q1));
    for (i = 0; i < 16; i++) {
        ((uint8_t *)q1)[i] = (uint8_t)((i * 3) & 0x1f);
        expected[i] = mem[((uint8_t *)q1)[i]];
    }
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "u8 gather i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got[i], expected[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x0f02ec91); /* vldrb.s32 q0,[r1,q1] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memset(q1, 0, sizeof(q1));
    memset(expected, 0, sizeof(expected));
    for (i = 0; i < 4; i++) {
        uint32_t offset = (uint32_t)(i * 2 + 1);
        uint32_t value = mem[offset];

        if (value & 0x80) {
            value |= 0xffffff00;
        }
        test_arm_store_le((uint8_t *)q1 + i * 4, 4, offset);
        test_arm_store_le(expected + i * 4, 4, value);
    }
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "s32 gather i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got[i], expected[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x0f13fc91); /* vldrh.u32 q0,[r1,q1,uxtw #1] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memset(q1, 0, sizeof(q1));
    memset(expected, 0, sizeof(expected));
    for (i = 0; i < 4; i++) {
        uint32_t offset = (uint32_t)(i + 4);
        uint32_t value = test_arm_load_le(mem + offset * 2, 2);

        test_arm_store_le((uint8_t *)q1 + i * 4, 4, offset);
        test_arm_store_le(expected + i * 4, 4, value);
    }
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "os gather i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got[i], expected[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x0f42ec81); /* vstrw.32 q0,[r1,q1] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memset(got_mem, 0xee, sizeof(got_mem));
    memset(q1, 0, sizeof(q1));
    memcpy(q0, qbytes, 16);
    memset(expected, 0xee, sizeof(expected));
    for (i = 0; i < 4; i++) {
        uint32_t offset = (uint32_t)(i * 4);

        test_arm_store_le((uint8_t *)q1 + i * 4, 4, offset);
        memcpy(expected + offset, qbytes + i * 4, 4);
    }
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, got_mem, sizeof(got_mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, data_addr, got_mem, sizeof(got_mem)));
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK_(got_mem[i] == expected[i],
                    "scatter i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got_mem[i], expected[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x0e02fc91); /* vldrb.u8 q0,[r1,q1] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memset(q1, 0, sizeof(q1));
    memset(expected, 0, sizeof(expected));
    for (i = 0; i < 16; i++) {
        ((uint8_t *)q1)[i] = (uint8_t)i;
    }
    expected[4] = mem[4];
    expected[5] = mem[5];
    expected[6] = mem[6];
    expected[7] = mem[7];
    base = (uint32_t)data_addr;
    vpr = 0x001100f0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "pred gather i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got[i], expected[i]);
    }
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memset(q1, 0, sizeof(q1));
    memset(expected, 0, sizeof(expected));
    for (i = 0; i < 16; i++) {
        ((uint8_t *)q1)[i] = (uint8_t)i;
    }
    memcpy(expected, initial, 8);
    memcpy(expected + 8, mem + 8, 8);
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
    epsr = xpsr_t | eci_a0a1;
    OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
    OK(uc_emu_start(uc, (code_start + 4) | 1,
                    code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "eci gather i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got[i], expected[i]);
    }
    TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                "epsr=0x%08x", epsr);
    OK(uc_close(uc));

    test_arm_m55_mve_ldst_expect_error(0x0e00fc91, UC_CPU_ARM_CORTEX_M55,
                                       UC_ERR_EXCEPTION);
    test_arm_m55_mve_ldst_expect_error(0x0e03fc91, UC_CPU_ARM_CORTEX_M55,
                                       UC_ERR_EXCEPTION);
    test_arm_m55_mve_ldst_expect_error(0x0e02fc91, UC_CPU_ARM_CORTEX_M33,
                                       UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_sg_imm(void)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint64_t data_addr = code_start + 0x2000;
    const uint8_t initial[16] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    };
    const uint8_t qbytes[16] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    };
    uint8_t mem[64];
    uint8_t expected[64];
    uint8_t got_mem[64];
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    uint64_t q1[2];
    const uint8_t *got = (const uint8_t *)q0;
    const uint8_t *got_q1 = (const uint8_t *)q1;
    uint32_t epsr;
    uint32_t vpr;
    size_t i;

    for (i = 0; i < sizeof(mem); i++) {
        mem[i] = (uint8_t)(0x40 + i);
    }

    test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, 0x1e04fd92); /* vldrw.u32 q0,[q1,#16] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memset(q1, 0, sizeof(q1));
    for (i = 0; i < 4; i++) {
        test_arm_store_le((uint8_t *)q1 + i * 4, 4,
                          (uint32_t)(data_addr + i * 4));
        memcpy(expected + i * 4, mem + 16 + i * 4, 4);
    }
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "imm w load i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got[i], expected[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1e04fdb2); /* vldrw.u32 q0,[q1,#16]! */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memset(q1, 0, sizeof(q1));
    for (i = 0; i < 4; i++) {
        test_arm_store_le((uint8_t *)q1 + i * 4, 4,
                          (uint32_t)(data_addr + i * 4));
    }
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q1, q1));
    for (i = 0; i < 4; i++) {
        uint32_t updated = test_arm_load_le(got_q1 + i * 4, 4);

        TEST_CHECK_(updated == (uint32_t)(data_addr + 16 + i * 4),
                    "imm w wb lane=%u got=0x%08x",
                    (unsigned)i, updated);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1f02fdb2); /* vldrd.u64 q0,[q1,#16]! */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memset(q1, 0xaa, sizeof(q1));
    test_arm_store_le((uint8_t *)q1, 4, (uint32_t)data_addr);
    test_arm_store_le((uint8_t *)q1 + 8, 4, (uint32_t)(data_addr + 16));
    memset(expected, 0, sizeof(expected));
    memcpy(expected, mem + 16, 8);
    memcpy(expected + 8, mem + 32, 8);
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q1, q1));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "imm d load i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got[i], expected[i]);
    }
    TEST_CHECK_(test_arm_load_le(got_q1, 4) == (uint32_t)(data_addr + 16),
                "d wb lane0=0x%08x", test_arm_load_le(got_q1, 4));
    TEST_CHECK_(test_arm_load_le(got_q1 + 8, 4) ==
                (uint32_t)(data_addr + 32),
                "d wb lane2=0x%08x", test_arm_load_le(got_q1 + 8, 4));
    TEST_CHECK_(got_q1[4] == 0xaa && got_q1[12] == 0xaa,
                "d wb odd lanes changed");
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1e01fd22); /* vstrw.32 q0,[q1,#-4]! */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memset(got_mem, 0xee, sizeof(got_mem));
    memset(expected, 0xee, sizeof(expected));
    memcpy(q0, qbytes, 16);
    memset(q1, 0, sizeof(q1));
    for (i = 0; i < 4; i++) {
        test_arm_store_le((uint8_t *)q1 + i * 4, 4,
                          (uint32_t)(data_addr + 4 + i * 4));
        memcpy(expected + i * 4, qbytes + i * 4, 4);
    }
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, got_mem, sizeof(got_mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, data_addr, got_mem, sizeof(got_mem)));
    OK(uc_reg_read(uc, UC_ARM_REG_Q1, q1));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got_mem[i] == expected[i],
                    "imm w store i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got_mem[i], expected[i]);
    }
    for (i = 0; i < 4; i++) {
        uint32_t updated = test_arm_load_le(got_q1 + i * 4, 4);

        TEST_CHECK_(updated == (uint32_t)(data_addr + i * 4),
                    "imm w store wb lane=%u got=0x%08x",
                    (unsigned)i, updated);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1f01fd82); /* vstrd.64 q0,[q1,#8] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memset(got_mem, 0xee, sizeof(got_mem));
    memset(expected, 0xee, sizeof(expected));
    memcpy(q0, qbytes, 16);
    memset(q1, 0xaa, sizeof(q1));
    test_arm_store_le((uint8_t *)q1, 4, (uint32_t)data_addr);
    test_arm_store_le((uint8_t *)q1 + 8, 4, (uint32_t)(data_addr + 16));
    memcpy(expected + 8, qbytes, 8);
    memcpy(expected + 24, qbytes + 8, 8);
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, got_mem, sizeof(got_mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, data_addr, got_mem, sizeof(got_mem)));
    for (i = 0; i < 40; i++) {
        TEST_CHECK_(got_mem[i] == expected[i],
                    "imm d store i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got_mem[i], expected[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1e04fdb2); /* vldrw.u32 q0,[q1,#16]! */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memset(q1, 0, sizeof(q1));
    for (i = 0; i < 4; i++) {
        test_arm_store_le((uint8_t *)q1 + i * 4, 4,
                          (uint32_t)(data_addr + i * 4));
    }
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
    epsr = xpsr_t | eci_a0a1;
    OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
    OK(uc_emu_start(uc, (code_start + 4) | 1,
                    code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
    for (i = 0; i < 8; i++) {
        TEST_CHECK_(got[i] == initial[i],
                    "eci imm load preserved i=%u got=0x%02x",
                    (unsigned)i, got[i]);
    }
    for (i = 2; i < 4; i++) {
        uint32_t updated = test_arm_load_le(got_q1 + i * 4, 4);

        TEST_CHECK_(updated == (uint32_t)(data_addr + 16 + i * 4),
                    "eci imm wb lane=%u got=0x%08x",
                    (unsigned)i, updated);
    }
    TEST_CHECK_(test_arm_load_le(got_q1, 4) == (uint32_t)data_addr,
                "eci imm lane0 updated");
    TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                "epsr=0x%08x", epsr);
    OK(uc_close(uc));

    test_arm_m55_mve_ldst_expect_error(0x1e01fd90, UC_CPU_ARM_CORTEX_M55,
                                       UC_ERR_EXCEPTION);
    test_arm_m55_mve_ldst_expect_error(0x1e01fdd2, UC_CPU_ARM_CORTEX_M55,
                                       UC_ERR_EXCEPTION);
    test_arm_m55_mve_ldst_expect_error(0x1e04fd92, UC_CPU_ARM_CORTEX_M33,
                                       UC_ERR_EXCEPTION);
}

static void test_arm_m55_mve_interleaved(void)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint64_t data_addr = code_start + 0x2000;
    const uint8_t initial_q0[16] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    };
    const uint8_t initial_q1[16] = {
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    const uint8_t qbytes0[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const uint8_t qbytes1[16] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };
    const uint8_t qbytes2[16] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    };
    const uint8_t qbytes3[16] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    };
    const uint8_t off_vld2b[4] = { 0, 2, 12, 14 };
    const uint8_t off_vld4h[4] = { 0, 0, 5, 5 };
    const uint8_t off_vst2w[4] = { 0, 4, 24, 28 };
    const uint8_t off_vst4b[4] = { 0, 1, 10, 11 };
    uc_engine *uc;
    uint8_t code[8];
    uint8_t mem[96];
    uint8_t expected[96];
    uint8_t got_mem[96];
    uint8_t exp_q0[16];
    uint8_t exp_q1[16];
    uint8_t exp_q2[16];
    uint8_t exp_q3[16];
    uint64_t q0[2];
    uint64_t q1[2];
    uint64_t q2[2];
    uint64_t q3[2];
    uint8_t *dst_q[4] = { exp_q0, exp_q1, exp_q2, exp_q3 };
    const uint8_t *src_q[4] = { qbytes0, qbytes1, qbytes2, qbytes3 };
    uint32_t base;
    uint32_t epsr;
    uint32_t vpr;
    size_t beat;
    size_t i;

    for (i = 0; i < sizeof(mem); i++) {
        mem[i] = (uint8_t)(0x50 + i);
    }

    test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, 0x1e00fc91); /* vld2.8 {q0,q1},[r1] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial_q0, 16);
    memcpy(q1, initial_q1, 16);
    memcpy(exp_q0, initial_q0, 16);
    memcpy(exp_q1, initial_q1, 16);
    for (beat = 0; beat < 4; beat++) {
        size_t off = off_vld2b[beat];
        size_t addr = off * 2;

        exp_q0[off] = mem[addr];
        exp_q1[off] = mem[addr + 1];
        exp_q0[off + 1] = mem[addr + 2];
        exp_q1[off + 1] = mem[addr + 3];
    }
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q1, q1));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(((uint8_t *)q0)[i] == exp_q0[i],
                    "vld2 q0 i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, ((uint8_t *)q0)[i], exp_q0[i]);
        TEST_CHECK_(((uint8_t *)q1)[i] == exp_q1[i],
                    "vld2 q1 i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, ((uint8_t *)q1)[i], exp_q1[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1e81fcb1); /* vld4.16 {q0-q3},[r1]! */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, qbytes0, 16);
    memcpy(q1, qbytes1, 16);
    memcpy(q2, qbytes2, 16);
    memcpy(q3, qbytes3, 16);
    memcpy(exp_q0, qbytes0, 16);
    memcpy(exp_q1, qbytes1, 16);
    memcpy(exp_q2, qbytes2, 16);
    memcpy(exp_q3, qbytes3, 16);
    for (beat = 0; beat < 4; beat++) {
        size_t off = off_vld4h[beat];
        size_t addr = off * 8 + (beat & 1) * 4;
        unsigned y = (beat & 1) ? 2 : 0;

        test_arm_store_le(dst_q[y] + off * 2, 2,
                          test_arm_load_le(mem + addr, 2));
        test_arm_store_le(dst_q[y + 1] + off * 2, 2,
                          test_arm_load_le(mem + addr + 2, 2));
    }
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_Q2, q2));
    OK(uc_reg_write(uc, UC_ARM_REG_Q3, q3));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_read(uc, UC_ARM_REG_Q2, q2));
    OK(uc_reg_read(uc, UC_ARM_REG_Q3, q3));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &base));
    TEST_CHECK_(base == (uint32_t)(data_addr + 64),
                "vld4 wb base=0x%08x", base);
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(((uint8_t *)q0)[i] == exp_q0[i],
                    "vld4 q0 i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, ((uint8_t *)q0)[i], exp_q0[i]);
        TEST_CHECK_(((uint8_t *)q1)[i] == exp_q1[i],
                    "vld4 q1 i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, ((uint8_t *)q1)[i], exp_q1[i]);
        TEST_CHECK_(((uint8_t *)q2)[i] == exp_q2[i],
                    "vld4 q2 i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, ((uint8_t *)q2)[i], exp_q2[i]);
        TEST_CHECK_(((uint8_t *)q3)[i] == exp_q3[i],
                    "vld4 q3 i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, ((uint8_t *)q3)[i], exp_q3[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1f00fca1); /* vst2.32 {q0,q1},[r1]! */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memset(got_mem, 0xee, sizeof(got_mem));
    memset(expected, 0xee, sizeof(expected));
    memcpy(q0, qbytes0, 16);
    memcpy(q1, qbytes1, 16);
    for (beat = 0; beat < 4; beat++) {
        size_t off = off_vst2w[beat];
        size_t lane = (off >> 3) * 4;

        memcpy(expected + off, src_q[beat & 1] + lane, 4);
    }
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, got_mem, sizeof(got_mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, data_addr, got_mem, sizeof(got_mem)));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &base));
    TEST_CHECK_(base == (uint32_t)(data_addr + 32),
                "vst2 wb base=0x%08x", base);
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK_(got_mem[i] == expected[i],
                    "vst2 i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got_mem[i], expected[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1e01fc81); /* vst4.8 {q0-q3},[r1] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memset(got_mem, 0xee, sizeof(got_mem));
    memset(expected, 0xee, sizeof(expected));
    memcpy(q0, qbytes0, 16);
    memcpy(q1, qbytes1, 16);
    memcpy(q2, qbytes2, 16);
    memcpy(q3, qbytes3, 16);
    for (beat = 0; beat < 4; beat++) {
        size_t off = off_vst4b[beat];
        size_t addr = off * 4;

        expected[addr] = qbytes0[off];
        expected[addr + 1] = qbytes1[off];
        expected[addr + 2] = qbytes2[off];
        expected[addr + 3] = qbytes3[off];
    }
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, got_mem, sizeof(got_mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_Q2, q2));
    OK(uc_reg_write(uc, UC_ARM_REG_Q3, q3));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, data_addr, got_mem, sizeof(got_mem)));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &base));
    TEST_CHECK_(base == (uint32_t)data_addr, "vst4 base=0x%08x", base);
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK_(got_mem[i] == expected[i],
                    "vst4 i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, got_mem[i], expected[i]);
    }
    OK(uc_close(uc));

    test_arm_emit32(code, 4, 0x1e00fc91); /* vld2.8 {q0,q1},[r1] */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial_q0, 16);
    memcpy(q1, initial_q1, 16);
    memcpy(exp_q0, initial_q0, 16);
    memcpy(exp_q1, initial_q1, 16);
    for (beat = 2; beat < 4; beat++) {
        size_t off = off_vld2b[beat];
        size_t addr = off * 2;

        exp_q0[off] = mem[addr];
        exp_q1[off] = mem[addr + 1];
        exp_q0[off + 1] = mem[addr + 2];
        exp_q1[off + 1] = mem[addr + 3];
    }
    base = (uint32_t)data_addr;
    vpr = 0;
    OK(uc_mem_write(uc, data_addr, mem, sizeof(mem)));
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &base));
    OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
    epsr = xpsr_t | eci_a0a1;
    OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
    OK(uc_emu_start(uc, (code_start + 4) | 1,
                    code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(((uint8_t *)q0)[i] == exp_q0[i],
                    "eci vld2 q0 i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, ((uint8_t *)q0)[i], exp_q0[i]);
        TEST_CHECK_(((uint8_t *)q1)[i] == exp_q1[i],
                    "eci vld2 q1 i=%u got=0x%02x expected=0x%02x",
                    (unsigned)i, ((uint8_t *)q1)[i], exp_q1[i]);
    }
    TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                "epsr=0x%08x", epsr);
    OK(uc_close(uc));

    test_arm_m55_mve_ldst_expect_error(0x1f80fc91, UC_CPU_ARM_CORTEX_M55,
                                       UC_ERR_EXCEPTION);
    test_arm_m55_mve_ldst_expect_error(0x1e40fc91, UC_CPU_ARM_CORTEX_M55,
                                       UC_ERR_EXCEPTION);
    test_arm_m55_mve_ldst_expect_error(0xfe00fc91, UC_CPU_ARM_CORTEX_M55,
                                       UC_ERR_EXCEPTION);
    test_arm_m55_mve_ldst_expect_error(0xbe01fc91, UC_CPU_ARM_CORTEX_M55,
                                       UC_ERR_EXCEPTION);
    test_arm_m55_mve_ldst_expect_error(0x1e00fc9f, UC_CPU_ARM_CORTEX_M55,
                                       UC_ERR_EXCEPTION);
    test_arm_m55_mve_ldst_expect_error(0x1e00fcbd, UC_CPU_ARM_CORTEX_M55,
                                       UC_ERR_EXCEPTION);
    test_arm_m55_mve_ldst_expect_error(0x1e00fc91, UC_CPU_ARM_CORTEX_M33,
                                       UC_ERR_EXCEPTION);
}

static void test_arm_m55_vpsel(void)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint8_t initial[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const uint8_t qn_bytes[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const uint8_t qm_bytes[16] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    };
    const uint8_t expected[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    };
    const uint8_t expected_eci[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q0[2];
    uint64_t q1[2];
    uint64_t q2[2];
    const uint8_t *got = (const uint8_t *)q0;
    uint32_t epsr;
    uint32_t vpr;
    size_t i;
    uc_err err;

    test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, 0x0f05fe33); /* vpsel q0,q1,q2 */

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, qn_bytes, 16);
    memcpy(q2, qm_bytes, 16);
    vpr = 0x000000ff;
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_Q2, q2));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected[i], "i=%u got=0x%02x",
                    (unsigned)i, got[i]);
    }
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q0, initial, 16);
    memcpy(q1, qn_bytes, 16);
    memcpy(q2, qm_bytes, 16);
    vpr = 0x0000ff00;
    OK(uc_reg_write(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_Q2, q2));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &vpr));
    OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
    epsr = xpsr_t | eci_a0a1;
    OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
    OK(uc_emu_start(uc, (code_start + 4) | 1, code_start + sizeof(code), 0,
                    0));
    OK(uc_reg_read(uc, UC_ARM_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
    for (i = 0; i < 16; i++) {
        TEST_CHECK_(got[i] == expected_eci[i], "i=%u got=0x%02x",
                    (unsigned)i, got[i]);
    }
    TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                "epsr=0x%08x", epsr);
    OK(uc_close(uc));

    test_arm_emit32(code, 0, 0x0f05fe73); /* vpsel q8,q1,q2 */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, 4,
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    err = uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0);
    TEST_CHECK_(err == UC_ERR_EXCEPTION, "err=%u", (unsigned)err);
    OK(uc_close(uc));

    test_arm_emit32(code, 0, 0x0f05fe33); /* vpsel q0,q1,q2 */
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, 4,
                    UC_CPU_ARM_CORTEX_M33);
    test_arm_enable_vfp(uc);
    err = uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0);
    TEST_CHECK_(err == UC_ERR_EXCEPTION, "err=%u", (unsigned)err);
    OK(uc_close(uc));
}

typedef enum test_arm_mve_cmp_kind {
    TEST_ARM_MVE_CMP_EQ,
    TEST_ARM_MVE_CMP_NE,
    TEST_ARM_MVE_CMP_CS,
    TEST_ARM_MVE_CMP_HI,
    TEST_ARM_MVE_CMP_GE,
    TEST_ARM_MVE_CMP_LT,
    TEST_ARM_MVE_CMP_GT,
    TEST_ARM_MVE_CMP_LE,
} test_arm_mve_cmp_kind;

static uint16_t test_arm_mve_expected_cmp_p0(const uint8_t *n,
                                             const uint8_t *m,
                                             uint32_t scalar,
                                             unsigned esize,
                                             bool is_scalar,
                                             bool is_signed,
                                             test_arm_mve_cmp_kind kind,
                                             uint16_t pred)
{
    uint16_t p0 = 0;
    unsigned i;

    for (i = 0; i < 16; i += esize) {
        uint32_t lhs = test_arm_load_le(n + i, esize);
        uint32_t rhs = is_scalar ? scalar : test_arm_load_le(m + i, esize);
        uint16_t lane_mask = ((1U << esize) - 1) << i;
        bool result;

        if (is_scalar && esize < 4) {
            rhs &= (1U << (esize * 8)) - 1;
        }

        if (is_signed) {
            int64_t slhs = test_arm_sign_extend(lhs, esize * 8);
            int64_t srhs = test_arm_sign_extend(rhs, esize * 8);

            switch (kind) {
            case TEST_ARM_MVE_CMP_GE:
            case TEST_ARM_MVE_CMP_CS:
                result = slhs >= srhs;
                break;
            case TEST_ARM_MVE_CMP_GT:
                result = slhs > srhs;
                break;
            case TEST_ARM_MVE_CMP_LT:
                result = slhs < srhs;
                break;
            case TEST_ARM_MVE_CMP_LE:
                result = slhs <= srhs;
                break;
            case TEST_ARM_MVE_CMP_EQ:
                result = slhs == srhs;
                break;
            case TEST_ARM_MVE_CMP_NE:
                result = slhs != srhs;
                break;
            default:
                result = false;
                break;
            }
        } else {
            switch (kind) {
            case TEST_ARM_MVE_CMP_CS:
            case TEST_ARM_MVE_CMP_GE:
                result = lhs >= rhs;
                break;
            case TEST_ARM_MVE_CMP_GT:
            case TEST_ARM_MVE_CMP_HI:
                result = lhs > rhs;
                break;
            case TEST_ARM_MVE_CMP_LT:
                result = lhs < rhs;
                break;
            case TEST_ARM_MVE_CMP_LE:
                result = lhs <= rhs;
                break;
            case TEST_ARM_MVE_CMP_EQ:
                result = lhs == rhs;
                break;
            case TEST_ARM_MVE_CMP_NE:
                result = lhs != rhs;
                break;
            default:
                result = false;
                break;
            }
        }

        if (result) {
            p0 |= lane_mask;
        }
    }

    return p0 & pred;
}

static void test_arm_m55_mve_vcmp_run(uint32_t insn, const uint8_t *n,
                                      const uint8_t *m, uint32_t initial_vpr,
                                      uint32_t r3, uint32_t expected_vpr,
                                      bool eci)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q1[2];
    uint64_t q2[2];
    uint32_t epsr;
    uint32_t vpr;

    test_arm_emit32(code, 0, 0x0a10eeec); /* vmsr vpr,r0 */
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q1, n, 16);
    if (m) {
        memcpy(q2, m, 16);
    } else {
        memset(q2, 0, sizeof(q2));
    }
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_Q2, q2));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &initial_vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &r3));
    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &vpr));
    TEST_CHECK_(vpr == expected_vpr,
                "insn=0x%08x vpr=0x%08x expected=0x%08x",
                insn, vpr, expected_vpr);
    if (eci) {
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    }
    OK(uc_close(uc));
}

static void test_arm_m55_mve_vcmp(void)
{
    const uint8_t bytes_n[16] = {
        0x00, 0x01, 0x80, 0xff, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const uint8_t bytes_m[16] = {
        0x00, 0x02, 0x80, 0x7f, 0x05, 0x05, 0x06, 0x08,
        0x18, 0x09, 0x0b, 0x0b, 0x0d, 0x0d, 0x0f, 0x0f,
    };
    uint8_t words_n[16];
    uint8_t words_m[16];
    uint8_t scalar_n[16];
    uint8_t scalar_h[16];
    uint32_t expected_p0;
    uint32_t expected_vpr;
    uint32_t r3 = 0;

    test_arm_store_le(words_n, 4, 0xffffffff);
    test_arm_store_le(words_n + 4, 4, 0x80000000);
    test_arm_store_le(words_n + 8, 4, 0x7fffffff);
    test_arm_store_le(words_n + 12, 4, 0x00000002);
    test_arm_store_le(words_m, 4, 0x00000001);
    test_arm_store_le(words_m + 4, 4, 0xffffffff);
    test_arm_store_le(words_m + 8, 4, 0x80000000);
    test_arm_store_le(words_m + 12, 4, 0x00000002);

    expected_p0 = test_arm_mve_expected_cmp_p0(bytes_n, bytes_m, 0, 1,
                                               false, false,
                                               TEST_ARM_MVE_CMP_EQ, 0xffff);
    test_arm_m55_mve_vcmp_run(0x0f04fe03, bytes_n, bytes_m, 0, 0,
                              expected_p0, false);

    expected_p0 = test_arm_mve_expected_cmp_p0(words_n, words_m, 0, 4,
                                               false, true,
                                               TEST_ARM_MVE_CMP_GE, 0xffff);
    test_arm_m55_mve_vcmp_run(0x1f04fe23, words_n, words_m, 0, 0,
                              expected_p0, false);

    expected_p0 = test_arm_mve_expected_cmp_p0(words_n, words_m, 0, 4,
                                               false, false,
                                               TEST_ARM_MVE_CMP_CS, 0xffff);
    test_arm_m55_mve_vcmp_run(0x0f05fe23, words_n, words_m, 0, 0,
                              expected_p0, false);

    expected_p0 = test_arm_mve_expected_cmp_p0(bytes_n, bytes_m, 0, 1,
                                               false, false,
                                               TEST_ARM_MVE_CMP_HI, 0xffff);
    test_arm_m55_mve_vcmp_run(0x0f85fe03, bytes_n, bytes_m, 0, 0,
                              expected_p0, false);

    expected_p0 = test_arm_mve_expected_cmp_p0(bytes_n, bytes_m, 0, 1,
                                               false, true,
                                               TEST_ARM_MVE_CMP_LT, 0xffff);
    test_arm_m55_mve_vcmp_run(0x1f84fe03, bytes_n, bytes_m, 0, 0,
                              expected_p0, false);

    expected_p0 = test_arm_mve_expected_cmp_p0(words_n, words_m, 0, 4,
                                               false, true,
                                               TEST_ARM_MVE_CMP_LE, 0xffff);
    test_arm_m55_mve_vcmp_run(0x1f85fe23, words_n, words_m, 0, 0,
                              expected_p0, false);

    memset(scalar_n, 0, sizeof(scalar_n));
    test_arm_store_le(scalar_n, 4, 0);
    test_arm_store_le(scalar_n + 4, 4, 1);
    test_arm_store_le(scalar_n + 8, 4, 0xffffffff);
    test_arm_store_le(scalar_n + 12, 4, 0);
    expected_p0 = test_arm_mve_expected_cmp_p0(scalar_n, NULL, 0, 4,
                                               true, false,
                                               TEST_ARM_MVE_CMP_EQ, 0xffff);
    test_arm_m55_mve_vcmp_run(0x0f4ffe23, scalar_n, NULL, 0, 0,
                              expected_p0, false);

    r3 = 0;
    test_arm_store_le(scalar_n + 12, 4, 0x80000000);
    expected_p0 = test_arm_mve_expected_cmp_p0(scalar_n, NULL, r3, 4,
                                               true, true,
                                               TEST_ARM_MVE_CMP_GT, 0xffff);
    test_arm_m55_mve_vcmp_run(0x1f63fe23, scalar_n, NULL, 0, r3,
                              expected_p0, false);

    r3 = 0x102;
    expected_p0 = test_arm_mve_expected_cmp_p0(bytes_n, NULL, r3, 1,
                                               true, false,
                                               TEST_ARM_MVE_CMP_HI, 0xffff);
    test_arm_m55_mve_vcmp_run(0x0fe3fe03, bytes_n, NULL, 0, r3,
                              expected_p0, false);

    memset(scalar_h, 0, sizeof(scalar_h));
    test_arm_store_le(scalar_h, 2, 0x8000);
    test_arm_store_le(scalar_h + 2, 2, 0x8001);
    test_arm_store_le(scalar_h + 4, 2, 0x8002);
    test_arm_store_le(scalar_h + 6, 2, 0x7fff);
    test_arm_store_le(scalar_h + 8, 2, 0);
    test_arm_store_le(scalar_h + 10, 2, 0xffff);
    test_arm_store_le(scalar_h + 12, 2, 1);
    test_arm_store_le(scalar_h + 14, 2, 0x9000);
    r3 = 0x8001;
    expected_p0 = test_arm_mve_expected_cmp_p0(scalar_h, NULL, r3, 2,
                                               true, true,
                                               TEST_ARM_MVE_CMP_LT, 0xffff);
    test_arm_m55_mve_vcmp_run(0x1fc3fe13, scalar_h, NULL, 0, r3,
                              expected_p0, false);

    expected_p0 = test_arm_mve_expected_cmp_p0(scalar_h, NULL, r3, 2,
                                               true, true,
                                               TEST_ARM_MVE_CMP_LE, 0xffff);
    test_arm_m55_mve_vcmp_run(0x1fe3fe13, scalar_h, NULL, 0, r3,
                              expected_p0, false);

    expected_p0 = test_arm_mve_expected_cmp_p0(bytes_n, bytes_m, 0, 1,
                                               false, false,
                                               TEST_ARM_MVE_CMP_NE, 0xffff);
    expected_vpr = 0x00aa0000 | expected_p0;
    test_arm_m55_mve_vcmp_run(0x4f84fe43, bytes_n, bytes_m, 0, 0,
                              expected_vpr, false);

    expected_p0 = test_arm_mve_expected_cmp_p0(bytes_n, bytes_m, 0, 1,
                                               false, false,
                                               TEST_ARM_MVE_CMP_NE, 0xffff);
    expected_vpr = 0x00000055 | (expected_p0 & 0xff00);
    test_arm_m55_mve_vcmp_run(0x0f84fe03, bytes_n, bytes_m, 0x00000055, 0,
                              expected_vpr, true);

    test_arm_m55_mve_2op_expect_error(0x0f20fe03, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f4dfe23, UC_CPU_ARM_CORTEX_M55,
                                      UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(0x0f04fe03, UC_CPU_ARM_CORTEX_M33,
                                      UC_ERR_EXCEPTION);
}

static uint32_t test_arm_mve_vcmp_fp_insn(uint32_t base, bool fp16,
                                          unsigned mask, unsigned qn,
                                          unsigned qm)
{
    uint32_t view = base;

    if (fp16) {
        view |= 1U << 28;
    }
    view |= ((mask >> 3) & 1) << 22;
    view |= (mask & 7) << 13;
    view |= (qn & 7) << 17;
    view |= ((qm >> 3) & 1) << 5;
    view |= (qm & 7) << 1;
    return test_arm_mve_view_to_t32(view);
}

static uint32_t test_arm_mve_vcmp_fp_scalar_insn(uint32_t base, bool fp16,
                                                 unsigned mask, unsigned qn,
                                                 unsigned rm)
{
    uint32_t view = base;

    if (fp16) {
        view |= 1U << 28;
    }
    view |= ((mask >> 3) & 1) << 22;
    view |= (mask & 7) << 13;
    view |= (qn & 7) << 17;
    view |= rm & 15;
    return test_arm_mve_view_to_t32(view);
}

static void test_arm_m55_mve_vcmp_fp_run(uint32_t insn, const uint8_t *n,
                                         const uint8_t *m,
                                         uint32_t initial_vpr, uint32_t r3,
                                         uint32_t expected_vpr, bool eci,
                                         bool expected_ioc)
{
    const uint32_t xpsr_t = 1U << 24;
    const uint32_t eci_a0a1 = 2U << 12;
    const uint32_t epsr_condexec_mask = 0xfc00 | (3U << 25);
    const uint32_t fpscr_ioc = 1U;
    uc_engine *uc;
    uint8_t code[8];
    uint64_t q1[2];
    uint64_t q2[2];
    uint32_t epsr;
    uint32_t fpscr = 0;
    uint32_t vpr;

    test_arm_emit32(code, 0, 0x0a10eeec);
    test_arm_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM,
                    UC_MODE_THUMB | UC_MODE_MCLASS,
                    (const char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_M55);
    test_arm_enable_vfp(uc);
    memcpy(q1, n, 16);
    if (m) {
        memcpy(q2, m, 16);
    } else {
        memset(q2, 0, sizeof(q2));
    }
    OK(uc_reg_write(uc, UC_ARM_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM_REG_Q2, q2));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &initial_vpr));
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &r3));
    OK(uc_reg_write(uc, UC_ARM_REG_FPSCR, &fpscr));

    if (eci) {
        OK(uc_emu_start(uc, code_start | 1, code_start + 4, 0, 0));
        epsr = xpsr_t | eci_a0a1;
        OK(uc_reg_write(uc, UC_ARM_REG_EPSR, &epsr));
        OK(uc_emu_start(uc, (code_start + 4) | 1,
                        code_start + sizeof(code), 0, 0));
    } else {
        OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0,
                        0));
    }

    OK(uc_reg_read(uc, UC_ARM_REG_VPR, &vpr));
    OK(uc_reg_read(uc, UC_ARM_REG_FPSCR, &fpscr));
    TEST_CHECK_(vpr == expected_vpr,
                "insn=0x%08x vpr=0x%08x expected=0x%08x",
                insn, vpr, expected_vpr);
    TEST_CHECK_(((fpscr & fpscr_ioc) != 0) == expected_ioc,
                "insn=0x%08x fpscr=0x%08x expected_ioc=%u",
                insn, fpscr, expected_ioc ? 1 : 0);
    if (eci) {
        OK(uc_reg_read(uc, UC_ARM_REG_EPSR, &epsr));
        TEST_CHECK_((epsr & epsr_condexec_mask) == 0,
                    "epsr=0x%08x", epsr);
    }
    OK(uc_close(uc));
}

static void test_arm_m55_mve_vcmp_fp(void)
{
    const uint32_t vcmpeq_base = 0xee310f00;
    const uint32_t vcmpne_base = 0xee310f80;
    const uint32_t vcmplt_base = 0xee311f80;
    const uint32_t vcmpgt_scalar_base = 0xee311f60;
    const uint32_t vcmple_scalar_base = 0xee311fe0;
    const uint8_t f32_eq_n[16] = {
        0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x00, 0x40,
        0x00, 0x00, 0x40, 0x40, 0x00, 0x00, 0x80, 0x40,
    };
    const uint8_t f32_eq_m[16] = {
        0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x40, 0x00, 0x00, 0xa0, 0x40,
    };
    const uint8_t f32_nan_n[16] = {
        0x00, 0x00, 0x80, 0x3f, 0x01, 0x00, 0x80, 0x7f,
        0x00, 0x00, 0x80, 0x40, 0x00, 0x00, 0xa0, 0x40,
    };
    const uint8_t f32_nan_m[16] = {
        0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x00, 0x40,
        0x00, 0x00, 0x80, 0x40, 0x00, 0x00, 0xc0, 0x40,
    };
    const uint8_t f16_scalar_n[16] = {
        0x00, 0xbc, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x40,
        0x00, 0xc0, 0x00, 0x42, 0x00, 0x38, 0x00, 0xb8,
    };
    const uint8_t f16_scalar_le_n[16] = {
        0x00, 0xbc, 0x01, 0x7c, 0x00, 0x00, 0x00, 0x3c,
        0x00, 0x80, 0x00, 0xc0, 0x00, 0x38, 0x00, 0x7c,
    };
    uint32_t insn;

    insn = test_arm_mve_vcmp_fp_insn(vcmpeq_base, false, 0, 1, 2);
    test_arm_m55_mve_vcmp_fp_run(insn, f32_eq_n, f32_eq_m, 0, 0,
                                 0x00000f0f, false, false);

    insn = test_arm_mve_vcmp_fp_insn(vcmpeq_base, false, 10, 1, 2);
    test_arm_m55_mve_vcmp_fp_run(insn, f32_eq_n, f32_eq_m, 0, 0,
                                 0x00aa0f0f, false, false);

    insn = test_arm_mve_vcmp_fp_insn(vcmpne_base, false, 0, 1, 2);
    test_arm_m55_mve_vcmp_fp_run(insn, f32_nan_n, f32_nan_m, 0, 0,
                                 0x0000f0f0, false, true);

    insn = test_arm_mve_vcmp_fp_insn(vcmplt_base, false, 0, 1, 2);
    test_arm_m55_mve_vcmp_fp_run(insn, f32_nan_n, f32_nan_m, 0, 0,
                                 0x0000f0f0, false, true);

    insn = test_arm_mve_vcmp_fp_scalar_insn(vcmpgt_scalar_base, true, 0,
                                            1, 15);
    test_arm_m55_mve_vcmp_fp_run(insn, f16_scalar_n, NULL, 0, 0,
                                 0x00003cf0, false, false);

    insn = test_arm_mve_vcmp_fp_scalar_insn(vcmple_scalar_base, true, 0,
                                            1, 3);
    test_arm_m55_mve_vcmp_fp_run(insn, f16_scalar_le_n, NULL, 0, 0,
                                 0x00000f3f, false, true);

    insn = test_arm_mve_vcmp_fp_insn(vcmpeq_base, false, 0, 1, 2);
    test_arm_m55_mve_vcmp_fp_run(insn, f32_eq_n, f32_eq_m, 0x00000055,
                                 0, 0x00000f55, true, false);

    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vcmp_fp_scalar_insn(vcmpgt_scalar_base, false, 0,
                                         1, 13),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vcmp_fp_insn(vcmpeq_base, false, 0, 1, 8),
        UC_CPU_ARM_CORTEX_M55, UC_ERR_EXCEPTION);
    test_arm_m55_mve_2op_expect_error(
        test_arm_mve_vcmp_fp_insn(vcmpeq_base, false, 0, 1, 2),
        UC_CPU_ARM_CORTEX_M33, UC_ERR_EXCEPTION);
}

//
// Some notes:
//   Qemu raise a special exception EXCP_EXCEPTION_EXIT to handle the
//   EXC_RETURN. We can't help user handle EXC_RETURN since unicorn is designed
//   not to handle any CPU exception.
//
static void test_arm_m_exc_return_hook_interrupt(uc_engine *uc, int intno,
                                                 void *data)
{
    int r_pc;

    OK(uc_reg_read(uc, UC_ARM_REG_PC, &r_pc));
    TEST_CHECK(intno == 8); // EXCP_EXCEPTION_EXIT: Return from v7M exception.
    TEST_CHECK((r_pc | 1) == 0xFFFFFFFD);
    OK(uc_emu_stop(uc));
}

static void test_arm_m_exc_return(void)
{
    uc_engine *uc;
    char code[] = "\x6f\xf0\x02\x00\x00\x47"; // mov r0, #0xFFFFFFFD; bx r0;
    int r_ipsr;
    int r_sp = 0x8000;
    uc_hook hook;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code,
                    sizeof(code) - 1, UC_CPU_ARM_CORTEX_M7);
    OK(uc_mem_map(uc, r_sp - 0x1000, 0x1000, UC_PROT_ALL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_INTR,
                   test_arm_m_exc_return_hook_interrupt, NULL, 0, 0));

    r_sp -= 0x1c;
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));

    r_ipsr = 16; // We are in whatever exception.
    OK(uc_reg_write(uc, UC_ARM_REG_IPSR, &r_ipsr));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0,
                    2)); // Just execute 2 instructions.

    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
}

// For details, see https://github.com/unicorn-engine/unicorn/issues/1494.
static void test_arm_und32_to_svc32(void)
{
    uc_engine *uc;
    // # MVN r0, #0
    // # MOVS pc, lr
    // # MVN r0, #0
    // # MVN r0, #0
    char code[] =
        "\x00\x00\xe0\xe3\x0e\xf0\xb0\xe1\x00\x00\xe0\xe3\x00\x00\xe0\xe3";
    int r_cpsr, r_sp, r_spsr, r_lr;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_A9));

    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    // https://www.keil.com/pack/doc/CMSIS/Core_A/html/group__CMSIS__CPSR__M.html
    r_cpsr = 0x40000093; // SVC32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_sp = 0x12345678;
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));

    r_cpsr = 0x4000009b; // UND32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_spsr = 0x40000093; // Save previous CPSR
    OK(uc_reg_write(uc, UC_ARM_REG_SPSR, &r_spsr));
    r_sp = 0xDEAD0000;
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));
    r_lr = code_start + 8;
    OK(uc_reg_write(uc, UC_ARM_REG_LR, &r_lr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 3));

    OK(uc_reg_read(uc, UC_ARM_REG_SP, &r_sp));

    TEST_CHECK(r_sp == 0x12345678);

    OK(uc_close(uc));
}

static void test_arm_usr32_to_svc32(void)
{
    uc_engine *uc;
    int r_cpsr, r_sp, r_spsr, r_lr;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_A9));

    // https://www.keil.com/pack/doc/CMSIS/Core_A/html/group__CMSIS__CPSR__M.html
    r_cpsr = 0x40000093; // SVC32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_sp = 0x12345678;
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));
    r_lr = 0x00102220;
    OK(uc_reg_write(uc, UC_ARM_REG_LR, &r_lr));

    r_cpsr = 0x4000009b; // UND32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_spsr = 0x40000093; // Save previous CPSR
    OK(uc_reg_write(uc, UC_ARM_REG_SPSR, &r_spsr));
    r_sp = 0xDEAD0000;
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));
    r_lr = 0x00509998;
    OK(uc_reg_write(uc, UC_ARM_REG_LR, &r_lr));

    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &r_cpsr));
    TEST_CHECK((r_cpsr & ((1 << 4) - 1)) == 0xb); // We are in UND32

    r_cpsr = 0x40000090; // USR32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_sp = 0x0010000;
    OK(uc_reg_write(uc, UC_ARM_REG_R13, &r_sp));
    r_lr = 0x0001234;
    OK(uc_reg_write(uc, UC_ARM_REG_LR, &r_lr));

    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &r_cpsr));
    TEST_CHECK((r_cpsr & ((1 << 4) - 1)) == 0); // We are in USR32

    r_cpsr = 0x40000093; // SVC32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));

    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &r_cpsr));
    OK(uc_reg_read(uc, UC_ARM_REG_SP, &r_sp));
    TEST_CHECK((r_cpsr & ((1 << 4) - 1)) == 3); // We are in SVC32
    TEST_CHECK(r_sp == 0x12345678);

    OK(uc_close(uc));
}

static void test_arm_v8(void)
{
    char code[] = "\xd0\xe8\xff\x17"; // LDAEXD.W R1, [R0]
    uc_engine *uc;
    uint32_t r_r1 = LEINT32(0xdeadbeef);
    uint32_t r_r0;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_M33);

    r_r0 = 0x8000;
    OK(uc_mem_map(uc, r_r0, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, r_r0, (void *)&r_r1, 4));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &r_r0));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r_r1));

    TEST_CHECK(r_r1 == 0xdeadbeef);

    OK(uc_close(uc));
}

static void test_arm_thumb_smlabb(void)
{
    char code[] = "\x13\xfb\x01\x23";
    uint32_t r_r1, r_r2, r_r3;
    uc_engine *uc;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_M7);

    r_r3 = 5;
    r_r1 = 7;
    r_r2 = 9;
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &r_r3));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r_r1));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r_r2));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R3, &r_r3));

    TEST_CHECK(r_r3 == 5 * 7 + 9);

    OK(uc_close(uc));
}

static void test_arm_not_allow_privilege_escalation(void)
{
    uc_engine *uc;
    int r_cpsr, r_sp, r_spsr, r_lr;
    // E3C6601F : BIC     r6, r6, #&1F
    // E3866013 : ORR     r6, r6, #&13
    // E121F006 : MSR     cpsr_c, r6 ; switch to SVC32 (should be ineffective
    // from USR32)
    // E1A00000 : MOV     r0,r0 EF000011 : SWI     OS_Exit
    char code[] = "\x1f\x60\xc6\xe3\x13\x60\x86\xe3\x06\xf0\x21\xe1\x00\x00\xa0"
                  "\xe1\x11\x00\x00\xef";

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);

    // https://www.keil.com/pack/doc/CMSIS/Core_A/html/group__CMSIS__CPSR.html
    r_cpsr = 0x40000013; // SVC32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_spsr = 0x40000013;
    OK(uc_reg_write(uc, UC_ARM_REG_SPSR, &r_spsr));
    r_sp = 0x12345678;
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));
    r_lr = 0x00102220;
    OK(uc_reg_write(uc, UC_ARM_REG_LR, &r_lr));

    r_cpsr = 0x40000010; // USR32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_sp = 0x0010000;
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));
    r_lr = 0x0001234;
    OK(uc_reg_write(uc, UC_ARM_REG_LR, &r_lr));

    uc_assert_err(
        UC_ERR_EXCEPTION,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_SP, &r_sp));
    OK(uc_reg_read(uc, UC_ARM_REG_LR, &r_lr));
    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &r_cpsr));

    TEST_CHECK((r_cpsr & ((1 << 4) - 1)) == 0); // Stay in USR32
    TEST_CHECK(r_lr == 0x1234);
    TEST_CHECK(r_sp == 0x10000);

    OK(uc_close(uc));
}

static void test_arm_mrc(void)
{
    uc_engine *uc;
    // mrc p15, #0, r1, c13, c0, #3
    char code[] = "\x1d\xee\x70\x1f";

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_MAX);

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static void test_arm_hflags_rebuilt(void)
{
    // MRS     r6, apsr
    // BIC     r6, r6, #&1F
    // ORR     r6, r6, #&10
    // MSR     cpsr_c, r6
    // SWI     OS_EnterOS
    // MSR     cpsr_c, r6
    char code[] = "\x00\x60\x0f\xe1\x1f\x60\xc6\xe3\x10\x60\x86\xe3\x06\xf0\x21"
                  "\xe1\x16\x00\x02\xef\x06\xf0\x21\xe1";
    uc_engine *uc;
    uint32_t r_cpsr, r_spsr, r_r13, r_r14, r_pc;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A9);

    r_cpsr = 0x40000013; // SVC32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_spsr = 0x40000013;
    OK(uc_reg_write(uc, UC_ARM_REG_SPSR, &r_spsr));
    r_r13 = 0x12345678; // SP
    OK(uc_reg_write(uc, UC_ARM_REG_R13, &r_r13));
    r_r14 = 0x00102220; // LR
    OK(uc_reg_write(uc, UC_ARM_REG_R14, &r_r14));

    r_cpsr = 0x40000010; // USR32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_r13 = 0x0010000; // SP
    OK(uc_reg_write(uc, UC_ARM_REG_R13, &r_r13));
    r_r14 = 0x0001234; // LR
    OK(uc_reg_write(uc, UC_ARM_REG_R14, &r_r14));

    uc_assert_err(
        UC_ERR_EXCEPTION,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    r_cpsr = 0x60000013;
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_cpsr = 0x60000010;
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_cpsr = 0x60000013;
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));

    OK(uc_reg_read(uc, UC_ARM_REG_PC, &r_pc));

    OK(uc_emu_start(uc, r_pc, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &r_cpsr));
    OK(uc_reg_read(uc, UC_ARM_REG_R13, &r_r13));
    OK(uc_reg_read(uc, UC_ARM_REG_R14, &r_r14));

    TEST_CHECK(r_cpsr == 0x60000010);
    TEST_CHECK(r_r13 == 0x00010000);
    TEST_CHECK(r_r14 == 0x00001234);

    OK(uc_close(uc));
}

static bool test_arm_mem_access_abort_hook_mem(uc_engine *uc, uc_mem_type type,
                                               uint64_t addr, int size,
                                               int64_t val, void *data)
{
    OK(uc_reg_read(uc, UC_ARM_REG_PC, data));
    return false;
}

static bool test_arm_mem_access_abort_hook_insn_invalid(uc_engine *uc,
                                                        void *data)
{
    OK(uc_reg_read(uc, UC_ARM_REG_PC, data));
    return false;
}

static void test_arm_mem_access_abort(void)
{
    // LDR     r0, [r0]
    // Undefined instruction
    char code[] = "\x00\x00\x90\xe5\x00\xa0\xf0\xf7";
    uc_engine *uc;
    uint32_t r_pc, r_r0, r_pc_in_hook;
    uc_hook hk, hkk;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A9);

    r_r0 = 0x990000;
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &r_r0));

    OK(uc_hook_add(uc, &hk, UC_HOOK_MEM_UNMAPPED,
                   test_arm_mem_access_abort_hook_mem, (void *)&r_pc_in_hook, 1,
                   0));
    OK(uc_hook_add(uc, &hkk, UC_HOOK_INSN_INVALID,
                   test_arm_mem_access_abort_hook_insn_invalid,
                   (void *)&r_pc_in_hook, 1, 0));

    uc_assert_err(UC_ERR_READ_UNMAPPED,
                  uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_PC, &r_pc));

    TEST_CHECK(r_pc == r_pc_in_hook);

    uc_assert_err(UC_ERR_INSN_INVALID,
                  uc_emu_start(uc, code_start + 4, code_start + 8, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_PC, &r_pc));

    TEST_CHECK(r_pc == r_pc_in_hook);

    uc_assert_err(UC_ERR_FETCH_UNMAPPED,
                  uc_emu_start(uc, 0x900000, 0x900000 + 8, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_PC, &r_pc));

    TEST_CHECK(r_pc == r_pc_in_hook);

    OK(uc_close(uc));
}

static void test_arm_read_sctlr(void)
{
    uc_engine *uc;
    uc_arm_cp_reg reg;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc));

    // SCTLR. See arm reference.
    reg.cp = 15;
    reg.is64 = 0;
    reg.sec = 0;
    reg.crn = 1;
    reg.crm = 0;
    reg.opc1 = 0;
    reg.opc2 = 0;

    OK(uc_reg_read(uc, UC_ARM_REG_CP_REG, &reg));

    TEST_CHECK((uint32_t)((reg.val >> 31) & 1) == 0);

    OK(uc_close(uc));
}

static void test_arm_be_cpsr_sctlr(void)
{
    uc_engine *uc;
    uc_arm_cp_reg reg;
    uint32_t cpsr;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(
        uc, UC_CPU_ARM_1176)); // big endian code, big endian data

    // SCTLR. See arm reference.
    reg.cp = 15;
    reg.is64 = 0;
    reg.sec = 0;
    reg.crn = 1;
    reg.crm = 0;
    reg.opc1 = 0;
    reg.opc2 = 0;

    OK(uc_reg_read(uc, UC_ARM_REG_CP_REG, &reg));
    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr));

    TEST_CHECK((reg.val & (1 << 7)) != 0);
    TEST_CHECK((cpsr & (1 << 9)) != 0);

    OK(uc_close(uc));

    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARMBE8, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_A15));

    // SCTLR. See arm reference.
    reg.cp = 15;
    reg.is64 = 0;
    reg.sec = 0;
    reg.crn = 1;
    reg.crm = 0;
    reg.opc1 = 0;
    reg.opc2 = 0;

    OK(uc_reg_read(uc, UC_ARM_REG_CP_REG, &reg));
    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr));

    // SCTLR.B == 0
    TEST_CHECK((reg.val & (1 << 7)) == 0);
    TEST_CHECK((cpsr & (1 << 9)) != 0);

    OK(uc_close(uc));
}

static void test_arm_switch_endian(void)
{
    uc_engine *uc;
    char code[] = "\x00\x00\x91\xe5"; // ldr r0, [r1]
    uint32_t r_r1 = (uint32_t)code_start;
    uint32_t r_r0, r_cpsr;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r_r1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));

    // Little endian
    TEST_CHECK(r_r0 == 0xe5910000);

    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_cpsr |= (1 << 9);
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));

    // Big endian
    TEST_CHECK(r_r0 == 0x000091e5);

    OK(uc_close(uc));
}

static void test_armeb_ldrb(void)
{
    uc_engine *uc;
    const char test_code[] = "\xe5\xd2\x10\x00"; // ldrb r1, [r2]
    uint64_t data_address = 0x800000;
    int r1 = 0x1234;
    int r2 = data_address;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_BIG_ENDIAN,
                    test_code, sizeof(test_code) - 1, UC_CPU_ARM_1176);

    OK(uc_mem_map(uc, data_address, 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, data_address, "\x66\x67\x68\x69", 4));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(test_code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r1));

    TEST_CHECK(r1 == 0x66);

    OK(uc_close(uc));
}

static void test_arm_context_save(void)
{
    uc_engine *uc;
    uc_engine *uc2;
    char code[] = "\x83\xb0"; // sub    sp, #0xc
    uc_context *ctx;
    uint32_t pc;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_R5);

    OK(uc_context_alloc(uc, &ctx));
    OK(uc_context_save(uc, ctx));
    OK(uc_context_reg_read(ctx, UC_ARM_REG_PC, (void *)&pc));
    OK(uc_context_reg_write(ctx, UC_ARM_REG_PC, (void *)&pc));
    OK(uc_context_restore(uc, ctx));

    uc_common_setup(&uc2, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A7); // Note the different CPU model

    OK(uc_context_restore(uc2, ctx));

    OK(uc_context_free(ctx));
    OK(uc_close(uc));
    OK(uc_close(uc2));
}

static void test_arm_thumb2(void)
{
    uc_engine *uc;
    // MOVS  R0, #0x24
    // AND.W R0, R0, #4
    char code[] = "\x24\x20\x00\xF0\x04\x00";
    uint32_t r_r0;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1, UC_CPU_ARM_CORTEX_R5);

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));

    TEST_CHECK(r_r0 == 0x4);

    OK(uc_close(uc));
}

static void test_armeb_be32_thumb2(void)
{
    uc_engine *uc;
    // MOVS  R0, #0x24
    // AND.W R0, R0, #4
    char code[] = "\x20\x24\xF0\x00\x00\x04";
    uint32_t r_r0;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1, UC_CPU_ARM_CORTEX_R5);

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));

    TEST_CHECK(r_r0 == 0x4);

    OK(uc_close(uc));
}

static bool test_arm_mem_read_write_cb(uc_engine *uc, int type,
                                       uint64_t address, int size,
                                       int64_t value, void *user_data)
{
    uint64_t *count = (uint64_t *)user_data;
    switch (type) {
    case UC_MEM_READ:
        count[0]++;
        break;
    case UC_MEM_WRITE:
        count[1]++;
        break;
    }

    return 0;
}
static void test_arm_mem_hook_read_write(void)
{
    uc_engine *uc;
    // ldr r1, [sp]
    // str r1, [sp, #4]
    // ldr r2, [sp, #4]
    // str r2, [sp]
    const char code[] =
        "\x00\x10\x9d\xe5\x04\x10\x8d\xe5\x04\x20\x9d\xe5\x00\x20\x8d\xe5";
    uint32_t r_sp;
    r_sp = 0x9000;
    uc_hook hk;
    uint64_t counter[2] = {0, 0};

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);

    uc_reg_write(uc, UC_ARM_REG_SP, &r_sp);
    uc_mem_map(uc, 0x8000, 1024 * 16, UC_PROT_ALL);

    OK(uc_hook_add(uc, &hk, UC_HOOK_MEM_READ, test_arm_mem_read_write_cb,
                   counter, 1, 0));
    OK(uc_hook_add(uc, &hk, UC_HOOK_MEM_WRITE, test_arm_mem_read_write_cb,
                   counter, 1, 0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    TEST_CHECK(counter[0] == 2 && counter[1] == 2);
    OK(uc_close(uc));
}

static void test_arm_thumb_it_mem_read_cb(uc_engine *uc, uc_mem_type type,
                                          uint64_t address, int size,
                                          int64_t value, void *user_data)
{
    uint64_t *count = (uint64_t *)user_data;

    (void)uc;
    (void)type;
    (void)address;
    (void)size;
    (void)value;

    (*count)++;
}

static void test_arm_thumb_it_mem_hook(void)
{
    uc_engine *uc;
    uc_hook hk;
    uint8_t code[] = {
        0x00, 0x28, /* cmp r0, #0 */
        0x1c, 0xbf, /* itt ne */
        0x11, 0x68, /* ldrne r1, [r2] */
        0x00, 0x29, /* cmpne r1, #0 */
        0x00, 0xe0, /* b.n #0x100c */
        0x00, 0xbf, /* nop */
        0x03, 0x2c, /* cmp r4, #3 */
        0x00, 0xd3, /* bcc #0x1012 */
        0x01, 0x23, /* movs r3, #1 */
        0x02, 0x23, /* movs r3, #2 */
    };
    uint32_t r0 = 1;
    uint32_t r1 = 0;
    uint32_t r2 = code_start + 0x200;
    uint32_t r3 = 0;
    uint32_t r4 = 1;
    uint32_t data = LEINT32(1);
    uint64_t count = 0;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS,
                    (char *)code, sizeof(code), UC_CPU_ARM_CORTEX_M7);

    OK(uc_mem_write(uc, r2, &data, sizeof(data)));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &r0));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r1));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r2));
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &r3));
    OK(uc_reg_write(uc, UC_ARM_REG_R4, &r4));

    OK(uc_hook_add(uc, &hk, UC_HOOK_MEM_READ,
                   test_arm_thumb_it_mem_read_cb, &count, 1, 0));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R3, &r3));
    TEST_CHECK(r3 == 2);
    TEST_CHECK(count == 1);

    OK(uc_close(uc));
}

typedef struct {
    uint64_t v0;
    uint64_t v1;
    uint64_t size;
    uint64_t pc;
} _last_cmp_info;

static void _uc_hook_sub_cmp(uc_engine *uc, uint64_t address, uint64_t arg1,
                             uint64_t arg2, uint32_t size,
                             _last_cmp_info *user_data)
{
    user_data->pc = address;
    user_data->size = size;
    user_data->v0 = arg1;
    user_data->v1 = arg2;
}

static void test_arm_tcg_opcode_cmp(void)
{
    uc_engine *uc;
    const char code[] = "\x04\x00\x9f\xe5" // ldr   r0, [pc, #4]
                        "\x04\x10\x9f\xe5" // ldr   r1, [pc, #4]
                        "\x01\x00\x50\xe1" // cmp   r0, r1
                        "\x05\x00\x00\x00" // (5)
                        "\x03\x00\x00\x00" // (3)
        ;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);

    uc_hook hook;
    _last_cmp_info cmp_info = {0};

    OK(uc_hook_add(uc, &hook, UC_HOOK_TCG_OPCODE, (void *)_uc_hook_sub_cmp,
                   (void *)&cmp_info, 1, 0, UC_TCG_OP_SUB, UC_TCG_OP_FLAG_CMP));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 3));
    TEST_CHECK(cmp_info.v0 == 5 && cmp_info.v1 == 3);
    TEST_CHECK(cmp_info.pc == 0x1008);
    TEST_CHECK(cmp_info.size == 32);
    OK(uc_close(uc));
}

static void test_arm_thumb_tcg_opcode_cmn(void)
{
    uc_engine *uc;
    const char code[] = "\x01\x48"         // ldr  r0, [pc, #4]
                        "\x02\x49"         // ldr  r1, [pc, #8]
                        "\x00\xbf"         // nop
                        "\xc8\x42"         // cmn  r0, r1
                        "\x05\x00\x00\x00" // (5)
                        "\x03\x00\x00\x00" // (3)
        ;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);

    uc_hook hook;
    _last_cmp_info cmp_info = {0};

    OK(uc_hook_add(uc, &hook, UC_HOOK_TCG_OPCODE, (void *)_uc_hook_sub_cmp,
                   (void *)&cmp_info, 1, 0, UC_TCG_OP_SUB, UC_TCG_OP_FLAG_CMP));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 4));
    TEST_CHECK(cmp_info.v0 == 5 && cmp_info.v1 == 3);
    TEST_CHECK(cmp_info.pc == 0x1006);
    TEST_CHECK(cmp_info.size == 32);
    OK(uc_close(uc));
}

static void test_arm_cp15_c1_c0_2(void)
{
    uc_engine *uc;
    uint32_t val = 0x12345678;
    uint32_t read_val;

    // Initialize emulator in ARM mode
    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_A15));

    // Write to CP15 C1_C0_2
    OK(uc_reg_write(uc, UC_ARM_REG_C1_C0_2, &val));

    // Read from CP15 C1_C0_2
    OK(uc_reg_read(uc, UC_ARM_REG_C1_C0_2, &read_val));

    TEST_CHECK(read_val == val);

    OK(uc_close(uc));
}

static void test_arm_mrrc_cp15_c15_1_cpu(uc_cpu_arm cpu)
{
    uc_engine *uc;
    uc_arm_cp_reg reg = {
        .cp = 15,
        .is64 = 1,
        .sec = 0,
        .crm = 15,
        .opc1 = 1,
        .val = 0x0123456789abcdefULL,
    };
    const char code[] = "\x1f\x1f\x40\xec"
                        "\x1f\x1f\x50\xec";
    uint32_t r0 = 0x76543210;
    uint32_t r1 = 0x89abcdef;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    cpu);

    OK(uc_reg_write(uc, UC_ARM_REG_R0, &r0));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r1));
    OK(uc_reg_write(uc, UC_ARM_REG_CP_REG, &reg));
    OK(uc_reg_read(uc, UC_ARM_REG_CP_REG, &reg));
    TEST_CHECK(reg.val == 0);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r1));

    TEST_CHECK(r0 == 0);
    TEST_CHECK(r1 == 0);

    OK(uc_close(uc));
}

static void test_arm_mrrc_cp15_c15_1(void)
{
    test_arm_mrrc_cp15_c15_1_cpu(UC_CPU_ARM_CORTEX_A9);
    test_arm_mrrc_cp15_c15_1_cpu(UC_CPU_ARM_CORTEX_A15);
    test_arm_mrrc_cp15_c15_1_cpu(UC_CPU_ARM_MAX);
}

static bool test_arm_v7_lpae_hook_tlb(uc_engine *uc, uint64_t addr,
                                      uc_mem_type type, uc_tlb_entry *result,
                                      void *user_data)
{
    result->paddr = addr + 0x100000000;
    result->perms = UC_PROT_ALL;
    return 1;
}

static void test_arm_v7_lpae_hook_read(uc_engine *uc, uc_mem_type type,
                                       uint64_t address, int size,
                                       uint64_t value, void *user_data)
{
    TEST_CHECK(address == 0x100001000);
}

static void test_arm_v7_lpae(void)
{
    uc_engine *uc;
    uc_hook hook_read, hook_tlb;
    uint32_t reg;
    char code[] = "\x00\x10\x90\xe5"; // ldr r1, [r0]
    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_A7));

    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_hook_add(uc, &hook_tlb, UC_HOOK_TLB_FILL, test_arm_v7_lpae_hook_tlb,
                   NULL, 1, 0));
    OK(uc_hook_add(uc, &hook_read, UC_HOOK_MEM_READ, test_arm_v7_lpae_hook_read,
                   NULL, 1, 0));

    reg = 0x1000;
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &reg));
    OK(uc_mem_map(uc, 0x100001000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x100001000, code, sizeof(code)));
    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &reg));
    TEST_CHECK(reg == 0xe5901000);

    OK(uc_close(uc));
}

static void test_arm_svc_interrupt(uc_engine *uc, int intno, void *user_data)
{
    uint32_t esr;
    OK(uc_reg_read(uc, UC_ARM_REG_ESR, &esr));
    switch (intno) {
    // SVC
    case 2:
        TEST_CHECK((esr & 0xff) == 0x42);
        break;
    // HVC
    case 3:
        TEST_CHECK((esr & 0xff) == 0x33);
        break;
    }
}

static void test_arm_svc_hvc_syndrome(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x42, 0x00, 0x00, 0xef, // svc #0x42
        0x73, 0x03, 0x40, 0xe1, // hvc #0x33
    };

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, (char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_A15);

    uc_hook hook;
    OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_arm_svc_interrupt, NULL, 1,
                   0));

    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_close(uc));
}

static int test_arm_hook_insn_wfi_callback(uc_engine *uc, void *user_data)
{
    WFI_HOOK_INSN_RESULT *result = (WFI_HOOK_INSN_RESULT *)user_data;
    result->called = true;
    return 0;
}

static void test_arm_hook_insn_wfi(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\x30\xbf";
    WFI_HOOK_INSN_RESULT result = {false};

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);
    OK(uc_hook_add(uc, &hook, UC_HOOK_INSN, test_arm_hook_insn_wfi_callback, &result, 1, 0,
                   UC_ARM_INS_WFI));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));
    TEST_CHECK(result.called == true);

    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
}

TEST_LIST = {{"test_arm_nop", test_arm_nop},
             {"test_arm_thumb_sub", test_arm_thumb_sub},
             {"test_armeb_sub", test_armeb_sub},
             {"test_armeb_be8_sub", test_armeb_be8_sub},
             {"test_arm_thumbeb_sub", test_arm_thumbeb_sub},
             {"test_arm_thumb_ite", test_arm_thumb_ite},
             {"test_arm_m_thumb_mrs", test_arm_m_thumb_mrs},
             {"test_arm_i8mm", test_arm_i8mm},
             {"test_arm_bf16", test_arm_bf16},
             {"test_arm_m_control", test_arm_m_control},
             {"test_arm_m55_mve_id", test_arm_m55_mve_id},
             {"test_arm_m55_vpr_public_reg", test_arm_m55_vpr_public_reg},
             {"test_arm_m55_vpr_sysreg", test_arm_m55_vpr_sysreg},
             {"test_arm_m55_fpscr_ltpsize", test_arm_m55_fpscr_ltpsize},
             {"test_arm_m55_fpscr_nzcvqc_sysreg",
              test_arm_m55_fpscr_nzcvqc_sysreg},
             {"test_arm_m55_vlstm_lazy_preserve",
              test_arm_m55_vlstm_lazy_preserve},
             {"test_arm_m55_vlstm_lazy_fault",
              test_arm_m55_vlstm_lazy_fault},
             {"test_arm_m55_sysreg_mem", test_arm_m55_sysreg_mem},
             {"test_arm_m55_vscclrm", test_arm_m55_vscclrm},
             {"test_arm_m55_vctp", test_arm_m55_vctp},
             {"test_arm_m55_mve_eci", test_arm_m55_mve_eci},
             {"test_arm_m55_vpst_vpnot", test_arm_m55_vpst_vpnot},
             {"test_arm_m55_mve_logic", test_arm_m55_mve_logic},
             {"test_arm_m55_mve_add_sub", test_arm_m55_mve_add_sub},
             {"test_arm_m55_mve_scalar_2op", test_arm_m55_mve_scalar_2op},
             {"test_arm_m55_mve_vbrsr", test_arm_m55_mve_vbrsr},
             {"test_arm_m55_mve_scalar_halving_sat",
              test_arm_m55_mve_scalar_halving_sat},
             {"test_arm_m55_mve_mulh", test_arm_m55_mve_mulh},
             {"test_arm_m55_mve_vmull", test_arm_m55_mve_vmull},
             {"test_arm_m55_mve_minmax", test_arm_m55_mve_minmax},
             {"test_arm_m55_mve_vabd", test_arm_m55_mve_vabd},
             {"test_arm_m55_mve_halving", test_arm_m55_mve_halving},
             {"test_arm_m55_mve_qaddsub", test_arm_m55_mve_qaddsub},
             {"test_arm_m55_mve_shift", test_arm_m55_mve_shift},
             {"test_arm_m55_mve_qdmulh", test_arm_m55_mve_qdmulh},
             {"test_arm_m55_mve_qdmladh", test_arm_m55_mve_qdmladh},
             {"test_arm_m55_mve_qdmull", test_arm_m55_mve_qdmull},
             {"test_arm_m55_mve_scalar_qdmull",
              test_arm_m55_mve_scalar_qdmull},
             {"test_arm_m55_mve_scalar_acc",
              test_arm_m55_mve_scalar_acc},
             {"test_arm_m55_mve_carry", test_arm_m55_mve_carry},
             {"test_arm_m55_mve_fp_scalar",
              test_arm_m55_mve_fp_scalar},
             {"test_arm_m55_mve_cadd", test_arm_m55_mve_cadd},
             {"test_arm_m55_mve_vimm", test_arm_m55_mve_vimm},
             {"test_arm_m55_mve_shift_imm", test_arm_m55_mve_shift_imm},
             {"test_arm_m55_mve_scalar_shift",
              test_arm_m55_mve_scalar_shift},
             {"test_arm_m55_mve_gpr_shift",
              test_arm_m55_mve_gpr_shift},
             {"test_arm_m55_mve_qshift_imm", test_arm_m55_mve_qshift_imm},
             {"test_arm_m55_mve_vshll", test_arm_m55_mve_vshll},
             {"test_arm_m55_mve_shrn_imm", test_arm_m55_mve_shrn_imm},
             {"test_arm_m55_mve_qshrn_imm", test_arm_m55_mve_qshrn_imm},
             {"test_arm_m55_mve_movn", test_arm_m55_mve_movn},
             {"test_arm_m55_mve_reduce", test_arm_m55_mve_reduce},
             {"test_arm_m55_mve_dualacc", test_arm_m55_mve_dualacc},
             {"test_arm_m55_mve_vshlc", test_arm_m55_mve_vshlc},
             {"test_arm_m55_mve_vdup", test_arm_m55_mve_vdup},
             {"test_arm_m55_mve_vmov_2gp", test_arm_m55_mve_vmov_2gp},
             {"test_arm_m55_mve_vidup", test_arm_m55_mve_vidup},
             {"test_arm_m55_mve_1op", test_arm_m55_mve_1op},
             {"test_arm_m55_mve_fp_convert_round",
              test_arm_m55_mve_fp_convert_round},
             {"test_arm_m55_mve_fp_vector", test_arm_m55_mve_fp_vector},
             {"test_arm_m55_mve_vldrw_vstrw", test_arm_m55_mve_vldrw_vstrw},
             {"test_arm_m55_mve_vldrbh_vstrbh",
              test_arm_m55_mve_vldrbh_vstrbh},
             {"test_arm_m55_mve_vldst_widen_narrow",
              test_arm_m55_mve_vldst_widen_narrow},
             {"test_arm_m55_mve_sg", test_arm_m55_mve_sg},
             {"test_arm_m55_mve_sg_imm", test_arm_m55_mve_sg_imm},
             {"test_arm_m55_mve_interleaved",
              test_arm_m55_mve_interleaved},
             {"test_arm_m55_vpsel", test_arm_m55_vpsel},
             {"test_arm_m55_mve_vcmp", test_arm_m55_mve_vcmp},
             {"test_arm_m55_mve_vcmp_fp", test_arm_m55_mve_vcmp_fp},
             {"test_arm_m_exc_return", test_arm_m_exc_return},
             {"test_arm_und32_to_svc32", test_arm_und32_to_svc32},
             {"test_arm_usr32_to_svc32", test_arm_usr32_to_svc32},
             {"test_arm_v8", test_arm_v8},
             {"test_arm_thumb_smlabb", test_arm_thumb_smlabb},
             {"test_arm_not_allow_privilege_escalation",
              test_arm_not_allow_privilege_escalation},
             {"test_arm_mrc", test_arm_mrc},
             {"test_arm_hflags_rebuilt", test_arm_hflags_rebuilt},
             {"test_arm_mem_access_abort", test_arm_mem_access_abort},
             {"test_arm_read_sctlr", test_arm_read_sctlr},
             {"test_arm_be_cpsr_sctlr", test_arm_be_cpsr_sctlr},
             {"test_arm_switch_endian", test_arm_switch_endian},
             {"test_armeb_ldrb", test_armeb_ldrb},
             {"test_arm_context_save", test_arm_context_save},
             {"test_arm_thumb2", test_arm_thumb2},
             {"test_armeb_be32_thumb2", test_armeb_be32_thumb2},
             {"test_arm_mem_hook_read_write", test_arm_mem_hook_read_write},
             {"test_arm_thumb_it_mem_hook", test_arm_thumb_it_mem_hook},
             {"test_arm_tcg_opcode_cmp", test_arm_tcg_opcode_cmp},
             {"test_arm_thumb_tcg_opcode_cmn", test_arm_thumb_tcg_opcode_cmn},
             {"test_arm_cp15_c1_c0_2", test_arm_cp15_c1_c0_2},
             {"test_arm_mrrc_cp15_c15_1", test_arm_mrrc_cp15_c15_1},
             {"test_arm_v7_lpae", test_arm_v7_lpae},
             {"test_arm_svc_hvc_syndrome", test_arm_svc_hvc_syndrome},
             {"test_arm_hook_insn_wfi", test_arm_hook_insn_wfi},
             {NULL, NULL}};
