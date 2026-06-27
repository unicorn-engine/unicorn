#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;
const uint64_t s390x_data_start = 0x2000;
const uint64_t s390x_cr0_vector_afp = 0x0000000000060000ull;

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static void s390x_check_bytes(const char *name, const uint8_t *actual,
                              const uint8_t *expected, size_t size);

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

static void run_logic_case(const uint8_t code[4], uint64_t r1,
                           uint64_t r2, uint64_t r3,
                           uint64_t expected_r1, uint32_t expected_cc)
{
    uc_engine *uc;
    uint64_t pswm;

    OK(uc_open(UC_ARCH_S390X, UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_S390X_GEN15A));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, 4));
    OK(uc_reg_write(uc, UC_S390X_REG_R4, &r1));
    OK(uc_reg_write(uc, UC_S390X_REG_R2, &r2));
    OK(uc_reg_write(uc, UC_S390X_REG_R3, &r3));

    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_S390X_REG_R4, &r1));
    OK(uc_reg_read(uc, UC_S390X_REG_PSWM, &pswm));
    TEST_CHECK(r1 == expected_r1);
    TEST_CHECK(((pswm >> 44) & 3) == expected_cc);

    OK(uc_close(uc));
}

static void test_s390x_mie3_logic(void)
{
    const uint8_t ncrk[] = "\xb9\xf5\x30\x42";
    const uint8_t nnrk[] = "\xb9\x74\x30\x42";
    const uint8_t nork[] = "\xb9\x76\x30\x42";
    const uint8_t nxrk[] = "\xb9\x77\x30\x42";
    const uint8_t ocrk[] = "\xb9\x75\x30\x42";
    const uint8_t ncgrk[] = "\xb9\xe5\x30\x42";
    const uint8_t nngrk[] = "\xb9\x64\x30\x42";
    const uint8_t nogrk[] = "\xb9\x66\x30\x42";
    const uint8_t nxgrk[] = "\xb9\x67\x30\x42";
    const uint8_t ocgrk[] = "\xb9\x65\x30\x42";
    const uint64_t high = 0xaaaaaaaa00000000ull;

    run_logic_case(ncrk, high, 0xf0, 0x0f, high | 0xf0, 1);
    run_logic_case(nnrk, high, 0xf0f0, 0x0ff0, high | 0xffffff0f, 1);
    run_logic_case(nork, high, 0xffffffff, 0, high, 0);
    run_logic_case(nxrk, high, 0x12345678, 0x12345678,
                   high | 0xffffffff, 1);
    run_logic_case(ocrk, high, 0x00f0, 0x0ff0, high | 0xfffff0ff, 1);
    run_logic_case(ncgrk, 0, 0xff00ff00ff00ff00ull,
                   0x00ff00ff00ff00ffull, 0xff00ff00ff00ff00ull, 1);
    run_logic_case(nngrk, 0, 0xffff0000ffff0000ull,
                   0x00ff00ff00ff00ffull, 0xff00ffffff00ffffull, 1);
    run_logic_case(nogrk, 0, 0xffffffffffffffffull, 0, 0, 0);
    run_logic_case(nxgrk, 0, 0x123456789abcdef0ull,
                   0x123456789abcdef0ull, 0xffffffffffffffffull, 1);
    run_logic_case(ocgrk, 0, 0x00000000000000f0ull,
                   0x0000000000000ff0ull, 0xfffffffffffff0ffull, 1);
}

static void run_select_case(const uint8_t code[6], uint64_t r1,
                            uint64_t r2, uint64_t r3,
                            uint64_t expected_r1)
{
    uc_engine *uc;

    OK(uc_open(UC_ARCH_S390X, UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_S390X_GEN15A));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, 6));
    OK(uc_reg_write(uc, UC_S390X_REG_R4, &r1));
    OK(uc_reg_write(uc, UC_S390X_REG_R2, &r2));
    OK(uc_reg_write(uc, UC_S390X_REG_R3, &r3));

    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    OK(uc_reg_read(uc, UC_S390X_REG_R4, &r1));
    TEST_CHECK(r1 == expected_r1);

    OK(uc_close(uc));
}

static void test_s390x_mie3_select(void)
{
    const uint8_t selr_true[] = "\x12\x00\xb9\xf0\x38\x42";
    const uint8_t selr_false[] = "\x12\x00\xb9\xf0\x34\x42";
    const uint8_t selgr_true[] = "\x12\x00\xb9\xe3\x38\x42";
    const uint8_t selgr_false[] = "\x12\x00\xb9\xe3\x34\x42";
    const uint8_t selfhr_true[] = "\x12\x00\xb9\xc0\x38\x42";
    const uint8_t selfhr_false[] = "\x12\x00\xb9\xc0\x34\x42";
    const uint64_t r1 = 0xaaaabbbbccccddddull;
    const uint64_t r2 = 0x1111222233334444ull;
    const uint64_t r3 = 0x5555666677778888ull;

    run_select_case(selr_true, r1, r2, r3, 0xaaaabbbb33334444ull);
    run_select_case(selr_false, r1, r2, r3, 0xaaaabbbb77778888ull);
    run_select_case(selgr_true, r1, r2, r3, r2);
    run_select_case(selgr_false, r1, r2, r3, r3);
    run_select_case(selfhr_true, r1, r2, r3, 0x11112222ccccddddull);
    run_select_case(selfhr_false, r1, r2, r3, 0x55556666ccccddddull);
}

static void test_s390x_locfhr(void)
{
    const uint8_t locfhr_true[] = "\x12\x00\xb9\xe0\x80\x42";
    const uint8_t locfhr_false[] = "\x12\x00\xb9\xe0\x40\x42";
    const uint64_t r1 = 0x1111111122222222ull;
    const uint64_t r2 = 0x3333333344444444ull;

    run_select_case(locfhr_true, r1, r2, 0, 0x3333333322222222ull);
    run_select_case(locfhr_false, r1, r2, 0, r1);
}

static uint64_t s390x_pack_bytes(const uint8_t *bytes)
{
    uint64_t value = 0;
    int i;

    for (i = 0; i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

static void s390x_unpack_bytes(uint64_t value, uint8_t *bytes)
{
    int i;

    for (i = 7; i >= 0; i--) {
        bytes[i] = value;
        value >>= 8;
    }
}

static uint32_t s390x_read_cc(uc_engine *uc)
{
    uint64_t pswm;

    OK(uc_reg_read(uc, UC_S390X_REG_PSWM, &pswm));
    return (pswm >> 44) & 3;
}

static void run_s390x_chrl_case(const uint8_t code[6],
                                const uint8_t data[8], uint64_t r4,
                                uint32_t expected_cc)
{
    uc_engine *uc;

    OK(uc_open(UC_ARCH_S390X, UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_S390X_GEN15A));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, 6));
    OK(uc_mem_write(uc, s390x_data_start, data, 8));
    OK(uc_reg_write(uc, UC_S390X_REG_R4, &r4));

    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    TEST_CHECK(s390x_read_cc(uc) == expected_cc);

    OK(uc_close(uc));
}

static void test_s390x_compare_halfword_relative_long(void)
{
    const uint8_t chrl[] = { 0xc6, 0x45, 0x00, 0x00, 0x08, 0x00 };
    const uint8_t cghrl[] = { 0xc6, 0x44, 0x00, 0x00, 0x08, 0x00 };
    const uint8_t wide_positive[] = {
        0x7f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t signed_negative[] = {
        0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    uint64_t r4;

    r4 = 100000;
    run_s390x_chrl_case(chrl, wide_positive, r4, 2);
    run_s390x_chrl_case(cghrl, wide_positive, r4, 2);

    r4 = 0;
    run_s390x_chrl_case(chrl, signed_negative, r4, 2);
    run_s390x_chrl_case(cghrl, signed_negative, r4, 2);
}

static void run_s390x_clgit_case(const uint8_t code[6])
{
    uc_engine *uc;
    uint64_t r4 = 0x8000;

    OK(uc_open(UC_ARCH_S390X, UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_S390X_GEN15A));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, 6));
    OK(uc_reg_write(uc, UC_S390X_REG_R4, &r4));

    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    OK(uc_close(uc));
}

static void test_s390x_compare_logical_immediate_trap(void)
{
    const uint8_t clfit[] = { 0xec, 0x40, 0x80, 0x00, 0x40, 0x73 };
    const uint8_t clgit[] = { 0xec, 0x40, 0x80, 0x00, 0x40, 0x71 };

    run_s390x_clgit_case(clfit);
    run_s390x_clgit_case(clgit);
}

static void s390x_setup_scalar_case(uc_engine **uc, const uint8_t *code,
                                    size_t code_size)
{
    OK(uc_open(UC_ARCH_S390X, UC_MODE_BIG_ENDIAN, uc));
    OK(uc_ctl_set_cpu_model(*uc, UC_CPU_S390X_GEN15A));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, code_size));
}

static void test_s390x_mie2_add_sub_halfword(void)
{
    const uint8_t code[] = {
        0xe3, 0x40, 0x20, 0x00, 0x00, 0x38,
        0xe3, 0x40, 0x20, 0x02, 0x00, 0x39,
    };
    const uint8_t data[] = { 0xff, 0xfe, 0x00, 0x04 };
    uc_engine *uc;
    uint64_t r2 = s390x_data_start;
    uint64_t r4 = 5;

    s390x_setup_scalar_case(&uc, code, sizeof(code));
    OK(uc_mem_write(uc, s390x_data_start, data, sizeof(data)));
    OK(uc_reg_write(uc, UC_S390X_REG_R2, &r2));
    OK(uc_reg_write(uc, UC_S390X_REG_R4, &r4));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_S390X_REG_R4, &r4));
    TEST_CHECK(r4 == UINT64_MAX);
    TEST_CHECK(s390x_read_cc(uc) == 1);

    OK(uc_close(uc));
}

static void test_s390x_mie2_branch_indirect(void)
{
    const uint8_t code[] = {
        0xe3, 0x80, 0x20, 0x00, 0x00, 0x47,
        0xa7, 0x49, 0x00, 0x01,
    };
    uint8_t target[8];
    uc_engine *uc;
    uint64_t r2 = s390x_data_start;
    uint64_t r4 = 0x1234;

    s390x_unpack_bytes(code_start + sizeof(code), target);
    s390x_setup_scalar_case(&uc, code, sizeof(code));
    OK(uc_mem_write(uc, s390x_data_start, target, sizeof(target)));
    OK(uc_reg_write(uc, UC_S390X_REG_R2, &r2));
    OK(uc_reg_write(uc, UC_S390X_REG_R4, &r4));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_S390X_REG_R4, &r4));
    TEST_CHECK(r4 == 0x1234);

    OK(uc_close(uc));
}

static void test_s390x_lzrf(void)
{
    const uint8_t lzrf[] = { 0xe3, 0x40, 0x20, 0x00, 0x00, 0x3b };
    const uint8_t value[] = { 0x12, 0x34, 0x56, 0x78 };
    uc_engine *uc;
    uint64_t r2 = s390x_data_start;
    uint64_t r4 = 0xaaaaaaaa55555555ull;

    s390x_setup_scalar_case(&uc, lzrf, sizeof(lzrf));
    OK(uc_mem_write(uc, s390x_data_start, value, sizeof(value)));
    OK(uc_reg_write(uc, UC_S390X_REG_R2, &r2));
    OK(uc_reg_write(uc, UC_S390X_REG_R4, &r4));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(lzrf), 0, 0));

    OK(uc_reg_read(uc, UC_S390X_REG_R4, &r4));
    TEST_CHECK(r4 == 0xaaaaaaaa12345600ull);
    OK(uc_close(uc));
}

static void test_s390x_monitor_call(void)
{
    const uint8_t mc_disabled[] = {
        0xaf, 0x00, 0x20, 0x00,
        0xa7, 0x49, 0x00, 0x7b,
    };
    const uint8_t mc_invalid_class[] = { 0xaf, 0x10, 0x20, 0x00 };
    const uint8_t mc_enabled[] = { 0xaf, 0x00, 0x20, 0x00 };
    const uint8_t expected_class[] = { 0x00, 0x00 };
    const uint8_t expected_code[] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x20, 0x00,
    };
    uint8_t actual_class[sizeof(expected_class)];
    uint8_t actual_code[sizeof(expected_code)];
    uc_engine *uc;
    uint64_t r2 = s390x_data_start;
    uint64_t r4 = 0;
    uint64_t cr8 = 0x8000;

    s390x_setup_scalar_case(&uc, mc_disabled, sizeof(mc_disabled));
    OK(uc_reg_write(uc, UC_S390X_REG_R2, &r2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(mc_disabled),
                    0, 0));

    OK(uc_reg_read(uc, UC_S390X_REG_R4, &r4));
    TEST_CHECK(r4 == 123);
    OK(uc_close(uc));

    s390x_setup_scalar_case(&uc, mc_invalid_class,
                            sizeof(mc_invalid_class));
    OK(uc_reg_write(uc, UC_S390X_REG_R2, &r2));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start,
                               code_start + sizeof(mc_invalid_class), 0, 0));
    OK(uc_close(uc));

    s390x_setup_scalar_case(&uc, mc_enabled, sizeof(mc_enabled));
    OK(uc_mem_map(uc, 0, 0x1000, UC_PROT_ALL));
    OK(uc_reg_write(uc, UC_S390X_REG_R2, &r2));
    OK(uc_reg_write(uc, UC_S390X_REG_CR8, &cr8));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start,
                               code_start + sizeof(mc_enabled), 0, 0));
    OK(uc_mem_read(uc, 0x94, actual_class, sizeof(actual_class)));
    OK(uc_mem_read(uc, 0xb0, actual_code, sizeof(actual_code)));
    s390x_check_bytes("mc_class", actual_class, expected_class,
                      sizeof(actual_class));
    s390x_check_bytes("mc_code", actual_code, expected_code,
                      sizeof(actual_code));
    OK(uc_close(uc));
}

static void test_s390x_mie3_move_right_to_left(void)
{
    const uint8_t mvcrl[] = { 0xe5, 0x0a, 0x20, 0x01, 0x30, 0x00 };
    const uint8_t input[] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };
    const uint8_t expected[] = {
        0x10, 0x10, 0x11, 0x12, 0x13, 0x14, 0x16, 0x17,
    };
    uint8_t actual[sizeof(input)];
    uc_engine *uc;
    size_t i;
    uint64_t r0 = 4;
    uint64_t r2 = s390x_data_start;
    uint64_t r3 = s390x_data_start;

    s390x_setup_scalar_case(&uc, mvcrl, sizeof(mvcrl));
    OK(uc_mem_write(uc, s390x_data_start, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_S390X_REG_R0, &r0));
    OK(uc_reg_write(uc, UC_S390X_REG_R2, &r2));
    OK(uc_reg_write(uc, UC_S390X_REG_R3, &r3));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(mvcrl), 0, 0));

    OK(uc_mem_read(uc, s390x_data_start, actual, sizeof(actual)));
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK(actual[i] == expected[i]);
    }
    OK(uc_close(uc));
}

static void run_s390x_mie2_mul_pair_case(const uint8_t *code,
                                         size_t code_size, uint64_t r2,
                                         uint64_t r3, uint64_t r4, uint64_t r5,
                                         const uint8_t *data,
                                         size_t data_size,
                                         uint64_t expected_high,
                                         uint64_t expected_low)
{
    uc_engine *uc;
    uint64_t data_addr = s390x_data_start;
    uint64_t r2_value = data_size != 0 ? data_addr : r2;

    s390x_setup_scalar_case(&uc, code, code_size);
    if (data_size != 0) {
        OK(uc_mem_write(uc, s390x_data_start, data, data_size));
    }
    OK(uc_reg_write(uc, UC_S390X_REG_R2, &r2_value));
    OK(uc_reg_write(uc, UC_S390X_REG_R3, &r3));
    OK(uc_reg_write(uc, UC_S390X_REG_R4, &r4));
    OK(uc_reg_write(uc, UC_S390X_REG_R5, &r5));

    OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));

    OK(uc_reg_read(uc, UC_S390X_REG_R4, &r4));
    OK(uc_reg_read(uc, UC_S390X_REG_R5, &r5));
    TEST_CHECK(r4 == expected_high);
    TEST_CHECK(r5 == expected_low);

    OK(uc_close(uc));
}

static void test_s390x_mie2_multiply_128(void)
{
    const uint8_t mgrk[] = { 0xb9, 0xec, 0x30, 0x42 };
    const uint8_t mg[] = { 0xe3, 0x40, 0x20, 0x00, 0x00, 0x84 };
    const uint8_t four[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
    };

    run_s390x_mie2_mul_pair_case(mgrk, sizeof(mgrk),
                                 (uint64_t)(int64_t)-3, 7, 0, 0,
                                 NULL, 0, UINT64_MAX,
                                 (uint64_t)(int64_t)-21);
    run_s390x_mie2_mul_pair_case(mg, sizeof(mg), 0, 0, 0,
                                 (uint64_t)(int64_t)-6, four,
                                 sizeof(four), UINT64_MAX,
                                 (uint64_t)(int64_t)-24);
}

static void run_s390x_mie2_multiply_cc_case(const uint8_t *code,
                                            size_t code_size, uint64_t r2,
                                            uint64_t r3, uint64_t r4,
                                            const uint8_t *data,
                                            size_t data_size,
                                            uint64_t expected_r4,
                                            uint32_t expected_cc)
{
    uc_engine *uc;
    uint64_t data_addr = s390x_data_start;

    s390x_setup_scalar_case(&uc, code, code_size);
    if (data_size != 0) {
        OK(uc_mem_write(uc, s390x_data_start, data, data_size));
        OK(uc_reg_write(uc, UC_S390X_REG_R2, &data_addr));
    } else {
        OK(uc_reg_write(uc, UC_S390X_REG_R2, &r2));
    }
    OK(uc_reg_write(uc, UC_S390X_REG_R3, &r3));
    OK(uc_reg_write(uc, UC_S390X_REG_R4, &r4));

    OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));

    OK(uc_reg_read(uc, UC_S390X_REG_R4, &r4));
    TEST_CHECK(r4 == expected_r4);
    TEST_CHECK(s390x_read_cc(uc) == expected_cc);

    OK(uc_close(uc));
}

static void test_s390x_mie2_multiply_single_cc(void)
{
    const uint8_t mgh[] = { 0xe3, 0x40, 0x20, 0x00, 0x00, 0x3c };
    const uint8_t msrkc[] = { 0xb9, 0xfd, 0x30, 0x42 };
    const uint8_t msc[] = { 0xe3, 0x40, 0x20, 0x00, 0x00, 0x53 };
    const uint8_t msgrkc[] = { 0xb9, 0xed, 0x30, 0x42 };
    const uint8_t msgc[] = { 0xe3, 0x40, 0x20, 0x00, 0x00, 0x83 };
    const uint8_t neg_three_h[] = { 0xff, 0xfd };
    const uint8_t four_w[] = { 0x00, 0x00, 0x00, 0x04 };
    const uint8_t three_g[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    };
    uc_engine *uc;
    uint64_t r2 = s390x_data_start;
    uint64_t r4 = (uint64_t)(int64_t)-7;

    s390x_setup_scalar_case(&uc, mgh, sizeof(mgh));
    OK(uc_mem_write(uc, s390x_data_start, neg_three_h,
                    sizeof(neg_three_h)));
    OK(uc_reg_write(uc, UC_S390X_REG_R2, &r2));
    OK(uc_reg_write(uc, UC_S390X_REG_R4, &r4));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(mgh), 0, 0));

    OK(uc_reg_read(uc, UC_S390X_REG_R4, &r4));
    TEST_CHECK(r4 == 21);
    OK(uc_close(uc));

    run_s390x_mie2_multiply_cc_case(msrkc, sizeof(msrkc),
                                    0x7fffffffull, 2,
                                    0xaaaaaaaa00000000ull, NULL, 0,
                                    0xaaaaaaaafffffffeull, 3);
    run_s390x_mie2_multiply_cc_case(msc, sizeof(msc), 0, 0,
                                    0xaaaaaaaa00000003ull, four_w,
                                    sizeof(four_w),
                                    0xaaaaaaaa0000000cull, 2);
    run_s390x_mie2_multiply_cc_case(msgrkc, sizeof(msgrkc),
                                    0x7fffffffffffffffull, 2, 0, NULL, 0,
                                    UINT64_MAX - 1, 3);
    run_s390x_mie2_multiply_cc_case(msgc, sizeof(msgc), 0, 0,
                                    (uint64_t)(int64_t)-7, three_g,
                                    sizeof(three_g),
                                    (uint64_t)(int64_t)-21, 1);
}

static void test_s390x_kma_query(void)
{
    const uint8_t kma_query[] = { 0xb9, 0x29, 0x60, 0x24 };
    const uint8_t kma_bad_pair[] = { 0xb9, 0x29, 0x20, 0x24 };
    const uint8_t expected[] = {
        0x80, 0x00, 0x38, 0x38, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    uint8_t actual[sizeof(expected)];
    uc_engine *uc;
    uint64_t r0 = 0;
    uint64_t r1 = s390x_data_start;
    uint64_t r2 = s390x_data_start + 0x100;
    uint64_t r4 = s390x_data_start + 0x200;
    uint64_t r6 = s390x_data_start + 0x300;
    size_t i;

    s390x_setup_scalar_case(&uc, kma_query, sizeof(kma_query));
    OK(uc_reg_write(uc, UC_S390X_REG_R0, &r0));
    OK(uc_reg_write(uc, UC_S390X_REG_R1, &r1));
    OK(uc_reg_write(uc, UC_S390X_REG_R2, &r2));
    OK(uc_reg_write(uc, UC_S390X_REG_R4, &r4));
    OK(uc_reg_write(uc, UC_S390X_REG_R6, &r6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(kma_query), 0, 0));

    OK(uc_mem_read(uc, s390x_data_start, actual, sizeof(actual)));
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK(actual[i] == expected[i]);
    }
    OK(uc_close(uc));

    s390x_setup_scalar_case(&uc, kma_bad_pair, sizeof(kma_bad_pair));
    OK(uc_reg_write(uc, UC_S390X_REG_R0, &r0));
    OK(uc_reg_write(uc, UC_S390X_REG_R1, &r1));
    OK(uc_reg_write(uc, UC_S390X_REG_R2, &r2));
    OK(uc_reg_write(uc, UC_S390X_REG_R4, &r4));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start,
                               code_start + sizeof(kma_bad_pair), 0, 0));
    OK(uc_close(uc));
}

static void s390x_write_vec(uc_engine *uc, unsigned int reg,
                            const uint8_t bytes[16])
{
    uint64_t low = s390x_pack_bytes(bytes);
    uint64_t high = s390x_pack_bytes(bytes + 8);

    OK(uc_reg_write(uc, UC_S390X_REG_F0 + reg, &low));
    OK(uc_reg_write(uc, UC_S390X_REG_F0_HI + reg, &high));
}

static void s390x_read_vec(uc_engine *uc, unsigned int reg, uint8_t bytes[16])
{
    uint64_t low;
    uint64_t high;

    OK(uc_reg_read(uc, UC_S390X_REG_F0 + reg, &low));
    OK(uc_reg_read(uc, UC_S390X_REG_F0_HI + reg, &high));
    s390x_unpack_bytes(low, bytes);
    s390x_unpack_bytes(high, bytes + 8);
}

static void s390x_check_bytes(const char *name, const uint8_t *actual,
                              const uint8_t *expected, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (actual[i] != expected[i]) {
            break;
        }
    }

    if (!TEST_CHECK(i == len)) {
        TEST_MSG("%s[%zu]: expected 0x%02x, got 0x%02x",
                 name, i, expected[i], actual[i]);
    }
}

static void s390x_setup_vector_case(uc_engine **uc, const uint8_t *code,
                                    size_t code_size)
{
    uint64_t cr0;
    uint64_t r2 = s390x_data_start;

    OK(uc_open(UC_ARCH_S390X, UC_MODE_BIG_ENDIAN, uc));
    OK(uc_ctl_set_cpu_model(*uc, UC_CPU_S390X_GEN15A));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, code_size));
    OK(uc_reg_read(*uc, UC_S390X_REG_CR0, &cr0));
    cr0 |= s390x_cr0_vector_afp;
    OK(uc_reg_write(*uc, UC_S390X_REG_CR0, &cr0));
    OK(uc_reg_write(*uc, UC_S390X_REG_R2, &r2));
}

static void run_s390x_ve2_load_case(const uint8_t code[6],
                                    const uint8_t input[16],
                                    const uint8_t initial[16],
                                    const uint8_t expected[16])
{
    uc_engine *uc;
    uint8_t actual[16];

    s390x_setup_vector_case(&uc, code, 6);
    OK(uc_mem_write(uc, s390x_data_start, input, 16));
    s390x_write_vec(uc, 0, initial);

    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    s390x_read_vec(uc, 0, actual);
    s390x_check_bytes("vector", actual, expected, 16);
    OK(uc_close(uc));
}

static void run_s390x_ve2_store_case(const uint8_t code[6],
                                     const uint8_t input[16],
                                     const uint8_t expected[16])
{
    uc_engine *uc;
    uint8_t actual[16];
    uint8_t memory[16];
    int i;

    for (i = 0; i < 16; i++) {
        memory[i] = 0xa5;
    }

    s390x_setup_vector_case(&uc, code, 6);
    OK(uc_mem_write(uc, s390x_data_start, memory, sizeof(memory)));
    s390x_write_vec(uc, 0, input);

    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    OK(uc_mem_read(uc, s390x_data_start, actual, sizeof(actual)));
    s390x_check_bytes("memory", actual, expected, 16);
    OK(uc_close(uc));
}

static void run_s390x_ve2_shift_case(const char *name, const uint8_t code[6],
                                     const uint8_t v1[16],
                                     const uint8_t v2[16],
                                     const uint8_t expected[16])
{
    uc_engine *uc;
    uint8_t actual[16];

    s390x_setup_vector_case(&uc, code, 6);
    s390x_write_vec(uc, 1, v1);
    s390x_write_vec(uc, 2, v2);

    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    s390x_read_vec(uc, 0, actual);
    s390x_check_bytes(name, actual, expected, 16);
    OK(uc_close(uc));
}

static void run_s390x_ve2_invalid_case(const uint8_t code[6])
{
    uc_engine *uc;

    s390x_setup_vector_case(&uc, code, 6);
    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + 6, 0, 0));
    OK(uc_close(uc));
}

static void run_vstrs_case(const uint8_t *code, const uint8_t searched[16],
                           const uint8_t substr[16], uint8_t substr_len,
                           uint64_t expected_offset, uint32_t expected_cc)
{
    uc_engine *uc;
    uint8_t length[16] = { 0 };
    uint64_t cr0;
    uint64_t offset;
    uint64_t high;
    uint64_t pswm;

    OK(uc_open(UC_ARCH_S390X, UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_S390X_GEN15A));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, 6));

    length[7] = substr_len;
    OK(uc_reg_read(uc, UC_S390X_REG_CR0, &cr0));
    cr0 |= s390x_cr0_vector_afp;
    OK(uc_reg_write(uc, UC_S390X_REG_CR0, &cr0));
    s390x_write_vec(uc, 1, searched);
    s390x_write_vec(uc, 2, substr);
    s390x_write_vec(uc, 3, length);

    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    OK(uc_reg_read(uc, UC_S390X_REG_F0, &offset));
    OK(uc_reg_read(uc, UC_S390X_REG_F0_HI, &high));
    OK(uc_reg_read(uc, UC_S390X_REG_PSWM, &pswm));
    TEST_CHECK(offset == expected_offset);
    TEST_CHECK(high == 0);
    TEST_CHECK(((pswm >> 44) & 3) == expected_cc);

    OK(uc_close(uc));
}

static void test_s390x_vstrs(void)
{
    uint8_t vstrs[] = "\xe7\x01\x20\x00\x30\x8b";
    uint8_t vstrs_zs[] = "\xe7\x01\x20\x20\x30\x8b";
    uint8_t vstrs16[] = "\xe7\x01\x21\x00\x30\x8b";
    uint8_t vstrs32[] = "\xe7\x01\x22\x00\x30\x8b";
    uint8_t vstrs_bad_m5[] = "\xe7\x01\x23\x00\x30\x8b";
    uint8_t vstrs_bad_m6[] = "\xe7\x01\x20\x10\x30\x8b";
    const uint8_t searched_full[16] = {
        'a', 'b', 'c', 'n', 'e', 'e', 'd', 'l',
        'e', 'x', 'y', 'z', '0', '1', '2', '3',
    };
    const uint8_t substr_nee[16] = {
        'n', 'e', 'e', 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t searched_partial[16] = {
        'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',
        'x', 'x', 'x', 'x', 'x', 'x', 'n', 'e',
    };
    const uint8_t searched_zs[16] = {
        'a', 'b', 0, 'n', 'e', 'e', 'd', 'l',
        'e', 'x', 'y', 'z', '0', '1', '2', '3',
    };
    const uint8_t substr_needle[16] = {
        'n', 'e', 'e', 'd', 'l', 'e', 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t searched16[16] = {
        0x11, 0x11, 0x22, 0x22, 0xab, 0xcd, 0x34, 0x56,
        0xab, 0xcd, 0x34, 0x56, 0x77, 0x77, 0x88, 0x88,
    };
    const uint8_t substr16[16] = {
        0xab, 0xcd, 0x34, 0x56, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t searched32[16] = {
        0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    };
    const uint8_t substr32[16] = {
        0x0a, 0x0b, 0x0c, 0x0d, 0x11, 0x12, 0x13, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0,
    };

    run_vstrs_case(vstrs, searched_full, substr_nee, 3, 3, 2);
    run_vstrs_case(vstrs, searched_partial, substr_nee, 3, 14, 3);
    run_vstrs_case(vstrs_zs, searched_zs, substr_needle, 6, 16, 1);
    run_vstrs_case(vstrs16, searched16, substr16, 4, 4, 2);
    run_vstrs_case(vstrs32, searched32, substr32, 8, 4, 2);
    run_s390x_ve2_invalid_case(vstrs_bad_m5);
    run_s390x_ve2_invalid_case(vstrs_bad_m6);
}

static void run_s390x_vbperm_case(const uint8_t v1[16], const uint8_t v2[16],
                                  const uint8_t expected[16])
{
    const uint8_t vbperm[] = { 0xe7, 0x01, 0x20, 0x00, 0x00, 0x85 };
    uc_engine *uc;
    uint8_t actual[16];

    s390x_setup_vector_case(&uc, vbperm, sizeof(vbperm));
    s390x_write_vec(uc, 1, v1);
    s390x_write_vec(uc, 2, v2);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(vbperm), 0, 0));

    s390x_read_vec(uc, 0, actual);
    s390x_check_bytes("vbperm", actual, expected, sizeof(actual));
    OK(uc_close(uc));
}

static void test_s390x_vbperm(void)
{
    const uint8_t selected_bits[16] = {
        0xa5, 0x5a, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t selectors[16] = {
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
    };
    const uint8_t expected_selected[16] = {
        0, 0, 0, 0, 0, 0, 0xa5, 0x5a,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t all_ones[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    const uint8_t selectors_with_overflow[16] = {
        0, 1, 2, 3, 4, 5, 6, 7,
        128, 129, 130, 131, 132, 133, 134, 135,
    };
    const uint8_t expected_overflow[16] = {
        0, 0, 0, 0, 0, 0, 0xff, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };

    run_s390x_vbperm_case(selected_bits, selectors, expected_selected);
    run_s390x_vbperm_case(all_ones, selectors_with_overflow,
                          expected_overflow);
}

static void run_s390x_vmsl_case(const uint8_t code[6],
                                const uint8_t expected[16])
{
    const uint8_t v2[] = {
        0, 0, 0, 0, 0, 0, 0, 2,
        0, 0, 0, 0, 0, 0, 0, 3,
    };
    const uint8_t v3[] = {
        0, 0, 0, 0, 0, 0, 0, 4,
        0, 0, 0, 0, 0, 0, 0, 5,
    };
    const uint8_t v4[] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 7,
    };
    uc_engine *uc;
    uint8_t actual[16];

    s390x_setup_vector_case(&uc, code, 6);
    s390x_write_vec(uc, 2, v2);
    s390x_write_vec(uc, 3, v3);
    s390x_write_vec(uc, 4, v4);

    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    s390x_read_vec(uc, 0, actual);
    s390x_check_bytes("vmsl", actual, expected, sizeof(actual));
    OK(uc_close(uc));
}

static void test_s390x_vmsl(void)
{
    const uint8_t vmsl[] = { 0xe7, 0x02, 0x33, 0x00, 0x40, 0xb8 };
    const uint8_t vmsl_shifted[] = {
        0xe7, 0x02, 0x33, 0xc0, 0x40, 0xb8,
    };
    const uint8_t vmsl_invalid_m5[] = {
        0xe7, 0x02, 0x32, 0x00, 0x40, 0xb8,
    };
    const uint8_t expected[] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 30,
    };
    const uint8_t expected_shifted[] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 53,
    };

    run_s390x_vmsl_case(vmsl, expected);
    run_s390x_vmsl_case(vmsl_shifted, expected_shifted);
    run_s390x_ve2_invalid_case(vmsl_invalid_m5);
}

static void run_s390x_vfp3_case(const char *name, const uint8_t code[6],
                                const uint8_t v2[16],
                                const uint8_t v3[16],
                                const uint8_t expected[16])
{
    uc_engine *uc;
    uint8_t actual[16];

    s390x_setup_vector_case(&uc, code, 6);
    s390x_write_vec(uc, 1, v2);
    s390x_write_vec(uc, 2, v3);

    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    s390x_read_vec(uc, 0, actual);
    s390x_check_bytes(name, actual, expected, sizeof(actual));
    OK(uc_close(uc));
}

static void run_s390x_vfp4_case(const char *name, const uint8_t code[6],
                                const uint8_t v2[16],
                                const uint8_t v3[16],
                                const uint8_t v4[16],
                                const uint8_t expected[16])
{
    uc_engine *uc;
    uint8_t actual[16];

    s390x_setup_vector_case(&uc, code, 6);
    s390x_write_vec(uc, 1, v2);
    s390x_write_vec(uc, 2, v3);
    s390x_write_vec(uc, 3, v4);

    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    s390x_read_vec(uc, 0, actual);
    s390x_check_bytes(name, actual, expected, sizeof(actual));
    OK(uc_close(uc));
}

static void run_s390x_vfp2_case(const char *name, const uint8_t code[6],
                                const uint8_t v2[16],
                                const uint8_t expected[16])
{
    uc_engine *uc;
    uint8_t actual[16];

    s390x_setup_vector_case(&uc, code, 6);
    s390x_write_vec(uc, 1, v2);

    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    s390x_read_vec(uc, 0, actual);
    s390x_check_bytes(name, actual, expected, sizeof(actual));
    OK(uc_close(uc));
}

static void run_s390x_vfp2_cc_case(const char *name, const uint8_t code[6],
                                   const uint8_t v2[16],
                                   const uint8_t expected[16],
                                   uint32_t expected_cc)
{
    uc_engine *uc;
    uint8_t actual[16];

    s390x_setup_vector_case(&uc, code, 6);
    s390x_write_vec(uc, 1, v2);

    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    s390x_read_vec(uc, 0, actual);
    s390x_check_bytes(name, actual, expected, sizeof(actual));
    TEST_CHECK(s390x_read_cc(uc) == expected_cc);
    OK(uc_close(uc));
}

static void run_s390x_wfc_case(const uint8_t code[6],
                               const uint8_t v1[16],
                               const uint8_t v2[16],
                               uint32_t expected_cc)
{
    uc_engine *uc;

    s390x_setup_vector_case(&uc, code, 6);
    s390x_write_vec(uc, 0, v1);
    s390x_write_vec(uc, 1, v2);

    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    TEST_CHECK(s390x_read_cc(uc) == expected_cc);
    OK(uc_close(uc));
}

static void run_s390x_vfp3_cc_case(const char *name, const uint8_t code[6],
                                   const uint8_t v2[16],
                                   const uint8_t v3[16],
                                   const uint8_t expected[16],
                                   uint32_t expected_cc)
{
    uc_engine *uc;
    uint8_t actual[16];

    s390x_setup_vector_case(&uc, code, 6);
    s390x_write_vec(uc, 1, v2);
    s390x_write_vec(uc, 2, v3);

    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    s390x_read_vec(uc, 0, actual);
    s390x_check_bytes(name, actual, expected, sizeof(actual));
    TEST_CHECK(s390x_read_cc(uc) == expected_cc);
    OK(uc_close(uc));
}

static void test_s390x_vfp_minmax(void)
{
    const uint8_t vfmax64[] = { 0xe7, 0x01, 0x20, 0x00, 0x30, 0xef };
    const uint8_t vfmin64[] = { 0xe7, 0x01, 0x20, 0x00, 0x30, 0xee };
    const uint8_t vfmin64_abs[] = { 0xe7, 0x01, 0x20, 0x80, 0x30, 0xee };
    const uint8_t vfmax128[] = { 0xe7, 0x01, 0x20, 0x00, 0x40, 0xef };
    const uint8_t vfmax_bad_m5[] = { 0xe7, 0x01, 0x20, 0x01, 0x30, 0xef };
    const uint8_t vfmax_bad_m6[] = { 0xe7, 0x01, 0x20, 0x50, 0x30, 0xef };
    const uint8_t values_a[] = {
        0xc0, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t values_b[] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_max[] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_min[] = {
        0xc0, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_abs_min[] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_one[] = {
        0x3f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_two[] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    run_s390x_vfp3_case("vfmax64", vfmax64, values_a, values_b,
                        expected_max);
    run_s390x_vfp3_case("vfmin64", vfmin64, values_a, values_b,
                        expected_min);
    run_s390x_vfp3_case("vfmin64_abs", vfmin64_abs, values_a, values_b,
                        expected_abs_min);
    run_s390x_vfp3_case("vfmax128", vfmax128, quad_one, quad_two,
                        quad_two);
    run_s390x_ve2_invalid_case(vfmax_bad_m5);
    run_s390x_ve2_invalid_case(vfmax_bad_m6);
}

static void test_s390x_vfp_negated_fma(void)
{
    const uint8_t vfma64[] = { 0xe7, 0x01, 0x23, 0x00, 0x30, 0x8f };
    const uint8_t vfms64[] = { 0xe7, 0x01, 0x23, 0x00, 0x30, 0x8e };
    const uint8_t vfnma64[] = { 0xe7, 0x01, 0x23, 0x00, 0x30, 0x9f };
    const uint8_t vfnms64[] = { 0xe7, 0x01, 0x23, 0x00, 0x30, 0x9e };
    const uint8_t vfnma64_single[] = {
        0xe7, 0x01, 0x23, 0x08, 0x30, 0x9f,
    };
    const uint8_t vfnma32[] = { 0xe7, 0x01, 0x22, 0x00, 0x30, 0x9f };
    const uint8_t vfnma_bad_m5[] = { 0xe7, 0x01, 0x23, 0x01, 0x30, 0x9f };
    const uint8_t vfnma_bad_fpf[] = { 0xe7, 0x01, 0x25, 0x00, 0x30, 0x9f };
    const uint8_t mul_a64[] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t mul_b64[] = {
        0x40, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x3f, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t add_c64[] = {
        0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_vfma64[] = {
        0x40, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_vfms64[] = {
        0x40, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_vfnma64[] = {
        0xc0, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xbf, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_vfnms64[] = {
        0xc0, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_single[] = {
        0xc0, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t mul_a32[] = {
        0x40, 0x00, 0x00, 0x00, 0xc0, 0x80, 0x00, 0x00,
        0x3f, 0x80, 0x00, 0x00, 0xbf, 0x00, 0x00, 0x00,
    };
    const uint8_t mul_b32[] = {
        0x40, 0x40, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00,
        0xc0, 0x00, 0x00, 0x00, 0x40, 0x80, 0x00, 0x00,
    };
    const uint8_t add_c32[] = {
        0x3f, 0x80, 0x00, 0x00, 0x40, 0x40, 0x00, 0x00,
        0x3f, 0x00, 0x00, 0x00, 0xbf, 0x80, 0x00, 0x00,
    };
    const uint8_t expected_vfnma32[] = {
        0xc0, 0xe0, 0x00, 0x00, 0xbf, 0x80, 0x00, 0x00,
        0x3f, 0xc0, 0x00, 0x00, 0x40, 0x40, 0x00, 0x00,
    };

    run_s390x_vfp4_case("vfma64", vfma64, mul_a64, mul_b64, add_c64,
                        expected_vfma64);
    run_s390x_vfp4_case("vfms64", vfms64, mul_a64, mul_b64, add_c64,
                        expected_vfms64);
    run_s390x_vfp4_case("vfnma64", vfnma64, mul_a64, mul_b64, add_c64,
                        expected_vfnma64);
    run_s390x_vfp4_case("vfnms64", vfnms64, mul_a64, mul_b64, add_c64,
                        expected_vfnms64);
    run_s390x_vfp4_case("vfnma64_single", vfnma64_single, mul_a64,
                        mul_b64, add_c64, expected_single);
    run_s390x_vfp4_case("vfnma32", vfnma32, mul_a32, mul_b32, add_c32,
                        expected_vfnma32);
    run_s390x_ve2_invalid_case(vfnma_bad_m5);
    run_s390x_ve2_invalid_case(vfnma_bad_fpf);
}

static void test_s390x_vfp_arith_32_128(void)
{
    const uint8_t vfa32[] = { 0xe7, 0x01, 0x20, 0x00, 0x20, 0xe3 };
    const uint8_t vfd32[] = { 0xe7, 0x01, 0x20, 0x00, 0x20, 0xe5 };
    const uint8_t vfm32[] = { 0xe7, 0x01, 0x20, 0x00, 0x20, 0xe7 };
    const uint8_t vfs32[] = { 0xe7, 0x01, 0x20, 0x00, 0x20, 0xe2 };
    const uint8_t vfa128[] = { 0xe7, 0x01, 0x20, 0x00, 0x40, 0xe3 };
    const uint8_t vfd128[] = { 0xe7, 0x01, 0x20, 0x00, 0x40, 0xe5 };
    const uint8_t vfm128[] = { 0xe7, 0x01, 0x20, 0x00, 0x40, 0xe7 };
    const uint8_t vfs128[] = { 0xe7, 0x01, 0x20, 0x00, 0x40, 0xe2 };
    const uint8_t values_a32[] = {
        0x3f, 0x80, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
        0x40, 0x40, 0x00, 0x00, 0xc0, 0x80, 0x00, 0x00,
    };
    const uint8_t values_b32[] = {
        0x40, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00,
        0xbf, 0x80, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_add32[] = {
        0x40, 0x40, 0x00, 0x00, 0xbf, 0xc0, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0xc0, 0xc0, 0x00, 0x00,
    };
    const uint8_t expected_div32[] = {
        0x3f, 0x00, 0x00, 0x00, 0xc0, 0x80, 0x00, 0x00,
        0xc0, 0x40, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_mul32[] = {
        0x40, 0x00, 0x00, 0x00, 0xbf, 0x80, 0x00, 0x00,
        0xc0, 0x40, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_sub32[] = {
        0xbf, 0x80, 0x00, 0x00, 0xc0, 0x20, 0x00, 0x00,
        0x40, 0x80, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_one[] = {
        0x3f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_two[] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_three[] = {
        0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_four[] = {
        0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    run_s390x_vfp3_case("vfa32", vfa32, values_a32, values_b32,
                        expected_add32);
    run_s390x_vfp3_case("vfd32", vfd32, values_a32, values_b32,
                        expected_div32);
    run_s390x_vfp3_case("vfm32", vfm32, values_a32, values_b32,
                        expected_mul32);
    run_s390x_vfp3_case("vfs32", vfs32, values_a32, values_b32,
                        expected_sub32);
    run_s390x_vfp3_case("vfa128", vfa128, quad_one, quad_two, quad_three);
    run_s390x_vfp3_case("vfd128", vfd128, quad_four, quad_two, quad_two);
    run_s390x_vfp3_case("vfm128", vfm128, quad_two, quad_two, quad_four);
    run_s390x_vfp3_case("vfs128", vfs128, quad_four, quad_two, quad_two);
}

static void test_s390x_vfp_compare_32_128(void)
{
    const uint8_t wfc32[] = { 0xe7, 0x01, 0x00, 0x00, 0x20, 0xcb };
    const uint8_t wfk128[] = { 0xe7, 0x01, 0x00, 0x00, 0x40, 0xca };
    const uint8_t vfce32_cc[] = {
        0xe7, 0x01, 0x20, 0x10, 0x20, 0xe8,
    };
    const uint8_t vfche32[] = { 0xe7, 0x01, 0x20, 0x00, 0x20, 0xea };
    const uint8_t vfch128_cc[] = {
        0xe7, 0x01, 0x20, 0x10, 0x40, 0xeb,
    };
    const uint8_t f32_a[] = {
        0x3f, 0x80, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x40, 0x40, 0x00, 0x00, 0x40, 0x80, 0x00, 0x00,
    };
    const uint8_t f32_b[] = {
        0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x40, 0x00, 0x00, 0x40, 0xa0, 0x00, 0x00,
    };
    const uint8_t f32_c[] = {
        0x3f, 0x80, 0x00, 0x00, 0x40, 0x40, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x40, 0x80, 0x00, 0x00,
    };
    const uint8_t vfce_expected[] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t vfche_expected[] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    const uint8_t quad_one[] = {
        0x3f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_two[] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_all_ones[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };

    run_s390x_wfc_case(wfc32, quad_one, quad_two, 1);
    run_s390x_wfc_case(wfk128, quad_one, quad_one, 0);
    run_s390x_vfp3_cc_case("vfce32", vfce32_cc, f32_a, f32_b,
                           vfce_expected, 1);
    run_s390x_vfp3_case("vfche32", vfche32, f32_a, f32_c,
                        vfche_expected);
    run_s390x_vfp3_cc_case("vfch128", vfch128_cc, quad_two, quad_one,
                           quad_all_ones, 0);
}

static void test_s390x_vfp_convert_round(void)
{
    const uint8_t vcdg32[] = { 0xe7, 0x01, 0x00, 0x00, 0x20, 0xc3 };
    const uint8_t vcdlg32[] = { 0xe7, 0x01, 0x00, 0x00, 0x20, 0xc1 };
    const uint8_t vcgd32[] = { 0xe7, 0x01, 0x00, 0x00, 0x20, 0xc2 };
    const uint8_t vclgd32[] = { 0xe7, 0x01, 0x00, 0x00, 0x20, 0xc0 };
    const uint8_t vfi32[] = { 0xe7, 0x01, 0x00, 0x00, 0x20, 0xc7 };
    const uint8_t vfi128[] = { 0xe7, 0x01, 0x00, 0x00, 0x40, 0xc7 };
    const uint8_t vfll64[] = { 0xe7, 0x01, 0x00, 0x00, 0x30, 0xc4 };
    const uint8_t vflr128[] = { 0xe7, 0x01, 0x00, 0x00, 0x40, 0xc5 };
    const uint8_t int_values[] = {
        0x00, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xfe,
        0x00, 0x00, 0x00, 0x03, 0xff, 0xff, 0xff, 0xfc,
    };
    const uint8_t uint_values[] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
    };
    const uint8_t float_signed[] = {
        0x3f, 0x80, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
        0x40, 0x40, 0x00, 0x00, 0xc0, 0x80, 0x00, 0x00,
    };
    const uint8_t float_unsigned[] = {
        0x3f, 0x80, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x40, 0x40, 0x00, 0x00, 0x40, 0x80, 0x00, 0x00,
    };
    const uint8_t vfi_input32[] = {
        0x3f, 0xa0, 0x00, 0x00, 0xc0, 0x30, 0x00, 0x00,
        0x40, 0x50, 0x00, 0x00, 0xc0, 0x98, 0x00, 0x00,
    };
    const uint8_t vfi_expected32[] = {
        0x3f, 0x80, 0x00, 0x00, 0xc0, 0x40, 0x00, 0x00,
        0x40, 0x40, 0x00, 0x00, 0xc0, 0xa0, 0x00, 0x00,
    };
    const uint8_t double_one_two[] = {
        0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_one[] = {
        0x3f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_one_half[] = {
        0x3f, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_two[] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t double_one_from_quad[] = {
        0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    run_s390x_vfp2_case("vcdg32", vcdg32, int_values, float_signed);
    run_s390x_vfp2_case("vcdlg32", vcdlg32, uint_values, float_unsigned);
    run_s390x_vfp2_case("vcgd32", vcgd32, float_signed, int_values);
    run_s390x_vfp2_case("vclgd32", vclgd32, float_unsigned, uint_values);
    run_s390x_vfp2_case("vfi32", vfi32, vfi_input32, vfi_expected32);
    run_s390x_vfp2_case("vfi128", vfi128, quad_one_half, quad_two);
    run_s390x_vfp2_case("vfll64", vfll64, double_one_two, quad_one);
    run_s390x_vfp2_case("vflr128", vflr128, quad_one,
                        double_one_from_quad);
}

static void test_s390x_vfp_sign_sqrt_class(void)
{
    const uint8_t vfpso32[] = { 0xe7, 0x01, 0x00, 0x00, 0x20, 0xcc };
    const uint8_t vfpso128_abs[] = {
        0xe7, 0x01, 0x00, 0x20, 0x40, 0xcc,
    };
    const uint8_t vfsq32[] = { 0xe7, 0x01, 0x00, 0x00, 0x20, 0xce };
    const uint8_t vfsq128[] = { 0xe7, 0x01, 0x00, 0x00, 0x40, 0xce };
    const uint8_t vftci32[] = { 0xe7, 0x01, 0x30, 0x00, 0x20, 0x4a };
    const uint8_t vftci128[] = { 0xe7, 0x01, 0x30, 0x00, 0x40, 0x4a };
    const uint8_t sign_input32[] = {
        0x3f, 0x80, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    };
    const uint8_t sign_expected32[] = {
        0xbf, 0x80, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_neg_one[] = {
        0xbf, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_one[] = {
        0x3f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t sqrt_input32[] = {
        0x40, 0x80, 0x00, 0x00, 0x41, 0x10, 0x00, 0x00,
        0x41, 0x80, 0x00, 0x00, 0x41, 0xc8, 0x00, 0x00,
    };
    const uint8_t sqrt_expected32[] = {
        0x40, 0x00, 0x00, 0x00, 0x40, 0x40, 0x00, 0x00,
        0x40, 0x80, 0x00, 0x00, 0x40, 0xa0, 0x00, 0x00,
    };
    const uint8_t quad_two[] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_four[] = {
        0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t class_input32[] = {
        0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x00, 0x00, 0x00, 0x7f, 0x80, 0x00, 0x00,
    };
    const uint8_t class_expected32[] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t quad_all_ones[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };

    run_s390x_vfp2_case("vfpso32", vfpso32, sign_input32,
                        sign_expected32);
    run_s390x_vfp2_case("vfpso128", vfpso128_abs, quad_neg_one, quad_one);
    run_s390x_vfp2_case("vfsq32", vfsq32, sqrt_input32, sqrt_expected32);
    run_s390x_vfp2_case("vfsq128", vfsq128, quad_four, quad_two);
    run_s390x_vfp2_cc_case("vftci32", vftci32, class_input32,
                           class_expected32, 1);
    run_s390x_vfp2_cc_case("vftci128", vftci128, quad_one,
                           quad_all_ones, 0);
}

static void test_s390x_ve2_byte_reverse_load(void)
{
    const uint8_t data[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const uint8_t initial[16] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    };
    const uint8_t vlebrh[] = { 0xe6, 0x00, 0x20, 0x00, 0x00, 0x01 };
    const uint8_t vlbrrep_h[] = { 0xe6, 0x00, 0x20, 0x00, 0x10, 0x05 };
    const uint8_t vllebrz_f_left[] = {
        0xe6, 0x00, 0x20, 0x00, 0x60, 0x04,
    };
    const uint8_t vlbr_h[] = { 0xe6, 0x00, 0x20, 0x00, 0x10, 0x06 };
    const uint8_t vler_f[] = { 0xe6, 0x00, 0x20, 0x00, 0x20, 0x07 };
    const uint8_t expected_vlebrh[16] = {
        0x01, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    };
    const uint8_t expected_vlbrrep_h[16] = {
        0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
    };
    const uint8_t expected_vllebrz_f_left[16] = {
        0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_vlbr_h[16] = {
        0x01, 0x00, 0x03, 0x02, 0x05, 0x04, 0x07, 0x06,
        0x09, 0x08, 0x0b, 0x0a, 0x0d, 0x0c, 0x0f, 0x0e,
    };
    const uint8_t expected_vler_f[16] = {
        0x0c, 0x0d, 0x0e, 0x0f, 0x08, 0x09, 0x0a, 0x0b,
        0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03,
    };

    run_s390x_ve2_load_case(vlebrh, data, initial, expected_vlebrh);
    run_s390x_ve2_load_case(vlbrrep_h, data, initial, expected_vlbrrep_h);
    run_s390x_ve2_load_case(vllebrz_f_left, data, initial,
                            expected_vllebrz_f_left);
    run_s390x_ve2_load_case(vlbr_h, data, initial, expected_vlbr_h);
    run_s390x_ve2_load_case(vler_f, data, initial, expected_vler_f);
}

static void test_s390x_ve2_byte_reverse_store(void)
{
    const uint8_t input[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const uint8_t vstebrh[] = { 0xe6, 0x00, 0x20, 0x00, 0x00, 0x09 };
    const uint8_t vstbr_f[] = { 0xe6, 0x00, 0x20, 0x00, 0x20, 0x0e };
    const uint8_t vster_h[] = { 0xe6, 0x00, 0x20, 0x00, 0x10, 0x0f };
    const uint8_t expected_vstebrh[16] = {
        0x01, 0x00, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    };
    const uint8_t expected_vstbr_f[16] = {
        0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04,
        0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c,
    };
    const uint8_t expected_vster_h[16] = {
        0x0e, 0x0f, 0x0c, 0x0d, 0x0a, 0x0b, 0x08, 0x09,
        0x06, 0x07, 0x04, 0x05, 0x02, 0x03, 0x00, 0x01,
    };

    run_s390x_ve2_store_case(vstebrh, input, expected_vstebrh);
    run_s390x_ve2_store_case(vstbr_f, input, expected_vstbr_f);
    run_s390x_ve2_store_case(vster_h, input, expected_vster_h);
}

static void test_s390x_ve2_double_shift(void)
{
    const uint8_t vsld[] = { 0xe7, 0x01, 0x20, 0x01, 0x00, 0x86 };
    const uint8_t vsrd[] = { 0xe7, 0x01, 0x20, 0x01, 0x00, 0x87 };
    const uint8_t vsldb[] = { 0xe7, 0x01, 0x20, 0x01, 0x00, 0x77 };
    const uint8_t vsld_invalid[] = {
        0xe7, 0x01, 0x20, 0x08, 0x00, 0x86,
    };
    const uint8_t vsrd_invalid[] = {
        0xe7, 0x01, 0x20, 0x08, 0x00, 0x87,
    };
    const uint8_t v1_vsld[16] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t v2_vsld[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t v1_vsrd[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    const uint8_t v2_vsrd[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t v1_vsldb[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const uint8_t v2_vsldb[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const uint8_t expected_shift[16] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_vsldb[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };

    run_s390x_ve2_shift_case("vsld", vsld, v1_vsld, v2_vsld,
                             expected_shift);
    run_s390x_ve2_shift_case("vsrd", vsrd, v1_vsrd, v2_vsrd,
                             expected_shift);
    run_s390x_ve2_shift_case("vsldb", vsldb, v1_vsldb, v2_vsldb,
                             expected_vsldb);
    run_s390x_ve2_invalid_case(vsld_invalid);
    run_s390x_ve2_invalid_case(vsrd_invalid);
}

TEST_LIST = {
    {"test_s390x_lr", test_s390x_lr},
    {"test_s390x_compare_halfword_relative_long",
     test_s390x_compare_halfword_relative_long},
    {"test_s390x_compare_logical_immediate_trap",
     test_s390x_compare_logical_immediate_trap},
    {"test_s390x_mie2_add_sub_halfword",
     test_s390x_mie2_add_sub_halfword},
    {"test_s390x_mie2_branch_indirect", test_s390x_mie2_branch_indirect},
    {"test_s390x_mie2_multiply_128", test_s390x_mie2_multiply_128},
    {"test_s390x_mie2_multiply_single_cc",
     test_s390x_mie2_multiply_single_cc},
    {"test_s390x_lzrf", test_s390x_lzrf},
    {"test_s390x_kma_query", test_s390x_kma_query},
    {"test_s390x_monitor_call", test_s390x_monitor_call},
    {"test_s390x_mie3_move_right_to_left",
     test_s390x_mie3_move_right_to_left},
    {"test_s390x_mie3_logic", test_s390x_mie3_logic},
    {"test_s390x_mie3_select", test_s390x_mie3_select},
    {"test_s390x_locfhr", test_s390x_locfhr},
    {"test_s390x_vstrs", test_s390x_vstrs},
    {"test_s390x_vbperm", test_s390x_vbperm},
    {"test_s390x_vmsl", test_s390x_vmsl},
    {"test_s390x_vfp_minmax", test_s390x_vfp_minmax},
    {"test_s390x_vfp_negated_fma", test_s390x_vfp_negated_fma},
    {"test_s390x_vfp_arith_32_128", test_s390x_vfp_arith_32_128},
    {"test_s390x_vfp_compare_32_128", test_s390x_vfp_compare_32_128},
    {"test_s390x_vfp_convert_round", test_s390x_vfp_convert_round},
    {"test_s390x_vfp_sign_sqrt_class", test_s390x_vfp_sign_sqrt_class},
    {"test_s390x_ve2_byte_reverse_load", test_s390x_ve2_byte_reverse_load},
    {"test_s390x_ve2_byte_reverse_store", test_s390x_ve2_byte_reverse_store},
    {"test_s390x_ve2_double_shift", test_s390x_ve2_double_shift},
    {NULL, NULL},
};
