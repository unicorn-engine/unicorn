#include "unicorn_test.h"

#include <string.h>

const uint64_t code_start = 0x10000000;
const uint64_t code_len = 0x4000;

#define MIPS_OP_LWC2 (0x32u << 26)
#define MIPS_OP_LDC2 (0x36u << 26)
#define MIPS_OP_SWC2 (0x3au << 26)
#define MIPS_OP_SDC2 (0x3eu << 26)

#define MIPS_CP0_STATUS_FR (1u << 26)
#define MIPS_CP0_STATUS_CU1 (1u << 29)

static uint32_t mips_bitswap32(uint32_t value)
{
    value = ((value >> 1) & 0x55555555) | ((value & 0x55555555) << 1);
    value = ((value >> 2) & 0x33333333) | ((value & 0x33333333) << 2);
    value = ((value >> 4) & 0x0f0f0f0f) | ((value & 0x0f0f0f0f) << 4);

    return value;
}

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static uint32_t encode_loongson_lsdc2(uint32_t major, int rt, int rs, int rd,
                                      int offset, int op)
{
    return major | (rs << 21) | (rt << 16) | (rd << 11) |
           ((offset & 0xff) << 3) | op;
}

static uint32_t encode_loongson_gslsq(uint32_t major, int rt, int rs,
                                      int offset, int rt1)
{
    return major | 0x20 | (rs << 21) | (rt << 16) |
           (((offset >> 4) & 0x1ff) << 6) | rt1;
}

static uint32_t encode_loongson_gslsq_fpr(uint32_t major, int rt, int rs,
                                          int offset, int rt1)
{
    return major | 0x8020 | (rs << 21) | (rt << 16) |
           (((offset >> 4) & 0x1ff) << 6) | rt1;
}

static uint32_t encode_loongson_gsshfls(uint32_t major, int rt, int rs,
                                        int offset, int op)
{
    return major | (rs << 21) | (rt << 16) | ((offset & 0xff) << 6) | op;
}

static void enable_mips64_fpu(uc_engine *uc)
{
    uint64_t status;

    OK(uc_reg_read(uc, UC_MIPS_REG_CP0_STATUS, &status));
    status |= MIPS_CP0_STATUS_FR | MIPS_CP0_STATUS_CU1;
    OK(uc_reg_write(uc, UC_MIPS_REG_CP0_STATUS, &status));
}

static void test_mips_el_ori(void)
{
    uc_engine *uc;
    char code[] = "\x56\x34\x21\x34"; // ori $at, $at, 0x3456;
    int r_r1 = 0x6789;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_1, &r_r1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_1, &r_r1));

    TEST_CHECK(r_r1 == 0x77df);

    OK(uc_close(uc));
}

static void test_mips_eb_ori(void)
{
    uc_engine *uc;
    char code[] = "\x34\x21\x34\x56"; // ori $at, $at, 0x3456;
    int r_r1 = 0x6789;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_1, &r_r1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_1, &r_r1));

    TEST_CHECK(r_r1 == 0x77df);

    OK(uc_close(uc));
}

static void test_mips_stop_at_branch(void)
{
    uc_engine *uc;
    char code[] =
        "\x02\x00\x00\x08\x21\x10\x62\x00"; // j 0x8; addu $v0, $v1, $v0;
    int r_pc = 0x0;
    uint32_t v1 = 5;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);

    OK(uc_reg_write(uc, UC_MIPS_REG_V1, &v1));
    // Execute one instruction with branch delay slot.
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 1));

    OK(uc_reg_read(uc, UC_MIPS_REG_PC, &r_pc));
    OK(uc_reg_read(uc, UC_MIPS_REG_V0, &v1));

    // Even if we just execute one instruction, the instruction in the
    // delay slot would also be executed.
    TEST_CHECK(r_pc == code_start + 0x8);
    TEST_CHECK(v1 == 0x5);

    OK(uc_close(uc));
}

static void test_mips_stop_at_delay_slot(void)
{
    uc_engine *uc;
    char code[] =
        "\x02\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"; // j 0x8; nop;
    int r_pc = 0x0;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);

    // Stop at the delay slot by design.
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_PC, &r_pc));

    // The branch instruction isn't committed and the PC is not updated.
    // Users is responsible to restart emulation at the branch instruction.
    TEST_CHECK(r_pc == code_start);

    OK(uc_close(uc));
}

static void test_mips_stop_delay_slot_from_qiling(void)
{
    uc_engine *uc;
    // 24 06 00 03          addiu                $a2, $zero, 3
    // 10 a6 00 79          beq                  $a1, $a2, 0x1e8
    // 30 42 00 fc          andi                 $v0, $v0, 0xfc
    // 10 40 00 32          beqz                 $v0, 0x47c8c90
    // 24 ab ff da          addiu                $t3, $a1, -0x26
    // 2d 62 00 02          sltiu                $v0, $t3, 2
    // 10 40 00 32          beqz                 $v0, 0x47c8c9c
    // 00 00 00 00          nop
    char code[] =
        "\x24\x06\x00\x03\x10\xa6\x00\x79\x30\x42\x00\xfc\x10\x40\x00\x32\x24"
        "\xab\xff\xda\x2d\x62\x00\x02\x10\x40\x00\x32\x00\x00\x00\x00";
    uint32_t r_pc = 0x0;
    uint32_t r_v0 = 0xff;
    uint32_t r_a1 = 0x3;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_V0, &r_v0));
    OK(uc_reg_write(uc, UC_MIPS_REG_A1, &r_a1));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) + 16, 0, 2));

    OK(uc_reg_read(uc, UC_MIPS_REG_PC, &r_pc));
    OK(uc_reg_read(uc, UC_MIPS_REG_V0, &r_v0));
    TEST_CHECK(r_pc == code_start + 4 + 0x1e8);
    TEST_CHECK(r_v0 == 0xfc);

    OK(uc_close(uc));
}

static void test_mips_lwx_exception_issue_1314(void)
{
    uc_engine *uc;
    char code[] = "\x0a\xc8\x79\x7e"; // lwx $t9, $t9($s3)
    int reg;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_mem_map(uc, 0x10000, 0x4000, UC_PROT_ALL));

    // Enable DSP
    // https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/MD00090-2B-MIPS32PRA-AFP-06.02.pdf
    OK(uc_reg_read(uc, UC_MIPS_REG_CP0_STATUS, &reg));
    reg |= (1 << 24);
    OK(uc_reg_write(uc, UC_MIPS_REG_CP0_STATUS, &reg));

    reg = 0;
    OK(uc_reg_write(uc, UC_MIPS_REG_1, &reg));
    OK(uc_reg_write(uc, UC_MIPS_REG_T9, &reg));
    reg = LEINT32(0xdeadbeef);
    OK(uc_mem_write(uc, 0x10000, &reg, 4));
    reg = 0x10000;
    OK(uc_reg_write(uc, UC_MIPS_REG_S3, &reg));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_T9, &reg));

    TEST_CHECK(reg == 0xdeadbeef);

    OK(uc_close(uc));
}

static void test_mips_mips16(void)
{
    uc_engine *uc;
    char code[] = "\xC4\x6B\x49\xE3"; // li $v1, 0xC4;  addu $v0, $v1, $v0
    int r_v0 = 0x6789;
    int mips16_lowbit = 1;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_V0, &r_v0));

    OK(uc_emu_start(uc, code_start | mips16_lowbit,
                    code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_V0, &r_v0));

    TEST_CHECK(r_v0 == 0x684D);

    OK(uc_close(uc));
}

static void test_mips_mips32r6_mode_bitswap(void)
{
    uc_engine *uc;
    char code[] = "\x7c\x03\x10\x20";
    uint32_t r2 = 0;
    uint32_t r3 = 0x12345678;

    uc_common_setup(&uc, UC_ARCH_MIPS,
                    UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN | UC_MODE_MIPS32R6,
                    code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_3, &r3));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_2, &r2));
    TEST_CHECK(r2 == mips_bitswap32(r3));

    OK(uc_close(uc));
}

static void test_mips_micro_mode_li16(void)
{
    uc_engine *uc;
    char code[] = "\x2a\xed";
    uint32_t r2 = 0;

    uc_common_setup(&uc, UC_ARCH_MIPS,
                    UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN | UC_MODE_MICRO,
                    code, sizeof(code) - 1);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_2, &r2));
    TEST_CHECK(r2 == 0x2a);

    OK(uc_close(uc));
}

static void test_mips_nanomips_model_move16(void)
{
    uc_engine *uc;
    char code[] = "\xc5\x10";
    uint32_t r5 = 0x12345678;
    uint32_t r6 = 0;

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS32_I7200));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_MIPS_REG_5, &r5));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 1));

    OK(uc_reg_read(uc, UC_MIPS_REG_6, &r6));
    TEST_CHECK(r6 == r5);

    OK(uc_close(uc));
}

static void test_mips_mips3_mode_opens(void)
{
    uc_engine *uc;

    OK(uc_open(UC_ARCH_MIPS,
               UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN | UC_MODE_MIPS3, &uc));
    OK(uc_close(uc));

    TEST_CHECK(uc_open(UC_ARCH_MIPS,
                       UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN | UC_MODE_MIPS3,
                       &uc) == UC_ERR_MODE);
}

static void test_mips_msa_w_reg_roundtrip(void)
{
    uc_engine *uc;
    uint8_t w0[16] = {
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };
    uint8_t w7[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    uint8_t w31[16] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    };
    uint8_t out[16] = { 0 };

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS32_P5600));

    OK(uc_reg_write(uc, UC_MIPS_REG_W0, w0));
    OK(uc_reg_read(uc, UC_MIPS_REG_W0, out));
    TEST_CHECK(memcmp(out, w0, sizeof(w0)) == 0);

    memset(out, 0, sizeof(out));
    OK(uc_reg_write(uc, UC_MIPS_REG_W7, w7));
    OK(uc_reg_read(uc, UC_MIPS_REG_W7, out));
    TEST_CHECK(memcmp(out, w7, sizeof(w7)) == 0);

    memset(out, 0, sizeof(out));
    OK(uc_reg_write(uc, UC_MIPS_REG_W31, w31));
    OK(uc_reg_read(uc, UC_MIPS_REG_W31, out));
    TEST_CHECK(memcmp(out, w31, sizeof(w31)) == 0);

    OK(uc_close(uc));
}

static void test_mips_mips_fpr(void)
{
    uc_engine *uc;
    uint64_t r_f1;
    // ks.asm("li $t1, 0x42f6e979;mtc1 $t1, $f1")
    const char code[] = "\xf6\x42\x09\x3c\x79\xe9\x29\x35\x00\x08\x89\x44";
    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32, code, sizeof(code) - 1);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_F1, (void *)&r_f1));

    TEST_CHECK(r_f1 = 0x42f6e979);

    OK(uc_close(uc));
}

static void test_mips_simple_coredump_2134(void)
{
    uc_engine *uc;
    const char code[] = "\x25\xc8\x80\x03\x25\x78\xe0\x03\x09\xf8\x20\x03\x10\x00\x18\x24";
    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32, code, sizeof(code) - 1);

    uc_assert_err(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0), UC_ERR_FETCH_UNMAPPED);

    OK(uc_close(uc));
}

static void test_mips_simple_coredump_2137(void)
{
    uc_engine *uc;
    const char code[] = "\x1c\x00\x40\x54\xe8\x00\xc4\xaf";
    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32, code, sizeof(code) - 1);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static void test_mips64_loongson2f_status(void)
{
    uc_engine *uc;
    uint64_t status = 0;
    const uint64_t expected = (1ULL << 22) | (1ULL << 7) | (1ULL << 6) |
                              (1ULL << 5) | (1ULL << 2);

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_LITTLE_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_LOONGSON_2F));
    OK(uc_reg_read(uc, UC_MIPS_REG_CP0_STATUS, &status));

    TEST_CHECK((status & expected) == expected);

    OK(uc_close(uc));
}

static void test_mips64_loongson3a_dmult(void)
{
    uc_engine *uc;
    uint64_t r2 = 0x100000000ull;
    uint64_t r3 = 0x12;
    uint64_t r4 = 0;
    const char code[] = "\x70\x43\x20\x11";

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_LOONGSON_3A1000));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &r2));
    OK(uc_reg_write(uc, UC_MIPS_REG_3, &r3));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_4, &r4));
    TEST_CHECK(r4 == 0x1200000000ull);

    OK(uc_close(uc));

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_LOONGSON_3A4000));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &r2));
    OK(uc_reg_write(uc, UC_MIPS_REG_3, &r3));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_4, &r4));
    TEST_CHECK(r4 == 0x1200000000ull);

    OK(uc_close(uc));
}

static void test_mips64_loongson3a_requires_lext(void)
{
    uc_engine *uc;
    uint64_t r2 = 0x100000000ull;
    uint64_t r3 = 0x12;
    const char code[] = "\x70\x43\x20\x11";

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_MIPS64R2_GENERIC));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &r2));
    OK(uc_reg_write(uc, UC_MIPS_REG_3, &r3));

    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_mips64_loongson3a_load_zero_prefetch(void)
{
    uc_engine *uc;
    uint64_t r2 = 0x20000000ull;
    const char code[] = "\xdc\x40\x00\x00";

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_LOONGSON_3A1000));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &r2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_MIPS64R2_GENERIC));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &r2));

    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(code) - 1, 0, 0) ==
               UC_ERR_READ_UNMAPPED);

    OK(uc_close(uc));
}

static void test_mips64_loongson3a_lext_lsdc2_gpr(void)
{
    uc_engine *uc;
    uint64_t data_base = 0x20000000ull;
    uint64_t index = 0x20;
    uint64_t r8 = 0;
    uint64_t r9 = 0;
    uint64_t r10 = 0;
    uint64_t r11 = 0;
    uint64_t r12 = 0xaa;
    uint64_t r13 = 0x1234;
    uint64_t r14 = 0x89abcdef;
    uint64_t r15 = 0x1122334455667788ull;
    uint8_t data[0x50] = { 0 };
    uint8_t result[16];
    uint8_t expected[] = {
        0xaa, 0x00, 0x12, 0x34, 0x89, 0xab, 0xcd, 0xef,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    };
    uint32_t code[] = {
        BEINT32(encode_loongson_lsdc2(MIPS_OP_LDC2, 8, 2, 3, 1, 0)),
        BEINT32(encode_loongson_lsdc2(MIPS_OP_LDC2, 9, 2, 3, 3, 1)),
        BEINT32(encode_loongson_lsdc2(MIPS_OP_LDC2, 10, 2, 3, 5, 2)),
        BEINT32(encode_loongson_lsdc2(MIPS_OP_LDC2, 11, 2, 3, 9, 3)),
        BEINT32(encode_loongson_lsdc2(MIPS_OP_SDC2, 12, 2, 3, 0x30, 0)),
        BEINT32(encode_loongson_lsdc2(MIPS_OP_SDC2, 13, 2, 3, 0x32, 1)),
        BEINT32(encode_loongson_lsdc2(MIPS_OP_SDC2, 14, 2, 3, 0x34, 2)),
        BEINT32(encode_loongson_lsdc2(MIPS_OP_SDC2, 15, 2, 3, 0x38, 3)),
    };

    data[index + 1] = 0x80;
    data[index + 3] = 0x12;
    data[index + 4] = 0x34;
    data[index + 5] = 0x80;
    data[index + 8] = 0x01;
    data[index + 9] = 0x01;
    data[index + 10] = 0x02;
    data[index + 11] = 0x03;
    data[index + 12] = 0x04;
    data[index + 13] = 0x05;
    data[index + 14] = 0x06;
    data[index + 15] = 0x07;
    data[index + 16] = 0x08;

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_LOONGSON_3A1000));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_map(uc, data_base, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, data_base, data, sizeof(data)));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &data_base));
    OK(uc_reg_write(uc, UC_MIPS_REG_3, &index));
    OK(uc_reg_write(uc, UC_MIPS_REG_12, &r12));
    OK(uc_reg_write(uc, UC_MIPS_REG_13, &r13));
    OK(uc_reg_write(uc, UC_MIPS_REG_14, &r14));
    OK(uc_reg_write(uc, UC_MIPS_REG_15, &r15));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_8, &r8));
    OK(uc_reg_read(uc, UC_MIPS_REG_9, &r9));
    OK(uc_reg_read(uc, UC_MIPS_REG_10, &r10));
    OK(uc_reg_read(uc, UC_MIPS_REG_11, &r11));
    OK(uc_mem_read(uc, data_base + index + 0x30, result, sizeof(result)));

    TEST_CHECK(r8 == 0xffffffffffffff80ull);
    TEST_CHECK(r9 == 0x1234);
    TEST_CHECK(r10 == 0xffffffff80000001ull);
    TEST_CHECK(r11 == 0x0102030405060708ull);
    TEST_CHECK(memcmp(result, expected, sizeof(expected)) == 0);

    OK(uc_close(uc));
}

static void test_mips64_loongson3a_lext_lsdc2_requires_lext(void)
{
    uc_engine *uc;
    uint64_t data_base = 0x20000000ull;
    uint64_t index = 0;
    uint32_t code[] = {
        BEINT32(encode_loongson_lsdc2(MIPS_OP_LDC2, 8, 2, 3, 0, 2)),
    };

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_MIPS64R2_GENERIC));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_map(uc, data_base, 0x1000, UC_PROT_ALL));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &data_base));
    OK(uc_reg_write(uc, UC_MIPS_REG_3, &index));

    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code),
                            0, 0) == UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_mips64_loongson3a_lext_gslsq_gpr(void)
{
    uc_engine *uc;
    uint64_t data_base = 0x20000000ull;
    uint64_t r8 = 0;
    uint64_t r9 = 0;
    uint64_t r10 = 0x8877665544332211ull;
    uint64_t r11 = 0x0102030405060708ull;
    uint8_t data[0x50] = { 0 };
    uint8_t result[16];
    uint8_t expected[] = {
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    uint32_t code[] = {
        BEINT32(encode_loongson_gslsq(MIPS_OP_LWC2, 8, 2, 0x10, 9)),
        BEINT32(encode_loongson_gslsq(MIPS_OP_SWC2, 10, 2, 0x30, 11)),
    };

    data[0x10] = 0x11;
    data[0x11] = 0x22;
    data[0x12] = 0x33;
    data[0x13] = 0x44;
    data[0x14] = 0x55;
    data[0x15] = 0x66;
    data[0x16] = 0x77;
    data[0x17] = 0x88;
    data[0x18] = 0x99;
    data[0x19] = 0xaa;
    data[0x1a] = 0xbb;
    data[0x1b] = 0xcc;
    data[0x1c] = 0xdd;
    data[0x1d] = 0xee;
    data[0x1e] = 0xff;
    data[0x1f] = 0x00;

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_LOONGSON_3A1000));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_map(uc, data_base, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, data_base, data, sizeof(data)));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &data_base));
    OK(uc_reg_write(uc, UC_MIPS_REG_10, &r10));
    OK(uc_reg_write(uc, UC_MIPS_REG_11, &r11));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_8, &r8));
    OK(uc_reg_read(uc, UC_MIPS_REG_9, &r9));
    OK(uc_mem_read(uc, data_base + 0x30, result, sizeof(result)));

    TEST_CHECK(r8 == 0x1122334455667788ull);
    TEST_CHECK(r9 == 0x99aabbccddeeff00ull);
    TEST_CHECK(memcmp(result, expected, sizeof(expected)) == 0);

    OK(uc_close(uc));
}

static void test_mips64_loongson3a_lext_gslsq_requires_lext(void)
{
    uc_engine *uc;
    uint64_t data_base = 0x20000000ull;
    uint32_t code[] = {
        BEINT32(encode_loongson_gslsq(MIPS_OP_LWC2, 8, 2, 0x10, 9)),
    };

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_MIPS64R2_GENERIC));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_map(uc, data_base, 0x1000, UC_PROT_ALL));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &data_base));

    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code),
                            0, 0) == UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_mips64_loongson3a_lext_lsdc2_fpr(void)
{
    uc_engine *uc;
    uint64_t data_base = 0x20000000ull;
    uint64_t index = 0x20;
    uint64_t f8 = 0xaaaabbbbccccdddduLL;
    uint64_t f9 = 0;
    uint64_t f10 = 0x12345678a1b2c3d4ull;
    uint64_t f11 = 0x0102030405060708ull;
    uint8_t data[0x50] = { 0 };
    uint8_t result[16];
    uint8_t expected[] = {
        0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    uint32_t code[] = {
        BEINT32(encode_loongson_lsdc2(MIPS_OP_LDC2, 8, 2, 3, 4, 6)),
        BEINT32(encode_loongson_lsdc2(MIPS_OP_LDC2, 9, 2, 3, 8, 7)),
        BEINT32(encode_loongson_lsdc2(MIPS_OP_SDC2, 10, 2, 3, 0x30, 6)),
        BEINT32(encode_loongson_lsdc2(MIPS_OP_SDC2, 11, 2, 3, 0x38, 7)),
    };

    data[index + 4] = 0x11;
    data[index + 5] = 0x22;
    data[index + 6] = 0x33;
    data[index + 7] = 0x44;
    data[index + 8] = 0x55;
    data[index + 9] = 0x66;
    data[index + 10] = 0x77;
    data[index + 11] = 0x88;
    data[index + 12] = 0x99;
    data[index + 13] = 0xaa;
    data[index + 14] = 0xbb;
    data[index + 15] = 0xcc;

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_LOONGSON_3A1000));
    enable_mips64_fpu(uc);
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_map(uc, data_base, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, data_base, data, sizeof(data)));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &data_base));
    OK(uc_reg_write(uc, UC_MIPS_REG_3, &index));
    OK(uc_reg_write(uc, UC_MIPS_REG_F8, &f8));
    OK(uc_reg_write(uc, UC_MIPS_REG_F10, &f10));
    OK(uc_reg_write(uc, UC_MIPS_REG_F11, &f11));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_F8, &f8));
    OK(uc_reg_read(uc, UC_MIPS_REG_F9, &f9));
    OK(uc_mem_read(uc, data_base + index + 0x30, result, sizeof(result)));

    TEST_CHECK(f8 == 0xaaaabbbb11223344ull);
    TEST_CHECK(f9 == 0x5566778899aabbccull);
    TEST_CHECK(memcmp(result, expected, sizeof(expected)) == 0);

    OK(uc_close(uc));
}

static void test_mips64_loongson3a_lext_gslsq_fpr(void)
{
    uc_engine *uc;
    uint64_t data_base = 0x20000000ull;
    uint64_t f8 = 0;
    uint64_t f9 = 0;
    uint64_t f10 = 0x8877665544332211ull;
    uint64_t f11 = 0x0102030405060708ull;
    uint8_t data[0x50] = { 0 };
    uint8_t result[16];
    uint8_t expected[] = {
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    uint32_t code[] = {
        BEINT32(encode_loongson_gslsq_fpr(MIPS_OP_LWC2, 8, 2, 0x10, 9)),
        BEINT32(encode_loongson_gslsq_fpr(MIPS_OP_SWC2, 10, 2, 0x30, 11)),
    };

    data[0x10] = 0x11;
    data[0x11] = 0x22;
    data[0x12] = 0x33;
    data[0x13] = 0x44;
    data[0x14] = 0x55;
    data[0x15] = 0x66;
    data[0x16] = 0x77;
    data[0x17] = 0x88;
    data[0x18] = 0x99;
    data[0x19] = 0xaa;
    data[0x1a] = 0xbb;
    data[0x1b] = 0xcc;
    data[0x1c] = 0xdd;
    data[0x1d] = 0xee;
    data[0x1e] = 0xff;
    data[0x1f] = 0x00;

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_LOONGSON_3A1000));
    enable_mips64_fpu(uc);
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_map(uc, data_base, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, data_base, data, sizeof(data)));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &data_base));
    OK(uc_reg_write(uc, UC_MIPS_REG_F10, &f10));
    OK(uc_reg_write(uc, UC_MIPS_REG_F11, &f11));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_F8, &f8));
    OK(uc_reg_read(uc, UC_MIPS_REG_F9, &f9));
    OK(uc_mem_read(uc, data_base + 0x30, result, sizeof(result)));

    TEST_CHECK(f8 == 0x1122334455667788ull);
    TEST_CHECK(f9 == 0x99aabbccddeeff00ull);
    TEST_CHECK(memcmp(result, expected, sizeof(expected)) == 0);

    OK(uc_close(uc));
}

static void test_mips64_loongson3a_lext_shifted_fpr(void)
{
    uc_engine *uc;
    uint64_t data_base = 0x20000000ull;
    uint64_t f8 = 0xaaaaaaaa55555555ull;
    uint64_t f9 = 0xbbbbbbbb66666666ull;
    uint64_t f10 = 0;
    uint64_t f11 = 0;
    uint64_t f12 = 0x00000000a1b2c3d4ull;
    uint64_t f13 = 0x00000000b1b2b3b4ull;
    uint64_t f14 = 0xc1c2c3c4c5c6c7c8ull;
    uint64_t f15 = 0xd1d2d3d4d5d6d7d8ull;
    uint8_t data[0x60] = { 0 };
    uint8_t result[0x40];
    uint8_t expected[0x40] = { 0 };
    uint32_t code[] = {
        BEINT32(encode_loongson_gsshfls(MIPS_OP_LWC2, 8, 2, 0, 4)),
        BEINT32(encode_loongson_gsshfls(MIPS_OP_LWC2, 9, 2, 3, 5)),
        BEINT32(encode_loongson_gsshfls(MIPS_OP_LWC2, 10, 2, 8, 6)),
        BEINT32(encode_loongson_gsshfls(MIPS_OP_LWC2, 11, 2, 15, 7)),
        BEINT32(encode_loongson_gsshfls(MIPS_OP_SWC2, 12, 2, 0x20, 4)),
        BEINT32(encode_loongson_gsshfls(MIPS_OP_SWC2, 13, 2, 0x33, 5)),
        BEINT32(encode_loongson_gsshfls(MIPS_OP_SWC2, 14, 2, 0x40, 6)),
        BEINT32(encode_loongson_gsshfls(MIPS_OP_SWC2, 15, 2, 0x57, 7)),
    };

    data[0] = 0x10;
    data[1] = 0x20;
    data[2] = 0x30;
    data[3] = 0x40;
    data[8] = 0x01;
    data[9] = 0x02;
    data[10] = 0x03;
    data[11] = 0x04;
    data[12] = 0x05;
    data[13] = 0x06;
    data[14] = 0x07;
    data[15] = 0x08;
    expected[0] = 0xa1;
    expected[1] = 0xb2;
    expected[2] = 0xc3;
    expected[3] = 0xd4;
    expected[0x10] = 0xb1;
    expected[0x11] = 0xb2;
    expected[0x12] = 0xb3;
    expected[0x13] = 0xb4;
    expected[0x20] = 0xc1;
    expected[0x21] = 0xc2;
    expected[0x22] = 0xc3;
    expected[0x23] = 0xc4;
    expected[0x24] = 0xc5;
    expected[0x25] = 0xc6;
    expected[0x26] = 0xc7;
    expected[0x27] = 0xc8;
    expected[0x30] = 0xd1;
    expected[0x31] = 0xd2;
    expected[0x32] = 0xd3;
    expected[0x33] = 0xd4;
    expected[0x34] = 0xd5;
    expected[0x35] = 0xd6;
    expected[0x36] = 0xd7;
    expected[0x37] = 0xd8;

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_LOONGSON_3A1000));
    enable_mips64_fpu(uc);
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_map(uc, data_base, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, data_base, data, sizeof(data)));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &data_base));
    OK(uc_reg_write(uc, UC_MIPS_REG_F8, &f8));
    OK(uc_reg_write(uc, UC_MIPS_REG_F9, &f9));
    OK(uc_reg_write(uc, UC_MIPS_REG_F12, &f12));
    OK(uc_reg_write(uc, UC_MIPS_REG_F13, &f13));
    OK(uc_reg_write(uc, UC_MIPS_REG_F14, &f14));
    OK(uc_reg_write(uc, UC_MIPS_REG_F15, &f15));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_F8, &f8));
    OK(uc_reg_read(uc, UC_MIPS_REG_F9, &f9));
    OK(uc_reg_read(uc, UC_MIPS_REG_F10, &f10));
    OK(uc_reg_read(uc, UC_MIPS_REG_F11, &f11));
    OK(uc_mem_read(uc, data_base + 0x20, result, sizeof(result)));

    TEST_CHECK(f8 == 0xaaaaaaaa10203040ull);
    TEST_CHECK(f9 == 0xbbbbbbbb10203040ull);
    TEST_CHECK(f10 == 0x0102030405060708ull);
    TEST_CHECK(f11 == 0x0102030405060708ull);
    TEST_CHECK(memcmp(result, expected, sizeof(expected)) == 0);

    OK(uc_close(uc));
}

static void test_mips64_loongson3a_pagemask(void)
{
    uc_engine *uc;
    uint64_t r8 = 0x2000;
    uint64_t r9 = 0;
    uint64_t r10 = 0x6000;
    uint64_t r11 = 0;
    uint32_t code[] = {
        BEINT32(0x40882800), /* mtc0 t0, PageMask */
        BEINT32(0x40092800), /* mfc0 t1, PageMask */
        BEINT32(0x408a2800), /* mtc0 t2, PageMask */
        BEINT32(0x400b2800), /* mfc0 t3, PageMask */
    };

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_LOONGSON_3A1000));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_reg_write(uc, UC_MIPS_REG_8, &r8));
    OK(uc_reg_write(uc, UC_MIPS_REG_10, &r10));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_9, &r9));
    OK(uc_reg_read(uc, UC_MIPS_REG_11, &r11));

    TEST_CHECK(r9 == 0);
    TEST_CHECK(r11 == r10);

    OK(uc_close(uc));
}

static void test_mips64_octeon_arithmetic(void)
{
    uc_engine *uc;
    uint64_t r2 = 0xf0;
    uint64_t r3 = 0x11;
    uint64_t r14 = 0x10000000000000ffull;
    uint64_t r15 = 0x0000ff0000000000ull;
    uint64_t r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r16, r17;
    const char code[] =
        "\x70\x43\x20\x28" /* baddu r4,r2,r3 */
        "\x70\x43\x28\x03" /* dmul  r5,r2,r3 */
        "\x70\x46\x39\x3a" /* exts  r6,r2,4,7 */
        "\x70\x67\x3c\x32" /* cins  r7,r3,16,7 */
        "\x71\xc0\x40\x2c" /* pop   r8,r14 */
        "\x71\xc0\x48\x2d" /* dpop  r9,r14 */
        "\x70\x43\x50\x2a" /* seq   r10,r2,r3 */
        "\x70\x43\x58\x2b" /* sne   r11,r2,r3 */
        "\x70\x4c\x3c\x2e" /* seqi  r12,r2,0xf0 */
        "\x70\x4d\x04\x6f" /* snei  r13,r2,0x11 */
        "\x71\xf0\x3a\x3b" /* exts32 r16,r15,40,7 */
        "\x70\x71\x3a\x33"; /* cins32 r17,r3,40,7 */

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_OCTEON68XX));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &r2));
    OK(uc_reg_write(uc, UC_MIPS_REG_3, &r3));
    OK(uc_reg_write(uc, UC_MIPS_REG_14, &r14));
    OK(uc_reg_write(uc, UC_MIPS_REG_15, &r15));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_4, &r4));
    OK(uc_reg_read(uc, UC_MIPS_REG_5, &r5));
    OK(uc_reg_read(uc, UC_MIPS_REG_6, &r6));
    OK(uc_reg_read(uc, UC_MIPS_REG_7, &r7));
    OK(uc_reg_read(uc, UC_MIPS_REG_8, &r8));
    OK(uc_reg_read(uc, UC_MIPS_REG_9, &r9));
    OK(uc_reg_read(uc, UC_MIPS_REG_10, &r10));
    OK(uc_reg_read(uc, UC_MIPS_REG_11, &r11));
    OK(uc_reg_read(uc, UC_MIPS_REG_12, &r12));
    OK(uc_reg_read(uc, UC_MIPS_REG_13, &r13));
    OK(uc_reg_read(uc, UC_MIPS_REG_16, &r16));
    OK(uc_reg_read(uc, UC_MIPS_REG_17, &r17));

    TEST_CHECK(r4 == 0x1);
    TEST_CHECK(r5 == 0xff0);
    TEST_CHECK(r6 == 0xf);
    TEST_CHECK(r7 == 0x110000);
    TEST_CHECK(r8 == 8);
    TEST_CHECK(r9 == 9);
    TEST_CHECK(r10 == 0);
    TEST_CHECK(r11 == 1);
    TEST_CHECK(r12 == 1);
    TEST_CHECK(r13 == 1);
    TEST_CHECK(r16 == UINT64_MAX);
    TEST_CHECK(r17 == 0x0000110000000000ull);

    OK(uc_close(uc));
}

static void test_mips64_octeon_bbit(void)
{
    uc_engine *uc;
    uint64_t r2 = 0x10;
    uint64_t r3 = 0;
    uint64_t r4, r5, r6, r7, r8;
    const char code[] =
        "\xe8\x44\x00\x02" /* bbit1   r2,4,+2 */
        "\x34\x04\x00\x01" /* ori     r4,zero,1 */
        "\x34\x05\x00\x22" /* ori     r5,zero,0x22 */
        "\xd8\x64\x00\x02" /* bbit032 r3,36,+2 */
        "\x34\x06\x00\x02" /* ori     r6,zero,2 */
        "\x34\x07\x00\x44" /* ori     r7,zero,0x44 */
        "\x34\x08\x00\x55"; /* ori     r8,zero,0x55 */

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_OCTEON68XX));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &r2));
    OK(uc_reg_write(uc, UC_MIPS_REG_3, &r3));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_4, &r4));
    OK(uc_reg_read(uc, UC_MIPS_REG_5, &r5));
    OK(uc_reg_read(uc, UC_MIPS_REG_6, &r6));
    OK(uc_reg_read(uc, UC_MIPS_REG_7, &r7));
    OK(uc_reg_read(uc, UC_MIPS_REG_8, &r8));

    TEST_CHECK(r4 == 1);
    TEST_CHECK(r5 == 0);
    TEST_CHECK(r6 == 2);
    TEST_CHECK(r7 == 0);
    TEST_CHECK(r8 == 0x55);

    OK(uc_close(uc));
}

static void test_mips64_octeon_requires_octeon(void)
{
    uc_engine *uc;
    uint64_t r2 = 0xf0;
    uint64_t r3 = 0x11;
    const char code[] = "\x70\x43\x20\x28";

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_MIPS64_MIPS64R2_GENERIC));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_MIPS_REG_2, &r2));
    OK(uc_reg_write(uc, UC_MIPS_REG_3, &r3));

    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_mips_cp0_count_compare(void)
{
    uc_engine *uc;
    char code[] =
        "\x40\x88\x48\x00" /* mtc0 $t0, Count */
        "\x40\x09\x48\x00" /* mfc0 $t1, Count */
        "\x40\x8a\x58\x00" /* mtc0 $t2, Compare */
        "\x40\x0b\x58\x00"; /* mfc0 $t3, Compare */
    uint32_t t0 = 0x12345678;
    uint32_t t1 = 0;
    uint32_t t2 = 0xdeadbeef;
    uint32_t t3 = 0;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_MIPS_REG_T2, &t2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_MIPS_REG_T1, &t1));
    OK(uc_reg_read(uc, UC_MIPS_REG_T3, &t3));

    TEST_CHECK(t1 == t0);
    TEST_CHECK(t3 == t2);

    OK(uc_close(uc));
}

TEST_LIST = {
    {"test_mips_stop_at_branch", test_mips_stop_at_branch},
    {"test_mips_stop_at_delay_slot", test_mips_stop_at_delay_slot},
    {"test_mips_el_ori", test_mips_el_ori},
    {"test_mips_eb_ori", test_mips_eb_ori},
    {"test_mips_lwx_exception_issue_1314", test_mips_lwx_exception_issue_1314},
    {"test_mips_mips16", test_mips_mips16},
    {"test_mips_mips32r6_mode_bitswap", test_mips_mips32r6_mode_bitswap},
    {"test_mips_micro_mode_li16", test_mips_micro_mode_li16},
    {"test_mips_nanomips_model_move16", test_mips_nanomips_model_move16},
    {"test_mips_mips3_mode_opens", test_mips_mips3_mode_opens},
    {"test_mips_msa_w_reg_roundtrip", test_mips_msa_w_reg_roundtrip},
    {"test_mips_mips_fpr", test_mips_mips_fpr},
    {"test_mips_stop_delay_slot_from_qiling",
     test_mips_stop_delay_slot_from_qiling},
     {"test_mips_simple_coredump_2134", test_mips_simple_coredump_2134},
     {"test_mips_simple_coredump_2137", test_mips_simple_coredump_2137},
     {"test_mips64_loongson2f_status", test_mips64_loongson2f_status},
     {"test_mips64_loongson3a_dmult", test_mips64_loongson3a_dmult},
     {"test_mips64_loongson3a_requires_lext",
      test_mips64_loongson3a_requires_lext},
     {"test_mips64_loongson3a_load_zero_prefetch",
      test_mips64_loongson3a_load_zero_prefetch},
     {"test_mips64_loongson3a_lext_lsdc2_gpr",
      test_mips64_loongson3a_lext_lsdc2_gpr},
     {"test_mips64_loongson3a_lext_lsdc2_requires_lext",
      test_mips64_loongson3a_lext_lsdc2_requires_lext},
     {"test_mips64_loongson3a_lext_gslsq_gpr",
      test_mips64_loongson3a_lext_gslsq_gpr},
     {"test_mips64_loongson3a_lext_gslsq_requires_lext",
      test_mips64_loongson3a_lext_gslsq_requires_lext},
     {"test_mips64_loongson3a_lext_lsdc2_fpr",
      test_mips64_loongson3a_lext_lsdc2_fpr},
     {"test_mips64_loongson3a_lext_gslsq_fpr",
      test_mips64_loongson3a_lext_gslsq_fpr},
     {"test_mips64_loongson3a_lext_shifted_fpr",
      test_mips64_loongson3a_lext_shifted_fpr},
     {"test_mips64_loongson3a_pagemask",
      test_mips64_loongson3a_pagemask},
     {"test_mips64_octeon_arithmetic", test_mips64_octeon_arithmetic},
     {"test_mips64_octeon_bbit", test_mips64_octeon_bbit},
     {"test_mips64_octeon_requires_octeon",
      test_mips64_octeon_requires_octeon},
     {"test_mips_cp0_count_compare", test_mips_cp0_count_compare},
    {NULL, NULL}};
