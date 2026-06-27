#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

typedef struct PpcCodeHookTrace {
    uint64_t address[2];
    uint32_t size[2];
    uint32_t count;
} PpcCodeHookTrace;

static void test_ppc64_prefixed_code_hook(uc_engine *uc, uint64_t address,
                                          uint32_t size, void *user_data)
{
    PpcCodeHookTrace *trace = (PpcCodeHookTrace *)user_data;

    (void)uc;
    if (trace->count < 2) {
        trace->address[trace->count] = address;
        trace->size[trace->count] = size;
    }
    trace->count++;
}

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

/* IBM AIX fadd/floating-add instruction reference. */
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

static void test_ppc32_spr_mftb(void)
{
    uc_engine *uc;
    uint32_t r3,r4,r6,r7;
    uint64_t t1,t2;

    char code[] = (
        "\x7c\x6d\x42\xe6" //        mftbu r3
        "\x7c\x8c\x42\xe6" //        mftb  r4
        "\x38\xa0\x00\x00" //        li    r5, 0
        "\x38\xa5\x00\x01" // .loop: addi  r5, r5, 1
        "\x2c\x05\x04\x00" //        cmpwi r5, 1024
        "\x41\x80\xff\xf8" //        blt .loop
        "\x7c\xcd\x42\xe6" //        mftbu r6
        "\x7c\xec\x42\xe6" //        mftb  r7
    );

    uc_common_setup(&uc, UC_ARCH_PPC, UC_MODE_32 | UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_PPC_REG_3, &r3));
    OK(uc_reg_read(uc, UC_PPC_REG_4, &r4));
    OK(uc_reg_read(uc, UC_PPC_REG_6, &r6));
    OK(uc_reg_read(uc, UC_PPC_REG_7, &r7));

    OK(uc_close(uc));

    t1 = ((uint64_t)r3 << 32) | r4;
    t2 = ((uint64_t)r6 << 32) | r7;
    TEST_CHECK(t1 != t2);
}

static void run_ppc64_power10_byte_reverse(const char *code, uint64_t expected)
{
    uc_engine *uc;
    uint64_t src = 0x0123456789abcdefull;
    uint64_t dst = 0;

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, 4));

    OK(uc_reg_write(uc, UC_PPC_REG_3, &src));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_4, &dst));

    TEST_CHECK(dst == expected);

    OK(uc_close(uc));
}

static void test_ppc64_power10_brd(void)
{
    run_ppc64_power10_byte_reverse("\x7c\x64\x01\x76",
                                   0xefcdab8967452301ull);
}

static void test_ppc64_power10_brw(void)
{
    run_ppc64_power10_byte_reverse("\x7c\x64\x01\x36",
                                   0x67452301efcdab89ull);
}

static void test_ppc64_power10_brh(void)
{
    run_ppc64_power10_byte_reverse("\x7c\x64\x01\xb6",
                                   0x23016745ab89efcdull);
}

static void run_ppc64_power10_mask_op(const char *code, uint64_t src,
                                      uint64_t mask, uint64_t expected)
{
    uc_engine *uc;
    uint64_t dst = 0;

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, 4));

    OK(uc_reg_write(uc, UC_PPC_REG_3, &src));
    OK(uc_reg_write(uc, UC_PPC_REG_5, &mask));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_4, &dst));

    TEST_CHECK(dst == expected);

    OK(uc_close(uc));
}

static void test_ppc64_power10_cfuged(void)
{
    run_ppc64_power10_mask_op("\x7c\x64\x29\xb8", 0x0123456789abcdefull,
                              0x00ff00ff00ff00ffull,
                              0x014589cd2367abefull);
}

static void test_ppc64_power10_cntlzdm(void)
{
    run_ppc64_power10_mask_op("\x7c\x64\x28\x76", 0x0010000000000000ull,
                              0x00ff000000000000ull, 3);
    run_ppc64_power10_mask_op("\x7c\x64\x28\x76", 0,
                              0x00ff000000000000ull, 8);
}

static void test_ppc64_power10_cnttzdm(void)
{
    run_ppc64_power10_mask_op("\x7c\x64\x2c\x76", 0x1000,
                              0xff00, 4);
    run_ppc64_power10_mask_op("\x7c\x64\x2c\x76", 0,
                              0xff00, 8);
}

static void test_ppc64_power10_pdepd(void)
{
    run_ppc64_power10_mask_op("\x7c\x64\x29\x38", 0xb, 0xf0, 0xb0);
}

static void test_ppc64_power10_pextd(void)
{
    run_ppc64_power10_mask_op("\x7c\x64\x29\x78", 0xb0, 0xf0, 0xb);
}

static void test_ppc64_power10_mask_op_requires_isa310(void)
{
    uc_engine *uc;
    uint64_t src = 0xb;
    uint64_t mask = 0xf0;
    const char code[] = "\x7c\x64\x29\x38";

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    OK(uc_reg_write(uc, UC_PPC_REG_3, &src));
    OK(uc_reg_write(uc, UC_PPC_REG_5, &mask));
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                            0, 0) == UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_ppc64_power10_setbc(void)
{
    uc_engine *uc;
    uint32_t cr1 = 0x4;
    uint64_t r4, r5, r6, r7, r8, r9, r10, r11;
    char code[] =
        "\x7c\x85\x03\x00" /* setbc   r4, 5 */
        "\x7c\xa5\x03\x40" /* setbcr  r5, 5 */
        "\x7c\xc5\x03\x80" /* setnbc  r6, 5 */
        "\x7c\xe5\x03\xc0" /* setnbcr r7, 5 */
        "\x7d\x06\x03\x00" /* setbc   r8, 6 */
        "\x7d\x26\x03\x40" /* setbcr  r9, 6 */
        "\x7d\x46\x03\x80" /* setnbc  r10, 6 */
        "\x7d\x66\x03\xc0"; /* setnbcr r11, 6 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    OK(uc_reg_write(uc, UC_PPC_REG_CR1, &cr1));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_PPC_REG_4, &r4));
    OK(uc_reg_read(uc, UC_PPC_REG_5, &r5));
    OK(uc_reg_read(uc, UC_PPC_REG_6, &r6));
    OK(uc_reg_read(uc, UC_PPC_REG_7, &r7));
    OK(uc_reg_read(uc, UC_PPC_REG_8, &r8));
    OK(uc_reg_read(uc, UC_PPC_REG_9, &r9));
    OK(uc_reg_read(uc, UC_PPC_REG_10, &r10));
    OK(uc_reg_read(uc, UC_PPC_REG_11, &r11));

    TEST_CHECK(r4 == 1);
    TEST_CHECK(r5 == 0);
    TEST_CHECK(r6 == UINT64_MAX);
    TEST_CHECK(r7 == 0);
    TEST_CHECK(r8 == 0);
    TEST_CHECK(r9 == 1);
    TEST_CHECK(r10 == 0);
    TEST_CHECK(r11 == UINT64_MAX);

    OK(uc_close(uc));
}

static void test_ppc64_power10_setbc_requires_isa310(void)
{
    uc_engine *uc;
    uint32_t cr1 = 0x4;
    const char code[] = "\x7c\x85\x03\x00";

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    OK(uc_reg_write(uc, UC_PPC_REG_CR1, &cr1));
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                            0, 0) == UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void run_ppc64_power10_vector_mask_op(const char *op,
                                             const uint8_t src[16],
                                             const uint8_t mask[16],
                                             const uint8_t expected[16])
{
    uc_engine *uc;
    uint64_t src_addr = code_start + 0x1000;
    uint64_t mask_addr = code_start + 0x1010;
    uint64_t dst_addr = code_start + 0x1020;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    int i;
    char code[16] =
        "\x7c\x80\x60\xce" /* lvx  v4, 0, r12 */
        "\x7c\xa0\x68\xce" /* lvx  v5, 0, r13 */
        "\0\0\0\0"
        "\x7c\x60\x71\xce"; /* stvx v3, 0, r14 */

    memcpy(code + 8, op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, src_addr, src, 16));
    OK(uc_mem_write(uc, mask_addr, mask, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 25;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &src_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &mask_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));

    for (i = 0; i < 16; i++) {
        TEST_CHECK(dst[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void test_ppc64_power10_vcfuged(void)
{
    const uint8_t src[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const uint8_t mask[16] = {
        0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
        0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
    };
    const uint8_t expected[16] = {
        0x01, 0x45, 0x89, 0xcd, 0x23, 0x67, 0xab, 0xef,
        0xfd, 0xb9, 0x75, 0x31, 0xec, 0xa8, 0x64, 0x20,
    };

    run_ppc64_power10_vector_mask_op("\x10\x64\x2d\x4d", src, mask,
                                     expected);
}

static void test_ppc64_power10_vclzdm(void)
{
    const uint8_t src[16] = {
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t mask[16] = {
        0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t expected[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
    };

    run_ppc64_power10_vector_mask_op("\x10\x64\x2f\x84", src, mask,
                                     expected);
}

static void test_ppc64_power10_vctzdm(void)
{
    const uint8_t src[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t mask[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00,
    };
    const uint8_t expected[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
    };

    run_ppc64_power10_vector_mask_op("\x10\x64\x2f\xc4", src, mask,
                                     expected);
}

static void test_ppc64_power10_vpdepd(void)
{
    const uint8_t src[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34,
    };
    const uint8_t mask[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff,
    };
    const uint8_t expected[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x34,
    };

    run_ppc64_power10_vector_mask_op("\x10\x64\x2d\xcd", src, mask,
                                     expected);
}

static void test_ppc64_power10_vpextd(void)
{
    const uint8_t src[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x34,
    };
    const uint8_t mask[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff,
    };
    const uint8_t expected[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34,
    };

    run_ppc64_power10_vector_mask_op("\x10\x64\x2d\x8d", src, mask,
                                     expected);
}

static void test_ppc64_power10_vmx_mask_materialize_extract(void)
{
    uc_engine *uc;
    uint64_t b_addr = code_start + 0x1000;
    uint64_t expand_addr = code_start + 0x1100;
    uint64_t half_addr = code_start + 0x1200;
    uint64_t w_addr = code_start + 0x1300;
    uint64_t d_addr = code_start + 0x1400;
    uint64_t q_addr = code_start + 0x1500;
    uint64_t bmi_addr = code_start + 0x1600;
    uint64_t msr;
    uint64_t value;
    uint8_t dst[16];
    const uint64_t b_mask = 0xa55a;
    const uint64_t h_mask = 0xa5;
    const uint64_t w_mask = 0x0a;
    const uint64_t d_mask = 0x02;
    const uint64_t q_mask = 1;
    const uint8_t expected_b[16] = {
        0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0x00, 0xff,
        0x00, 0xff, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00,
    };
    const uint8_t expected_h[16] = {
        0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff,
    };
    const uint8_t expected_w[16] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_d[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t expected_q[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    const uint8_t expected_bmi[16] = {
        0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00,
        0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff,
    };
    const char code[] =
        "\x10\x90\x2e\x42"
        "\x7c\x80\xd9\xce"
        "\x10\xc8\x26\x42"
        "\x10\xe0\x26\x42"
        "\x7c\xe0\xe1\xce"
        "\x10\xb1\x3e\x42"
        "\x7c\xa0\xe9\xce"
        "\x11\x09\x2e\x42"
        "\x10\xd2\x4e\x42"
        "\x7c\xc0\xf1\xce"
        "\x11\x4a\x36\x42"
        "\x10\xf3\x5e\x42"
        "\x7c\xe0\xf9\xce"
        "\x11\x8b\x3e\x42"
        "\x11\x14\x6e\x42"
        "\x7d\x00\x81\xce"
        "\x11\xcc\x46\x42"
        "\x11\x34\x96\x55"
        "\x7d\x20\x79\xce"
        "\x12\x58\x26\x42"
        "\x12\x79\x26\x42"
        "\x12\x9b\x2e\x42"
        "\x12\xdd\x36\x42"
        "\x12\xbe\x3e\x42";

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 25;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_5, &b_mask));
    OK(uc_reg_write(uc, UC_PPC_REG_7, &h_mask));
    OK(uc_reg_write(uc, UC_PPC_REG_9, &w_mask));
    OK(uc_reg_write(uc, UC_PPC_REG_11, &d_mask));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &q_mask));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &bmi_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_16, &q_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_27, &b_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_28, &expand_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_29, &half_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_30, &w_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_31, &d_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, b_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected_b, sizeof(dst)) == 0);
    OK(uc_mem_read(uc, expand_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected_b, sizeof(dst)) == 0);
    OK(uc_mem_read(uc, half_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected_h, sizeof(dst)) == 0);
    OK(uc_mem_read(uc, w_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected_w, sizeof(dst)) == 0);
    OK(uc_mem_read(uc, d_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected_d, sizeof(dst)) == 0);
    OK(uc_mem_read(uc, q_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected_q, sizeof(dst)) == 0);
    OK(uc_mem_read(uc, bmi_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected_bmi, sizeof(dst)) == 0);

    OK(uc_reg_read(uc, UC_PPC_REG_6, &value));
    TEST_CHECK(value == b_mask);
    OK(uc_reg_read(uc, UC_PPC_REG_8, &value));
    TEST_CHECK(value == h_mask);
    OK(uc_reg_read(uc, UC_PPC_REG_10, &value));
    TEST_CHECK(value == w_mask);
    OK(uc_reg_read(uc, UC_PPC_REG_12, &value));
    TEST_CHECK(value == d_mask);
    OK(uc_reg_read(uc, UC_PPC_REG_14, &value));
    TEST_CHECK(value == q_mask);
    OK(uc_reg_read(uc, UC_PPC_REG_18, &value));
    TEST_CHECK(value == 0x0800000000000000ull);
    OK(uc_reg_read(uc, UC_PPC_REG_19, &value));
    TEST_CHECK(value == 0x0800000000000000ull);
    OK(uc_reg_read(uc, UC_PPC_REG_20, &value));
    TEST_CHECK(value == 0x0800000000000000ull);
    OK(uc_reg_read(uc, UC_PPC_REG_21, &value));
    TEST_CHECK(value == 0x0800000000000000ull);
    OK(uc_reg_read(uc, UC_PPC_REG_22, &value));
    TEST_CHECK(value == 0x0800000000000000ull);

    OK(uc_close(uc));
}

static void test_ppc64_power10_vector_mask_requires_isa310(void)
{
    uc_engine *uc;
    size_t i;
    uint64_t msr;
    static const uint8_t code[][4] = {
        { 0x10, 0x64, 0x2d, 0xcd },
        { 0x10, 0x90, 0x2e, 0x42 },
        { 0x11, 0x34, 0x96, 0x55 },
    };

    for (i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, code[i], sizeof(code[i])));

        OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
        msr |= 1ull << 25;
        OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

        TEST_CHECK(uc_emu_start(uc, code_start,
                                code_start + sizeof(code[i]), 0, 0) ==
                   UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

static void run_ppc64_power10_vmx_quad_op(const uint8_t op[4],
                                          const uint8_t a[16],
                                          const uint8_t b[16],
                                          const uint8_t seed[16],
                                          const uint8_t expected[16])
{
    uc_engine *uc;
    uint64_t a_addr = code_start + 0x1000;
    uint64_t b_addr = code_start + 0x1010;
    uint64_t seed_addr = code_start + 0x1020;
    uint64_t dst_addr = code_start + 0x1030;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    uint8_t code[20] = {
        0x7c, 0x60, 0x70, 0xce,
        0x7c, 0x80, 0x60, 0xce,
        0x7c, 0xa0, 0x68, 0xce,
        0, 0, 0, 0,
        0x7c, 0x60, 0x79, 0xce,
    };

    memcpy(code + 12, op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, a_addr, a, 16));
    OK(uc_mem_write(uc, b_addr, b, 16));
    OK(uc_mem_write(uc, seed_addr, seed, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 25;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &a_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &b_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &seed_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_vmx_quad_shift_rotate(void)
{
    const uint8_t zero[16] = { 0 };
    const uint8_t a[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const uint8_t a_neg[16] = {
        0x81, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const uint8_t sh68[16] = {
        0, 0, 0, 0, 0, 0, 0, 0x44,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t sh4[16] = {
        0, 0, 0, 0, 0, 0, 0, 0x04,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t sh65[16] = {
        0, 0, 0, 0, 0, 0, 0, 0x41,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t rot12[16] = {
        0, 0, 0, 0, 0, 0, 0, 0x0c,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t mask_nm[16] = {
        0, 0, 0, 0, 0, 0x08, 0x5f, 0x05,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t mask_mi[16] = {
        0, 0, 0, 0, 0, 0x10, 0x4f, 0x09,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t seed[16] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    };
    const uint8_t vslq[16] = {
        0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x00,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t vsrq[16] = {
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
        0xff, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21,
    };
    const uint8_t vsraq[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xc0, 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7,
    };
    const uint8_t vrlq[16] = {
        0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0xed,
        0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x00, 0x12,
    };
    const uint8_t vrlqnm[16] = {
        0x00, 0x68, 0xac, 0xf1, 0x35, 0x79, 0xbd, 0xff,
        0xdb, 0x97, 0x53, 0x0e, 0, 0, 0, 0,
    };
    const uint8_t vrlqmi[16] = {
        0xaa, 0xaa, 0xcf, 0x13, 0x57, 0x9b, 0xdf, 0xfd,
        0xb9, 0x75, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    };

    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x29\x05",
                                  a, sh68, zero, vslq);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2a\x05",
                                  a, sh4, zero, vsrq);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2b\x05",
                                  a_neg, sh65, zero, vsraq);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x28\x05",
                                  a, rot12, zero, vrlq);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x29\x45",
                                  a, mask_nm, zero, vrlqnm);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x28\x45",
                                  a, mask_mi, seed, vrlqmi);
}

static void test_ppc64_power10_vmx_doubleword_immediate_shift(void)
{
    const uint8_t zero[16] = { 0 };
    const uint8_t a[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const uint8_t b[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    };
    const uint8_t vsldbi4[16] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff,
        0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x01,
    };
    const uint8_t vsrdbi4[16] = {
        0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
        0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
    };

    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x29\x16",
                                  a, b, zero, vsldbi4);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2b\x16",
                                  a, b, zero, vsrdbi4);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x28\x16",
                                  a, b, zero, a);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2a\x16",
                                  a, b, zero, b);
}

static void run_ppc64_power10_vmx_quad_compare_dot(const uint8_t op[4],
                                                   const uint8_t a[16],
                                                   const uint8_t b[16],
                                                   uint32_t expected_cr6)
{
    uc_engine *uc;
    uint64_t a_addr = code_start + 0x1000;
    uint64_t b_addr = code_start + 0x1010;
    uint64_t dst_addr = code_start + 0x1020;
    uint64_t msr;
    uint32_t cr6 = 0;
    uint8_t code[16] = {
        0x7c, 0x80, 0x60, 0xce,
        0x7c, 0xa0, 0x68, 0xce,
        0, 0, 0, 0,
        0x7c, 0x60, 0x79, 0xce,
    };

    memcpy(code + 8, op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, a_addr, a, 16));
    OK(uc_mem_write(uc, b_addr, b, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 25;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &a_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &b_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_CR6, &cr6));
    TEST_CHECK(cr6 == expected_cr6);

    OK(uc_close(uc));
}

static void run_ppc64_power10_vcmpq_cr(const uint8_t op[4],
                                       const uint8_t a[16],
                                       const uint8_t b[16], int cr_reg,
                                       uint32_t expected)
{
    uc_engine *uc;
    uint64_t a_addr = code_start + 0x1000;
    uint64_t b_addr = code_start + 0x1010;
    uint64_t msr;
    uint32_t cr = 0;
    uint8_t code[12] = {
        0x7c, 0x80, 0x60, 0xce,
        0x7c, 0xa0, 0x68, 0xce,
        0, 0, 0, 0,
    };

    memcpy(code + 8, op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, a_addr, a, 16));
    OK(uc_mem_write(uc, b_addr, b, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 25;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &a_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &b_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, cr_reg, &cr));
    TEST_CHECK(cr == expected);

    OK(uc_close(uc));
}

static void test_ppc64_power10_vmx_quad_compare(void)
{
    const uint8_t zero[16] = { 0 };
    const uint8_t all_true[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    const uint8_t all_false[16] = { 0 };
    const uint8_t a[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const uint8_t b[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x0f,
    };
    const uint8_t neg[16] = {
        0x81, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };

    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x29\xc7",
                                  a, a, zero, all_true);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x29\xc7",
                                  a, b, zero, all_false);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2a\x87",
                                  a, b, zero, all_true);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2b\x87",
                                  neg, a, zero, all_false);
    run_ppc64_power10_vmx_quad_compare_dot(
        (const uint8_t *)"\x10\x64\x2d\xc7", a, a, 0x8);
    run_ppc64_power10_vmx_quad_compare_dot(
        (const uint8_t *)"\x10\x64\x2d\xc7", a, b, 0x2);
    run_ppc64_power10_vcmpq_cr((const uint8_t *)"\x11\x04\x29\x41",
                               neg, a, UC_PPC_REG_CR2, 0x8);
    run_ppc64_power10_vcmpq_cr((const uint8_t *)"\x11\x84\x29\x01",
                               neg, a, UC_PPC_REG_CR3, 0x4);
}

static void test_ppc64_power10_vmx_quad_compare_invalid(void)
{
    uc_engine *uc;
    uint64_t msr;
    const uint8_t code[] = {
        0x11, 0xa4, 0x29, 0x01,
    };

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 25;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code),
                            0, 0) == UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_ppc64_power10_vmx_multiply_dword(void)
{
    const uint8_t zero[16] = { 0 };
    const uint8_t a[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    };
    const uint8_t b[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    };
    const uint8_t vmulesd[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8,
    };
    const uint8_t vmulosd[16] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0x0f,
    };
    const uint8_t vmuleud[16] = {
        0, 0, 0, 0, 0, 0, 0, 0x03,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8,
    };
    const uint8_t vmulld[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8,
        0, 0, 0, 0, 0, 0, 0, 0x0f,
    };

    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2b\xc8",
                                  a, b, zero, vmulesd);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x29\xc8",
                                  a, b, zero, vmulosd);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2a\xc8",
                                  a, b, zero, vmuleud);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x28\xc8",
                                  a, b, zero, vmulosd);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x29\xc9",
                                  a, b, zero, vmulld);
}

static void test_ppc64_power10_vmx_multiply_high(void)
{
    const uint8_t zero[16] = { 0 };
    const uint8_t dword_a[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    };
    const uint8_t dword_b[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    };
    const uint8_t word_a[16] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x00, 0x00,
    };
    const uint8_t word_b[16] = {
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00,
    };
    const uint8_t vmulhsw[16] = {
        0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0,
        0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0x01,
    };
    const uint8_t vmulhuw[16] = {
        0, 0, 0, 0x01, 0, 0, 0, 0,
        0, 0, 0, 0x01, 0, 0, 0, 0x01,
    };
    const uint8_t vmulhsd[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t vmulhud[16] = {
        0, 0, 0, 0, 0, 0, 0, 0x03,
        0, 0, 0, 0, 0, 0, 0, 0,
    };

    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2b\x89",
                                  word_a, word_b, zero, vmulhsw);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2a\x89",
                                  word_a, word_b, zero, vmulhuw);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2b\xc9",
                                  dword_a, dword_b, zero, vmulhsd);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2a\xc9",
                                  dword_a, dword_b, zero, vmulhud);
}

static void test_ppc64_power10_vmx_vextsd2q(void)
{
    const uint8_t zero[16] = { 0 };
    const uint8_t src[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    const uint8_t expected[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };

    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x7b\x26\x02",
                                  src, zero, zero, expected);
}

static void run_ppc64_power10_vmx_vextd_op(const uint8_t op[4],
                                           const uint8_t a[16],
                                           const uint8_t b[16],
                                           uint64_t index,
                                           const uint8_t expected[16])
{
    uc_engine *uc;
    uint64_t a_addr = code_start + 0x1000;
    uint64_t b_addr = code_start + 0x1010;
    uint64_t dst_addr = code_start + 0x1020;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    uint8_t code[16] = {
        0x7c, 0x80, 0x60, 0xce,
        0x7c, 0xa0, 0x68, 0xce,
        0, 0, 0, 0,
        0x7c, 0x60, 0x79, 0xce,
    };

    memcpy(code + 8, op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, a_addr, a, 16));
    OK(uc_mem_write(uc, b_addr, b, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 25;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_6, &index));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &a_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &b_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void run_ppc64_power10_vmx_vins_gpr_op(const uint8_t op[4],
                                              const uint8_t seed[16],
                                              uint64_t index,
                                              uint64_t value,
                                              const uint8_t expected[16])
{
    uc_engine *uc;
    uint64_t seed_addr = code_start + 0x1000;
    uint64_t dst_addr = code_start + 0x1010;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    uint8_t code[12] = {
        0x7c, 0x60, 0x70, 0xce,
        0, 0, 0, 0,
        0x7c, 0x60, 0x79, 0xce,
    };

    memcpy(code + 4, op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, seed_addr, seed, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 25;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_6, &index));
    OK(uc_reg_write(uc, UC_PPC_REG_7, &value));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &seed_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void run_ppc64_power10_vmx_vins_vector_op(const uint8_t op[4],
                                                 const uint8_t seed[16],
                                                 const uint8_t src[16],
                                                 uint64_t index,
                                                 const uint8_t expected[16])
{
    uc_engine *uc;
    uint64_t seed_addr = code_start + 0x1000;
    uint64_t src_addr = code_start + 0x1010;
    uint64_t dst_addr = code_start + 0x1020;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    uint8_t code[16] = {
        0x7c, 0x60, 0x70, 0xce,
        0x7c, 0xe0, 0x68, 0xce,
        0, 0, 0, 0,
        0x7c, 0x60, 0x79, 0xce,
    };

    memcpy(code + 8, op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, seed_addr, seed, 16));
    OK(uc_mem_write(uc, src_addr, src, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 25;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_6, &index));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &src_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &seed_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_vmx_extract_double(void)
{
    const uint8_t a[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const uint8_t b[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const uint8_t vextdubvlx[16] = {
        0, 0, 0, 0, 0, 0, 0, 0x02,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t vextduhvrx[16] = {
        0, 0, 0, 0, 0, 0, 0x1b, 0x1c,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t vextduwvlx[16] = {
        0, 0, 0, 0, 0x0e, 0x0f, 0x10, 0x11,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t vextddvrx[16] = {
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0, 0, 0, 0, 0, 0, 0, 0,
    };

    run_ppc64_power10_vmx_vextd_op((const uint8_t *)"\x10\x64\x29\x98",
                                   a, b, 2, vextdubvlx);
    run_ppc64_power10_vmx_vextd_op((const uint8_t *)"\x10\x64\x29\x9b",
                                   a, b, 3, vextduhvrx);
    run_ppc64_power10_vmx_vextd_op((const uint8_t *)"\x10\x64\x29\x9c",
                                   a, b, 14, vextduwvlx);
    run_ppc64_power10_vmx_vextd_op((const uint8_t *)"\x10\x64\x29\x9f",
                                   a, b, 1, vextddvrx);
}

static void test_ppc64_power10_vmx_insert_gpr(void)
{
    const uint8_t seed[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const uint64_t value = 0x1122334455667788ull;
    const uint8_t vinsblx[16] = {
        0x00, 0x11, 0x22, 0x88, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const uint8_t vinshrx[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0x77, 0x88, 0xdd, 0xee, 0xff,
    };
    const uint8_t vinswrx[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0x55, 0x66, 0x77, 0x88, 0xee, 0xff,
    };
    const uint8_t vinsdrx[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xff,
    };
    const uint8_t vinsw[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x55, 0x66,
        0x77, 0x88, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const uint8_t vinsd[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    };

    run_ppc64_power10_vmx_vins_gpr_op(
        (const uint8_t *)"\x10\x66\x3a\x0f", seed, 3, value, vinsblx);
    run_ppc64_power10_vmx_vins_gpr_op(
        (const uint8_t *)"\x10\x66\x3b\x4f", seed, 3, value, vinshrx);
    run_ppc64_power10_vmx_vins_gpr_op(
        (const uint8_t *)"\x10\x66\x3b\x8f", seed, 2, value, vinswrx);
    run_ppc64_power10_vmx_vins_gpr_op(
        (const uint8_t *)"\x10\x66\x3b\xcf", seed, 1, value, vinsdrx);
    run_ppc64_power10_vmx_vins_gpr_op(
        (const uint8_t *)"\x10\x66\x38\xcf", seed, 0, value, vinsw);
    run_ppc64_power10_vmx_vins_gpr_op(
        (const uint8_t *)"\x10\x68\x39\xcf", seed, 0, value, vinsd);
}

static void test_ppc64_power10_vmx_insert_vector(void)
{
    const uint8_t seed[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const uint8_t src[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    };
    const uint8_t vinsbvlx[16] = {
        0x00, 0x11, 0xa7, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const uint8_t vinshvrx[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xa6, 0xa7, 0xcc, 0xdd, 0xee, 0xff,
    };
    const uint8_t vinswvlx[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0xa4, 0xa5, 0xa6,
        0xa7, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const uint8_t vinswvrx[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xa4, 0xa5, 0xa6, 0xa7, 0xff,
    };

    run_ppc64_power10_vmx_vins_vector_op(
        (const uint8_t *)"\x10\x66\x38\x0f", seed, src, 2, vinsbvlx);
    run_ppc64_power10_vmx_vins_vector_op(
        (const uint8_t *)"\x10\x66\x39\x4f", seed, src, 4, vinshvrx);
    run_ppc64_power10_vmx_vins_vector_op(
        (const uint8_t *)"\x10\x66\x38\x8f", seed, src, 5, vinswvlx);
    run_ppc64_power10_vmx_vins_vector_op(
        (const uint8_t *)"\x10\x66\x39\x8f", seed, src, 1, vinswvrx);
}

static void test_ppc64_power10_vmx_divmod_word(void)
{
    const uint8_t zero[16] = { 0 };
    const uint8_t a[16] = {
        0xff, 0xff, 0xff, 0xf6, 0x00, 0x00, 0x00, 0x14,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    };
    const uint8_t b[16] = {
        0x00, 0x00, 0x00, 0x03, 0xff, 0xff, 0xff, 0xfc,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t vdivsw[16] = {
        0xff, 0xff, 0xff, 0xfd, 0xff, 0xff, 0xff, 0xfb,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    };
    const uint8_t vdivuw[16] = {
        0x55, 0x55, 0x55, 0x52, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    };
    const uint8_t vmodsw[16] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t vmoduw[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x29\x8b",
                                  a, b, zero, vdivsw);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x28\x8b",
                                  a, b, zero, vdivuw);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2f\x8b",
                                  a, b, zero, vmodsw);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2e\x8b",
                                  a, b, zero, vmoduw);
}

static void test_ppc64_power10_vmx_divmod_dword(void)
{
    const uint8_t zero[16] = { 0 };
    const uint8_t a_signed[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf6,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t b_signed[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    const uint8_t a_zero[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    };
    const uint8_t b_zero[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t a_unsigned[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf6,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    };
    const uint8_t b_unsigned[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t vdivsd[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t vmodsd[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t vdivsd_zero[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    };
    const uint8_t vmodsd_zero[16] = { 0 };
    const uint8_t vdivud[16] = {
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x52,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    };
    const uint8_t vmodud[16] = { 0 };

    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x29\xcb",
                                  a_signed, b_signed, zero, vdivsd);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2f\xcb",
                                  a_signed, b_signed, zero, vmodsd);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x29\xcb",
                                  a_zero, b_zero, zero, vdivsd_zero);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2f\xcb",
                                  a_zero, b_zero, zero, vmodsd_zero);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x28\xcb",
                                  a_unsigned, b_unsigned, zero, vdivud);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2e\xcb",
                                  a_unsigned, b_unsigned, zero, vmodud);
}

static void test_ppc64_power10_vmx_divide_extended(void)
{
    const uint8_t zero[16] = { 0 };
    const uint8_t a_word[16] = {
        0x00, 0x00, 0x00, 0x05, 0xff, 0xff, 0xff, 0xfb,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    };
    const uint8_t b_word_signed[16] = {
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t b_word_unsigned[16] = {
        0x00, 0x00, 0x00, 0x04, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    };
    const uint8_t vdivesw[16] = {
        0x40, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t vdiveuw[16] = {
        0x40, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfb,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    };
    const uint8_t a_dword[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb,
    };
    const uint8_t b_dword[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
    };
    const uint8_t a_dword_edge[16] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    };
    const uint8_t b_dword_edge[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t a_dword_unsigned[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    };
    const uint8_t b_dword_unsigned[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t vdivesd[16] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t vdivesd_edge[16] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    };
    const uint8_t vdiveud[16] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    };
    const uint8_t a_quad_pos[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    };
    const uint8_t a_quad_neg[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb,
    };
    const uint8_t b_quad[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
    };
    const uint8_t vdivesq_pos[16] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t vdivesq_neg[16] = {
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2b\x8b",
                                  a_word, b_word_signed, zero, vdivesw);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2a\x8b",
                                  a_word, b_word_unsigned, zero, vdiveuw);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2b\xcb",
                                  a_dword, b_dword, zero, vdivesd);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2b\xcb",
                                  a_dword_edge, b_dword_edge, zero,
                                  vdivesd_edge);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2a\xcb",
                                  a_dword_unsigned, b_dword_unsigned, zero,
                                  vdiveud);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2b\x0b",
                                  a_quad_pos, b_quad, zero, vdivesq_pos);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2b\x0b",
                                  a_quad_neg, b_quad, zero, vdivesq_neg);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2a\x0b",
                                  a_quad_pos, b_quad, zero, vdivesq_pos);
}

static void test_ppc64_power10_vmx_divmod_quad(void)
{
    const uint8_t zero[16] = { 0 };
    const uint8_t pos100[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64,
    };
    const uint8_t neg100[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x9c,
    };
    const uint8_t seven[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    };
    const uint8_t int128_min[16] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t neg_one[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    const uint8_t vdivuq[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e,
    };
    const uint8_t vmoduq[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    };
    const uint8_t vdivsq[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf2,
    };
    const uint8_t vmodsq[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    };

    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x28\x0b",
                                  pos100, seven, zero, vdivuq);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2e\x0b",
                                  pos100, seven, zero, vmoduq);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x29\x0b",
                                  neg100, seven, zero, vdivsq);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2f\x0b",
                                  neg100, seven, zero, vmodsq);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x28\x0b",
                                  pos100, zero, zero, pos100);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2e\x0b",
                                  pos100, zero, zero, zero);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x29\x0b",
                                  int128_min, neg_one, zero, int128_min);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x2f\x0b",
                                  int128_min, neg_one, zero, zero);
}

static void run_ppc64_power10_vmx_vstri_op(const uint8_t op[4],
                                           const uint8_t src[16],
                                           uint32_t initial_cr6,
                                           const uint8_t expected[16],
                                           uint32_t expected_cr6)
{
    uc_engine *uc;
    uint64_t src_addr = code_start + 0x1000;
    uint64_t dst_addr = code_start + 0x1100;
    uint64_t msr;
    uint32_t cr6;
    uint8_t dst[16] = { 0 };
    uint8_t code[12] = {
        0x7c, 0xa0, 0x60, 0xce,
        0, 0, 0, 0,
        0x7c, 0x60, 0x79, 0xce,
    };

    memcpy(code + 4, op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, src_addr, src, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 25;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &src_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_CR6, &initial_cr6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    OK(uc_reg_read(uc, UC_PPC_REG_CR6, &cr6));

    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);
    TEST_CHECK(cr6 == expected_cr6);

    OK(uc_close(uc));
}

static void test_ppc64_power10_vmx_string_isolate(void)
{
    const uint8_t vstribl_src[16] = {
        0x11, 0x22, 0x00, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    };
    const uint8_t vstribr_src[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x00, 0x0d, 0x0e, 0x0f,
    };
    const uint8_t vstrihl_src[16] = {
        0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x55, 0x66,
        0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
    };
    const uint8_t vstrihr_src[16] = {
        0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x00, 0x00,
        0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77,
    };
    const uint8_t vstribl_expected[16] = {
        0x11, 0x22, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t vstribr_expected[16] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0x0d, 0x0e, 0x0f,
    };
    const uint8_t vstrihl_expected[16] = {
        0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t vstrihr_expected[16] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77,
    };

    run_ppc64_power10_vmx_vstri_op((const uint8_t *)"\x10\x60\x2c\x0d",
                                   vstribl_src, 8, vstribl_expected, 2);
    run_ppc64_power10_vmx_vstri_op((const uint8_t *)"\x10\x61\x28\x0d",
                                   vstribr_src, 8, vstribr_expected, 8);
    run_ppc64_power10_vmx_vstri_op((const uint8_t *)"\x10\x62\x2c\x0d",
                                   vstrihl_src, 8, vstrihl_expected, 2);
    run_ppc64_power10_vmx_vstri_op((const uint8_t *)"\x10\x63\x28\x0d",
                                   vstrihr_src, 8, vstrihr_expected, 8);
}

static void run_ppc64_power10_vmx_vclr_op(const uint8_t op[4],
                                          uint64_t count,
                                          const uint8_t expected[16])
{
    uc_engine *uc;
    uint64_t src_addr = code_start + 0x1000;
    uint64_t dst_addr = code_start + 0x1100;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    const uint8_t src[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    uint8_t code[12] = {
        0x7c, 0x80, 0x60, 0xce,
        0, 0, 0, 0,
        0x7c, 0x60, 0x79, 0xce,
    };

    memcpy(code + 4, op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, src_addr, src, sizeof(src)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 25;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_5, &count));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &src_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_vmx_clear_bytes(void)
{
    const uint8_t vclrlb5[16] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const uint8_t vclrlb16[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const uint8_t vclrrb5[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t vclrrb11[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0, 0, 0, 0, 0,
    };

    run_ppc64_power10_vmx_vclr_op((const uint8_t *)"\x10\x64\x29\x8d",
                                  5, vclrlb5);
    run_ppc64_power10_vmx_vclr_op((const uint8_t *)"\x10\x64\x29\x8d",
                                  16, vclrlb16);
    run_ppc64_power10_vmx_vclr_op((const uint8_t *)"\x10\x64\x29\xcd",
                                  5, vclrrb5);
    run_ppc64_power10_vmx_vclr_op((const uint8_t *)"\x10\x64\x29\xcd",
                                  11, vclrrb11);
}

static void test_ppc64_power10_vmx_string_clear_legacy_buckets(void)
{
    const uint8_t zero[16] = { 0 };
    const uint8_t a[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const uint8_t b[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const uint8_t vmrghb[16] = {
        0x00, 0xa0, 0x01, 0xa1, 0x02, 0xa2, 0x03, 0xa3,
        0x04, 0xa4, 0x05, 0xa5, 0x06, 0xa6, 0x07, 0xa7,
    };
    const uint8_t vmrglw[16] = {
        0x08, 0x09, 0x0a, 0x0b, 0xa8, 0xa9, 0xaa, 0xab,
        0x0c, 0x0d, 0x0e, 0x0f, 0xac, 0xad, 0xae, 0xaf,
    };

    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x28\x0c",
                                  a, b, zero, vmrghb);
    run_ppc64_power10_vmx_quad_op((const uint8_t *)"\x10\x64\x29\x8c",
                                  a, b, zero, vmrglw);
}

static void test_ppc64_power10_vmx_string_clear_requires_isa310(void)
{
    uc_engine *uc;
    size_t i;
    uint64_t msr;
    static const uint8_t code[][4] = {
        { 0x10, 0x60, 0x28, 0x0d },
        { 0x10, 0x60, 0x2c, 0x0d },
        { 0x10, 0x64, 0x29, 0x8d },
        { 0x10, 0x64, 0x29, 0xcd },
    };

    for (i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, code[i], sizeof(code[i])));

        OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
        msr |= 1ull << 25;
        OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

        TEST_CHECK(uc_emu_start(uc, code_start,
                                code_start + sizeof(code[i]), 0, 0) ==
                   UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

static void run_ppc64_vmx_va_op(const uint8_t op[4], int cpu_model,
                                const uint8_t a[16], const uint8_t b[16],
                                const uint8_t c[16],
                                const uint8_t expected[16])
{
    uc_engine *uc;
    uint64_t a_addr = code_start + 0x1000;
    uint64_t b_addr = code_start + 0x1010;
    uint64_t c_addr = code_start + 0x1020;
    uint64_t dst_addr = code_start + 0x1030;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    uint8_t code[20] = {
        0x7c, 0x80, 0x60, 0xce,
        0x7c, 0xa0, 0x68, 0xce,
        0x7c, 0xc0, 0x70, 0xce,
        0, 0, 0, 0,
        0x7c, 0x60, 0x79, 0xce,
    };

    memcpy(code + 12, op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, cpu_model));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, a_addr, a, 16));
    OK(uc_mem_write(uc, b_addr, b, 16));
    OK(uc_mem_write(uc, c_addr, c, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 25;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &a_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &b_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &c_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_isa300_vmx_multiply_sum_dword(void)
{
    const uint8_t vmsumudm_a[16] = {
        0, 0, 0, 0, 0, 0, 0, 3,
        0, 0, 0, 0, 0, 0, 0, 5,
    };
    const uint8_t vmsumudm_b[16] = {
        0, 0, 0, 0, 0, 0, 0, 7,
        0, 0, 0, 0, 0, 0, 0, 11,
    };
    const uint8_t vmsumudm_c[16] = {
        0, 0, 0, 0, 0, 0, 0, 1,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0,
    };
    const uint8_t vmsumudm_expected[16] = {
        0, 0, 0, 0, 0, 0, 0, 2,
        0, 0, 0, 0, 0, 0, 0, 0x3c,
    };
    const uint8_t vmladduhm_a[16] = {
        0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
        0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08,
    };
    const uint8_t vmladduhm_b[16] = {
        0x00, 0x09, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c,
        0x00, 0x0d, 0x00, 0x0e, 0x00, 0x0f, 0x00, 0x10,
    };
    const uint8_t vmladduhm_c[16] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
    };
    const uint8_t vmladduhm_expected[16] = {
        0x00, 0x09, 0x00, 0x15, 0x00, 0x21, 0x00, 0x32,
        0x00, 0x41, 0x00, 0x57, 0x00, 0x69, 0x00, 0x84,
    };

    run_ppc64_vmx_va_op((const uint8_t *)"\x10\x64\x29\xa3",
                        UC_CPU_PPC64_POWER9_V2_0, vmsumudm_a, vmsumudm_b,
                        vmsumudm_c, vmsumudm_expected);
    run_ppc64_vmx_va_op((const uint8_t *)"\x10\x64\x29\xa2",
                        UC_CPU_PPC64_POWER8_V2_0, vmladduhm_a, vmladduhm_b,
                        vmladduhm_c, vmladduhm_expected);
}

static void test_ppc64_power10_vmx_multiply_sum_carry_dword(void)
{
    const uint8_t all_ones[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    const uint8_t expected[16] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 2,
    };

    run_ppc64_vmx_va_op((const uint8_t *)"\x10\x64\x29\x97",
                        UC_CPU_PPC64_POWER10_V1_0, all_ones, all_ones,
                        all_ones, expected);
}

static void test_ppc64_isa300_vmx_multiply_sum_requires_isa300(void)
{
    uc_engine *uc;
    uint64_t msr;
    const uint8_t code[] = { 0x10, 0x64, 0x29, 0xa3 };

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER8_V2_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 25;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0) ==
               UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_ppc64_power10_vmx_multiply_sum_carry_requires_isa310(void)
{
    uc_engine *uc;
    uint64_t msr;
    const uint8_t code[] = { 0x10, 0x64, 0x29, 0x97 };

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 25;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0) ==
               UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void run_ppc64_dfp_fixqq_roundtrip(const uint8_t src[16])
{
    uc_engine *uc;
    uint64_t src_addr = code_start + 0x1000;
    uint64_t dst_addr = code_start + 0x1100;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    const uint8_t code[] = {
        0x7c, 0xa0, 0x60, 0xce,
        0xfc, 0x80, 0x2f, 0xc4,
        0xfc, 0x61, 0x27, 0xc4,
        0x7c, 0x60, 0x79, 0xce,
    };

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, src_addr, src, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 13);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &src_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, src, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_dfp_fixqq_roundtrip(void)
{
    const uint8_t positive[16] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    };
    const uint8_t negative[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    };

    run_ppc64_dfp_fixqq_roundtrip(positive);
    run_ppc64_dfp_fixqq_roundtrip(negative);
}

static void test_ppc64_dfp_fixqq_invalid(void)
{
    uc_engine *uc;
    size_t i;
    uint64_t msr;
    static const uint8_t code[][4] = {
        { 0xfc, 0x62, 0x27, 0xc4 },
        { 0xfc, 0xa0, 0x2f, 0xc4 },
        { 0xfc, 0x61, 0x2f, 0xc4 },
        { 0xfc, 0x61, 0x27, 0xc5 },
    };

    for (i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, code[i], sizeof(code[i])));

        OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
        msr |= (1ull << 25) | (1ull << 13);
        OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

        TEST_CHECK(uc_emu_start(uc, code_start,
                                code_start + sizeof(code[i]), 0, 0) ==
                   UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

static void test_ppc64_power10_vmx_divmod_requires_isa310(void)
{
    uc_engine *uc;
    size_t i;
    uint64_t msr;
    static const uint8_t code[][4] = {
        { 0x10, 0x64, 0x28, 0x0b },
        { 0x10, 0x64, 0x28, 0x8b },
        { 0x10, 0x64, 0x28, 0xcb },
        { 0x10, 0x64, 0x29, 0x0b },
        { 0x10, 0x64, 0x29, 0x8b },
        { 0x10, 0x64, 0x29, 0xcb },
        { 0x10, 0x64, 0x2a, 0x0b },
        { 0x10, 0x64, 0x2a, 0x8b },
        { 0x10, 0x64, 0x2a, 0xcb },
        { 0x10, 0x64, 0x2b, 0x0b },
        { 0x10, 0x64, 0x2b, 0x8b },
        { 0x10, 0x64, 0x2b, 0xcb },
        { 0x10, 0x64, 0x2e, 0x0b },
        { 0x10, 0x64, 0x2e, 0x8b },
        { 0x10, 0x64, 0x2e, 0xcb },
        { 0x10, 0x64, 0x2f, 0x0b },
        { 0x10, 0x64, 0x2f, 0x8b },
        { 0x10, 0x64, 0x2f, 0xcb },
    };

    for (i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, code[i], sizeof(code[i])));

        OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
        msr |= 1ull << 25;
        OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

        TEST_CHECK(uc_emu_start(uc, code_start,
                                code_start + sizeof(code[i]), 0, 0) ==
                   UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

static void test_ppc64_power10_vmx_quad_requires_isa310(void)
{
    uc_engine *uc;
    size_t i;
    uint64_t msr;
    static const uint8_t code[][4] = {
        { 0x10, 0x64, 0x29, 0x05 },
        { 0x10, 0x64, 0x28, 0x05 },
        { 0x10, 0x64, 0x29, 0x16 },
        { 0x10, 0x64, 0x29, 0xc7 },
        { 0x11, 0x84, 0x29, 0x01 },
        { 0x10, 0x64, 0x29, 0xc9 },
        { 0x10, 0x64, 0x2b, 0x89 },
        { 0x10, 0x7b, 0x26, 0x02 },
        { 0x10, 0x64, 0x29, 0x98 },
        { 0x10, 0x66, 0x3a, 0x0f },
        { 0x10, 0x66, 0x38, 0xcf },
        { 0x10, 0x66, 0x38, 0x0f },
    };

    for (i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, code[i], sizeof(code[i])));

        OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
        msr |= 1ull << 25;
        OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

        TEST_CHECK(uc_emu_start(uc, code_start,
                                code_start + sizeof(code[i]), 0, 0) ==
                   UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

static void run_ppc64_power10_vsx_8rr_3src_op(const char *op,
                                              const uint8_t a[16],
                                              const uint8_t b[16],
                                              const uint8_t c[16],
                                              const uint8_t expected[16])
{
    uc_engine *uc;
    uint64_t a_addr = code_start + 0x1000;
    uint64_t b_addr = code_start + 0x1010;
    uint64_t c_addr = code_start + 0x1020;
    uint64_t dst_addr = code_start + 0x1030;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    int i;
    char code[24] =
        "\x7c\x80\x60\xce" /* lvx  v4, 0, r12 */
        "\x7c\xa0\x68\xce" /* lvx  v5, 0, r13 */
        "\x7c\xc0\x70\xce" /* lvx  v6, 0, r14 */
        "\0\0\0\0\0\0\0\0"
        "\x7c\x60\x79\xce"; /* stvx v3, 0, r15 */

    memcpy(code + 12, op, 8);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, a_addr, a, 16));
    OK(uc_mem_write(uc, b_addr, b, 16));
    OK(uc_mem_write(uc, c_addr, c, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &a_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &b_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &c_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));

    for (i = 0; i < 16; i++) {
        TEST_CHECK(dst[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void run_ppc64_power10_vsx_8rr_splat_op(const char *op,
                                               const uint8_t expected[16])
{
    uc_engine *uc;
    uint64_t dst_addr = code_start + 0x1000;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    char code[12] =
        "\0\0\0\0\0\0\0\0"
        "\x7c\x60\x79\xce"; /* stvx v3, 0, r15 */

    memcpy(code, op, 8);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static uint8_t ppc_xxeval_byte(uint8_t a, uint8_t b, uint8_t c, uint8_t imm)
{
    uint8_t result = 0;
    int bit;

    for (bit = 0; bit < 8; bit++) {
        uint8_t index = (((a >> bit) & 1) << 2) |
                        (((b >> bit) & 1) << 1) |
                        ((c >> bit) & 1);

        if (imm & (1 << (7 - index))) {
            result |= 1 << bit;
        }
    }

    return result;
}

static void test_ppc64_power10_xxeval(void)
{
    const uint8_t a[16] = {
        0x00, 0xff, 0x55, 0xaa, 0x0f, 0xf0, 0x33, 0xcc,
        0x11, 0x22, 0x44, 0x88, 0x7e, 0x81, 0x18, 0xe7,
    };
    const uint8_t b[16] = {
        0xff, 0x00, 0xaa, 0x55, 0xf0, 0x0f, 0xcc, 0x33,
        0x88, 0x44, 0x22, 0x11, 0x81, 0x7e, 0xe7, 0x18,
    };
    const uint8_t c[16] = {
        0x3c, 0xc3, 0x5a, 0xa5, 0x96, 0x69, 0x0f, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0xfe, 0xef, 0xdc, 0xcd,
    };
    uint8_t expected[16];
    int i;

    for (i = 0; i < 16; i++) {
        expected[i] = ppc_xxeval_byte(a[i], b[i], c[i], 0x96);
    }

    run_ppc64_power10_vsx_8rr_3src_op(
        "\x05\x00\x00\x96"
        "\x88\x64\x29\x9f",
        a, b, c, expected);
}

static void test_ppc64_power10_xxblendvb(void)
{
    const uint8_t a[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const uint8_t b[16] = {
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };
    const uint8_t c[16] = {
        0x00, 0x80, 0x7f, 0xff, 0x01, 0x81, 0x40, 0xc0,
        0x08, 0x88, 0x70, 0xf0, 0x10, 0x90, 0x20, 0xa0,
    };
    uint8_t expected[16];
    int i;

    for (i = 0; i < 16; i++) {
        expected[i] = c[i] & 0x80 ? b[i] : a[i];
    }

    run_ppc64_power10_vsx_8rr_3src_op(
        "\x05\x00\x00\x00"
        "\x84\x64\x29\x8f",
        a, b, c, expected);
}

static void test_ppc64_power10_xxblendvd(void)
{
    const uint8_t a[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };
    const uint8_t b[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    };
    const uint8_t c[16] = {
        0x80, 0, 0, 0, 0, 0, 0, 0,
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    const uint8_t expected[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };

    run_ppc64_power10_vsx_8rr_3src_op(
        "\x05\x00\x00\x00"
        "\x84\x64\x29\xbf",
        a, b, c, expected);
}

static uint8_t ppc_xxpermx_byte(const uint8_t a[16], const uint8_t b[16],
                                uint8_t c, uint8_t uim)
{
    uint8_t idx;

    if ((c >> 5) != uim) {
        return 0;
    }

    idx = c & 0x1f;
    if (idx < 16) {
        return a[idx];
    }
    return b[idx - 16];
}

static void test_ppc64_power10_xxpermx(void)
{
    const uint8_t a[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const uint8_t b[16] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    };
    const uint8_t c[16] = {
        0x20, 0x2f, 0x30, 0x3f, 0x00, 0x40, 0x25, 0x35,
        0x21, 0x31, 0x22, 0x32, 0x23, 0x33, 0x24, 0x34,
    };
    uint8_t expected[16];
    int i;

    for (i = 0; i < 16; i++) {
        expected[i] = ppc_xxpermx_byte(a, b, c[i], 1);
    }

    run_ppc64_power10_vsx_8rr_3src_op(
        "\x05\x00\x00\x01"
        "\x88\x64\x29\x8f",
        a, b, c, expected);
}

static void test_ppc64_power10_xxspltiw(void)
{
    const uint8_t expected[16] = {
        0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44,
        0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44,
    };

    run_ppc64_power10_vsx_8rr_splat_op(
        "\x05\x00\x11\x22"
        "\x80\x67\x33\x44",
        expected);
}

static void test_ppc64_power10_xxspltidp(void)
{
    const uint8_t expected[16] = {
        0x3f, 0xf0, 0, 0, 0, 0, 0, 0,
        0x3f, 0xf0, 0, 0, 0, 0, 0, 0,
    };

    run_ppc64_power10_vsx_8rr_splat_op(
        "\x05\x00\x3f\x80"
        "\x80\x65\x00\x00",
        expected);
}

static void test_ppc64_power10_xxsplti32dx(void)
{
    uc_engine *uc;
    uint64_t dst_addr = code_start + 0x1000;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    const uint8_t expected[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    };
    const char code[] =
        "\x05\x00\x11\x22"
        "\x80\x67\x33\x44"
        "\x05\x00\x55\x66"
        "\x80\x63\x77\x88"
        "\x7c\x60\x79\xce"; /* stvx v3, 0, r15 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void run_ppc64_power10_xxgenpcv_op(const uint8_t op[4],
                                          const uint8_t src[16],
                                          const uint8_t expected[16])
{
    uc_engine *uc;
    uint64_t src_addr = code_start + 0x1000;
    uint64_t dst_addr = code_start + 0x1100;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    uint8_t code[12] = {
        0x7c, 0xa0, 0x60, 0xce,
        0, 0, 0, 0,
        0x7c, 0x80, 0x79, 0xce,
    };

    memcpy(&code[4], op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, src_addr, src, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &src_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_xxgenpcv(void)
{
    const uint8_t src[16] = {
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    };
    const uint8_t be_all[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const uint8_t le_all[16] = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    };
    const uint8_t sparse[16] = {
        0x80, 0x00, 0x00, 0x80, 0x00, 0x80, 0x00, 0x00,
        0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
    };
    const uint8_t be_exp_sparse[16] = {
        0x00, 0x11, 0x12, 0x01, 0x14, 0x02, 0x16, 0x17,
        0x18, 0x03, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x04,
    };
    const uint8_t be_comp_sparse[16] = {
        0x00, 0x03, 0x05, 0x09, 0x0f, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t le_exp_sparse[16] = {
        0x04, 0x1e, 0x1d, 0x03, 0x1b, 0x02, 0x19, 0x18,
        0x17, 0x01, 0x15, 0x14, 0x13, 0x12, 0x11, 0x00,
    };
    const uint8_t le_comp_sparse[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0f, 0x0c, 0x0a, 0x06, 0x00,
    };

    run_ppc64_power10_xxgenpcv_op(
        (const uint8_t *)"\xf0\x80\x2f\x29", src, be_all);
    run_ppc64_power10_xxgenpcv_op(
        (const uint8_t *)"\xf0\x81\x2f\x29", src, be_all);
    run_ppc64_power10_xxgenpcv_op(
        (const uint8_t *)"\xf0\x82\x2f\x29", src, le_all);
    run_ppc64_power10_xxgenpcv_op(
        (const uint8_t *)"\xf0\x83\x2f\x29", src, le_all);
    run_ppc64_power10_xxgenpcv_op(
        (const uint8_t *)"\xf0\x80\x2f\x2b", src, be_all);
    run_ppc64_power10_xxgenpcv_op(
        (const uint8_t *)"\xf0\x80\x2f\x69", src, be_all);
    run_ppc64_power10_xxgenpcv_op(
        (const uint8_t *)"\xf0\x80\x2f\x6b", src, be_all);
    run_ppc64_power10_xxgenpcv_op(
        (const uint8_t *)"\xf0\x80\x2f\x29", sparse, be_exp_sparse);
    run_ppc64_power10_xxgenpcv_op(
        (const uint8_t *)"\xf0\x81\x2f\x29", sparse, be_comp_sparse);
    run_ppc64_power10_xxgenpcv_op(
        (const uint8_t *)"\xf0\x82\x2f\x29", sparse, le_exp_sparse);
    run_ppc64_power10_xxgenpcv_op(
        (const uint8_t *)"\xf0\x83\x2f\x29", sparse, le_comp_sparse);
}

static void run_ppc64_power10_lxvkq_op(const uint8_t op[4],
                                       const uint8_t expected[16])
{
    uc_engine *uc;
    uint64_t dst_addr = code_start + 0x1000;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    uint8_t code[8] = {
        0, 0, 0, 0,
        0x7c, 0x80, 0x79, 0xce,
    };

    memcpy(code, op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_lxvkq(void)
{
    const uint8_t positive_two[16] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t negative_zero[16] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t positive_inf[16] = {
        0x7f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t dquiet_nan[16] = {
        0x7f, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0, 0, 0, 0, 0, 0, 0, 0,
    };

    run_ppc64_power10_lxvkq_op(
        (const uint8_t *)"\xf0\x9f\x12\xd1", positive_two);
    run_ppc64_power10_lxvkq_op(
        (const uint8_t *)"\xf0\x9f\x82\xd1", negative_zero);
    run_ppc64_power10_lxvkq_op(
        (const uint8_t *)"\xf0\x9f\x42\xd1", positive_inf);
    run_ppc64_power10_lxvkq_op(
        (const uint8_t *)"\xf0\x9f\x4a\xd1", dquiet_nan);
}

static void test_ppc64_power10_xxgenpcv_lxvkq_invalid(void)
{
    uc_engine *uc;
    size_t i;
    uint64_t msr;
    static const uint8_t code[][4] = {
        { 0xf0, 0x84, 0x2f, 0x29 },
        { 0xf0, 0x9f, 0x02, 0xd1 },
        { 0xf0, 0x9f, 0x52, 0xd1 },
        { 0xf0, 0x9f, 0xca, 0xd1 },
        { 0xf0, 0x9e, 0x12, 0xd1 },
    };

    for (i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, code[i], sizeof(code[i])));

        OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
        msr |= (1ull << 25) | (1ull << 23);
        OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

        TEST_CHECK(uc_emu_start(uc, code_start,
                                code_start + sizeof(code[i]), 0, 0) ==
                   UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

static void test_ppc64_power10_xxgenpcv_lxvkq_requires_isa310(void)
{
    uc_engine *uc;
    uint64_t msr;
    size_t i;
    static const uint8_t code[][4] = {
        { 0xf0, 0x80, 0x2f, 0x29 },
        { 0xf0, 0x9f, 0x12, 0xd1 },
    };

    for (i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, code[i], sizeof(code[i])));

        OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
        msr |= (1ull << 25) | (1ull << 23);
        OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

        TEST_CHECK(uc_emu_start(uc, code_start,
                                code_start + sizeof(code[i]), 0, 0) ==
                   UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

static void run_ppc64_power10_xvtlsbb(const uint8_t src[16],
                                      uint32_t expected)
{
    uc_engine *uc;
    uint64_t src_addr = code_start + 0x1000;
    uint64_t msr;
    uint32_t cr2 = 0;
    const char code[] =
        "\x7c\x80\x60\xce" /* lvx     v4, 0, r12 */
        "\xf1\x02\x27\x6e"; /* xvtlsbb cr2, vs36 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, src_addr, src, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &src_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_CR2, &cr2));
    TEST_CHECK(cr2 == expected);

    OK(uc_close(uc));
}

static void test_ppc64_power10_xvtlsbb(void)
{
    const uint8_t all_false[16] = { 0 };
    const uint8_t all_true[16] = {
        1, 3, 5, 7, 9, 0x0b, 0x0d, 0x0f,
        0x11, 0x13, 0x15, 0x17, 0x19, 0x1b, 0x1d, 0x1f,
    };
    const uint8_t mixed[16] = {
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    run_ppc64_power10_xvtlsbb(all_false, 2);
    run_ppc64_power10_xvtlsbb(all_true, 8);
    run_ppc64_power10_xvtlsbb(mixed, 0);
}

static void ppc64_store_be32(uint8_t dest[4], uint32_t value)
{
    dest[0] = value >> 24;
    dest[1] = value >> 16;
    dest[2] = value >> 8;
    dest[3] = value;
}

static uint64_t ppc64_load_be64(const uint8_t src[8])
{
    uint64_t value = 0;
    int i;

    for (i = 0; i < 8; i++) {
        value = (value << 8) | src[i];
    }

    return value;
}

static uint32_t ppc64_vgnb_opcode(int rt, int vrb, int n)
{
    return (0x04u << 26) | ((uint32_t)rt << 21) |
           ((uint32_t)n << 16) | ((uint32_t)vrb << 11) | 0x4ccu;
}

static uint32_t ppc64_x_opcode(int rt, int ra, int rb, int opc2, int opc3,
                               int rc)
{
    return (0x1fu << 26) | ((uint32_t)rt << 21) |
           ((uint32_t)ra << 16) | ((uint32_t)rb << 11) |
           ((uint32_t)opc3 << 6) | ((uint32_t)opc2 << 1) |
           (uint32_t)rc;
}

static uint32_t ppc64_fp_xo4_opcode(int rt, int opc4, int rb)
{
    return (0x3fu << 26) | ((uint32_t)rt << 21) |
           ((uint32_t)opc4 << 16) | ((uint32_t)rb << 11) |
           (0x12u << 6) | (0x07u << 1);
}

static uint32_t ppc64_slbiag_opcode(int rs, int l)
{
    return ppc64_x_opcode(rs, l, 0, 0x12, 0x1a, 0);
}

static uint64_t ppc64_vgnb_ref(const uint8_t src[16], int n)
{
    static const uint64_t mask[6][5] = {
        {
            0xAAAAAAAAAAAAAAAAULL, 0xccccccccccccccccULL,
            0xf0f0f0f0f0f0f0f0ULL, 0xff00ff00ff00ff00ULL,
            0xffff0000ffff0000ULL
        },
        {
            0x9249249249249249ULL, 0xC30C30C30C30C30CULL,
            0xF00F00F00F00F00FULL, 0xFF0000FF0000FF00ULL,
            0xFFFF00000000FFFFULL
        },
        {
            0x8888888888888888ULL, 0,
            0xf000f000f000f000ULL, 0, 0xFFFF000000000000ULL
        },
        {
            0x8421084210842108ULL, 0, 0xF0000F0000F0000FULL, 0, 0
        },
        {
            0x8208208208208208ULL, 0, 0xF00000F00000F000ULL, 0, 0
        },
        {
            0x8102040810204081ULL, 0, 0xF000000F000000F0ULL, 0, 0
        }
    };
    uint64_t hi = ppc64_load_be64(src);
    uint64_t lo = ppc64_load_be64(src + 8);
    uint64_t m;
    int i;
    int nbits = (64 + n - 1) / n;
    int sh;

    lo <<= n * nbits - 64;

    for (i = 0, sh = n - 1; i < 5; i++, sh <<= 1) {
        m = mask[n - 2][i];
        if (m) {
            hi &= m;
            lo &= m;
        }
        if (sh < 64) {
            hi = (hi << sh) | hi;
            lo = (lo << sh) | lo;
        }
    }

    m = ~(~0ULL >> nbits);
    hi &= m;
    lo &= m;
    lo >>= nbits;

    return hi | lo;
}

static void run_ppc64_power10_vgnb(int n, const uint8_t src[16])
{
    uc_engine *uc;
    uint64_t src_addr = code_start + 0x1000;
    uint64_t msr;
    uint64_t r3;
    uint32_t op = ppc64_vgnb_opcode(3, 4, n);
    uint8_t code[8] = {
        0x7c, 0x80, 0x60, 0xce,
        0, 0, 0, 0,
    };

    ppc64_store_be32(code + 4, op);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, src_addr, src, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &src_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_3, &r3));
    TEST_CHECK(r3 == ppc64_vgnb_ref(src, n));

    OK(uc_close(uc));
}

static void test_ppc64_power10_vgnb(void)
{
    const uint8_t src[16] = {
        0x81, 0x42, 0x24, 0x18, 0xff, 0x00, 0x99, 0x66,
        0x3c, 0xc3, 0x5a, 0xa5, 0x01, 0x80, 0x7e, 0xe7,
    };

    run_ppc64_power10_vgnb(2, src);
    run_ppc64_power10_vgnb(3, src);
    run_ppc64_power10_vgnb(7, src);
}

static void test_ppc64_power10_vgnb_undefined_no_change(void)
{
    uc_engine *uc;
    uint64_t msr;
    uint64_t r3;
    uint64_t initial = 0x0123456789abcdefULL;
    int i;

    for (i = 0; i < 2; i++) {
        uint32_t op = ppc64_vgnb_opcode(3, 4, i);
        uint8_t code[4];

        ppc64_store_be32(code, op);

        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, code, sizeof(code)));

        OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
        msr |= (1ull << 25) | (1ull << 23);
        OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
        OK(uc_reg_write(uc, UC_PPC_REG_3, &initial));

        OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
        OK(uc_reg_read(uc, UC_PPC_REG_3, &r3));
        TEST_CHECK(r3 == initial);

        OK(uc_close(uc));
    }
}

static void test_ppc64_power10_vgnb_invalid(void)
{
    uc_engine *uc;
    uint64_t msr;
    uint32_t op = ppc64_vgnb_opcode(3, 4, 2) | 0x00080000u;
    uint8_t code[4];

    ppc64_store_be32(code, op);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0) ==
               UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_ppc64_power10_vgnb_requires_isa310(void)
{
    uc_engine *uc;
    uint64_t msr;
    uint32_t op = ppc64_vgnb_opcode(3, 4, 2);
    uint8_t code[4];

    ppc64_store_be32(code, op);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0) ==
               UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static uint64_t ppc64_addg6s_ref(uint64_t a, uint64_t b)
{
    uint64_t carry = 0;
    uint64_t t = 0;
    int i;

    for (i = 0; i < 16; i++) {
        t += (a >> (i * 4)) & 0xf;
        t += (b >> (i * 4)) & 0xf;
        t = (t & 0x10) != 0;
        carry |= t << (i * 4);
    }

    carry ^= 0x1111111111111111ULL;
    return carry * 6;
}

static void test_ppc64_isa206_bcd_addg6s(void)
{
    uc_engine *uc;
    uint64_t r3 = 0x0901090109010901ULL;
    uint64_t r4 = 0x0109010901090109ULL;
    uint64_t r5;
    uint64_t r6;
    uint32_t op0 = ppc64_x_opcode(5, 3, 4, 0x0a, 0x02, 0);
    uint32_t op1 = ppc64_x_opcode(6, 3, 4, 0x0a, 0x12, 0);
    uint8_t code[8];

    ppc64_store_be32(code, op0);
    ppc64_store_be32(code + 4, op1);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER7_V2_3));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_reg_write(uc, UC_PPC_REG_3, &r3));
    OK(uc_reg_write(uc, UC_PPC_REG_4, &r4));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_5, &r5));
    OK(uc_reg_read(uc, UC_PPC_REG_6, &r6));
    TEST_CHECK(r5 == ppc64_addg6s_ref(r3, r4));
    TEST_CHECK(r6 == ppc64_addg6s_ref(r3, r4));

    OK(uc_close(uc));
}

static void test_ppc64_isa206_bcd_convert(void)
{
    uc_engine *uc;
    uint64_t r3;
    uint64_t r4 = 0x0000000100000001ULL;
    uint64_t r5;
    uint64_t r6;
    uint64_t r7 = 0x0009876500012345ULL;
    uint32_t cdtbcd_r3_r4 = ppc64_x_opcode(4, 3, 0, 0x1a, 0x08, 0);
    uint32_t cbcdtd_r5_r7 = ppc64_x_opcode(7, 5, 0, 0x1a, 0x09, 0);
    uint32_t cdtbcd_r6_r5 = ppc64_x_opcode(5, 6, 0, 0x1a, 0x08, 0);
    uint8_t code[12];

    ppc64_store_be32(code, cdtbcd_r3_r4);
    ppc64_store_be32(code + 4, cbcdtd_r5_r7);
    ppc64_store_be32(code + 8, cdtbcd_r6_r5);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER7_V2_3));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_reg_write(uc, UC_PPC_REG_4, &r4));
    OK(uc_reg_write(uc, UC_PPC_REG_7, &r7));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_3, &r3));
    OK(uc_reg_read(uc, UC_PPC_REG_5, &r5));
    OK(uc_reg_read(uc, UC_PPC_REG_6, &r6));
    TEST_CHECK(r3 == r4);
    TEST_CHECK(r5 != 0);
    TEST_CHECK(r6 == r7);

    OK(uc_close(uc));
}

static void test_ppc64_isa206_bcd_requires_bcda(void)
{
    uc_engine *uc;
    uint32_t code[] = {
        ppc64_x_opcode(5, 3, 4, 0x0a, 0x02, 0),
        ppc64_x_opcode(4, 3, 0, 0x1a, 0x08, 0),
        ppc64_x_opcode(4, 3, 0, 0x1a, 0x09, 0),
    };
    uint8_t insn[4];
    size_t i;

    for (i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        ppc64_store_be32(insn, code[i]);

        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER5_V2_1));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, insn, sizeof(insn)));

        TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(insn),
                                0, 0) == UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

static void test_ppc64_isa300_slbiag(void)
{
    uc_engine *uc;
    uint64_t r3 = 0x1000000000000000ull;
    uint64_t r4 = 0x2000000000000000ull;
    uint64_t pc = 0;
    uint32_t code[] = {
        ppc64_slbiag_opcode(3, 0),
        ppc64_slbiag_opcode(4, 1),
    };
    uint8_t insn[8];

    ppc64_store_be32(insn, code[0]);
    ppc64_store_be32(insn + 4, code[1]);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, insn, sizeof(insn)));
    OK(uc_reg_write(uc, UC_PPC_REG_3, &r3));
    OK(uc_reg_write(uc, UC_PPC_REG_4, &r4));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(insn), 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_PC, &pc));
    TEST_CHECK(pc == code_start + sizeof(insn));

    OK(uc_close(uc));
}

static void test_ppc64_isa300_slbiag_exceptions(void)
{
    uc_engine *uc;
    uint64_t msr;
    uint32_t insns[] = {
        ppc64_slbiag_opcode(3, 0),
        ppc64_slbiag_opcode(3, 0),
        ppc64_slbiag_opcode(3, 0) | 0x00020000u,
        ppc64_slbiag_opcode(3, 0) | 0x00000800u,
    };
    uc_cpu_ppc64 models[] = {
        UC_CPU_PPC64_POWER8_V2_0,
        UC_CPU_PPC64_POWER9_V2_0,
        UC_CPU_PPC64_POWER9_V2_0,
        UC_CPU_PPC64_POWER9_V2_0,
    };
    bool pr[] = { false, true, false, false };
    uint8_t code[4];
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        ppc64_store_be32(code, insns[i]);

        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, models[i]));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, code, sizeof(code)));

        if (pr[i]) {
            OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
            msr |= 1ull << 14;
            OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
        }

        TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code),
                                0, 0) == UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

static void test_ppc64_isa300_mffscdrn(void)
{
    uc_engine *uc;
    uint64_t msr;
    uint32_t fpscr = 0xff;
    uint64_t f4;
    uint64_t f5;
    uint64_t f6;
    uint64_t f7;
    uint64_t f8 = 5ull << 32;
    uint64_t mode = fpscr;
    uint32_t code[] = {
        ppc64_fp_xo4_opcode(4, 0x14, 8),
        ppc64_fp_xo4_opcode(5, 0x15, 2),
        ppc64_fp_xo4_opcode(6, 0x00, 0),
        ppc64_fp_xo4_opcode(7, 0x18, 0),
    };
    uint8_t insn[16];
    size_t i;

    for (i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        ppc64_store_be32(insn + i * 4, code[i]);
    }

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, insn, sizeof(insn)));
    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 13;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_FPSCR, &fpscr));
    OK(uc_reg_write(uc, UC_PPC_REG_FPR8, &f8));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(insn), 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_FPR4, &f4));
    OK(uc_reg_read(uc, UC_PPC_REG_FPR5, &f5));
    OK(uc_reg_read(uc, UC_PPC_REG_FPR6, &f6));
    OK(uc_reg_read(uc, UC_PPC_REG_FPR7, &f7));

    TEST_CHECK(f4 == mode);
    TEST_CHECK(f5 == ((5ull << 32) | mode));
    TEST_CHECK(f6 == ((2ull << 32) | mode));
    TEST_CHECK(f7 == ((2ull << 32) | mode));

    OK(uc_close(uc));
}

static void test_ppc64_isa300_mffscdrn_requires_isa300(void)
{
    uc_engine *uc;
    uint64_t msr;
    uint32_t code[] = {
        ppc64_fp_xo4_opcode(4, 0x01, 0),
        ppc64_fp_xo4_opcode(4, 0x18, 0),
        ppc64_fp_xo4_opcode(4, 0x14, 8),
        ppc64_fp_xo4_opcode(5, 0x15, 2),
        ppc64_fp_xo4_opcode(4, 0x16, 8),
        ppc64_fp_xo4_opcode(5, 0x17, 2),
    };
    uint8_t insn[4];
    size_t i;

    for (i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        ppc64_store_be32(insn, code[i]);

        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER8_V2_0));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, insn, sizeof(insn)));
        OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
        msr |= 1ull << 13;
        OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

        TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(insn),
                                0, 0) == UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

static void test_ppc64_power10_vsx_bf16_convert(void)
{
    uc_engine *uc;
    uint64_t src_addr = code_start + 0x1000;
    uint64_t dst_addr = code_start + 0x1010;
    uint64_t msr;
    const uint8_t src[16] = {
        0x3f, 0x80, 0x00, 0x00,
        0xc0, 0x00, 0x00, 0x00,
        0x40, 0x40, 0x00, 0x00,
        0x3f, 0x00, 0x00, 0x00,
    };
    uint8_t dst[16] = { 0 };
    const char code[] =
        "\x7c\xa0\x60\xce" /* lvx          v5,0,r12 */
        "\xf0\x91\x2f\x6f" /* xvcvspbf16  vs36,vs37 */
        "\xf0\xb0\x27\x6f" /* xvcvbf16spn vs37,vs36 */
        "\x7c\xa0\x69\xce"; /* stvx         v5,0,r13 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, src_addr, src, sizeof(src)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &src_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, src, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_mma_xxsetaccz(void)
{
    uc_engine *uc;
    uint64_t src_addr = code_start + 0x1000;
    uint64_t dst_addr = code_start + 0x1100;
    uint64_t msr;
    uint8_t dst[64] = { 0xff };
    uint8_t expected[64] = { 0 };
    const uint8_t src[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10,
    };
    const char code[] =
        "\x7c\x00\x66\x98" /* lxvd2x    vs0,0,r12 */
        "\x7c\x20\x6e\x98" /* lxvd2x    vs1,0,r13 */
        "\x7c\x40\x76\x98" /* lxvd2x    vs2,0,r14 */
        "\x7c\x60\x7e\x98" /* lxvd2x    vs3,0,r15 */
        "\x7c\x03\x01\x62" /* xxsetaccz acc0 */
        "\x7c\x00\x87\x98" /* stxvd2x   vs0,0,r16 */
        "\x7c\x20\x8f\x98" /* stxvd2x   vs1,0,r17 */
        "\x7c\x40\x97\x98" /* stxvd2x   vs2,0,r18 */
        "\x7c\x60\x9f\x98"; /* stxvd2x   vs3,0,r19 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, src_addr, src, sizeof(src)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &src_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &src_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &src_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &src_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_16, &dst_addr));
    dst_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_17, &dst_addr));
    dst_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_18, &dst_addr));
    dst_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_19, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, code_start + 0x1100, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_mma_acc_moves(void)
{
    uc_engine *uc;
    uint64_t src_addr = code_start + 0x1000;
    uint64_t dst_addr = code_start + 0x1100;
    uint64_t msr;
    uint8_t dst[64] = { 0 };
    uint8_t src[64];
    size_t i;
    const char code[] =
        "\x7c\x00\x66\x98" /* lxvd2x  vs0,0,r12 */
        "\x7c\x20\x6e\x98" /* lxvd2x  vs1,0,r13 */
        "\x7c\x40\x76\x98" /* lxvd2x  vs2,0,r14 */
        "\x7c\x60\x7e\x98" /* lxvd2x  vs3,0,r15 */
        "\x7c\x00\x01\x62" /* xxmfacc acc0 */
        "\x7c\x01\x01\x62" /* xxmtacc acc0 */
        "\x7c\x00\x87\x98" /* stxvd2x vs0,0,r16 */
        "\x7c\x20\x8f\x98" /* stxvd2x vs1,0,r17 */
        "\x7c\x40\x97\x98" /* stxvd2x vs2,0,r18 */
        "\x7c\x60\x9f\x98"; /* stxvd2x vs3,0,r19 */

    for (i = 0; i < sizeof(src); i++) {
        src[i] = (uint8_t)(0x13 + i * 9);
    }

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, src_addr, src, sizeof(src)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &src_addr));
    src_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_13, &src_addr));
    src_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_14, &src_addr));
    src_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_15, &src_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_16, &dst_addr));
    dst_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_17, &dst_addr));
    dst_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_18, &dst_addr));
    dst_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_19, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, code_start + 0x1100, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, src, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void run_ppc64_power10_mma_ger_op(const char *op,
                                         const uint8_t a[16],
                                         const uint8_t b[16],
                                         const uint8_t expected[64])
{
    uc_engine *uc;
    uint64_t a_addr = code_start + 0x1000;
    uint64_t b_addr = code_start + 0x1010;
    uint64_t dst_addr = code_start + 0x1100;
    uint64_t msr;
    uint8_t dst[64] = { 0 };
    char code[28] =
        "\x7c\xa0\x60\xce" /* lvx  v5,0,r12 */
        "\x7c\xc0\x68\xce" /* lvx  v6,0,r13 */
        "\0\0\0\0"
        "\x7c\x00\x77\x98" /* stxvd2x vs0,0,r14 */
        "\x7c\x20\x7f\x98" /* stxvd2x vs1,0,r15 */
        "\x7c\x40\x87\x98" /* stxvd2x vs2,0,r16 */
        "\x7c\x60\x8f\x98"; /* stxvd2x vs3,0,r17 */

    memcpy(code + 8, op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, a_addr, a, 16));
    OK(uc_mem_write(uc, b_addr, b, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &a_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &b_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &dst_addr));
    dst_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));
    dst_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_16, &dst_addr));
    dst_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_17, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, code_start + 0x1100, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_mma_integer_ger(void)
{
    const uint8_t a[16] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    };
    const uint8_t b[16] = {
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    };
    const uint8_t expected[64] = {
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08,
    };

    run_ppc64_power10_mma_ger_op("\xec\x05\x30\x1e", a, b, expected);
}

static void test_ppc64_power10_mma_f32_ger(void)
{
    const uint8_t a[16] = {
        0x3f, 0x80, 0x00, 0x00, 0x3f, 0x80, 0x00, 0x00,
        0x3f, 0x80, 0x00, 0x00, 0x3f, 0x80, 0x00, 0x00,
    };
    const uint8_t b[16] = {
        0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    };
    const uint8_t expected[64] = {
        0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    };

    run_ppc64_power10_mma_ger_op("\xec\x05\x30\xde", a, b, expected);
}

static void test_ppc64_power10_mma_prefixed_f32_ger(void)
{
    uc_engine *uc;
    uint64_t a_addr = code_start + 0x1000;
    uint64_t b_addr = code_start + 0x1010;
    uint64_t dst_addr = code_start + 0x1100;
    uint64_t msr;
    uint8_t dst[64] = { 0 };
    const uint8_t a[16] = {
        0x3f, 0x80, 0x00, 0x00, 0x3f, 0x80, 0x00, 0x00,
        0x3f, 0x80, 0x00, 0x00, 0x3f, 0x80, 0x00, 0x00,
    };
    const uint8_t b[16] = {
        0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    };
    const uint8_t expected[64] = {
        0x40, 0x00, 0x00, 0x00, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const char code[] =
        "\x7c\xa0\x60\xce" /* lvx      v5,0,r12 */
        "\x7c\xc0\x68\xce" /* lvx      v6,0,r13 */
        "\x07\x90\x00\x88" /* pmx prefix, xmsk=8, ymsk=8 */
        "\xec\x05\x30\xde" /* pmxvf32ger acc0,vs37,vs38 */
        "\x7c\x00\x77\x98" /* stxvd2x vs0,0,r14 */
        "\x7c\x20\x7f\x98" /* stxvd2x vs1,0,r15 */
        "\x7c\x40\x87\x98" /* stxvd2x vs2,0,r16 */
        "\x7c\x60\x8f\x98"; /* stxvd2x vs3,0,r17 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, a_addr, a, 16));
    OK(uc_mem_write(uc, b_addr, b, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &a_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &b_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &dst_addr));
    dst_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));
    dst_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_16, &dst_addr));
    dst_addr += 16;
    OK(uc_reg_write(uc, UC_PPC_REG_17, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, code_start + 0x1100, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_mma_requires_isa310(void)
{
    uc_engine *uc;
    uint64_t msr;
    static const uint8_t code[][4] = {
        { 0x7c, 0x00, 0x01, 0x62 },
        { 0x7c, 0x01, 0x01, 0x62 },
        { 0x7c, 0x03, 0x01, 0x62 },
        { 0xec, 0x05, 0x30, 0x1e },
    };
    size_t i;

    for (i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, code[i], sizeof(code[i])));

        OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
        msr |= (1ull << 25) | (1ull << 23);
        OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

        TEST_CHECK(uc_emu_start(uc, code_start,
                                code_start + sizeof(code[i]), 0, 0) ==
                   UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

static void run_ppc64_vsx_qp_madd_op(const char *op,
                                     const uint8_t addend[16],
                                     const uint8_t a[16],
                                     const uint8_t b[16],
                                     const uint8_t expected[16])
{
    uc_engine *uc;
    uint64_t addend_addr = code_start + 0x1000;
    uint64_t a_addr = code_start + 0x1010;
    uint64_t b_addr = code_start + 0x1020;
    uint64_t dst_addr = code_start + 0x1030;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    char code[20] =
        "\x7c\x80\x60\xce" /* lvx  v4,0,r12 */
        "\x7c\xa0\x68\xce" /* lvx  v5,0,r13 */
        "\x7c\xc0\x70\xce" /* lvx  v6,0,r14 */
        "\0\0\0\0"
        "\x7c\x80\x79\xce"; /* stvx v4,0,r15 */

    memcpy(code + 12, op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, addend_addr, addend, 16));
    OK(uc_mem_write(uc, a_addr, a, 16));
    OK(uc_mem_write(uc, b_addr, b, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &addend_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &a_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &b_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void run_ppc64_vsx_qp_xform_op(const char *op,
                                      const uint8_t a[16],
                                      const uint8_t b[16],
                                      const uint8_t expected[16])
{
    uc_engine *uc;
    uint64_t a_addr = code_start + 0x1000;
    uint64_t b_addr = code_start + 0x1010;
    uint64_t dst_addr = code_start + 0x1020;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    char code[16] =
        "\x7c\xa0\x60\xce" /* lvx  v5,0,r12 */
        "\x7c\xc0\x68\xce" /* lvx  v6,0,r13 */
        "\0\0\0\0"
        "\x7c\x80\x71\xce"; /* stvx v4,0,r14 */

    memcpy(code + 8, op, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, a_addr, a, 16));
    OK(uc_mem_write(uc, b_addr, b, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &a_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &b_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void run_ppc64_vsx_qp_convert_roundtrip(const char *to_qp,
                                               const char *from_qp,
                                               const uint8_t src[16])
{
    uc_engine *uc;
    uint64_t src_addr = code_start + 0x1000;
    uint64_t dst_addr = code_start + 0x1010;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    char code[16] =
        "\x7c\xa0\x60\xce" /* lvx  v5,0,r12 */
        "\0\0\0\0"
        "\0\0\0\0"
        "\x7c\xc0\x69\xce"; /* stvx v6,0,r13 */

    memcpy(code + 4, to_qp, 4);
    memcpy(code + 8, from_qp, 4);

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_mem_write(uc, src_addr, src, 16));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &src_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));
    TEST_CHECK(memcmp(dst, src, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_vsx_qp_multiply_add(void)
{
    const uint8_t qp_zero[16] = { 0 };
    const uint8_t qp_one[16] = {
        0x3f, 0xff, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t qp_two[16] = {
        0x40, 0x00, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t qp_negative_two[16] = {
        0xc0, 0x00, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };

    run_ppc64_vsx_qp_madd_op("\xfc\x85\x33\x08", qp_zero, qp_one,
                             qp_two, qp_two);
    run_ppc64_vsx_qp_madd_op("\xfc\x85\x33\x09", qp_zero, qp_one,
                             qp_two, qp_two);
    run_ppc64_vsx_qp_madd_op("\xfc\x85\x33\x48", qp_zero, qp_one,
                             qp_two, qp_two);
    run_ppc64_vsx_qp_madd_op("\xfc\x85\x33\x88", qp_zero, qp_one,
                             qp_two, qp_negative_two);
    run_ppc64_vsx_qp_madd_op("\xfc\x85\x33\xc8", qp_zero, qp_one,
                             qp_two, qp_negative_two);
}

static void test_ppc64_power10_vsx_qp_compare_minmax(void)
{
    const uint8_t qp_one[16] = {
        0x3f, 0xff, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t qp_two[16] = {
        0x40, 0x00, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint8_t false_mask[16] = { 0 };
    const uint8_t true_mask[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };

    run_ppc64_vsx_qp_xform_op("\xfc\x85\x30\x88", qp_one, qp_one,
                              true_mask);
    run_ppc64_vsx_qp_xform_op("\xfc\x85\x31\x88", qp_two, qp_one,
                              true_mask);
    run_ppc64_vsx_qp_xform_op("\xfc\x85\x31\xc8", qp_one, qp_two,
                              false_mask);
    run_ppc64_vsx_qp_xform_op("\xfc\x85\x35\x48", qp_one, qp_two,
                              qp_two);
    run_ppc64_vsx_qp_xform_op("\xfc\x85\x35\xc8", qp_one, qp_two,
                              qp_one);
}

static void test_ppc64_power10_vsx_qp_convert(void)
{
    const uint8_t unsigned_two[16] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 2,
    };
    const uint8_t signed_negative_two[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    };

    run_ppc64_vsx_qp_convert_roundtrip("\xfc\x83\x2e\x88",
                                       "\xfc\xc0\x26\x88",
                                       unsigned_two);
    run_ppc64_vsx_qp_convert_roundtrip("\xfc\x8b\x2e\x88",
                                       "\xfc\xc8\x26\x88",
                                       signed_negative_two);
}

static void test_ppc64_vsx_qp_multiply_add_requires_isa300(void)
{
    uc_engine *uc;
    uint64_t msr;
    const char code[] = "\xfc\x85\x33\x08";

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER8_V2_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_ppc64_power10_vsx_requires_isa310(void)
{
    uc_engine *uc;
    uint64_t src_addr = code_start + 0x1000;
    uint64_t msr;
    const uint8_t zero[16] = { 0 };
    static const char code[][8] = {
        {
            "\x7c\x80\x60\xce"
            "\xf1\x02\x27\x6e"
        },
        {
            "\x7c\xa0\x60\xce"
            "\xf0\x91\x2f\x6f"
        },
        {
            "\x7c\x80\x60\xce"
            "\xf0\x90\x27\x6f"
        },
        {
            "\x7c\x80\x60\xce"
            "\xfc\x85\x30\x88"
        },
        {
            "\x7c\x80\x60\xce"
            "\xfc\x80\x26\x88"
        },
    };
    size_t i;

    for (i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, code[i], sizeof(code[i])));
        OK(uc_mem_write(uc, src_addr, zero, 16));

        OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
        msr |= (1ull << 25) | (1ull << 23);
        OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
        OK(uc_reg_write(uc, UC_PPC_REG_12, &src_addr));

        TEST_CHECK(uc_emu_start(uc, code_start,
                                code_start + sizeof(code[i]), 0, 0) ==
                   UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

static void setup_ppc64_hash(uc_engine **uc, const char *code, size_t size)
{
    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, uc));
    OK(uc_ctl_set_cpu_model(*uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static void test_ppc64_power10_hash_store_check(void)
{
    uc_engine *uc;
    uint64_t base = code_start + 0x1008;
    uint64_t rb = 0x0123456789abcdefull;
    uint8_t stored[8] = { 0 };
    const uint8_t expected[8] = {
        0xdc, 0x02, 0xcd, 0xe3, 0xd6, 0x91, 0x1f, 0xba,
    };
    const char code[] =
        "\x7f\xe4\x2d\xa5" /* hashst  -8(r4), r5 */
        "\x7f\xe4\x2d\xe5"; /* hashchk -8(r4), r5 */

    setup_ppc64_hash(&uc, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_PPC_REG_4, &base));
    OK(uc_reg_write(uc, UC_PPC_REG_5, &rb));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, base - 8, stored, sizeof(stored)));
    TEST_CHECK(memcmp(stored, expected, sizeof(stored)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_hash_key_spr(void)
{
    uc_engine *uc;
    uint64_t base = code_start + 0x1008;
    uint64_t rb = 0x0123456789abcdefull;
    uint64_t key = 0x1122334455667788ull;
    uint8_t stored[8] = { 0 };
    const uint8_t expected[8] = {
        0x96, 0xbf, 0xa7, 0x47, 0xe0, 0x45, 0x85, 0xe2,
    };
    const char code[] =
        "\x7c\xd4\x73\xa6" /* mtspr HASHKEYR, r6 */
        "\x7f\xe4\x2d\xa5"; /* hashst -8(r4), r5 */

    setup_ppc64_hash(&uc, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_PPC_REG_4, &base));
    OK(uc_reg_write(uc, UC_PPC_REG_5, &rb));
    OK(uc_reg_write(uc, UC_PPC_REG_6, &key));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, base - 8, stored, sizeof(stored)));
    TEST_CHECK(memcmp(stored, expected, sizeof(stored)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_hash_check_mismatch(void)
{
    uc_engine *uc;
    uint64_t base = code_start + 0x1008;
    uint64_t rb = 0x1123456789abcdefull;
    const uint8_t stored[8] = {
        0xdc, 0x02, 0xcd, 0xe3, 0xd6, 0x91, 0x1f, 0xba,
    };
    const char code[] = "\x7f\xe4\x2d\xe5"; /* hashchk -8(r4), r5 */

    setup_ppc64_hash(&uc, code, sizeof(code) - 1);
    OK(uc_mem_write(uc, base - 8, stored, sizeof(stored)));
    OK(uc_reg_write(uc, UC_PPC_REG_4, &base));
    OK(uc_reg_write(uc, UC_PPC_REG_5, &rb));

    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                            0, 0) == UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_ppc64_power10_hash_privileged(void)
{
    uc_engine *uc;
    uint64_t base = code_start + 0x1008;
    uint64_t rb = 0x0123456789abcdefull;
    uint8_t stored[8] = { 0 };
    const uint8_t expected[8] = {
        0xdc, 0x02, 0xcd, 0xe3, 0xd6, 0x91, 0x1f, 0xba,
    };
    const char code[] =
        "\x7f\xe4\x2d\x25" /* hashstp  -8(r4), r5 */
        "\x7f\xe4\x2d\x65"; /* hashchkp -8(r4), r5 */

    setup_ppc64_hash(&uc, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_PPC_REG_4, &base));
    OK(uc_reg_write(uc, UC_PPC_REG_5, &rb));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, base - 8, stored, sizeof(stored)));
    TEST_CHECK(memcmp(stored, expected, sizeof(stored)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_hash_privileged_requires_sv(void)
{
    uc_engine *uc;
    uint64_t base = code_start + 0x1008;
    uint64_t rb = 0x0123456789abcdefull;
    uint64_t msr;
    const char code[] = "\x7f\xe4\x2d\x25"; /* hashstp -8(r4), r5 */

    setup_ppc64_hash(&uc, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_PPC_REG_4, &base));
    OK(uc_reg_write(uc, UC_PPC_REG_5, &rb));
    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 14;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));

    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                            0, 0) == UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_ppc64_power10_hash_ra0_invalid(void)
{
    uc_engine *uc;
    uint64_t rb = 0x0123456789abcdefull;
    const char code[] = "\x7f\xe0\x2d\xa5"; /* hashst -8(0), r5 */

    setup_ppc64_hash(&uc, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_PPC_REG_5, &rb));

    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                            0, 0) == UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_ppc64_power9_hash_nop(void)
{
    uc_engine *uc;
    uint64_t rb = 0x0123456789abcdefull;
    uint64_t pc = 0;
    const char code[] = "\x7f\xe0\x2d\xa5"; /* hashst -8(0), r5 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_PPC_REG_5, &rb));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_PC, &pc));
    TEST_CHECK(pc == code_start + sizeof(code) - 1);

    OK(uc_close(uc));
}

static void test_ppc64_power10_prefixed_load_store(void)
{
    uc_engine *uc;
    uint64_t data = 0x20000;
    uint64_t r5, r6, r7, r8;
    uint64_t r9 = 0x1122334455667788ull;
    uint64_t r10 = 0xfedcba9876543210ull;
    uint8_t store_w[4] = { 0 };
    uint8_t store_d[8] = { 0 };
    const uint8_t pc_relative_src[4] = { 0xa5, 0xb6, 0xc7, 0xd8 };
    const uint8_t src[16] = {
        0x89, 0xab, 0xcd, 0xef,
        0x80, 0x00, 0x00, 0x01,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    };
    const char code[] =
        "\x06\x10\x00\x00\x80\xa0\x00\x80" /* plwz r5,0x80(0),1 */
        "\x06\x00\x00\x02\x80\xc0\x00\x00" /* plwz r6,0x20000(0) */
        "\x04\x00\x00\x02\xa4\xe0\x00\x04" /* plwa r7,0x20004(0) */
        "\x04\x00\x00\x02\xe5\x00\x00\x08" /* pld  r8,0x20008(0) */
        "\x06\x00\x00\x02\x91\x20\x00\x10" /* pstw r9,0x20010(0) */
        "\x04\x00\x00\x02\xf5\x40\x00\x18"; /* pstd r10,0x20018(0) */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_map(uc, data, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, code_start + 0x80, pc_relative_src,
                    sizeof(pc_relative_src)));
    OK(uc_mem_write(uc, data, src, sizeof(src)));
    OK(uc_reg_write(uc, UC_PPC_REG_9, &r9));
    OK(uc_reg_write(uc, UC_PPC_REG_10, &r10));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_5, &r5));
    OK(uc_reg_read(uc, UC_PPC_REG_6, &r6));
    OK(uc_reg_read(uc, UC_PPC_REG_7, &r7));
    OK(uc_reg_read(uc, UC_PPC_REG_8, &r8));
    OK(uc_mem_read(uc, data + 0x10, store_w, sizeof(store_w)));
    OK(uc_mem_read(uc, data + 0x18, store_d, sizeof(store_d)));

    TEST_CHECK(r5 == 0xa5b6c7d8);
    TEST_CHECK(r6 == 0x89abcdef);
    TEST_CHECK(r7 == 0xffffffff80000001ull);
    TEST_CHECK(r8 == 0x0123456789abcdefull);
    TEST_CHECK(memcmp(store_w, "\x55\x66\x77\x88", sizeof(store_w)) == 0);
    TEST_CHECK(memcmp(store_d, "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                      sizeof(store_d)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_prefixed_byte_half_load_store(void)
{
    uc_engine *uc;
    uint64_t data = 0x40000;
    uint64_t r21, r22, r23, r24;
    uint64_t r25 = 0x1122334455667788ull;
    uint64_t r26 = 0xaabbccddeeff0099ull;
    uint8_t store_b[1] = { 0 };
    uint8_t store_h[2] = { 0 };
    const uint8_t pc_relative_src[1] = { 0xee };
    const uint8_t src[8] = {
        0x7f, 0x00, 0x80, 0x01,
        0x80, 0x02, 0x00, 0x00,
    };
    const char code[] =
        "\x06\x00\x00\x04\x8a\xa0\x00\x00" /* plbz r21,0x40000(0) */
        "\x06\x00\x00\x04\xa2\xc0\x00\x02" /* plhz r22,0x40002(0) */
        "\x06\x00\x00\x04\xaa\xe0\x00\x04" /* plha r23,0x40004(0) */
        "\x06\x10\x00\x00\x8b\x00\x00\x88" /* plbz r24,0x88(0),1 */
        "\x06\x00\x00\x04\x9b\x20\x00\x10" /* pstb r25,0x40010(0) */
        "\x06\x00\x00\x04\xb3\x40\x00\x12"; /* psth r26,0x40012(0) */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_map(uc, data, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, code_start + 0xa0, pc_relative_src,
                    sizeof(pc_relative_src)));
    OK(uc_mem_write(uc, data, src, sizeof(src)));
    OK(uc_reg_write(uc, UC_PPC_REG_25, &r25));
    OK(uc_reg_write(uc, UC_PPC_REG_26, &r26));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_21, &r21));
    OK(uc_reg_read(uc, UC_PPC_REG_22, &r22));
    OK(uc_reg_read(uc, UC_PPC_REG_23, &r23));
    OK(uc_reg_read(uc, UC_PPC_REG_24, &r24));
    OK(uc_mem_read(uc, data + 0x10, store_b, sizeof(store_b)));
    OK(uc_mem_read(uc, data + 0x12, store_h, sizeof(store_h)));

    TEST_CHECK(r21 == 0x7f);
    TEST_CHECK(r22 == 0x8001);
    TEST_CHECK(r23 == 0xffffffffffff8002ull);
    TEST_CHECK(r24 == 0xee);
    TEST_CHECK(store_b[0] == 0x88);
    TEST_CHECK(memcmp(store_h, "\x00\x99", sizeof(store_h)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_prefixed_quad_load_store(void)
{
    uc_engine *uc;
    uint64_t data = 0x50000;
    uint64_t r12, r13;
    uint64_t r14 = 0x1122334455667788ull;
    uint64_t r15 = 0x99aabbccddeeff00ull;
    uint8_t stored[16] = { 0 };
    const uint8_t src[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const uint8_t expected[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    };
    const char code[] =
        "\x04\x00\x00\x05\xe1\x80\x00\x00" /* plq  r12,0x50000(0) */
        "\x04\x00\x00\x05\xf1\xc0\x00\x10"; /* pstq r14,0x50010(0) */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_map(uc, data, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, data, src, sizeof(src)));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &r14));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &r15));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_12, &r12));
    OK(uc_reg_read(uc, UC_PPC_REG_13, &r13));
    OK(uc_mem_read(uc, data + 0x10, stored, sizeof(stored)));

    TEST_CHECK(r12 == 0x0123456789abcdefull);
    TEST_CHECK(r13 == 0xfedcba9876543210ull);
    TEST_CHECK(memcmp(stored, expected, sizeof(stored)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_prefixed_quad_ra_rt_invalid(void)
{
    uc_engine *uc;
    uint64_t data = 0x50000;
    const char code[] =
        "\x04\x00\x00\x05\xe2\x10\x00\x00"; /* plq r16,0x50000(r16) */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_PPC_REG_16, &data));

    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                            0, 0) == UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_ppc64_power10_prefixed_float_load_store(void)
{
    uc_engine *uc;
    uint64_t data = 0x60000;
    uint64_t msr;
    uint64_t f4, f5, f8;
    uint64_t f6 = 0x3ff8000000000000ull;
    uint64_t f7 = 0xc010000000000000ull;
    uint8_t store_s[4] = { 0 };
    uint8_t store_d[8] = { 0 };
    const uint8_t pc_relative_src[4] = { 0x40, 0x00, 0x00, 0x00 };
    const uint8_t src[16] = {
        0x3f, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xc0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    const char code[] =
        "\x06\x00\x00\x06\xc0\x80\x00\x00" /* plfs  f4,0x60000(0) */
        "\x06\x00\x00\x06\xc8\xa0\x00\x08" /* plfd  f5,0x60008(0) */
        "\x06\x00\x00\x06\xd0\xc0\x00\x10" /* pstfs f6,0x60010(0) */
        "\x06\x00\x00\x06\xd8\xe0\x00\x18" /* pstfd f7,0x60018(0) */
        "\x06\x10\x00\x00\xc1\x00\x00\x88"; /* plfs  f8,0x88(0),1 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_map(uc, data, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, code_start + 0xa8, pc_relative_src,
                    sizeof(pc_relative_src)));
    OK(uc_mem_write(uc, data, src, sizeof(src)));
    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= 1ull << 13;
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_FPR6, &f6));
    OK(uc_reg_write(uc, UC_PPC_REG_FPR7, &f7));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_FPR4, &f4));
    OK(uc_reg_read(uc, UC_PPC_REG_FPR5, &f5));
    OK(uc_reg_read(uc, UC_PPC_REG_FPR8, &f8));
    OK(uc_mem_read(uc, data + 0x10, store_s, sizeof(store_s)));
    OK(uc_mem_read(uc, data + 0x18, store_d, sizeof(store_d)));

    TEST_CHECK(f4 == 0x3ff0000000000000ull);
    TEST_CHECK(f5 == 0xc000000000000000ull);
    TEST_CHECK(f8 == 0x4000000000000000ull);
    TEST_CHECK(memcmp(store_s, "\x3f\xc0\x00\x00", sizeof(store_s)) == 0);
    TEST_CHECK(memcmp(store_d, "\xc0\x10\x00\x00\x00\x00\x00\x00",
                      sizeof(store_d)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_prefixed_vsx_load_store(void)
{
    uc_engine *uc;
    uint64_t data = 0x70000;
    uint64_t src2_addr = data + 0x30;
    uint64_t dst1_addr = data + 0x40;
    uint64_t msr;
    uint8_t dst1[16] = { 0 };
    uint8_t dst2[16] = { 0 };
    const uint8_t src1[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const uint8_t src2[16] = {
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };
    const char code[] =
        "\x04\x00\x00\x07\xcc\x80\x00\x00" /* plxv  vs36,0x70000(0) */
        "\x7c\x80\x79\xce"                 /* stvx  v4,0,r15 */
        "\x7c\xa0\x70\xce"                 /* lvx   v5,0,r14 */
        "\x04\x00\x00\x07\xdc\xa0\x00\x20"; /* pstxv vs37,0x70020(0) */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_map(uc, data, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, data, src1, sizeof(src1)));
    OK(uc_mem_write(uc, src2_addr, src2, sizeof(src2)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &src2_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst1_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, dst1_addr, dst1, sizeof(dst1)));
    OK(uc_mem_read(uc, data + 0x20, dst2, sizeof(dst2)));

    TEST_CHECK(memcmp(dst1, src1, sizeof(dst1)) == 0);
    TEST_CHECK(memcmp(dst2, src2, sizeof(dst2)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_isa300_lxvwsx(void)
{
    uc_engine *uc;
    uint64_t data = 0xd0000;
    uint64_t dst_addr = data + 0x100;
    uint64_t msr;
    uint8_t dst[16] = { 0 };
    const uint8_t src[4] = { 0x12, 0x34, 0x56, 0x78 };
    const uint8_t expected[16] = {
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78,
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78,
    };
    const char code[] =
        "\x7c\x80\x62\xd9" /* lxvwsx vs36,0,r12 */
        "\x7c\x80\x69\xce"; /* stvx   v4,0,r13 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_map(uc, data, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, data, src, sizeof(src)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &data));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &dst_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, dst_addr, dst, sizeof(dst)));

    TEST_CHECK(memcmp(dst, expected, sizeof(dst)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_isa300_lxvwsx_requires_isa300(void)
{
    uc_engine *uc;
    uint64_t data = 0xd0000;
    uint64_t msr;
    const char code[] = "\x7c\x80\x62\xd9";

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER8_V2_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_map(uc, data, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &data));

    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

static void test_ppc64_power10_prefixed_vsx_scalar_load_store(void)
{
    uc_engine *uc;
    uint64_t data = 0x80000;
    uint64_t src_xsd_addr = data + 0x30;
    uint64_t src_xssp_addr = data + 0x40;
    uint64_t dst_xsd_addr = data + 0x50;
    uint64_t dst_xssp_addr = data + 0x60;
    uint64_t msr;
    uint8_t dst_xsd[16] = { 0 };
    uint8_t dst_xssp[16] = { 0 };
    uint8_t store_xsd[8] = { 0 };
    uint8_t store_xssp[4] = { 0 };
    const uint8_t src_load[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x40, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    };
    const uint8_t src_xsd[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    };
    const uint8_t src_xssp[16] = {
        0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    };
    const uint8_t scalar_xsd_expected[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t scalar_xssp_expected[16] = {
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const char code[] =
        "\x04\x00\x00\x08\xa8\x80\x00\x00" /* plxsd   vs36,0x80000(0) */
        "\x7c\x80\x79\xce"                 /* stvx    v4,0,r15 */
        "\x04\x00\x00\x08\xac\xa0\x00\x08" /* plxssp  vs37,0x80008(0) */
        "\x7c\xa0\x89\xce"                 /* stvx    v5,0,r17 */
        "\x7c\xc0\x70\xce"                 /* lvx     v6,0,r14 */
        "\x04\x00\x00\x08\xb8\xc0\x00\x20" /* pstxsd  vs38,0x80020(0) */
        "\x7c\xe0\x98\xce"                 /* lvx     v7,0,r19 */
        "\x04\x00\x00\x08\xbc\xe0\x00\x28"; /* pstxssp vs39,0x80028(0) */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_map(uc, data, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, data, src_load, sizeof(src_load)));
    OK(uc_mem_write(uc, src_xsd_addr, src_xsd, sizeof(src_xsd)));
    OK(uc_mem_write(uc, src_xssp_addr, src_xssp, sizeof(src_xssp)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &src_xsd_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_xsd_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_17, &dst_xssp_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_19, &src_xssp_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, dst_xsd_addr, dst_xsd, sizeof(dst_xsd)));
    OK(uc_mem_read(uc, dst_xssp_addr, dst_xssp, sizeof(dst_xssp)));
    OK(uc_mem_read(uc, data + 0x20, store_xsd, sizeof(store_xsd)));
    OK(uc_mem_read(uc, data + 0x28, store_xssp, sizeof(store_xssp)));

    TEST_CHECK(memcmp(dst_xsd, scalar_xsd_expected, sizeof(dst_xsd)) == 0);
    TEST_CHECK(memcmp(dst_xssp, scalar_xssp_expected,
                      sizeof(dst_xssp)) == 0);
    TEST_CHECK(memcmp(store_xsd, src_xsd, sizeof(store_xsd)) == 0);
    TEST_CHECK(memcmp(store_xssp, "\x3f\xc0\x00\x00",
                      sizeof(store_xssp)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_xvp_load_store(void)
{
    uc_engine *uc;
    uint64_t data = 0x90000;
    uint64_t src_v6_addr = data + 0x80;
    uint64_t src_v7_addr = data + 0x90;
    uint64_t dst_v4_addr = data + 0xa0;
    uint64_t dst_v5_addr = data + 0xb0;
    uint64_t msr;
    uint8_t dst_v4[16] = { 0 };
    uint8_t dst_v5[16] = { 0 };
    uint8_t store_pair[32] = { 0 };
    const uint8_t load_pair[32] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };
    const uint8_t store_v6[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const uint8_t store_v7[16] = {
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    };
    const uint8_t store_expected[32] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    };
    const char code[] =
        "\x18\xb2\x00\x00" /* lxvp  vs36,0(r18) */
        "\x7c\x80\x79\xce" /* stvx  v4,0,r15 */
        "\x7c\xa0\x81\xce" /* stvx  v5,0,r16 */
        "\x7c\xc0\x70\xce" /* lvx   v6,0,r14 */
        "\x7c\xe0\x88\xce" /* lvx   v7,0,r17 */
        "\x18\xf2\x00\x41"; /* stxvp vs38,0x40(r18) */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_map(uc, data, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, data, load_pair, sizeof(load_pair)));
    OK(uc_mem_write(uc, src_v6_addr, store_v6, sizeof(store_v6)));
    OK(uc_mem_write(uc, src_v7_addr, store_v7, sizeof(store_v7)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &src_v6_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_v4_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_16, &dst_v5_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_17, &src_v7_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_18, &data));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, dst_v4_addr, dst_v4, sizeof(dst_v4)));
    OK(uc_mem_read(uc, dst_v5_addr, dst_v5, sizeof(dst_v5)));
    OK(uc_mem_read(uc, data + 0x40, store_pair, sizeof(store_pair)));

    TEST_CHECK(memcmp(dst_v4, load_pair, sizeof(dst_v4)) == 0);
    TEST_CHECK(memcmp(dst_v5, load_pair + 16, sizeof(dst_v5)) == 0);
    TEST_CHECK(memcmp(store_pair, store_expected, sizeof(store_pair)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_xvpx_load_store(void)
{
    uc_engine *uc;
    uint64_t data = 0xa0000;
    uint64_t load_addr = data;
    uint64_t src_v10_addr = data + 0x80;
    uint64_t src_v11_addr = data + 0x90;
    uint64_t store_addr = data + 0x40;
    uint64_t dst_v8_addr = data + 0xa0;
    uint64_t dst_v9_addr = data + 0xb0;
    uint64_t msr;
    uint8_t dst_v8[16] = { 0 };
    uint8_t dst_v9[16] = { 0 };
    uint8_t store_pair[32] = { 0 };
    const uint8_t load_pair[32] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    };
    const uint8_t store_v10[16] = {
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    };
    const uint8_t store_v11[16] = {
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    };
    const uint8_t store_expected[32] = {
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    };
    const char code[] =
        "\x7d\x20\x62\x9a" /* lxvpx  vs40,0,r12 */
        "\x7d\x00\x69\xce" /* stvx   v8,0,r13 */
        "\x7d\x20\x79\xce" /* stvx   v9,0,r15 */
        "\x7d\x40\x70\xce" /* lvx    v10,0,r14 */
        "\x7d\x60\x88\xce" /* lvx    v11,0,r17 */
        "\x7d\x60\x83\x9a"; /* stxvpx vs42,0,r16 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_map(uc, data, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, load_addr, load_pair, sizeof(load_pair)));
    OK(uc_mem_write(uc, src_v10_addr, store_v10, sizeof(store_v10)));
    OK(uc_mem_write(uc, src_v11_addr, store_v11, sizeof(store_v11)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &load_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &dst_v8_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &src_v10_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_v9_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_16, &store_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_17, &src_v11_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, dst_v8_addr, dst_v8, sizeof(dst_v8)));
    OK(uc_mem_read(uc, dst_v9_addr, dst_v9, sizeof(dst_v9)));
    OK(uc_mem_read(uc, store_addr, store_pair, sizeof(store_pair)));

    TEST_CHECK(memcmp(dst_v8, load_pair, sizeof(dst_v8)) == 0);
    TEST_CHECK(memcmp(dst_v9, load_pair + 16, sizeof(dst_v9)) == 0);
    TEST_CHECK(memcmp(store_pair, store_expected, sizeof(store_pair)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_lxvr_stxvr(void)
{
    uc_engine *uc;
    uint64_t data = 0xc0000;
    uint64_t load_b_addr = data;
    uint64_t load_h_addr = data + 0x10;
    uint64_t load_w_addr = data + 0x20;
    uint64_t load_d_addr = data + 0x30;
    uint64_t store_b_addr = data + 0x40;
    uint64_t store_h_addr = data + 0x42;
    uint64_t store_w_addr = data + 0x44;
    uint64_t store_d_addr = data + 0x48;
    uint64_t seed_b_addr = data + 0x200;
    uint64_t seed_h_addr = data + 0x210;
    uint64_t seed_w_addr = data + 0x220;
    uint64_t seed_d_addr = data + 0x230;
    uint64_t dst_b_addr = data + 0x100;
    uint64_t dst_h_addr = data + 0x110;
    uint64_t dst_w_addr = data + 0x120;
    uint64_t dst_d_addr = data + 0x130;
    uint64_t msr;
    uint8_t dst_b[16] = { 0 };
    uint8_t dst_h[16] = { 0 };
    uint8_t dst_w[16] = { 0 };
    uint8_t dst_d[16] = { 0 };
    uint8_t store_b[1] = { 0 };
    uint8_t store_h[2] = { 0 };
    uint8_t store_w[4] = { 0 };
    uint8_t store_d[8] = { 0 };
    const uint8_t load_b[1] = { 0x11 };
    const uint8_t load_h[2] = { 0x22, 0x33 };
    const uint8_t load_w[4] = { 0x44, 0x55, 0x66, 0x77 };
    const uint8_t load_d[8] = {
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const uint8_t seed_b[16] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xfe,
    };
    const uint8_t seed_h[16] = {
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xab, 0xcd,
    };
    const uint8_t seed_w[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x34, 0x56, 0x78,
    };
    const uint8_t seed_d[16] = {
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    };
    const uint8_t expected_b[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11,
    };
    const uint8_t expected_h[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22, 0x33,
    };
    const uint8_t expected_w[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x44, 0x55, 0x66, 0x77,
    };
    const uint8_t expected_d[16] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const char code[] =
        "\x7c\x80\x60\x1b" /* lxvrbx  vs36,0,r12 */
        "\x7c\x80\xa1\xce" /* stvx    v4,0,r20 */
        "\x7c\xa0\x68\x5b" /* lxvrhx  vs37,0,r13 */
        "\x7c\xa0\xa9\xce" /* stvx    v5,0,r21 */
        "\x7c\xc0\x70\x9b" /* lxvrwx  vs38,0,r14 */
        "\x7c\xc0\xb1\xce" /* stvx    v6,0,r22 */
        "\x7c\xe0\x78\xdb" /* lxvrdx  vs39,0,r15 */
        "\x7c\xe0\xb9\xce" /* stvx    v7,0,r23 */
        "\x7d\x00\x80\xce" /* lvx     v8,0,r16 */
        "\x7d\x00\xc1\x1b" /* stxvrbx vs40,0,r24 */
        "\x7d\x20\x88\xce" /* lvx     v9,0,r17 */
        "\x7d\x20\xc9\x5b" /* stxvrhx vs41,0,r25 */
        "\x7d\x40\x90\xce" /* lvx     v10,0,r18 */
        "\x7d\x40\xd1\x9b" /* stxvrwx vs42,0,r26 */
        "\x7d\x60\x98\xce" /* lvx     v11,0,r19 */
        "\x7d\x60\xd9\xdb"; /* stxvrdx vs43,0,r27 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_map(uc, data, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, load_b_addr, load_b, sizeof(load_b)));
    OK(uc_mem_write(uc, load_h_addr, load_h, sizeof(load_h)));
    OK(uc_mem_write(uc, load_w_addr, load_w, sizeof(load_w)));
    OK(uc_mem_write(uc, load_d_addr, load_d, sizeof(load_d)));
    OK(uc_mem_write(uc, seed_b_addr, seed_b, sizeof(seed_b)));
    OK(uc_mem_write(uc, seed_h_addr, seed_h, sizeof(seed_h)));
    OK(uc_mem_write(uc, seed_w_addr, seed_w, sizeof(seed_w)));
    OK(uc_mem_write(uc, seed_d_addr, seed_d, sizeof(seed_d)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_12, &load_b_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_13, &load_h_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &load_w_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &load_d_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_16, &seed_b_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_17, &seed_h_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_18, &seed_w_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_19, &seed_d_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_20, &dst_b_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_21, &dst_h_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_22, &dst_w_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_23, &dst_d_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_24, &store_b_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_25, &store_h_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_26, &store_w_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_27, &store_d_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, dst_b_addr, dst_b, sizeof(dst_b)));
    OK(uc_mem_read(uc, dst_h_addr, dst_h, sizeof(dst_h)));
    OK(uc_mem_read(uc, dst_w_addr, dst_w, sizeof(dst_w)));
    OK(uc_mem_read(uc, dst_d_addr, dst_d, sizeof(dst_d)));
    OK(uc_mem_read(uc, store_b_addr, store_b, sizeof(store_b)));
    OK(uc_mem_read(uc, store_h_addr, store_h, sizeof(store_h)));
    OK(uc_mem_read(uc, store_w_addr, store_w, sizeof(store_w)));
    OK(uc_mem_read(uc, store_d_addr, store_d, sizeof(store_d)));

    TEST_CHECK(memcmp(dst_b, expected_b, sizeof(dst_b)) == 0);
    TEST_CHECK(memcmp(dst_h, expected_h, sizeof(dst_h)) == 0);
    TEST_CHECK(memcmp(dst_w, expected_w, sizeof(dst_w)) == 0);
    TEST_CHECK(memcmp(dst_d, expected_d, sizeof(dst_d)) == 0);
    TEST_CHECK(store_b[0] == 0xfe);
    TEST_CHECK(memcmp(store_h, "\xab\xcd", sizeof(store_h)) == 0);
    TEST_CHECK(memcmp(store_w, "\x12\x34\x56\x78", sizeof(store_w)) == 0);
    TEST_CHECK(memcmp(store_d, "\xde\xad\xbe\xef\xca\xfe\xba\xbe",
                      sizeof(store_d)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_prefixed_vsx_pair_load_store(void)
{
    uc_engine *uc;
    uint64_t data = 0xb0000;
    uint64_t src_v6_addr = data + 0x80;
    uint64_t src_v7_addr = data + 0x90;
    uint64_t dst_v4_addr = data + 0xa0;
    uint64_t dst_v5_addr = data + 0xb0;
    uint64_t msr;
    uint8_t dst_v4[16] = { 0 };
    uint8_t dst_v5[16] = { 0 };
    uint8_t store_pair[32] = { 0 };
    const uint8_t load_pair[32] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    };
    const uint8_t store_v6[16] = {
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    };
    const uint8_t store_v7[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    };
    const uint8_t store_expected[32] = {
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    };
    const char code[] =
        "\x04\x00\x00\x0b\xe8\xa0\x00\x00" /* plxvp  vs36,0xb0000(0) */
        "\x7c\x80\x79\xce"                 /* stvx   v4,0,r15 */
        "\x7c\xa0\x81\xce"                 /* stvx   v5,0,r16 */
        "\x7c\xc0\x70\xce"                 /* lvx    v6,0,r14 */
        "\x7c\xe0\x88\xce"                 /* lvx    v7,0,r17 */
        "\x04\x00\x00\x0b\xf8\xe0\x00\x40"; /* pstxvp vs38,0xb0040(0) */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_map(uc, data, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, data, load_pair, sizeof(load_pair)));
    OK(uc_mem_write(uc, src_v6_addr, store_v6, sizeof(store_v6)));
    OK(uc_mem_write(uc, src_v7_addr, store_v7, sizeof(store_v7)));

    OK(uc_reg_read(uc, UC_PPC_REG_MSR, &msr));
    msr |= (1ull << 25) | (1ull << 23);
    OK(uc_reg_write(uc, UC_PPC_REG_MSR, &msr));
    OK(uc_reg_write(uc, UC_PPC_REG_14, &src_v6_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &dst_v4_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_16, &dst_v5_addr));
    OK(uc_reg_write(uc, UC_PPC_REG_17, &src_v7_addr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, dst_v4_addr, dst_v4, sizeof(dst_v4)));
    OK(uc_mem_read(uc, dst_v5_addr, dst_v5, sizeof(dst_v5)));
    OK(uc_mem_read(uc, data + 0x40, store_pair, sizeof(store_pair)));

    TEST_CHECK(memcmp(dst_v4, load_pair, sizeof(dst_v4)) == 0);
    TEST_CHECK(memcmp(dst_v5, load_pair + 16, sizeof(dst_v5)) == 0);
    TEST_CHECK(memcmp(store_pair, store_expected, sizeof(store_pair)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_prefixed_negative_load_store(void)
{
    uc_engine *uc;
    uint64_t data = 0x30000;
    uint64_t base = data + 0x100;
    uint64_t r16, r17, r18;
    uint64_t r19 = 0xaabbccddeeff0011ull;
    uint64_t r20 = 0x0123456789abcdefull;
    uint8_t store_w[4] = { 0 };
    uint8_t store_d[8] = { 0 };
    const uint8_t src[16] = {
        0x01, 0x23, 0x45, 0x67,
        0x80, 0x00, 0x00, 0x01,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    };
    const char code[] =
        "\x06\x03\xff\xff\x82\x0f\xff\x00" /* plwz r16,-0x100(r15) */
        "\x04\x03\xff\xff\xa6\x2f\xff\x04" /* plwa r17,-0xfc(r15) */
        "\x04\x03\xff\xff\xe6\x4f\xff\x08" /* pld  r18,-0xf8(r15) */
        "\x06\x03\xff\xff\x92\x6f\xff\x20" /* pstw r19,-0xe0(r15) */
        "\x04\x03\xff\xff\xf6\x8f\xff\x28"; /* pstd r20,-0xd8(r15) */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_map(uc, data, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, data, src, sizeof(src)));
    OK(uc_reg_write(uc, UC_PPC_REG_15, &base));
    OK(uc_reg_write(uc, UC_PPC_REG_19, &r19));
    OK(uc_reg_write(uc, UC_PPC_REG_20, &r20));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_16, &r16));
    OK(uc_reg_read(uc, UC_PPC_REG_17, &r17));
    OK(uc_reg_read(uc, UC_PPC_REG_18, &r18));
    OK(uc_mem_read(uc, data + 0x20, store_w, sizeof(store_w)));
    OK(uc_mem_read(uc, data + 0x28, store_d, sizeof(store_d)));

    TEST_CHECK(r16 == 0x01234567);
    TEST_CHECK(r17 == 0xffffffff80000001ull);
    TEST_CHECK(r18 == 0x1122334455667788ull);
    TEST_CHECK(memcmp(store_w, "\xee\xff\x00\x11", sizeof(store_w)) == 0);
    TEST_CHECK(memcmp(store_d, "\x01\x23\x45\x67\x89\xab\xcd\xef",
                      sizeof(store_d)) == 0);

    OK(uc_close(uc));
}

static void test_ppc64_power10_prefixed_paddi(void)
{
    uc_engine *uc;
    uint64_t r11, r12, r13, r14, r15;
    const char code[] =
        "\x06\x00\x00\x01\x39\x6c\x23\x45" /* paddi r11,r12,0x12345 */
        "\x06\x00\x01\x23\x39\xa0\x45\x67" /* pli   r13,0x1234567 */
        "\x06\x10\x00\x00\x39\xc0\x00\x20" /* paddi r14,0,0x20,1 */
        "\x06\x03\xff\xff\x39\xe0\xff\xff"; /* pli   r15,-1 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    r12 = 0x100000000ull;
    OK(uc_reg_write(uc, UC_PPC_REG_12, &r12));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_11, &r11));
    OK(uc_reg_read(uc, UC_PPC_REG_13, &r13));
    OK(uc_reg_read(uc, UC_PPC_REG_14, &r14));
    OK(uc_reg_read(uc, UC_PPC_REG_15, &r15));

    TEST_CHECK(r11 == 0x100012345ull);
    TEST_CHECK(r13 == 0x1234567);
    TEST_CHECK(r14 == code_start + 0x10 + 0x20);
    TEST_CHECK(r15 == 0xffffffffffffffffull);

    OK(uc_close(uc));
}

static void test_ppc64_power10_prefixed_r_requires_ra0(void)
{
    uc_engine *uc;
    uint64_t r1 = 1;
    uint64_t pc = 0;
    const char code[] =
        "\x06\x10\x00\x00\x39\xc1\x00\x20"; /* paddi r14,r1,0x20,1 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_PPC_REG_1, &r1));

    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                            0, 0) == UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_PPC_REG_PC, &pc));
    TEST_CHECK(pc == code_start + sizeof(code) - 1);

    OK(uc_close(uc));
}

static void test_ppc64_power10_pnop(void)
{
    uc_engine *uc;
    uint64_t r3 = 0;
    uint64_t r4 = 0;
    uint64_t pc = 0;
    const char code[] =
        "\x07\x00\x00\x00\x38\x80\x00\x09" /* pnop, valid addi suffix */
        "\x38\x60\x00\x07"; /* addi r3,0,7 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_PPC_REG_3, &r3));
    OK(uc_reg_read(uc, UC_PPC_REG_4, &r4));
    OK(uc_reg_read(uc, UC_PPC_REG_PC, &pc));

    TEST_CHECK(r3 == 7);
    TEST_CHECK(r4 == 0);
    TEST_CHECK(pc == code_start + sizeof(code) - 1);

    OK(uc_close(uc));
}

static void test_ppc64_power10_pnop_invalid_suffix(void)
{
    uc_engine *uc;
    size_t i;
    static const uint8_t suffixes[][4] = {
        { 0x40, 0x00, 0x00, 0x00 }, /* bc */
        { 0x48, 0x00, 0x00, 0x00 }, /* b */
        { 0x44, 0x00, 0x00, 0x02 }, /* sc */
        { 0x44, 0x00, 0x00, 0x01 }, /* scv */
        { 0x4c, 0x00, 0x00, 0x20 }, /* bclr */
        { 0x4c, 0x00, 0x04, 0x20 }, /* bcctr */
        { 0x4c, 0x00, 0x04, 0x60 }, /* bctar */
        { 0x4c, 0x00, 0x01, 0x24 }, /* rfebb */
        { 0x4c, 0x00, 0x00, 0xa4 }, /* rfscv */
        { 0x4c, 0x00, 0x00, 0x24 }, /* rfid */
        { 0x4c, 0x00, 0x02, 0x24 }, /* hrfid */
        { 0x4c, 0x00, 0x02, 0x64 }, /* urfid */
        { 0x4c, 0x00, 0x02, 0xe4 }, /* stop */
        { 0x7c, 0x00, 0x01, 0x24 }, /* mtmsr L=0 */
        { 0x7c, 0x00, 0x01, 0x64 }, /* mtmsrd L=0 */
        { 0x00, 0x00, 0x02, 0x00 }, /* attn */
    };
    uint8_t code[8] = { 0x07, 0x00, 0x00, 0x00 };

    for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        memcpy(&code[4], suffixes[i], sizeof(suffixes[i]));

        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, code, sizeof(code)));

        TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code),
                                0, 0) == UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

static void test_ppc64_power10_prefixed_boundary(void)
{
    uc_engine *uc;
    uint64_t pc = 0;
    uint64_t start = code_start + 0x3c;
    const char code[] =
        "\x06\x00\x00\x02\x80\xc0\x00\x00"; /* plwz r6,0x20000(0) */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, start, code, sizeof(code) - 1));

    TEST_CHECK(uc_emu_start(uc, start, start + sizeof(code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_PPC_REG_PC, &pc));
    TEST_CHECK(pc == start + sizeof(code) - 1);

    OK(uc_close(uc));
}

static void test_ppc64_power10_prefixed_hook_size(void)
{
    uc_engine *uc;
    uc_hook hook;
    PpcCodeHookTrace trace = { 0 };
    const char code[] =
        "\x07\x00\x00\x00\x60\x00\x00\x00" /* pnop */
        "\x38\x60\x00\x07"; /* addi r3,0,7 */

    OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER10_V1_0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_hook_add(uc, &hook, UC_HOOK_CODE, test_ppc64_prefixed_code_hook,
                   &trace, 1, 0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    TEST_CHECK(trace.count == 2);
    TEST_CHECK(trace.address[0] == code_start);
    TEST_CHECK(trace.size[0] == 8);
    TEST_CHECK(trace.address[1] == code_start + 8);
    TEST_CHECK(trace.size[1] == 4);

    OK(uc_close(uc));
}

static void test_ppc64_power9_prefixed_rejected(void)
{
    uc_engine *uc;
    size_t i;
    static const uint8_t code[][8] = {
        {
            0x06, 0x00, 0x00, 0x02,
            0x80, 0xc0, 0x00, 0x00,
        },
        {
            0x06, 0x00, 0x00, 0x04,
            0x8a, 0xa0, 0x00, 0x00,
        },
        {
            0x04, 0x00, 0x00, 0x05,
            0xe1, 0x80, 0x00, 0x00,
        },
        {
            0x06, 0x00, 0x00, 0x06,
            0xc0, 0x80, 0x00, 0x00,
        },
        {
            0x04, 0x00, 0x00, 0x07,
            0xcc, 0x80, 0x00, 0x00,
        },
        {
            0x04, 0x00, 0x00, 0x08,
            0xa8, 0x80, 0x00, 0x00,
        },
        {
            0x04, 0x00, 0x00, 0x09,
            0xe8, 0xa0, 0x00, 0x00,
        },
        {
            0x07, 0x00, 0x00, 0x00,
            0x60, 0x00, 0x00, 0x00,
        },
    };

    for (i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, code[i], sizeof(code[i])));

        TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code[i]),
                                0, 0) == UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

static void test_ppc64_power9_xvp_rejected(void)
{
    uc_engine *uc;
    size_t i;
    static const uint8_t code[][4] = {
        {
            0x18, 0xa0, 0x00, 0x00,
        },
        {
            0x7d, 0x20, 0x62, 0x9a,
        },
        {
            0x7c, 0x80, 0x60, 0x1b,
        },
        {
            0xf0, 0x80, 0x2f, 0x29,
        },
        {
            0xf0, 0x9f, 0x12, 0xd1,
        },
    };

    for (i = 0; i < sizeof(code) / sizeof(code[0]); i++) {
        OK(uc_open(UC_ARCH_PPC, UC_MODE_64 | UC_MODE_BIG_ENDIAN, &uc));
        OK(uc_ctl_set_cpu_model(uc, UC_CPU_PPC64_POWER9_V2_0));
        OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
        OK(uc_mem_write(uc, code_start, code[i], sizeof(code[i])));

        TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code[i]),
                                0, 0) == UC_ERR_EXCEPTION);

        OK(uc_close(uc));
    }
}

TEST_LIST = {{"test_ppc32_add", test_ppc32_add},
             {"test_ppc32_fadd", test_ppc32_fadd},
             {"test_ppc32_sc", test_ppc32_sc},
             {"test_ppc32_cr", test_ppc32_cr},
             {"test_ppc32_spr_time", test_ppc32_spr_time},
             {"test_ppc32_spr_mftb", test_ppc32_spr_mftb},
             {"test_ppc64_power10_brd", test_ppc64_power10_brd},
             {"test_ppc64_power10_brw", test_ppc64_power10_brw},
             {"test_ppc64_power10_brh", test_ppc64_power10_brh},
             {"test_ppc64_power10_cfuged", test_ppc64_power10_cfuged},
             {"test_ppc64_power10_cntlzdm", test_ppc64_power10_cntlzdm},
             {"test_ppc64_power10_cnttzdm", test_ppc64_power10_cnttzdm},
             {"test_ppc64_power10_pdepd", test_ppc64_power10_pdepd},
             {"test_ppc64_power10_pextd", test_ppc64_power10_pextd},
             {"test_ppc64_power10_mask_op_requires_isa310",
              test_ppc64_power10_mask_op_requires_isa310},
             {"test_ppc64_power10_setbc", test_ppc64_power10_setbc},
             {"test_ppc64_power10_setbc_requires_isa310",
              test_ppc64_power10_setbc_requires_isa310},
             {"test_ppc64_power10_vcfuged", test_ppc64_power10_vcfuged},
             {"test_ppc64_power10_vclzdm", test_ppc64_power10_vclzdm},
             {"test_ppc64_power10_vctzdm", test_ppc64_power10_vctzdm},
             {"test_ppc64_power10_vpdepd", test_ppc64_power10_vpdepd},
             {"test_ppc64_power10_vpextd", test_ppc64_power10_vpextd},
             {"test_ppc64_power10_vmx_mask_materialize_extract",
              test_ppc64_power10_vmx_mask_materialize_extract},
             {"test_ppc64_power10_vector_mask_requires_isa310",
              test_ppc64_power10_vector_mask_requires_isa310},
             {"test_ppc64_power10_vmx_quad_shift_rotate",
              test_ppc64_power10_vmx_quad_shift_rotate},
             {"test_ppc64_power10_vmx_doubleword_immediate_shift",
              test_ppc64_power10_vmx_doubleword_immediate_shift},
             {"test_ppc64_power10_vmx_quad_compare",
              test_ppc64_power10_vmx_quad_compare},
             {"test_ppc64_power10_vmx_quad_compare_invalid",
              test_ppc64_power10_vmx_quad_compare_invalid},
             {"test_ppc64_power10_vmx_multiply_dword",
              test_ppc64_power10_vmx_multiply_dword},
             {"test_ppc64_power10_vmx_multiply_high",
              test_ppc64_power10_vmx_multiply_high},
             {"test_ppc64_power10_vmx_vextsd2q",
              test_ppc64_power10_vmx_vextsd2q},
             {"test_ppc64_power10_vmx_extract_double",
             test_ppc64_power10_vmx_extract_double},
             {"test_ppc64_power10_vmx_insert_gpr",
              test_ppc64_power10_vmx_insert_gpr},
             {"test_ppc64_power10_vmx_insert_vector",
              test_ppc64_power10_vmx_insert_vector},
             {"test_ppc64_power10_vmx_divmod_word",
              test_ppc64_power10_vmx_divmod_word},
             {"test_ppc64_power10_vmx_divmod_dword",
              test_ppc64_power10_vmx_divmod_dword},
             {"test_ppc64_power10_vmx_divide_extended",
             test_ppc64_power10_vmx_divide_extended},
             {"test_ppc64_power10_vmx_divmod_quad",
              test_ppc64_power10_vmx_divmod_quad},
             {"test_ppc64_power10_vmx_string_isolate",
              test_ppc64_power10_vmx_string_isolate},
             {"test_ppc64_power10_vmx_clear_bytes",
              test_ppc64_power10_vmx_clear_bytes},
             {"test_ppc64_power10_vmx_string_clear_legacy_buckets",
             test_ppc64_power10_vmx_string_clear_legacy_buckets},
             {"test_ppc64_power10_vmx_string_clear_requires_isa310",
              test_ppc64_power10_vmx_string_clear_requires_isa310},
             {"test_ppc64_isa300_vmx_multiply_sum_dword",
             test_ppc64_isa300_vmx_multiply_sum_dword},
             {"test_ppc64_power10_vmx_multiply_sum_carry_dword",
              test_ppc64_power10_vmx_multiply_sum_carry_dword},
             {"test_ppc64_isa300_vmx_multiply_sum_requires_isa300",
              test_ppc64_isa300_vmx_multiply_sum_requires_isa300},
             {"test_ppc64_power10_vmx_multiply_sum_carry_requires_isa310",
              test_ppc64_power10_vmx_multiply_sum_carry_requires_isa310},
             {"test_ppc64_dfp_fixqq_roundtrip",
              test_ppc64_dfp_fixqq_roundtrip},
             {"test_ppc64_dfp_fixqq_invalid",
              test_ppc64_dfp_fixqq_invalid},
             {"test_ppc64_power10_vmx_divmod_requires_isa310",
              test_ppc64_power10_vmx_divmod_requires_isa310},
             {"test_ppc64_power10_vmx_quad_requires_isa310",
              test_ppc64_power10_vmx_quad_requires_isa310},
             {"test_ppc64_power10_xxeval", test_ppc64_power10_xxeval},
             {"test_ppc64_power10_xxblendvb", test_ppc64_power10_xxblendvb},
             {"test_ppc64_power10_xxblendvd", test_ppc64_power10_xxblendvd},
             {"test_ppc64_power10_xxpermx", test_ppc64_power10_xxpermx},
             {"test_ppc64_power10_xxspltiw", test_ppc64_power10_xxspltiw},
             {"test_ppc64_power10_xxspltidp", test_ppc64_power10_xxspltidp},
             {"test_ppc64_power10_xxsplti32dx",
              test_ppc64_power10_xxsplti32dx},
             {"test_ppc64_power10_xxgenpcv", test_ppc64_power10_xxgenpcv},
             {"test_ppc64_power10_lxvkq", test_ppc64_power10_lxvkq},
             {"test_ppc64_power10_xxgenpcv_lxvkq_invalid",
              test_ppc64_power10_xxgenpcv_lxvkq_invalid},
             {"test_ppc64_power10_xxgenpcv_lxvkq_requires_isa310",
              test_ppc64_power10_xxgenpcv_lxvkq_requires_isa310},
             {"test_ppc64_power10_xvtlsbb", test_ppc64_power10_xvtlsbb},
             {"test_ppc64_power10_vgnb", test_ppc64_power10_vgnb},
             {"test_ppc64_power10_vgnb_undefined_no_change",
              test_ppc64_power10_vgnb_undefined_no_change},
             {"test_ppc64_power10_vgnb_invalid",
              test_ppc64_power10_vgnb_invalid},
             {"test_ppc64_power10_vgnb_requires_isa310",
              test_ppc64_power10_vgnb_requires_isa310},
             {"test_ppc64_isa206_bcd_addg6s",
              test_ppc64_isa206_bcd_addg6s},
             {"test_ppc64_isa206_bcd_convert",
              test_ppc64_isa206_bcd_convert},
             {"test_ppc64_isa206_bcd_requires_bcda",
              test_ppc64_isa206_bcd_requires_bcda},
             {"test_ppc64_isa300_slbiag",
              test_ppc64_isa300_slbiag},
             {"test_ppc64_isa300_slbiag_exceptions",
              test_ppc64_isa300_slbiag_exceptions},
             {"test_ppc64_isa300_mffscdrn",
              test_ppc64_isa300_mffscdrn},
             {"test_ppc64_isa300_mffscdrn_requires_isa300",
              test_ppc64_isa300_mffscdrn_requires_isa300},
             {"test_ppc64_power10_vsx_bf16_convert",
              test_ppc64_power10_vsx_bf16_convert},
             {"test_ppc64_power10_mma_xxsetaccz",
              test_ppc64_power10_mma_xxsetaccz},
             {"test_ppc64_power10_mma_acc_moves",
              test_ppc64_power10_mma_acc_moves},
             {"test_ppc64_power10_mma_integer_ger",
              test_ppc64_power10_mma_integer_ger},
             {"test_ppc64_power10_mma_f32_ger",
              test_ppc64_power10_mma_f32_ger},
             {"test_ppc64_power10_mma_prefixed_f32_ger",
              test_ppc64_power10_mma_prefixed_f32_ger},
             {"test_ppc64_power10_mma_requires_isa310",
              test_ppc64_power10_mma_requires_isa310},
             {"test_ppc64_vsx_qp_multiply_add",
              test_ppc64_vsx_qp_multiply_add},
             {"test_ppc64_power10_vsx_qp_compare_minmax",
              test_ppc64_power10_vsx_qp_compare_minmax},
             {"test_ppc64_power10_vsx_qp_convert",
              test_ppc64_power10_vsx_qp_convert},
             {"test_ppc64_vsx_qp_multiply_add_requires_isa300",
              test_ppc64_vsx_qp_multiply_add_requires_isa300},
             {"test_ppc64_power10_vsx_requires_isa310",
              test_ppc64_power10_vsx_requires_isa310},
             {"test_ppc64_power10_xvp_load_store",
              test_ppc64_power10_xvp_load_store},
             {"test_ppc64_power10_xvpx_load_store",
              test_ppc64_power10_xvpx_load_store},
             {"test_ppc64_power10_lxvr_stxvr",
              test_ppc64_power10_lxvr_stxvr},
             {"test_ppc64_power10_hash_store_check",
              test_ppc64_power10_hash_store_check},
             {"test_ppc64_power10_hash_key_spr",
              test_ppc64_power10_hash_key_spr},
             {"test_ppc64_power10_hash_check_mismatch",
              test_ppc64_power10_hash_check_mismatch},
             {"test_ppc64_power10_hash_privileged",
              test_ppc64_power10_hash_privileged},
             {"test_ppc64_power10_hash_privileged_requires_sv",
              test_ppc64_power10_hash_privileged_requires_sv},
             {"test_ppc64_power10_hash_ra0_invalid",
              test_ppc64_power10_hash_ra0_invalid},
             {"test_ppc64_power9_hash_nop", test_ppc64_power9_hash_nop},
             {"test_ppc64_power10_prefixed_load_store",
              test_ppc64_power10_prefixed_load_store},
             {"test_ppc64_power10_prefixed_byte_half_load_store",
              test_ppc64_power10_prefixed_byte_half_load_store},
             {"test_ppc64_power10_prefixed_quad_load_store",
              test_ppc64_power10_prefixed_quad_load_store},
             {"test_ppc64_power10_prefixed_quad_ra_rt_invalid",
              test_ppc64_power10_prefixed_quad_ra_rt_invalid},
             {"test_ppc64_power10_prefixed_float_load_store",
              test_ppc64_power10_prefixed_float_load_store},
             {"test_ppc64_power10_prefixed_vsx_load_store",
              test_ppc64_power10_prefixed_vsx_load_store},
             {"test_ppc64_isa300_lxvwsx", test_ppc64_isa300_lxvwsx},
             {"test_ppc64_isa300_lxvwsx_requires_isa300",
              test_ppc64_isa300_lxvwsx_requires_isa300},
             {"test_ppc64_power10_prefixed_vsx_scalar_load_store",
              test_ppc64_power10_prefixed_vsx_scalar_load_store},
             {"test_ppc64_power10_prefixed_vsx_pair_load_store",
              test_ppc64_power10_prefixed_vsx_pair_load_store},
             {"test_ppc64_power10_prefixed_negative_load_store",
              test_ppc64_power10_prefixed_negative_load_store},
             {"test_ppc64_power10_prefixed_paddi",
              test_ppc64_power10_prefixed_paddi},
             {"test_ppc64_power10_prefixed_r_requires_ra0",
              test_ppc64_power10_prefixed_r_requires_ra0},
             {"test_ppc64_power10_pnop", test_ppc64_power10_pnop},
             {"test_ppc64_power10_pnop_invalid_suffix",
              test_ppc64_power10_pnop_invalid_suffix},
             {"test_ppc64_power10_prefixed_boundary",
              test_ppc64_power10_prefixed_boundary},
             {"test_ppc64_power10_prefixed_hook_size",
              test_ppc64_power10_prefixed_hook_size},
             {"test_ppc64_power9_prefixed_rejected",
              test_ppc64_power9_prefixed_rejected},
             {"test_ppc64_power9_xvp_rejected",
              test_ppc64_power9_xvp_rejected},
             {NULL, NULL}};
