#include "acutest.h"
#include "unicorn/unicorn.h"
#include "unicorn_test.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size, uc_cpu_arm64 cpu)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_ctl_set_cpu_model(*uc, cpu));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

typedef struct _WFI_HOOK_INSN_RESULT {
    bool called;
} WFI_HOOK_INSN_RESULT;

static void test_arm64_until(void)
{
    uc_engine *uc;
    char code[] = "\x30\x00\x80\xd2\x11\x04\x80\xd2\x9c\x23\x00\x91";

    /*
    mov x16, #1
    mov x17, #0x20
    add x28, x28, 8
    */

    uint64_t r_x16 = 0x12341234;
    uint64_t r_x17 = 0x78907890;
    uint64_t r_pc = 0x00000000;
    uint64_t r_x28 = 0x12341234;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_A72);

    // initialize machine registers
    OK(uc_reg_write(uc, UC_ARM64_REG_X16, &r_x16));
    OK(uc_reg_write(uc, UC_ARM64_REG_X17, &r_x17));
    OK(uc_reg_write(uc, UC_ARM64_REG_X28, &r_x28));

    // emulate the three instructions
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 3));

    OK(uc_reg_read(uc, UC_ARM64_REG_X16, &r_x16));
    OK(uc_reg_read(uc, UC_ARM64_REG_X17, &r_x17));
    OK(uc_reg_read(uc, UC_ARM64_REG_X28, &r_x28));
    OK(uc_reg_read(uc, UC_ARM64_REG_PC, &r_pc));

    TEST_CHECK(r_x16 == 0x1);
    TEST_CHECK(r_x17 == 0x20);
    TEST_CHECK(r_x28 == 0x1234123c);
    TEST_CHECK(r_pc == (code_start + sizeof(code) - 1));

    OK(uc_close(uc));
}

static void test_arm64_code_patching(void)
{
    uc_engine *uc;
    char code[] = "\x00\x04\x00\x11"; // add w0, w0, 0x1
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_A72);
    // zero out x0
    uint64_t r_x0 = 0x0;
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &r_x0));
    // emulate the instruction
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    // check value
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &r_x0));
    TEST_CHECK(r_x0 == 0x1);
    // patch instruction
    char patch_code[] = "\x00\xfc\x1f\x11"; // add w0, w0, 0x7FF
    OK(uc_mem_write(uc, code_start, patch_code, sizeof(patch_code) - 1));
    // zero out x0
    r_x0 = 0x0;
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &r_x0));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(patch_code) - 1, 0, 0));
    // check value
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &r_x0));
    TEST_CHECK(r_x0 != 0x1);
    TEST_CHECK(r_x0 == 0x7ff);

    OK(uc_close(uc));
}

// Need to flush the cache before running the emulation after patching
static void test_arm64_code_patching_count(void)
{
    uc_engine *uc;
    char code[] = "\x00\x04\x00\x11"; // add w0, w0, 0x1
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_A72);
    // zero out x0
    uint64_t r_x0 = 0x0;
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &r_x0));
    // emulate the instruction
    OK(uc_emu_start(uc, code_start, -1, 0, 1));
    // check value
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &r_x0));
    TEST_CHECK(r_x0 == 0x1);
    // patch instruction
    char patch_code[] = "\x00\xfc\x1f\x11"; // add w0, w0, 0x7FF
    OK(uc_mem_write(uc, code_start, patch_code, sizeof(patch_code) - 1));
    OK(uc_ctl_remove_cache(uc, code_start,
                           code_start + sizeof(patch_code) - 1));
    // zero out x0
    r_x0 = 0x0;
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &r_x0));
    OK(uc_emu_start(uc, code_start, -1, 0, 1));
    // check value
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &r_x0));
    TEST_CHECK(r_x0 != 0x1);
    TEST_CHECK(r_x0 == 0x7ff);

    OK(uc_close(uc));
}

static void test_arm64_v8_cas(void)
{
    uc_engine *uc;
    char code[] = "\x28\xfd\xea\xc8"; // casal x10, x8, [x9]
    uint64_t r_x9, r_x8, mem;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);

    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, "\x00\x00\x00\x00\x00\x00\x00\x00", 8));
    r_x9 = 0x40000;
    OK(uc_reg_write(uc, UC_ARM64_REG_X9, &r_x9));
    r_x8 = 0xdeadbeafdeadbeaf;
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &r_x8));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, 0x40000, (void *)&mem, 8));

    TEST_CHECK(LEINT64(mem) == r_x8);

    OK(uc_close(uc));
}

static void test_arm64_lse_unaligned_exception_code(const char *code,
                                                    size_t size)
{
    uc_engine *uc;
    uint64_t x0 = 0x40001;
    uint64_t x2 = 0x1122334455667788ull;
    uint64_t x5 = 0x8877665544332211ull;
    uint64_t data = 0;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, size,
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &x0));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + size, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_close(uc));
}

static void test_arm64_lse_rcpc_unaligned(void)
{
    const char ldar[] = "\x01\xfc\xdf\xc8";
    const char stlr[] = "\x02\xfc\x9f\xc8";
    const char ldapr[] =
        "\x03\xc0\xbf\xf8" /* ldapr  x3,[x0] */
        "\x04\xc0\xbf\x78" /* ldaprh w4,[x0] */
        "\x05\xc0\xbf\x38"; /* ldaprb w5,[x0] */
    const char ldapur[] = "\x04\x00\x40\xd9";
    const char stlur[] = "\x05\x00\x00\xd9";
    uc_engine *uc;
    uint64_t x0 = 0x40001;
    uint64_t x3 = 0;
    uint64_t x4 = 0;
    uint64_t x5 = 0;
    uint64_t data = 0x1122334455667788ull;

    test_arm64_lse_unaligned_exception_code(ldar, sizeof(ldar) - 1);
    test_arm64_lse_unaligned_exception_code(stlr, sizeof(stlr) - 1);
    test_arm64_lse_unaligned_exception_code(ldapur, sizeof(ldapur) - 1);
    test_arm64_lse_unaligned_exception_code(stlur, sizeof(stlur) - 1);

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, ldapr,
                    sizeof(ldapr) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &x0));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(ldapr) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_read(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_read(uc, UC_ARM64_REG_X5, &x5));
    TEST_CHECK(x3 == 0x0011223344556677ull);
    TEST_CHECK(x4 == 0x6677);
    TEST_CHECK(x5 == 0x77);
    OK(uc_close(uc));
}

static void test_arm64_lse_signed_minmax_byte(void)
{
    uc_engine *uc;
    const char code[] =
        "\x02\x40\x21\x38" /* ldsmaxb w1,w2,[x0] */
        "\x04\x50\x23\x38"; /* ldsminb w3,w4,[x0] */
    uint64_t x0 = 0x40000;
    uint64_t x1 = 0x7f;
    uint64_t x2 = 0xffffffffffffffffull;
    uint64_t x3 = 0x80;
    uint64_t x4 = 0xffffffffffffffffull;
    uint8_t data = 0x80;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &x0));
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_read(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_mem_read(uc, 0x40000, &data, sizeof(data)));
    TEST_CHECK_(x2 == 0x80, "x2=0x%llx", x2);
    TEST_CHECK_(x4 == 0x7f, "x4=0x%llx", x4);
    TEST_CHECK_(data == 0x80, "data=0x%x", data);
    OK(uc_close(uc));
}

static void test_arm64_dgh_hint(void)
{
    uc_engine *uc;
    const char code[] =
        "\xdf\x20\x03\xd5" /* dgh */
        "\x40\x05\x80\xd2"; /* mov x0,#42 */
    uint64_t x0 = 0;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &x0));
    TEST_CHECK(x0 == 42);
    OK(uc_close(uc));

    x0 = 0;
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_A72);
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &x0));
    TEST_CHECK(x0 == 42);
    OK(uc_close(uc));
}

static void test_arm64_read_sctlr(void)
{
    uc_engine *uc;
    uc_arm64_cp_reg reg;

    OK(uc_open(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM, &uc));

    // SCTLR_EL1. See arm reference.
    reg.crn = 1;
    reg.crm = 0;
    reg.op0 = 0b11;
    reg.op1 = 0;
    reg.op2 = 0;

    OK(uc_reg_read(uc, UC_ARM64_REG_CP_REG, &reg));

    TEST_CHECK((reg.val >> 58) == 0);

    OK(uc_close(uc));
}

static uint32_t test_arm64_hook_insn_mrs_cb(uc_engine *uc, uc_arm64_reg reg,
                                       const uc_arm64_cp_reg *cp_reg)
{
    uint64_t r_x2 = 0x114514;

    OK(uc_reg_write(uc, reg, &r_x2));

    // Skip
    return 1;
}

static void test_arm64_hook_insn_mrs(void)
{
    uc_engine *uc;
    uc_hook hk;
    uint64_t r_x2;
    // mrs        x2, tpidrro_el0
    char code[] = "\x62\xd0\x3b\xd5";

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM,
                    code, sizeof(code) - 1, UC_CPU_ARM64_A72);

    OK(uc_hook_add(uc, &hk, UC_HOOK_INSN, (void *)test_arm64_hook_insn_mrs_cb, NULL,
                   1, 0, UC_ARM64_INS_MRS));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM64_REG_X2, &r_x2));

    TEST_CHECK(r_x2 == 0x114514);

    OK(uc_hook_del(uc, hk));

    OK(uc_close(uc));
}

static int test_arm64_hook_insn_wfi_callback(uc_engine *uc, void *user_data)
{
    WFI_HOOK_INSN_RESULT *result = (WFI_HOOK_INSN_RESULT *)user_data;
    result->called = true;
    return 0;
}

static void test_arm64_hook_insn_wfi(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\x7f\x20\x03\xd5"; // wfi
    WFI_HOOK_INSN_RESULT result = {false};

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM,
                    code, sizeof(code) - 1, UC_CPU_ARM64_A72);
    OK(uc_hook_add(uc, &hook, UC_HOOK_INSN, test_arm64_hook_insn_wfi_callback, &result, 1, 0,
                   UC_ARM64_INS_WFI));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    TEST_CHECK(result.called == true);

    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
}

static bool test_arm64_correct_address_in_small_jump_hook_callback(
    uc_engine *uc, int type, uint64_t address, int size, int64_t value,
    void *user_data)
{
    // Check registers
    uint64_t r_x0 = 0x0;
    uint64_t r_pc = 0x0;
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &r_x0));
    OK(uc_reg_read(uc, UC_ARM64_REG_PC, &r_pc));
    TEST_CHECK(r_x0 == 0x7F00);
    TEST_CHECK(r_pc == 0x7F00);

    // Check address
    // printf("%lx\n", address);
    TEST_CHECK(address == 0x7F00);

    return false;
}

static void test_arm64_correct_address_in_small_jump_hook(void)
{
    uc_engine *uc;
    // mov x0, 0x7F00;
    // br x0
    char code[] = "\x00\xe0\x8f\xd2\x00\x00\x1f\xd6";

    uint64_t r_x0 = 0x0;
    uint64_t r_pc = 0x0;
    uc_hook hook;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_A72);
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_UNMAPPED,
                   test_arm64_correct_address_in_small_jump_hook_callback, NULL,
                   1, 0));

    uc_assert_err(
        UC_ERR_FETCH_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &r_x0));
    OK(uc_reg_read(uc, UC_ARM64_REG_PC, &r_pc));
    TEST_CHECK(r_x0 == 0x7F00);
    TEST_CHECK(r_pc == 0x7F00);

    OK(uc_close(uc));
}

static bool test_arm64_correct_address_in_long_jump_hook_callback(
    uc_engine *uc, int type, uint64_t address, int size, int64_t value,
    void *user_data)
{
    // Check registers
    uint64_t r_x0 = 0x0;
    uint64_t r_pc = 0x0;
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &r_x0));
    OK(uc_reg_read(uc, UC_ARM64_REG_PC, &r_pc));
    TEST_CHECK(r_x0 == 0x7FFFFFFFFFFFFF00);
    TEST_CHECK(r_pc == 0x7FFFFFFFFFFFFF00);

    // Check address
    // printf("%lx\n", address);
    TEST_CHECK(address == 0x7FFFFFFFFFFFFF00);

    return false;
}

static void test_arm64_correct_address_in_long_jump_hook(void)
{
    uc_engine *uc;
    // mov x0, 0x7FFFFFFFFFFFFF00;
    // br x0
    char code[] = "\xe0\xdb\x78\xb2\x00\x00\x1f\xd6";

    uint64_t r_x0 = 0x0;
    uint64_t r_pc = 0x0;
    uc_hook hook;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_A72);
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_UNMAPPED,
                   test_arm64_correct_address_in_long_jump_hook_callback, NULL,
                   1, 0));

    uc_assert_err(
        UC_ERR_FETCH_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &r_x0));
    OK(uc_reg_read(uc, UC_ARM64_REG_PC, &r_pc));
    TEST_CHECK(r_x0 == 0x7FFFFFFFFFFFFF00);
    TEST_CHECK(r_pc == 0x7FFFFFFFFFFFFF00);

    OK(uc_close(uc));
}

static void test_arm64_block_sync_pc_cb(uc_engine *uc, uint64_t addr,
                                        uint32_t size, void *data)
{
    uint64_t pc;
    OK(uc_reg_read(uc, UC_ARM64_REG_PC, (void *)&pc));
    TEST_CHECK(pc == addr);
    uint64_t val = code_start;
    bool first = *(bool *)data;
    if (first) {
        OK(uc_reg_write(uc, UC_ARM64_REG_PC, (void *)&val));
        *(bool *)data = false;
    }
}

static void test_arm64_block_sync_pc(void)
{
    uc_engine *uc;
    // add x0, x0, #1234;bl t;t:mov x1, #5678;
    const char code[] = "\x00\x48\x13\x91\x01\x00\x00\x94\xc1\xc5\x82\xd2";
    uc_hook hk;
    uint64_t x0;
    bool data = true;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_A72);
    OK(uc_hook_add(uc, &hk, UC_HOOK_BLOCK, test_arm64_block_sync_pc_cb,
                   (void *)&data, code_start + 8, code_start + 12));

    x0 = 0;
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, (void *)&x0));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM64_REG_X0, (void *)&x0));

    TEST_CHECK(x0 == (1234 * 2));

    OK(uc_hook_del(uc, hk));
    OK(uc_close(uc));
}

static bool
test_arm64_block_invalid_mem_read_write_sync_cb(uc_engine *uc, int type,
                                                uint64_t address, int size,
                                                int64_t value, void *user_data)
{
    return 0;
}

static void test_arm64_block_invalid_mem_read_write_sync(void)
{
    uc_engine *uc;
    // mov x0, #1
    // mov x1, #2
    // ldr x0, [x1]
    const char code[] = "\x20\x00\x80\xd2\x41\x00\x80\xd2\x20\x00\x40\xf9";
    uint64_t r_pc, r_x0, r_x1;
    uc_hook hk;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_A72);

    OK(uc_hook_add(uc, &hk, UC_HOOK_MEM_READ,
                   test_arm64_block_invalid_mem_read_write_sync_cb, NULL, 1,
                   0));

    uc_assert_err(
        UC_ERR_READ_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM64_REG_PC, &r_pc));
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &r_x0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X1, &r_x1));

    TEST_CHECK(r_pc == code_start + 8);
    TEST_CHECK(r_x0 == 1);
    TEST_CHECK(r_x1 == 2);

    OK(uc_close(uc));
}

static void test_arm64_mmu(void)
{
    uc_engine *uc;
    char *data;
    char tlbe[8];
    uint64_t x0, x1, x2;
    /*
     * Not exact the binary, but aarch64-linux-gnu-as generate this code and
     reference sometimes data after ttb0_base.
     * // Read data from physical address
     * ldr X0, =0x40000000
     * ldr X1, [X0]

     * // Initialize translation table control registers
     * ldr X0, =0x180803F20
     * msr TCR_EL1, X0
     * ldr X0, =0xFFFFFFFF
     * msr MAIR_EL1, X0

     * // Set translation table
     * adr X0, ttb0_base
     * msr TTBR0_EL1, X0

     * // Enable caches and the MMU
     * mrs X0, SCTLR_EL1
     * orr X0, X0, #(0x1 << 2) // The C bit (data cache).
     * orr X0, X0, #(0x1 << 12) // The I bit (instruction cache)
     * orr X0, X0, #0x1 // The M bit (MMU).
     * msr SCTLR_EL1, X0
     * dsb SY
     * isb

     * // Read the same memory area through virtual address
     * ldr X0, =0x80000000
     * ldr X2, [X0]
     *
     * // Stop
     * b .
     */
    char code[] = "\x00\x81\x00\x58\x01\x00\x40\xf9\x00\x81\x00\x58\x40\x20\x18"
                  "\xd5\x00\x81\x00\x58\x00\xa2\x18\xd5\x40\x7f\x00\x10\x00\x20"
                  "\x18\xd5\x00\x10\x38\xd5\x00\x00\x7e\xb2\x00\x00\x74\xb2\x00"
                  "\x00\x40\xb2\x00\x10\x18\xd5\x9f\x3f\x03\xd5\xdf\x3f\x03\xd5"
                  "\xe0\x7f\x00\x58\x02\x00\x40\xf9\x00\x00\x00\x14\x1f\x20\x03"
                  "\xd5\x1f\x20\x03\xd5\x1F\x20\x03\xD5\x1F\x20\x03\xD5";

    data = malloc(0x1000);
    TEST_CHECK(data != NULL);

    OK(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_CPU));
    OK(uc_mem_map(uc, 0, 0x2000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0, code, sizeof(code) - 1));

    // generate tlb entries
    tlbe[0] = 0x41;
    tlbe[1] = 0x07;
    tlbe[2] = 0;
    tlbe[3] = 0;
    tlbe[4] = 0;
    tlbe[5] = 0;
    tlbe[6] = 0;
    tlbe[7] = 0;
    OK(uc_mem_write(uc, 0x1000, tlbe, sizeof(tlbe)));
    tlbe[3] = 0x40;
    OK(uc_mem_write(uc, 0x1008, tlbe, sizeof(tlbe)));
    OK(uc_mem_write(uc, 0x1010, tlbe, sizeof(tlbe)));
    OK(uc_mem_write(uc, 0x1018, tlbe, sizeof(tlbe)));

    // mentioned data referenced by the asm generated my aarch64-linux-gnu-as
    tlbe[0] = 0;
    tlbe[1] = 0;
    OK(uc_mem_write(uc, 0x1020, tlbe, sizeof(tlbe)));
    tlbe[0] = 0x20;
    tlbe[1] = 0x3f;
    tlbe[2] = 0x80;
    tlbe[3] = 0x80;
    tlbe[4] = 0x1;
    OK(uc_mem_write(uc, 0x1028, tlbe, sizeof(tlbe)));
    tlbe[0] = 0xff;
    tlbe[1] = 0xff;
    tlbe[2] = 0xff;
    tlbe[3] = 0xff;
    tlbe[4] = 0x00;
    OK(uc_mem_write(uc, 0x1030, tlbe, sizeof(tlbe)));
    tlbe[0] = 0x00;
    tlbe[1] = 0x00;
    tlbe[2] = 0x00;
    tlbe[3] = 0x80;
    OK(uc_mem_write(uc, 0x1038, tlbe, sizeof(tlbe)));

    for (size_t i = 0; i < 0x1000; i++) {
        data[i] = 0x44;
    }
    OK(uc_mem_map_ptr(uc, 0x40000000, 0x1000, UC_PROT_READ, data));

    OK(uc_emu_start(uc, 0, 0x44, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &x0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X2, &x2));

    TEST_CHECK(x0 == 0x80000000);
    TEST_CHECK(x1 == 0x4444444444444444);
    TEST_CHECK(x2 == 0x4444444444444444);
    free(data);
    OK(uc_close(uc));
}

static void test_arm64_pc_wrap(void)
{
    uc_engine *uc;
    // add x1 x2
    char add_x1_x2[] = "\x20\x00\x02\x8b";
    // add x1 x3
    char add_x1_x3[] = "\x20\x00\x03\x8b";
    uint64_t x0, x1, x2, x3;
    uint64_t pc = 0xFFFFFFFFFFFFFFFCULL;
    uint64_t page = 0xFFFFFFFFFFFFF000ULL;

    OK(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc));
    OK(uc_mem_map(uc, page, 4096, UC_PROT_READ | UC_PROT_EXEC));
    OK(uc_mem_write(uc, pc, add_x1_x2, sizeof(add_x1_x2) - 1));

    x1 = 1;
    x2 = 2;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));

    OK(uc_emu_start(uc, pc, pc + 4, 0, 1));

    OK(uc_mem_unmap(uc, page, 4096));

    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &x0));

    TEST_CHECK((x0 == 1 + 2));

    OK(uc_mem_map(uc, page, 4096, UC_PROT_READ | UC_PROT_EXEC));
    OK(uc_mem_write(uc, pc, add_x1_x3, sizeof(add_x1_x3) - 1));

    x1 = 5;
    x2 = 0;
    x3 = 5;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));

    OK(uc_emu_start(uc, pc, pc + 4, 0, 1));

    OK(uc_mem_unmap(uc, page, 4096));

    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &x0));

    TEST_CHECK((x0 == 5 + 5));

    OK(uc_close(uc));
}

static void test_arm64_mem_prot_regress_hook_mem(uc_engine *uc,
                                                 uc_mem_type type,
                                                 uint64_t address, int size,
                                                 int64_t value, void *user_data)
{
    // fprintf(stderr, "%s %p %d\n", (type == UC_MEM_WRITE) ? "UC_MEM_WRITE" :
    // "UC_MEM_READ", (void *)address, size);
}

static bool test_arm64_mem_prot_regress_hook_prot(uc_engine *uc,
                                                  uc_mem_type type,
                                                  uint64_t address, int size,
                                                  int64_t value,
                                                  void *user_data)
{
    // fprintf(stderr, "%s %p %d\n", (type == UC_MEM_WRITE_PROT) ?
    // "UC_MEM_WRITE_PROT" : ((type == UC_MEM_FETCH_PROT) ? "UC_MEM_FETCH_PROT"
    // : "UC_MEM_READ_PROT"), (void *)address, size);
    return false;
}

static bool test_arm64_mem_prot_regress_hook_unm(uc_engine *uc,
                                                 uc_mem_type type,
                                                 uint64_t address, int size,
                                                 int64_t value, void *user_data)
{
    // fprintf(stderr, "%s %p %d\n", (type == UC_MEM_WRITE_UNMAPPED) ?
    // "UC_MEM_WRITE_UNMAPPED" : ((type == UC_MEM_FETCH_UNMAPPED) ?
    // "UC_MEM_FETCH_UNMAPPED" : "UC_MEM_READ_UNMAPPED"), (void *)address,
    // size);
    return false;
}

// https://github.com/unicorn-engine/unicorn/issues/2078
static void test_arm64_mem_prot_regress(void)
{
    const uint8_t code[] = {
        0x08, 0x40, 0x5e, 0x78, // ldurh w8, [x0, #-0x1c]
    };

    uc_engine *uc;
    OK(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc));

    OK(uc_mem_map(uc, 0, 0x4000, UC_PROT_READ | UC_PROT_EXEC));
    OK(uc_mem_map(uc, 0x4000, 0xC000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, 0, code, sizeof(code)));
    uc_hook hh_mem;
    OK(uc_hook_add(uc, &hh_mem, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                   test_arm64_mem_prot_regress_hook_mem, NULL, 1, 0));

    uc_hook hh_prot;
    OK(uc_hook_add(uc, &hh_prot, UC_HOOK_MEM_PROT,
                   test_arm64_mem_prot_regress_hook_prot, NULL, 1, 0));

    uc_hook hh_unm;
    OK(uc_hook_add(uc, &hh_unm, UC_HOOK_MEM_UNMAPPED,
                   test_arm64_mem_prot_regress_hook_unm, NULL, 1, 0));

    const uint64_t value = 0x801b;
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &value));

    OK(uc_emu_start(uc, 0, sizeof(code), 0, 0));

    OK(uc_close(uc));
}

static bool test_arm64_mem_read_write_cb(uc_engine *uc, int type,
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
static void test_arm64_mem_hook_read_write(void)
{
    uc_engine *uc;
    // ldp x1, x2, [sp]
    // stp x1, x2,[sp]
    // ldp x1, x2, [sp]
    // stp x1, x2,[sp]
    const char code[] = {0xe1, 0x0b, 0x40, 0xa9, 0xe1, 0x0b, 0x00, 0xa9,
                         0xe1, 0x0b, 0x40, 0xa9, 0xe1, 0x0b, 0x00, 0xa9};
    uint64_t r_sp;
    r_sp = 0x16db6a040;
    uc_hook hk;
    uint64_t counter[2] = {0, 0};

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code),
                    UC_CPU_ARM64_A72);

    uc_reg_write(uc, UC_ARM64_REG_SP, &r_sp);
    uc_mem_map(uc, 0x16db68000, 1024 * 16, UC_PROT_ALL);

    OK(uc_hook_add(uc, &hk, UC_HOOK_MEM_READ, test_arm64_mem_read_write_cb,
                   counter, 1, 0));
    OK(uc_hook_add(uc, &hk, UC_HOOK_MEM_WRITE, test_arm64_mem_read_write_cb,
                   counter, 1, 0));

    uc_assert_err(UC_ERR_OK, uc_emu_start(uc, code_start,
                                          code_start + sizeof(code), 0, 0));

    TEST_CHECK(counter[0] == 4 && counter[1] == 4);
    OK(uc_close(uc));
}

static void test_arm64_pc_guarantee(void)
{
    uc_engine *uc;
    // ks.asm("mov x0, #1; mov x1, #2; ldr x0, [x1]")
    const char code[] = "\x20\x00\x80\xd2\x41\x00\x80\xd2\x20\x00\x40\xf9";
    uint64_t rip;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code),
                    UC_CPU_ARM64_A72);

    uc_assert_err(UC_ERR_READ_UNMAPPED, uc_emu_start(uc, code_start,
                                          code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM64_REG_PC, (void*)&rip));
    TEST_CHECK(rip == code_start + 8);
    OK(uc_close(uc));
}

static uint64_t test_arm64_pauth_cp_reg_read(uc_engine *uc, const uint32_t cpregid[5])
{
    uc_arm64_cp_reg reg = {
        .op0 = cpregid[0],
        .op1 = cpregid[1],
        .crn = cpregid[2],
        .crm = cpregid[3],
        .op2 = cpregid[4],
        .val = 0,
    };
    OK(uc_reg_read(uc, UC_ARM64_REG_CP_REG, &reg));
    return reg.val;
}

static void test_arm64_pauth_cp_reg_write(uc_engine *uc, const uint32_t cpregid[5], uint64_t value)
{
    uc_arm64_cp_reg reg = {
        .op0 = cpregid[0],
        .op1 = cpregid[1],
        .crn = cpregid[2],
        .crm = cpregid[3],
        .op2 = cpregid[4],
        .val = value,
    };
    OK(uc_reg_write(uc, UC_ARM64_REG_CP_REG, &reg));
}

static bool test_arm64_pauth_cp_reg_update(uc_engine *uc, const uint32_t cpregid[5], uint64_t clearmask, uint64_t setmask)
{
    uc_arm64_cp_reg reg = {
        .op0 = cpregid[0],
        .op1 = cpregid[1],
        .crn = cpregid[2],
        .crm = cpregid[3],
        .op2 = cpregid[4],
        .val = 0,
    };
    OK(uc_reg_read(uc, UC_ARM64_REG_CP_REG, &reg));
    reg.val &= ~clearmask;
    reg.val |= setmask;
    OK(uc_reg_write(uc, UC_ARM64_REG_CP_REG, &reg));
    OK(uc_reg_read(uc, UC_ARM64_REG_CP_REG, &reg));
    return (((reg.val & setmask) == setmask) && ((reg.val & clearmask) == 0));
}

static uint32_t test_arm64_mrs_sysreg(uint32_t rt,
                                      const uint32_t cpregid[5])
{
    return 0xd5200000 | (cpregid[0] << 19) | (cpregid[1] << 16) |
           (cpregid[2] << 12) | (cpregid[3] << 8) |
           (cpregid[4] << 5) | rt;
}

static uint32_t test_arm64_msr_sysreg(uint32_t rt,
                                      const uint32_t cpregid[5])
{
    return 0xd5000000 | (cpregid[0] << 19) | (cpregid[1] << 16) |
           (cpregid[2] << 12) | (cpregid[3] << 8) |
           (cpregid[4] << 5) | rt;
}

static void test_arm64_pauth_check_cpu_feat(uc_engine *uc)
{
    // Check the CPU actually supports any form of PAuth, i.e. any APA or API
    // bits are set.  At the time of writing, UC_CPU_ARM64_A72 does not support
    // PAuth, but UC_CPU_ARM64_MAX does.  This check is not required for any of
    // the PAuth tests to work, but helps with diagnostics when the selected
    // CPU does not support PAuth.

    const uint32_t ID_AA64ISAR1_EL1[5] = { 0b11, 0b000, 0b0000, 0b0110, 0b001 };
    const uint64_t ID_AA64ISAR1_EL1_APA_API_MASK = (0b1111ULL << 4) | (0b1111ULL << 8);
    uint64_t ID_AA64ISAR1_EL1_bits = test_arm64_pauth_cp_reg_read(uc, ID_AA64ISAR1_EL1);
    TEST_CHECK((ID_AA64ISAR1_EL1_bits & ID_AA64ISAR1_EL1_APA_API_MASK) != 0);
}

static void test_arm64_lse_rcpc_id_registers(void)
{
    uc_engine *uc;
    const char code[] = "\x1f\x20\x03\xd5"; /* nop */
    const uint32_t ID_AA64ISAR0_EL1[5] = { 3, 0, 0, 6, 0 };
    const uint32_t ID_AA64ISAR1_EL1[5] = { 3, 0, 0, 6, 1 };
    const uint32_t ID_AA64ISAR2_EL1[5] = { 3, 0, 0, 6, 2 };
    const uint32_t ID_AA64MMFR2_EL1[5] = { 3, 0, 0, 7, 2 };
    uint64_t isar0;
    uint64_t isar1;
    uint64_t isar2;
    uint64_t mmfr2;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    isar0 = test_arm64_pauth_cp_reg_read(uc, ID_AA64ISAR0_EL1);
    isar1 = test_arm64_pauth_cp_reg_read(uc, ID_AA64ISAR1_EL1);
    isar2 = test_arm64_pauth_cp_reg_read(uc, ID_AA64ISAR2_EL1);
    mmfr2 = test_arm64_pauth_cp_reg_read(uc, ID_AA64MMFR2_EL1);
    TEST_CHECK(((isar0 >> 20) & 0xf) == 2);
    TEST_CHECK(((isar1 >> 20) & 0xf) == 2);
    TEST_CHECK(((isar1 >> 48) & 0xf) == 1);
    TEST_CHECK(((isar1 >> 56) & 0xf) == 0);
    TEST_CHECK(((isar1 >> 60) & 0xf) == 0);
    TEST_CHECK(isar2 == 0);
    TEST_CHECK(((mmfr2 >> 32) & 0xf) == 0);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_A72);
    isar0 = test_arm64_pauth_cp_reg_read(uc, ID_AA64ISAR0_EL1);
    isar1 = test_arm64_pauth_cp_reg_read(uc, ID_AA64ISAR1_EL1);
    isar2 = test_arm64_pauth_cp_reg_read(uc, ID_AA64ISAR2_EL1);
    mmfr2 = test_arm64_pauth_cp_reg_read(uc, ID_AA64MMFR2_EL1);
    TEST_CHECK(((isar0 >> 20) & 0xf) == 0);
    TEST_CHECK(((isar1 >> 20) & 0xf) == 0);
    TEST_CHECK(((isar1 >> 48) & 0xf) == 0);
    TEST_CHECK(((isar1 >> 56) & 0xf) == 0);
    TEST_CHECK(((isar1 >> 60) & 0xf) == 0);
    TEST_CHECK(isar2 == 0);
    TEST_CHECK(((mmfr2 >> 32) & 0xf) == 0);
    OK(uc_close(uc));
}

static void test_arm64_a72_rejects_code(const char *code, size_t size)
{
    uc_engine *uc;
    uint64_t x0 = 0x40000;
    uint64_t x8 = 0;
    uint64_t x9 = 0x40000;
    uint64_t x10 = 0;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, size,
                    UC_CPU_ARM64_A72);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &x0));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_reg_write(uc, UC_ARM64_REG_X9, &x9));
    OK(uc_reg_write(uc, UC_ARM64_REG_X10, &x10));
    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + size, 0, 0));
    OK(uc_close(uc));
}

static void test_arm64_lse_rcpc_a72_rejects(void)
{
    const char casal[] = "\x28\xfd\xea\xc8";
    const char ldapr[] = "\x03\xc0\xbf\xf8";
    const char ldapur[] = "\x04\x00\x40\xd9";

    test_arm64_a72_rejects_code(casal, sizeof(casal) - 1);
    test_arm64_a72_rejects_code(ldapr, sizeof(ldapr) - 1);
    test_arm64_a72_rejects_code(ldapur, sizeof(ldapur) - 1);
}

static void test_arm64_sve_id_registers(void)
{
    uc_engine *uc;
    const char code[] = "\x1f\x20\x03\xd5"; /* nop */
    const uint32_t ID_AA64ISAR1_EL1[5] = { 3, 0, 0, 6, 1 };
    const uint32_t ID_AA64PFR0_EL1[5] = { 3, 0, 0, 4, 0 };
    const uint32_t ID_AA64PFR1_EL1[5] = { 3, 0, 0, 4, 1 };
    const uint32_t ID_AA64ZFR0_EL1[5] = { 3, 0, 0, 4, 4 };
    const uint32_t ID_AA64SMFR0_EL1[5] = { 3, 0, 0, 4, 5 };
    const uint64_t isar1_bf16 = 0xfULL << 44;
    const uint64_t isar1_i8mm = 0xfULL << 52;
    const uint64_t pfr0_sve = 0xfULL << 32;
    const uint64_t pfr1_mte = 0xfULL << 8;
    const uint64_t pfr1_sme = 0xfULL << 24;
    const uint64_t zfr0_svever = 0xfULL;
    const uint64_t zfr0_aes = 0xfULL << 4;
    const uint64_t zfr0_bitperm = 0xfULL << 16;
    const uint64_t zfr0_bf16 = 0xfULL << 20;
    const uint64_t zfr0_sha3 = 0xfULL << 32;
    const uint64_t zfr0_sm4 = 0xfULL << 40;
    const uint64_t zfr0_i8mm = 0xfULL << 44;
    const uint64_t zfr0_f32mm = 0xfULL << 52;
    const uint64_t zfr0_f64mm = 0xfULL << 56;
    const uint64_t smfr0_f32f32 = 1ULL << 32;
    const uint64_t smfr0_b16f32 = 1ULL << 34;
    const uint64_t smfr0_f16f32 = 1ULL << 35;
    const uint64_t smfr0_i8i32 = 0xfULL << 36;
    const uint64_t smfr0_f64f64 = 1ULL << 48;
    const uint64_t smfr0_i16i64 = 0xfULL << 52;
    const uint64_t smfr0_smever = 0xfULL << 56;
    const uint64_t smfr0_fa64 = 1ULL << 63;
    uint64_t isar1;
    uint64_t pfr0;
    uint64_t pfr1;
    uint64_t zfr0;
    uint64_t smfr0;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    isar1 = test_arm64_pauth_cp_reg_read(uc, ID_AA64ISAR1_EL1);
    pfr0 = test_arm64_pauth_cp_reg_read(uc, ID_AA64PFR0_EL1);
    pfr1 = test_arm64_pauth_cp_reg_read(uc, ID_AA64PFR1_EL1);
    zfr0 = test_arm64_pauth_cp_reg_read(uc, ID_AA64ZFR0_EL1);
    smfr0 = test_arm64_pauth_cp_reg_read(uc, ID_AA64SMFR0_EL1);
    TEST_CHECK(((isar1 & isar1_bf16) >> 44) == 1);
    TEST_CHECK(((isar1 & isar1_i8mm) >> 52) == 1);
    TEST_CHECK(((pfr0 & pfr0_sve) >> 32) == 1);
    TEST_CHECK(((pfr1 & pfr1_mte) >> 8) == 2);
    TEST_CHECK(((pfr1 & pfr1_sme) >> 24) == 1);
    TEST_CHECK((zfr0 & zfr0_svever) == 1);
    TEST_CHECK(((zfr0 & zfr0_aes) >> 4) == 2);
    TEST_CHECK(((zfr0 & zfr0_bitperm) >> 16) == 1);
    TEST_CHECK(((zfr0 & zfr0_bf16) >> 20) == 1);
    TEST_CHECK(((zfr0 & zfr0_sha3) >> 32) == 1);
    TEST_CHECK(((zfr0 & zfr0_sm4) >> 40) == 1);
    TEST_CHECK(((zfr0 & zfr0_i8mm) >> 44) == 1);
    TEST_CHECK(((zfr0 & zfr0_f32mm) >> 52) == 1);
    TEST_CHECK(((zfr0 & zfr0_f64mm) >> 56) == 1);
    TEST_CHECK(((smfr0 & smfr0_f32f32) >> 32) == 1);
    TEST_CHECK(((smfr0 & smfr0_b16f32) >> 34) == 1);
    TEST_CHECK(((smfr0 & smfr0_f16f32) >> 35) == 1);
    TEST_CHECK(((smfr0 & smfr0_i8i32) >> 36) == 0xf);
    TEST_CHECK(((smfr0 & smfr0_f64f64) >> 48) == 1);
    TEST_CHECK(((smfr0 & smfr0_i16i64) >> 52) == 0xf);
    TEST_CHECK(((smfr0 & smfr0_smever) >> 56) == 1);
    TEST_CHECK(((smfr0 & smfr0_fa64) >> 63) == 1);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_A72);
    isar1 = test_arm64_pauth_cp_reg_read(uc, ID_AA64ISAR1_EL1);
    pfr0 = test_arm64_pauth_cp_reg_read(uc, ID_AA64PFR0_EL1);
    pfr1 = test_arm64_pauth_cp_reg_read(uc, ID_AA64PFR1_EL1);
    zfr0 = test_arm64_pauth_cp_reg_read(uc, ID_AA64ZFR0_EL1);
    smfr0 = test_arm64_pauth_cp_reg_read(uc, ID_AA64SMFR0_EL1);
    TEST_CHECK((isar1 & isar1_bf16) == 0);
    TEST_CHECK((isar1 & isar1_i8mm) == 0);
    TEST_CHECK((pfr0 & pfr0_sve) == 0);
    TEST_CHECK((pfr1 & pfr1_mte) == 0);
    TEST_CHECK((pfr1 & pfr1_sme) == 0);
    TEST_CHECK(zfr0 == 0);
    TEST_CHECK(smfr0 == 0);
    OK(uc_close(uc));
}

#define SCTLR_EL1_EnIA (1ULL << 31)
#define SCTLR_EL1_EnIB (1ULL << 30)
#define SCTLR_EL1_EnDA (1ULL << 27)
#define SCTLR_EL1_EnDB (1ULL << 13)
static void test_arm64_pauth_setup(uc_engine *uc, uint64_t SCTLR_EL1_En_bits)
{
    // Minimal PAuth setup.  The tests are agnostic to VA size and MTE config,
    // so don't bother touching TCR_EL1 for now.  Proper setup for PAuth would
    // also involve configuring TCR_EL1 TxSZ, TBIx, TBDIx too.

    const uint32_t SCR_EL3[5] = { 0b11, 0b110, 0b0001, 0b0001, 0b000 };
    const uint64_t SCR_EL3_NS_RW_API = 1ULL | (1ULL << 10) | (1ULL << 17);
    TEST_CHECK(test_arm64_pauth_cp_reg_update(uc, SCR_EL3, 0, SCR_EL3_NS_RW_API));

    const uint32_t HCR_EL2[5] = { 0b11, 0b100, 0b0001, 0b0001, 0b000 };
    const uint64_t HCR_EL2_API = 1ULL << 41;
    TEST_CHECK(test_arm64_pauth_cp_reg_update(uc, HCR_EL2, 0, HCR_EL2_API));

    const uint32_t SCTLR_EL1[5] = { 0b11, 0b000, 0b0001, 0b0000, 0b000 };
    TEST_CHECK(test_arm64_pauth_cp_reg_update(uc, SCTLR_EL1, 0, SCTLR_EL1_En_bits));

    // Set up all keys.  Tests expect them being set even when not enabled.
    const uint32_t APIAKeyLo_EL1[5] = { 0b11, 0b000, 0b0010, 0b0001, 0b000 };
    const uint32_t APIAKeyHi_EL1[5] = { 0b11, 0b000, 0b0010, 0b0001, 0b001 };
    const uint32_t APIBKeyLo_EL1[5] = { 0b11, 0b000, 0b0010, 0b0001, 0b010 };
    const uint32_t APIBKeyHi_EL1[5] = { 0b11, 0b000, 0b0010, 0b0001, 0b011 };
    const uint32_t APDAKeyLo_EL1[5] = { 0b11, 0b000, 0b0010, 0b0010, 0b000 };
    const uint32_t APDAKeyHi_EL1[5] = { 0b11, 0b000, 0b0010, 0b0010, 0b001 };
    const uint32_t APDBKeyLo_EL1[5] = { 0b11, 0b000, 0b0010, 0b0010, 0b010 };
    const uint32_t APDBKeyHi_EL1[5] = { 0b11, 0b000, 0b0010, 0b0010, 0b011 };
    const uint32_t APGAKeyLo_EL1[5] = { 0b11, 0b000, 0b0010, 0b0011, 0b000 };
    const uint32_t APGAKeyHi_EL1[5] = { 0b11, 0b000, 0b0010, 0b0011, 0b001 };
    test_arm64_pauth_cp_reg_write(uc, APIAKeyLo_EL1, 0xAAAAAAAAAAAAAAAAULL);
    test_arm64_pauth_cp_reg_write(uc, APIAKeyHi_EL1, 0xBBBBBBBBBBBBBBBBULL);
    test_arm64_pauth_cp_reg_write(uc, APIBKeyLo_EL1, 0xCCCCCCCCCCCCCCCCULL);
    test_arm64_pauth_cp_reg_write(uc, APIBKeyHi_EL1, 0xDDDDDDDDDDDDDDDDULL);
    test_arm64_pauth_cp_reg_write(uc, APDAKeyLo_EL1, 0xAAAAAAAAAAAAAAAAULL); // == IA
    test_arm64_pauth_cp_reg_write(uc, APDAKeyHi_EL1, 0xBBBBBBBBBBBBBBBBULL);
    test_arm64_pauth_cp_reg_write(uc, APDBKeyLo_EL1, 0xEEEEEEEEEEEEEEEEULL);
    test_arm64_pauth_cp_reg_write(uc, APDBKeyHi_EL1, 0xFFFFFFFFFFFFFFFFULL);
    test_arm64_pauth_cp_reg_write(uc, APGAKeyLo_EL1, 0x0123456789ABCDEFULL);
    test_arm64_pauth_cp_reg_write(uc, APGAKeyHi_EL1, 0x0123456789ABCDEFULL);
}

static void test_arm64_pauth_vanilla(void) {
    // PAuth test w/o using any uc_ctl interfaces, just PAuth on the CPU.

    uc_engine *uc;
    const char code_paciza_x1[] = "\xe1\x23\xc1\xda"; // paciza x1
    const char code_autiza_x1[] = "\xe1\x33\xc1\xda"; // autiza x1
    const char code_autizb_x1[] = "\xe1\x37\xc1\xda"; // autizb x1
    const char code_autdza_x1[] = "\xe1\x3b\xc1\xda"; // autdza x1
    const char code_autia_x1_x0[] = "\x01\x10\xc1\xda"; // autia x1, x0
    const char code_xpaci_x1[] = "\xe1\x43\xc1\xda"; // xpaci x1

    // We expect a PAC added somewhere in pac_mask bits in order to make the
    // test agnostic of TxSZ and TBI.

    const uint64_t some_unsigned_pointer = 0x0000aaaabbbbccccULL;
    const uint64_t pac_mask = 0xffff000000000000ULL & ~(1ULL << 55);

    OK(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM64_MAX));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));

    test_arm64_pauth_check_cpu_feat(uc);
    test_arm64_pauth_setup(uc, SCTLR_EL1_EnIA | SCTLR_EL1_EnIB);

    // Verify that paciza signs a pointer.

    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &some_unsigned_pointer));
    OK(uc_mem_write(uc, code_start, code_paciza_x1, sizeof(code_paciza_x1)));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_paciza_x1) - 1, 0, 0));
    uint64_t signed_pointer = 0;
    OK(uc_reg_read(uc, UC_ARM64_REG_X1, &signed_pointer));
    TEST_CHECK(signed_pointer != some_unsigned_pointer);
    TEST_CHECK((signed_pointer & pac_mask) != 0);

    // Verify that xpaci results in original pointer.

    OK(uc_mem_write(uc, code_start, code_xpaci_x1, sizeof(code_xpaci_x1)));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_xpaci_x1) - 1, 0, 0));
    uint64_t stripped_pointer = 0;
    OK(uc_reg_read(uc, UC_ARM64_REG_X1, &stripped_pointer));
    TEST_CHECK(stripped_pointer == some_unsigned_pointer);

    // Verify autia behaviour.

    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &some_unsigned_pointer));
    OK(uc_mem_write(uc, code_start, code_autiza_x1, sizeof(code_autiza_x1)));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_autiza_x1) - 1, 0, 0));
    uint64_t authenticated_pointer = 0;
    OK(uc_reg_read(uc, UC_ARM64_REG_X1, &authenticated_pointer));
    TEST_CHECK((authenticated_pointer & pac_mask) != 0); // unsigned pointer is invalid

    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &signed_pointer));
    OK(uc_mem_write(uc, code_start, code_autiza_x1, sizeof(code_autiza_x1)));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_autiza_x1) - 1, 0, 0));
    authenticated_pointer = 0;
    OK(uc_reg_read(uc, UC_ARM64_REG_X1, &authenticated_pointer));
    TEST_CHECK((authenticated_pointer & pac_mask) == 0); // signed pointer is valid

    uint64_t diversifier = 1337;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &signed_pointer));
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &diversifier));
    OK(uc_mem_write(uc, code_start, code_autia_x1_x0, sizeof(code_autia_x1_x0)));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_autia_x1_x0) - 1, 0, 0));
    authenticated_pointer = 0;
    OK(uc_reg_read(uc, UC_ARM64_REG_X1, &authenticated_pointer));
    TEST_CHECK((authenticated_pointer & pac_mask) != 0); // wrong diversifier is invalid

    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &signed_pointer));
    OK(uc_mem_write(uc, code_start, code_autizb_x1, sizeof(code_autizb_x1)));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_autizb_x1) - 1, 0, 0));
    authenticated_pointer = 0;
    OK(uc_reg_read(uc, UC_ARM64_REG_X1, &authenticated_pointer));
    TEST_CHECK((authenticated_pointer & pac_mask) != 0); // wrong but enabled key is invalid

    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &signed_pointer));
    OK(uc_mem_write(uc, code_start, code_autdza_x1, sizeof(code_autdza_x1)));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_autdza_x1) - 1, 0, 0));
    authenticated_pointer = 0;
    OK(uc_reg_read(uc, UC_ARM64_REG_X1, &authenticated_pointer));
    TEST_CHECK((authenticated_pointer & pac_mask) != 0); // disabled but same value key is invalid

    OK(uc_close(uc));
}

static void test_arm64_pauth_ctl(void)
{
    // PAuth test for the uc_ctl interfaces.

    uc_engine *uc;
    const char code_paciza_x1[] = "\xe1\x23\xc1\xda"; // paciza x1

    // We expect a PAC added somewhere in pac_mask bits in order to make the
    // test agnostic of TxSZ and TBI.

    const uint64_t some_unsigned_pointer = 0x0000aaaabbbbccccULL;
    const uint64_t pac_mask = 0xffff000000000000ULL & ~(1ULL << 55);

    OK(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM64_MAX));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));

    test_arm64_pauth_check_cpu_feat(uc);
    test_arm64_pauth_setup(uc, SCTLR_EL1_EnIA | SCTLR_EL1_EnIB);

    // Verify that paciza and uc_ctl_pauth_sign() result in the same signed
    // pointer.

    OK(uc_mem_write(uc, code_start, code_paciza_x1, sizeof(code_paciza_x1)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &some_unsigned_pointer));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_paciza_x1) - 1, 0, 0));
    uint64_t signed_pointer_paciza = 0;
    OK(uc_reg_read(uc, UC_ARM64_REG_X1, &signed_pointer_paciza));
    TEST_CHECK(signed_pointer_paciza != some_unsigned_pointer);
    TEST_CHECK((signed_pointer_paciza & pac_mask) != 0);

    uint64_t signed_pointer = 0;
    OK(uc_ctl_pauth_sign(uc, some_unsigned_pointer, UC_ARM64_PAUTH_KEY_IA, 0, &signed_pointer));
    TEST_CHECK(signed_pointer == signed_pointer_paciza);

    // Verify that stripping the PAC results in the original pointer.

    uint64_t stripped_pointer = 0;
    OK(uc_ctl_pauth_strip(uc, signed_pointer, UC_ARM64_PAUTH_KEY_IA, &stripped_pointer));
    TEST_CHECK(stripped_pointer == some_unsigned_pointer);

    // Verify that authenticating works as expected.

    bool valid = true;
    OK(uc_ctl_pauth_auth(uc, some_unsigned_pointer, UC_ARM64_PAUTH_KEY_IA, 0, &valid));
    TEST_CHECK(!valid); // unsigned pointer
    valid = false;
    OK(uc_ctl_pauth_auth(uc, signed_pointer, UC_ARM64_PAUTH_KEY_IA, 0, &valid));
    TEST_CHECK(valid);  // signed pointer
    valid = true;
    OK(uc_ctl_pauth_auth(uc, signed_pointer, UC_ARM64_PAUTH_KEY_IA, 1337, &valid));
    TEST_CHECK(!valid); // wrong diversifier
    valid = true;
    OK(uc_ctl_pauth_auth(uc, signed_pointer, UC_ARM64_PAUTH_KEY_IB, 0, &valid));
    TEST_CHECK(!valid); // wrong but enabled key
    valid = true;
    OK(uc_ctl_pauth_auth(uc, signed_pointer, UC_ARM64_PAUTH_KEY_DA, 0, &valid));
    TEST_CHECK(!valid); // disabled but same value key

    OK(uc_close(uc));
}

static void test_arm64_mte_register_only(void)
{
    uc_engine *uc;
    const char code[] =
        "\x20\x0c\x82\x91" /* addg  x0,x1,#0x20,#3 */
        "\x22\x14\x81\xd1" /* subg  x2,x1,#0x10,#5 */
        "\x23\x10\xc4\x9a" /* irg   x3,x1,x4 */
        "\xc5\x14\xc7\x9a" /* gmi   x5,x6,x7 */
        "\x28\x01\xca\x9a" /* subp  x8,x9,x10 */
        "\x8b\x01\xcd\xba"; /* subps x11,x12,x13 */
    const uint32_t TCO[5] = { 3, 3, 4, 2, 7 };
    const uint32_t TFSRE0_EL1[5] = { 3, 0, 5, 6, 1 };
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    const uint32_t TFSR_EL2[5] = { 3, 4, 5, 6, 0 };
    const uint32_t TFSR_EL3[5] = { 3, 6, 5, 6, 0 };
    const uint64_t pstate_tco = 1ULL << 25;
    uint64_t x1 = 0x0a00000000001000ull;
    uint64_t x4 = 0;
    uint64_t x6 = 0x0b00000000000000ull;
    uint64_t x7 = 0x100;
    uint64_t x9 = 0xaa00000000002000ull;
    uint64_t x10 = 0xbb00000000000100ull;
    uint64_t x12 = 0xcc00000000000100ull;
    uint64_t x13 = 0xdd00000000000200ull;
    uint64_t x0, x2, x3, x5, x8, x11;
    uint32_t nzcv;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X9, &x9));
    OK(uc_reg_write(uc, UC_ARM64_REG_X10, &x10));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));
    OK(uc_reg_write(uc, UC_ARM64_REG_X13, &x13));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &x0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_read(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_read(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_reg_read(uc, UC_ARM64_REG_X11, &x11));
    OK(uc_reg_read(uc, UC_ARM64_REG_NZCV, &nzcv));

    test_arm64_pauth_cp_reg_write(uc, TCO, pstate_tco);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TCO) == pstate_tco);
    test_arm64_pauth_cp_reg_write(uc, TCO, 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TCO) == 0);

    test_arm64_pauth_cp_reg_write(uc, TFSRE0_EL1, 0x11);
    test_arm64_pauth_cp_reg_write(uc, TFSR_EL1, 0x22);
    test_arm64_pauth_cp_reg_write(uc, TFSR_EL2, 0x44);
    test_arm64_pauth_cp_reg_write(uc, TFSR_EL3, 0x88);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSRE0_EL1) == 0x11);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0x22);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL2) == 0x44);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL3) == 0x88);

    TEST_CHECK(x0 == 0x1020);
    TEST_CHECK(x2 == 0xff0);
    TEST_CHECK(x3 == 0x1000);
    TEST_CHECK(x5 == 0x900);
    TEST_CHECK(x8 == 0x1f00);
    TEST_CHECK(x11 == 0xffffffffffffff00ull);
    TEST_CHECK((nzcv & 0xf0000000u) == 0x80000000u);

    OK(uc_close(uc));
}

static void test_arm64_mte_enable_checks(uc_engine *uc, uint64_t tcf);

static void test_arm64_mte_ata_tag_generation(void)
{
    uc_engine *uc;
    const char code[] =
        "\x20\x0c\x82\x91" /* addg x0,x1,#0x20,#3 */
        "\x22\x14\x81\xd1" /* subg x2,x1,#0x10,#5 */
        "\x23\x10\xc4\x9a"; /* irg  x3,x1,x4 */
    const uint32_t RGSR_EL1[5] = { 3, 0, 1, 0, 5 };
    const uint32_t GCR_EL1[5] = { 3, 0, 1, 0, 6 };
    uint64_t x1 = 0x0200000000001000ull;
    uint64_t x4 = 0;
    uint64_t x0, x2, x3, rgsr;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    test_arm64_mte_enable_checks(uc, 0);
    test_arm64_pauth_cp_reg_write(uc, GCR_EL1, 0);
    test_arm64_pauth_cp_reg_write(uc, RGSR_EL1, 9);

    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &x0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    rgsr = test_arm64_pauth_cp_reg_read(uc, RGSR_EL1);

    TEST_CHECK(x0 == 0x0500000000001020ull);
    TEST_CHECK(x2 == 0x0700000000000ff0ull);
    TEST_CHECK(x3 == 0x0900000000001000ull);
    TEST_CHECK(rgsr == 9);

    OK(uc_close(uc));
}

static void test_arm64_mte_tag_load_store(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg  x2,[x1] */
        "\x23\x00\x60\xd9" /* ldg  x3,[x1] */
        "\x22\x18\x60\xd9" /* stzg x2,[x1,#0x10] */
        "\x24\x10\x60\xd9" /* ldg  x4,[x1,#0x10] */
        "\x22\x28\xa0\xd9" /* st2g x2,[x1,#0x20] */
        "\x25\x20\x60\xd9" /* ldg  x5,[x1,#0x20] */
        "\x26\x30\x60\xd9" /* ldg  x6,[x1,#0x30] */
        "\x21\xc0\x3f\x91" /* add  x1,x1,#0xff0 */
        "\x22\x08\xa0\xd9" /* st2g x2,[x1] */
        "\x27\x00\x60\xd9" /* ldg  x7,[x1] */
        "\x28\x10\x60\xd9"; /* ldg  x8,[x1,#0x10] */
    uint8_t fill[0x40];
    uint8_t zeroed[0x10];
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0x5000;
    uint64_t x4 = 0x6000;
    uint64_t x5 = 0x7000;
    uint64_t x6 = 0x8000;
    uint64_t x7 = 0x9000;
    uint64_t x8 = 0xa000;

    memset(fill, 0xaa, sizeof(fill));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x2000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, fill, sizeof(fill)));
    test_arm64_mte_enable_checks(uc, 0);

    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_read(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_read(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_read(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_read(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_read(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_mem_read(uc, 0x40010, zeroed, sizeof(zeroed)));

    TEST_CHECK(x3 == 0x0c00000000005000ull);
    TEST_CHECK(x4 == 0x0c00000000006000ull);
    TEST_CHECK(x5 == 0x0c00000000007000ull);
    TEST_CHECK(x6 == 0x0c00000000008000ull);
    TEST_CHECK(x7 == 0x0c00000000009000ull);
    TEST_CHECK(x8 == 0x0c0000000000a000ull);
    TEST_CHECK(memcmp(zeroed, "\0\0\0\0\0\0\0\0"
                              "\0\0\0\0\0\0\0\0",
                      sizeof(zeroed)) == 0);

    OK(uc_close(uc));
}

static void test_arm64_mte_tag_snapshot(void)
{
    uc_engine *uc;
    uc_context *ctx;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\x23\x00\x60\xd9"; /* ldg x3,[x1] */
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0x5000;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_context_alloc(uc, &ctx));
    OK(uc_ctl_context_mode(uc, UC_CTL_CONTEXT_MEMORY | UC_CTL_CONTEXT_CPU));
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    test_arm64_mte_enable_checks(uc, 0);

    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 1));
    OK(uc_context_save(uc, ctx));

    x2 = 0x0d00000000000000ull;
    x3 = 0x6000;
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 1));
    OK(uc_emu_start(uc, code_start + 4, code_start + sizeof(code) - 1, 0, 1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == 0x0d00000000006000ull);

    OK(uc_context_restore(uc, ctx));
    x3 = 0x7000;
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_emu_start(uc, code_start + 4, code_start + sizeof(code) - 1, 0, 1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == 0x0c00000000007000ull);

    OK(uc_context_free(ctx));
    OK(uc_close(uc));
}

static void test_arm64_mte_tag_multiple(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x00\xa0\xd9" /* stgm  x2,[x1] */
        "\x23\x00\xe0\xd9" /* ldgm  x3,[x1] */
        "\x24\x00\x60\xd9" /* ldg   x4,[x1] */
        "\x25\x10\x60\xd9" /* ldg   x5,[x1,#0x10] */
        "\x26\x00\x20\xd9" /* stzgm x6,[x1] */
        "\x27\x00\xe0\xd9"; /* ldgm  x7,[x1] */
    const uint32_t GMID_EL1[5] = { 3, 1, 0, 0, 4 };
    uint8_t fill[0x40];
    uint8_t zeroed[0x40];
    uint8_t expected_zero[0x40] = { 0 };
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0fedcba987654321ull;
    uint64_t x3 = 0;
    uint64_t x4 = 0x5000;
    uint64_t x5 = 0x6000;
    uint64_t x6 = 0xa;
    uint64_t x7 = 0;

    memset(fill, 0xaa, sizeof(fill));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, fill, sizeof(fill)));
    test_arm64_mte_enable_checks(uc, 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, GMID_EL1) == 6);

    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_read(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_read(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_read(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_mem_read(uc, 0x40000, zeroed, sizeof(zeroed)));

    TEST_CHECK(x3 == 0x0fedcba987654321ull);
    TEST_CHECK(x4 == 0x0100000000005000ull);
    TEST_CHECK(x5 == 0x0200000000006000ull);
    TEST_CHECK(x7 == 0x0fedcba98765aaaaull);
    TEST_CHECK(memcmp(zeroed, expected_zero, sizeof(zeroed)) == 0);

    OK(uc_close(uc));
}

static uint64_t test_arm64_mte_page_desc(uint64_t pa, unsigned attridx)
{
    return (pa & 0x0000fffffffff000ull) | 0x743 | (attridx << 2);
}

static uint64_t test_arm64_mte_code_page_desc(uint64_t pa, unsigned attridx)
{
    uint64_t desc = test_arm64_mte_page_desc(pa, attridx);

    return (desc & ~(3ULL << 6)) | (2ULL << 6);
}

static void test_arm64_mte_set_page_desc(uc_engine *uc, uint64_t va,
                                         uint64_t desc)
{
    const uint64_t l3_base = 0x102000;
    uint64_t l3_addr = l3_base + ((va >> 12) & 0x1ff) * sizeof(desc);

    OK(uc_mem_write(uc, l3_addr, &desc, sizeof(desc)));
}

static void test_arm64_mte_enable_identity_map(uc_engine *uc,
                                               uint64_t normal_va)
{
    const uint32_t MAIR_EL1[5] = { 3, 0, 10, 2, 0 };
    const uint32_t TCR_EL1[5] = { 3, 0, 2, 0, 2 };
    const uint32_t TTBR0_EL1[5] = { 3, 0, 2, 0, 0 };
    const uint64_t l1_base = 0x100000;
    const uint64_t l2_base = 0x101000;
    const uint64_t l3_base = 0x102000;
    const uint64_t mair = 0xf0 | (0xff << 8);
    const uint64_t tcr = 0x180803f20ull | (1ULL << 37);
    uint64_t l1[512] = { 0 };
    uint64_t l2[512] = { 0 };
    uint64_t l3[512];
    size_t i;

    for (i = 0; i < 512; i++) {
        unsigned attridx = (normal_va != UINT64_MAX &&
                            i == ((normal_va >> 12) & 0x1ff)) ? 1 : 0;

        if (i >= (code_start >> 12) &&
            i < ((code_start + code_len) >> 12)) {
            l3[i] = test_arm64_mte_code_page_desc(i << 12, attridx);
        } else {
            l3[i] = test_arm64_mte_page_desc(i << 12, attridx);
        }
    }

    l1[0] = l2_base | 3;
    l2[0] = l3_base | 3;

    OK(uc_mem_map(uc, l1_base, 0x3000, UC_PROT_ALL));
    OK(uc_mem_write(uc, l1_base, l1, sizeof(l1)));
    OK(uc_mem_write(uc, l2_base, l2, sizeof(l2)));
    OK(uc_mem_write(uc, l3_base, l3, sizeof(l3)));

    test_arm64_pauth_cp_reg_write(uc, MAIR_EL1, mair);
    test_arm64_pauth_cp_reg_write(uc, TCR_EL1, tcr);
    test_arm64_pauth_cp_reg_write(uc, TTBR0_EL1, l1_base);
}

static void test_arm64_mte_enable_checks_with_normal_page(uc_engine *uc,
                                                          uint64_t tcf,
                                                          uint64_t normal_va)
{
    const uint32_t SCTLR_EL1[5] = { 3, 0, 1, 0, 0 };
    const uint32_t HCR_EL2[5] = { 3, 4, 1, 1, 0 };
    const uint32_t SCR_EL3[5] = { 3, 6, 1, 1, 0 };

    test_arm64_mte_enable_identity_map(uc, normal_va);
    TEST_CHECK(test_arm64_pauth_cp_reg_update(uc, SCR_EL3, 0,
                                              1ULL | (1ULL << 10) |
                                              (1ULL << 26)));
    TEST_CHECK(test_arm64_pauth_cp_reg_update(uc, HCR_EL2, 0,
                                              (1ULL << 56) | (1ULL << 31)));
    TEST_CHECK(test_arm64_pauth_cp_reg_update(uc, SCTLR_EL1, 0,
                                              1ULL | (1ULL << 2) |
                                              (1ULL << 12) |
                                              (1ULL << 43) | tcf));
}

static void test_arm64_mte_enable_checks(uc_engine *uc, uint64_t tcf)
{
    test_arm64_mte_enable_checks_with_normal_page(uc, tcf, UINT64_MAX);
}

static void test_arm64_mte_store_tag_at(uc_engine *uc, uint64_t ptr,
                                        uint64_t tag)
{
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &ptr));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &tag));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));
}

static uint64_t test_arm64_mte_load_tag_at(uc_engine *uc, uint64_t ptr,
                                           uint64_t value)
{
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &ptr));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &value));
    OK(uc_emu_start(uc, code_start + 4, code_start + 8, 0, 1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &value));
    return value;
}

static void test_arm64_mte_checked_scalar_access(void)
{
    uc_engine *uc;
    const char sync_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\x83\x00\x40\xf9" /* ldr x3,[x4] */
        "\xc5\x00\x40\xf9"; /* ldr x5,[x6] */
    const char async_store_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xc3\x00\x00\xf9"; /* str x3,[x6] */
    const char tco_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xc3\x00\x40\xf9"; /* ldr x3,[x6] */
    const uint32_t TCO[5] = { 3, 3, 4, 2, 7 };
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    const uint64_t pstate_tco = 1ULL << 25;
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0;
    uint64_t x4 = 0x0c00000000040000ull;
    uint64_t x5 = 0;
    uint64_t x6 = 0x0d00000000040000ull;
    uint64_t data = 0x1122334455667788ull;
    uint64_t stored = 0xaabbccddeeff0011ull;
    uint64_t mem;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, sync_code,
                    sizeof(sync_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(sync_code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == data);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, async_store_code,
                    sizeof(async_store_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    x3 = stored;
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start,
                    code_start + sizeof(async_store_code) - 1, 0, 0));
    OK(uc_mem_read(uc, 0x40000, &mem, sizeof(mem)));
    TEST_CHECK(mem == stored);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 1);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, tco_code,
                    sizeof(tco_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_pauth_cp_reg_write(uc, TCO, pstate_tco);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    x3 = 0;
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(tco_code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == data);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));
}

static void test_arm64_mte_tco_msr_imm(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9"  /* stg x2,[x1] */
        "\x9f\x41\x03\xd5"  /* msr tco,#1 */
        "\xc3\x00\x40\xf9"  /* ldr x3,[x6] */
        "\x9f\x40\x03\xd5"  /* msr tco,#0 */
        "\xc5\x00\x40\xf9"; /* ldr x5,[x6] */
    const uint32_t TCO[5] = { 3, 3, 4, 2, 7 };
    const uint64_t pstate_tco = 1ULL << 25;
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0;
    uint64_t x5 = 0;
    uint64_t x6 = 0x0d00000000040000ull;
    uint64_t data = 0x1122334455667788ull;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));

    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                            0, 0) == UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_read(uc, UC_ARM64_REG_X5, &x5));
    TEST_CHECK(x3 == data);
    TEST_CHECK(x5 == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TCO) == 0);

    test_arm64_pauth_cp_reg_write(uc, TCO, pstate_tco);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TCO) == pstate_tco);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code + 4, 4,
                    UC_CPU_ARM64_A72);
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + 4, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_close(uc));
}

static void test_arm64_mte_lse_atomic_asym_sync_no_side_effect(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\x23\x00\x22\xf8"; /* ldadd x2,x3,[x1] */
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0;
    uint64_t data = 0x1122334455667788ull;
    uint64_t mem = 0;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    x1 = 0x0d00000000040000ull;
    x2 = 0x0102030405060708ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(uc_emu_start(uc, code_start + 4,
                            code_start + sizeof(code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40000, &mem, sizeof(mem)));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(mem == data);
    TEST_CHECK(x3 == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));
}

static void test_arm64_mte_ldapr_sync_tag_check(void)
{
    uc_engine *uc;
    const char non_sp_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\x23\xc0\xbf\xf8"; /* ldapr x3,[x1] */
    const char sp_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xe3\xc3\xbf\xf8"; /* ldapr x3,[sp] */
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0xaabbccddeeff0011ull;
    uint64_t sp = 0x0d00000000040000ull;
    uint64_t data = 0x1122334455667788ull;
    uint64_t mem = 0;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, non_sp_code,
                    sizeof(non_sp_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    x1 = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(uc_emu_start(uc, code_start + 4,
                            code_start + sizeof(non_sp_code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40000, &mem, sizeof(mem)));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(mem == data);
    TEST_CHECK(x3 == 0xaabbccddeeff0011ull);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, sp_code,
                    sizeof(sp_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    x1 = 0x40000;
    x2 = 0x0c00000000000000ull;
    x3 = 0;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    OK(uc_reg_write(uc, UC_ARM64_REG_SP, &sp));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_emu_start(uc, code_start + 4,
                    code_start + sizeof(sp_code) - 1, 0, 1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == data);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));
}

static void test_arm64_mte_lse_cas_asym_async_side_effect(void)
{
    uc_engine *uc;
    const char cas_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\x28\xfd\xea\xc8"; /* casal x10,x8,[x9] */
    const char casp_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\x82\xfc\x60\x48"; /* caspal x0,x1,x2,x3,[x4] */
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    uint64_t x0;
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3;
    uint64_t x4;
    uint64_t x8;
    uint64_t x9;
    uint64_t x10;
    uint64_t mem[2];
    uint64_t old_pair[2] = {
        0x1122334455667788ull,
        0x8877665544332211ull,
    };
    uint64_t new_pair[2] = {
        0x0102030405060708ull,
        0x9080706050403020ull,
    };

    mem[0] = 0;
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, cas_code,
                    sizeof(cas_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &mem[0], sizeof(mem[0])));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    x8 = 0xaabbccddeeff0011ull;
    x9 = 0x0d00000000040000ull;
    x10 = 0;
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_reg_write(uc, UC_ARM64_REG_X9, &x9));
    OK(uc_reg_write(uc, UC_ARM64_REG_X10, &x10));
    OK(uc_emu_start(uc, code_start + 4,
                    code_start + sizeof(cas_code) - 1, 0, 0));
    OK(uc_mem_read(uc, 0x40000, &mem[0], sizeof(mem[0])));
    OK(uc_reg_read(uc, UC_ARM64_REG_X10, &x10));
    TEST_CHECK(mem[0] == x8);
    TEST_CHECK(x10 == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 1);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, casp_code,
                    sizeof(casp_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, old_pair, sizeof(old_pair)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    x1 = 0x40000;
    x2 = 0x0c00000000000000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    x0 = old_pair[0];
    x1 = old_pair[1];
    x2 = new_pair[0];
    x3 = new_pair[1];
    x4 = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &x0));
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_emu_start(uc, code_start + 4,
                    code_start + sizeof(casp_code) - 1, 0, 0));
    OK(uc_mem_read(uc, 0x40000, mem, sizeof(mem)));
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &x0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X1, &x1));
    TEST_CHECK(mem[0] == new_pair[0]);
    TEST_CHECK(mem[1] == new_pair[1]);
    TEST_CHECK(x0 == old_pair[0]);
    TEST_CHECK(x1 == old_pair[1]);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 1);
    OK(uc_close(uc));
}

static void test_arm64_mte_exclusive_asym_access(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xc5\x7c\x5f\xc8" /* ldxr x5,[x6] */
        "\xc8\x7c\x07\xc8"; /* stxr w7,x8,[x6] */
    const char pair_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\x25\x19\x7f\xc8" /* ldxp x5,x6,[x9] */
        "\x28\x29\x27\xc8"; /* stxp w7,x8,x10,[x9] */
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x5 = 0;
    uint64_t x6;
    uint64_t x7 = 0xff;
    uint64_t x8 = 0xaabbccddeeff0011ull;
    uint64_t x9;
    uint64_t x10;
    uint64_t data = 0x1122334455667788ull;
    uint64_t mem = 0;
    uint64_t pair_mem[2];
    uint64_t pair_old[2] = {
        0x1122334455667788ull,
        0x8877665544332211ull,
    };
    uint64_t pair_new[2] = {
        0x0102030405060708ull,
        0x9080706050403020ull,
    };

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    x6 = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    TEST_CHECK(uc_emu_start(uc, code_start + 4, code_start + 8, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40000, &mem, sizeof(mem)));
    OK(uc_reg_read(uc, UC_ARM64_REG_X5, &x5));
    TEST_CHECK(mem == data);
    TEST_CHECK(x5 == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    x1 = 0x40000;
    x2 = 0x0c00000000000000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    x6 = 0x0c00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start + 4, code_start + 8, 0, 1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X5, &x5));
    TEST_CHECK(x5 == data);

    x6 = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_emu_start(uc, code_start + 8,
                    code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, 0x40000, &mem, sizeof(mem)));
    OK(uc_reg_read(uc, UC_ARM64_REG_X7, &x7));
    TEST_CHECK(mem == x8);
    TEST_CHECK(x7 == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 1);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, pair_code,
                    sizeof(pair_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, pair_old, sizeof(pair_old)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    x1 = 0x40000;
    x2 = 0x0c00000000000000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    x5 = 0;
    x6 = 0;
    x9 = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X9, &x9));
    TEST_CHECK(uc_emu_start(uc, code_start + 4, code_start + 8, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40000, pair_mem, sizeof(pair_mem)));
    OK(uc_reg_read(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_read(uc, UC_ARM64_REG_X6, &x6));
    TEST_CHECK(pair_mem[0] == pair_old[0]);
    TEST_CHECK(pair_mem[1] == pair_old[1]);
    TEST_CHECK(x5 == 0);
    TEST_CHECK(x6 == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, pair_code,
                    sizeof(pair_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, pair_old, sizeof(pair_old)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    x1 = 0x40000;
    x2 = 0x0c00000000000000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    x9 = 0x0c00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X9, &x9));
    OK(uc_emu_start(uc, code_start + 4, code_start + 8, 0, 1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_read(uc, UC_ARM64_REG_X6, &x6));
    TEST_CHECK(x5 == pair_old[0]);
    TEST_CHECK(x6 == pair_old[1]);

    x7 = 0xff;
    x8 = pair_new[0];
    x9 = 0x0d00000000040000ull;
    x10 = pair_new[1];
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_reg_write(uc, UC_ARM64_REG_X9, &x9));
    OK(uc_reg_write(uc, UC_ARM64_REG_X10, &x10));
    OK(uc_emu_start(uc, code_start + 8,
                    code_start + sizeof(pair_code) - 1, 0, 0));
    OK(uc_mem_read(uc, 0x40000, pair_mem, sizeof(pair_mem)));
    OK(uc_reg_read(uc, UC_ARM64_REG_X7, &x7));
    TEST_CHECK(pair_mem[0] == pair_new[0]);
    TEST_CHECK(pair_mem[1] == pair_new[1]);
    TEST_CHECK(x7 == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 1);
    OK(uc_close(uc));
}

static void test_arm64_mte_sp_addressing_tagchecked(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xe3\x03\x40\xf9" /* ldr x3,[sp] */
        "\xe4\x6b\x60\xf8" /* ldr x4,[sp,x0] */
        "\xe5\x03\x00\xf9" /* str x5,[sp] */
        "\xe5\x6b\x20\xf8"; /* str x5,[sp,x0] */
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    uint64_t x0 = 0;
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0;
    uint64_t x4 = 0;
    uint64_t x5;
    uint64_t sp = 0x0d00000000040000ull;
    uint64_t data = 0x1122334455667788ull;
    uint64_t stored = 0xaabbccddeeff0011ull;
    uint64_t mem = 0;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &x0));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_SP, &sp));
    OK(uc_emu_start(uc, code_start + 4, code_start + 8, 0, 1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == data);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    TEST_CHECK(uc_emu_start(uc, code_start + 8, code_start + 12, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_ARM64_REG_X4, &x4));
    TEST_CHECK(x4 == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    x1 = 0x40000;
    x2 = 0x0c00000000000000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    x5 = stored;
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &x0));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_SP, &sp));
    OK(uc_emu_start(uc, code_start + 12, code_start + 16, 0, 1));
    OK(uc_mem_read(uc, 0x40000, &mem, sizeof(mem)));
    TEST_CHECK(mem == stored);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);

    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    x5 = stored ^ 0xffffffffffffffffull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_emu_start(uc, code_start + 16,
                    code_start + sizeof(code) - 1, 0, 1));
    OK(uc_mem_read(uc, 0x40000, &mem, sizeof(mem)));
    TEST_CHECK(mem == x5);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 1);
    OK(uc_close(uc));
}

static void test_arm64_mte_sp_writeback_tagchecked(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xe3\x0f\x41\xf8" /* ldr x3,[sp,#0x10]! */
        "\xe5\x07\x01\xf8"; /* str x5,[sp],#0x10 */
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0;
    uint64_t x5 = 0xaabbccddeeff0011ull;
    uint64_t sp;
    uint64_t data = 0x1122334455667788ull;
    uint64_t mem = 0;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40010, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    sp = 0x0d0000000003fff0ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_SP, &sp));
    TEST_CHECK(uc_emu_start(uc, code_start + 4, code_start + 8, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_read(uc, UC_ARM64_REG_SP, &sp));
    TEST_CHECK(x3 == 0);
    TEST_CHECK(sp == 0x0d0000000003fff0ull);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    x1 = 0x40000;
    x2 = 0x0c00000000000000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    sp = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_SP, &sp));
    OK(uc_emu_start(uc, code_start + 8,
                    code_start + sizeof(code) - 1, 0, 1));
    OK(uc_mem_read(uc, 0x40000, &mem, sizeof(mem)));
    OK(uc_reg_read(uc, UC_ARM64_REG_SP, &sp));
    TEST_CHECK(mem == x5);
    TEST_CHECK(sp == 0x0d00000000040010ull);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 1);
    OK(uc_close(uc));
}

static void test_arm64_mte_pair_sp_tagchecked(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xe3\x13\x40\xa9" /* ldp x3,x4,[sp] */
        "\xe5\x1b\x81\xa8"; /* stp x5,x6,[sp],#0x10 */
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0;
    uint64_t x4 = 0;
    uint64_t x5 = 0xaabbccddeeff0011ull;
    uint64_t x6 = 0x8877665544332211ull;
    uint64_t sp = 0x0d00000000040000ull;
    uint64_t pair[2] = {
        0x1122334455667788ull,
        0x0102030405060708ull,
    };
    uint64_t mem[2];

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, pair, sizeof(pair)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_SP, &sp));
    OK(uc_emu_start(uc, code_start + 4, code_start + 8, 0, 1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_read(uc, UC_ARM64_REG_X4, &x4));
    TEST_CHECK(x3 == pair[0]);
    TEST_CHECK(x4 == pair[1]);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);

    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_SP, &sp));
    OK(uc_emu_start(uc, code_start + 8,
                    code_start + sizeof(code) - 1, 0, 1));
    OK(uc_mem_read(uc, 0x40000, mem, sizeof(mem)));
    OK(uc_reg_read(uc, UC_ARM64_REG_SP, &sp));
    TEST_CHECK(mem[0] == x5);
    TEST_CHECK(mem[1] == x6);
    TEST_CHECK(sp == 0x0d00000000040010ull);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 1);
    OK(uc_close(uc));
}

static void test_arm64_mte_pac_load_sp_tagchecked(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xe3\x07\x20\xf8" /* ldraa x3,[sp] */
        "\xe4\x1f\x20\xf8" /* ldraa x4,[sp,#8]! */
        "\xe3\x07\xa0\xf8" /* ldrab x3,[sp] */
        "\xe4\x1f\xa0\xf8"; /* ldrab x4,[sp,#8]! */
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0;
    uint64_t x4 = 0;
    uint64_t sp;
    uint64_t data = 0x1122334455667788ull;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    sp = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_SP, &sp));
    OK(uc_emu_start(uc, code_start + 4, code_start + 8, 0, 1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == data);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    x1 = 0x40000;
    x2 = 0x0c00000000000000ull;
    x3 = 0;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    sp = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_SP, &sp));
    OK(uc_emu_start(uc, code_start + 12, code_start + 16, 0, 1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == data);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40008, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    x1 = 0x40000;
    x2 = 0x0c00000000000000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    sp = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_SP, &sp));
    TEST_CHECK(uc_emu_start(uc, code_start + 8,
                            code_start + sizeof(code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_read(uc, UC_ARM64_REG_SP, &sp));
    TEST_CHECK(x4 == 0);
    TEST_CHECK(sp == 0x0d00000000040000ull);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40008, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    x1 = 0x40000;
    x2 = 0x0c00000000000000ull;
    x4 = 0;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));

    sp = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_SP, &sp));
    TEST_CHECK(uc_emu_start(uc, code_start + 16,
                            code_start + sizeof(code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_read(uc, UC_ARM64_REG_SP, &sp));
    TEST_CHECK(x4 == 0);
    TEST_CHECK(sp == 0x0d00000000040000ull);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));
}

static void test_arm64_mte_tcma0_tag_zero_unchecked(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\x83\x00\x40\xf9"; /* ldr x3,[x4] */
    const uint32_t TCR_EL1[5] = { 3, 0, 2, 0, 2 };
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    const uint64_t tcma0 = 1ULL << 57;
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0;
    uint64_t x4 = 0x40000;
    uint64_t data = 0x1122334455667788ull;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                            0, 0) == UC_ERR_EXCEPTION);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    TEST_CHECK(test_arm64_pauth_cp_reg_update(uc, TCR_EL1, 0, tcma0));
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    x3 = 0;
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == data);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));
}

static void test_arm64_mte_ldapur_stlur_unchecked(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg    x2,[x1] */
        "\x83\x00\x40\xd9" /* ldapur x3,[x4] */
        "\x85\x00\x00\xd9"; /* stlur  x5,[x4] */
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0;
    uint64_t x4 = 0x0d00000000040000ull;
    uint64_t x5 = 0x8877665544332211ull;
    uint64_t data = 0x1122334455667788ull;
    uint64_t written = 0;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_mem_read(uc, 0x40000, &written, sizeof(written)));
    TEST_CHECK(x3 == data);
    TEST_CHECK(written == x5);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));
}

static void test_arm64_mte_ldapur_stlur_variants_unchecked(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg      x2,[x1] */
        "\x86\x00\x40\x19" /* ldapurb  w6,[x4] */
        "\x87\x20\x40\x59" /* ldapurh  w7,[x4,#2] */
        "\x88\x40\x80\x19" /* ldapursb x8,[x4,#4] */
        "\x89\x50\xc0\x19" /* ldapursb w9,[x4,#5] */
        "\x8a\x60\x80\x59" /* ldapursh x10,[x4,#6] */
        "\x8b\x80\xc0\x59" /* ldapursh w11,[x4,#8] */
        "\x8c\xc0\x80\x99" /* ldapursw x12,[x4,#12] */
        "\x8d\xa0\x00\x19" /* stlurb   w13,[x4,#10] */
        "\x8e\xc0\x00\x59"; /* stlurh   w14,[x4,#12] */
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    const uint8_t data[16] = {
        0x7e, 0x11, 0x34, 0x12, 0x80, 0x81, 0x00, 0x80,
        0x34, 0x80, 0xaa, 0xbb, 0x98, 0xba, 0xdc, 0xfe,
    };
    uint8_t written[16];
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x4 = 0x0d00000000040000ull;
    uint64_t x6 = 0;
    uint64_t x7 = 0;
    uint64_t x8 = 0;
    uint64_t x9 = 0;
    uint64_t x10 = 0;
    uint64_t x11 = 0;
    uint64_t x12 = 0;
    uint64_t x13 = 0x5a;
    uint64_t x14 = 0xbeef;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X13, &x13));
    OK(uc_reg_write(uc, UC_ARM64_REG_X14, &x14));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_read(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_read(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_reg_read(uc, UC_ARM64_REG_X9, &x9));
    OK(uc_reg_read(uc, UC_ARM64_REG_X10, &x10));
    OK(uc_reg_read(uc, UC_ARM64_REG_X11, &x11));
    OK(uc_reg_read(uc, UC_ARM64_REG_X12, &x12));
    OK(uc_mem_read(uc, 0x40000, written, sizeof(written)));
    TEST_CHECK(x6 == 0x7e);
    TEST_CHECK(x7 == 0x1234);
    TEST_CHECK(x8 == 0xffffffffffffff80ull);
    TEST_CHECK(x9 == 0x00000000ffffff81ull);
    TEST_CHECK(x10 == 0xffffffffffff8000ull);
    TEST_CHECK(x11 == 0x00000000ffff8034ull);
    TEST_CHECK(x12 == 0xfffffffffedcba98ull);
    TEST_CHECK(written[10] == 0x5a);
    TEST_CHECK(written[12] == 0xef);
    TEST_CHECK(written[13] == 0xbe);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));
}

static void test_arm64_mte_unpriv_sp_no_tag_check(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg  x2,[x1] */
        "\xe3\x0b\x40\xf8"; /* ldtr x3,[sp] */
    const uint32_t TFSRE0_EL1[5] = { 3, 0, 5, 6, 1 };
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0;
    uint64_t sp = 0x0d00000000040000ull;
    uint64_t data = 0x1122334455667788ull;
    uint64_t desc;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_checks(uc, (1ULL << 38) | (1ULL << 42));
    desc = test_arm64_mte_page_desc(0x40000, 0) | (1ULL << 4);
    test_arm64_mte_set_page_desc(uc, 0x40000, desc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_SP, &sp));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == data);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSRE0_EL1) == 0);
    OK(uc_close(uc));
}

static void test_arm64_mte_unpriv_async_tag_check(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg  x2,[x1] */
        "\x83\x08\x40\xf8"; /* ldtr x3,[x4] */
    const uint32_t TFSRE0_EL1[5] = { 3, 0, 5, 6, 1 };
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    const uint32_t pstate_el1h = 5;
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0;
    uint64_t x4 = 0x0d00000000040000ull;
    uint64_t tfsre0;
    uint64_t tfsr;
    uc_err err;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    test_arm64_mte_enable_checks(uc, (2ULL << 38) | (1ULL << 42));
    OK(uc_reg_write(uc, UC_ARM64_REG_PSTATE, &pstate_el1h));
    OK(uc_ctl_flush_tb(uc));
    OK(uc_ctl_flush_tlb(uc));
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));
    err = uc_emu_start(uc, code_start + 4, code_start + sizeof(code) - 1,
                       0, 1);
    tfsre0 = test_arm64_pauth_cp_reg_read(uc, TFSRE0_EL1);
    tfsr = test_arm64_pauth_cp_reg_read(uc, TFSR_EL1);
    TEST_CHECK_(err == UC_ERR_OK && tfsre0 == 1 && tfsr == 0,
                "err=%u tfsre0=0x%llx tfsr=0x%llx", err,
                (unsigned long long)tfsre0, (unsigned long long)tfsr);
    OK(uc_close(uc));
}

static void test_arm64_mte_page_attrs(void)
{
    uc_engine *uc;
    const char tag_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\x23\x00\x60\xd9"; /* ldg x3,[x1] */
    const char check_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\x85\x00\x40\xf9"; /* ldr x5,[x4] */
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    uint64_t tagged_page = 0x40000;
    uint64_t normal_page = 0x41000;
    uint64_t tag = 0x0c00000000000000ull;
    uint64_t tagged_value = 0x1122334455667788ull;
    uint64_t normal_value = 0x8877665544332211ull;
    uint64_t x1, x2, x3, x4, x5;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, tag_code,
                    sizeof(tag_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, tagged_page, 0x2000, UC_PROT_ALL));
    OK(uc_mem_write(uc, tagged_page, &tagged_value, sizeof(tagged_value)));
    OK(uc_mem_write(uc, normal_page, &normal_value, sizeof(normal_value)));
    test_arm64_mte_enable_checks_with_normal_page(uc, 1ULL << 40,
                                                  normal_page);

    x1 = tagged_page;
    x2 = tag;
    x3 = 0x5000;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(tag_code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == 0x0c00000000005000ull);

    x1 = normal_page;
    x2 = 0x0d00000000000000ull;
    x3 = 0x6000;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(tag_code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == 0x6000);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, check_code,
                    sizeof(check_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, tagged_page, 0x2000, UC_PROT_ALL));
    OK(uc_mem_write(uc, tagged_page, &tagged_value, sizeof(tagged_value)));
    test_arm64_mte_enable_checks_with_normal_page(uc, 1ULL << 40,
                                                  normal_page);
    x1 = tagged_page;
    x2 = tag;
    x4 = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(check_code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, check_code,
                    sizeof(check_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, tagged_page, 0x2000, UC_PROT_ALL));
    OK(uc_mem_write(uc, normal_page, &normal_value, sizeof(normal_value)));
    test_arm64_mte_enable_checks_with_normal_page(uc, 1ULL << 40,
                                                  normal_page);
    x1 = normal_page;
    x2 = tag;
    x4 = 0x0d00000000041000ull;
    x5 = 0;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(check_code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X5, &x5));
    TEST_CHECK(x5 == normal_value);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));
}

static void test_arm64_bti_guarded_page(void)
{
    uc_engine *uc;
    const char code[] =
        "\x00\x00\x1f\xd6" /* br  x0 */
        "\x1f\x20\x03\xd5"; /* nop */
    const uint32_t SCTLR_EL1[5] = { 3, 0, 1, 0, 0 };
    uint64_t target = code_start + 4;
    uint64_t desc;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    test_arm64_mte_enable_checks_with_normal_page(uc, 0, code_start);
    TEST_CHECK(test_arm64_pauth_cp_reg_update(uc, SCTLR_EL1, 0,
                                              (1ULL << 35) |
                                              (1ULL << 36)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &target));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    test_arm64_mte_enable_checks_with_normal_page(uc, 0, code_start);
    desc = test_arm64_mte_code_page_desc(code_start, 1) | (1ULL << 50);
    test_arm64_mte_set_page_desc(uc, code_start, desc);
    TEST_CHECK(test_arm64_pauth_cp_reg_update(uc, SCTLR_EL1, 0,
                                              (1ULL << 35) |
                                              (1ULL << 36)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X0, &target));
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_close(uc));
}

static void test_arm64_mte_enable_stage2_identity(uc_engine *uc)
{
    const uint32_t VTCR_EL2[5] = { 3, 4, 2, 1, 2 };
    const uint32_t VTTBR_EL2[5] = { 3, 4, 2, 1, 0 };
    const uint64_t table_base = 0x110000;
    const uint64_t vtcr_t0sz_1gb = 34;
    uint64_t l2[512] = { 0 };

    l2[0] = 0x4fd;

    OK(uc_mem_map(uc, table_base, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, table_base, l2, sizeof(l2)));
    test_arm64_pauth_cp_reg_write(uc, VTCR_EL2, vtcr_t0sz_1gb);
    test_arm64_pauth_cp_reg_write(uc, VTTBR_EL2, table_base);
}

static void test_arm64_mte_enable_dct(uc_engine *uc, bool dct)
{
    const uint32_t SCTLR_EL1[5] = { 3, 0, 1, 0, 0 };
    const uint32_t HCR_EL2[5] = { 3, 4, 1, 1, 0 };
    const uint32_t SCR_EL3[5] = { 3, 6, 1, 1, 0 };
    uint64_t hcr = (1ULL << 56) | (1ULL << 31) | (1ULL << 12);

    if (dct) {
        hcr |= 1ULL << 57;
    }

    test_arm64_mte_enable_stage2_identity(uc);
    TEST_CHECK(test_arm64_pauth_cp_reg_update(uc, SCR_EL3, 0,
                                              1ULL | (1ULL << 10) |
                                              (1ULL << 26)));
    TEST_CHECK(test_arm64_pauth_cp_reg_update(uc, HCR_EL2, 0, hcr));
    TEST_CHECK(test_arm64_pauth_cp_reg_update(uc, SCTLR_EL1, 0,
                                              (1ULL << 2) |
                                              (1ULL << 12) |
                                              (1ULL << 43)));
}

static void test_arm64_mte_hcr_dct(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\x23\x00\x60\xd9"; /* ldg x3,[x1] */
    uint64_t data = 0x1122334455667788ull;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_dct(uc, true);
    x1 = 0x40000;
    x2 = 0x0c00000000000000ull;
    x3 = 0x5000;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == 0x0c00000000005000ull);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, &data, sizeof(data)));
    test_arm64_mte_enable_dct(uc, false);
    x1 = 0x40000;
    x2 = 0x0c00000000000000ull;
    x3 = 0x5000;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == 0x5000);
    OK(uc_close(uc));
}

static void test_arm64_mte_cross_page_fault_priority(void)
{
    uc_engine *uc;
    const char st2g_code[] =
        "\x22\x08\xa0\xd9" /* st2g x2,[x1] */
        "\x23\x00\x60\xd9"; /* ldg  x3,[x1] */
    const char checked_load_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\x83\x00\x40\xf9"; /* ldr x3,[x4] */
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
    uint64_t x4;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, st2g_code,
                    sizeof(st2g_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    test_arm64_mte_enable_checks(uc, 0);
    x1 = 0x40ff0;
    x2 = 0x0c00000000000000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + 4, 0, 1) ==
               UC_ERR_WRITE_UNMAPPED);
    OK(uc_mem_map(uc, 0x41000, 0x1000, UC_PROT_ALL));
    x3 = 0x5000;
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_emu_start(uc, code_start + 4, code_start + sizeof(st2g_code) - 1,
                    0, 1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == 0x5000);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, st2g_code,
                    sizeof(st2g_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x2000, UC_PROT_ALL));
    OK(uc_mem_protect(uc, 0x41000, 0x1000, UC_PROT_READ));
    test_arm64_mte_enable_checks(uc, 0);
    x1 = 0x40ff0;
    x2 = 0x0d00000000000000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + 4, 0, 1) ==
               UC_ERR_WRITE_PROT);
    OK(uc_mem_protect(uc, 0x41000, 0x1000, UC_PROT_ALL));
    x3 = 0x6000;
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_emu_start(uc, code_start + 4, code_start + sizeof(st2g_code) - 1,
                    0, 1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(x3 == 0x6000);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, checked_load_code,
                    sizeof(checked_load_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    x1 = 0x40ff0;
    x2 = 0x0c00000000000000ull;
    x3 = 0;
    x4 = 0x0d00000000040ffcull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 1));
    TEST_CHECK(uc_emu_start(uc, code_start + 4,
                            code_start + sizeof(checked_load_code) - 1,
                            0, 1) == UC_ERR_READ_UNMAPPED);
    OK(uc_close(uc));
}

static void test_arm64_mte_ata_disabled_tag_op_probe(void)
{
    uc_engine *uc;
    const char ldg_code[] = "\x23\x00\x60\xd9"; /* ldg x3,[x1] */
    const char ldgm_code[] = "\x23\x00\xe0\xd9"; /* ldgm x3,[x1] */
    const char stgm_code[] = "\x22\x00\xa0\xd9"; /* stgm x2,[x1] */
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0123456789abcdefull;
    uint64_t x3 = 0x0c00000000005000ull;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, ldg_code,
                    sizeof(ldg_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(ldg_code) - 1,
                            0, 0) == UC_ERR_READ_UNMAPPED);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, ldgm_code,
                    sizeof(ldgm_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(ldgm_code) - 1,
                            0, 0) == UC_ERR_READ_UNMAPPED);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, stgm_code,
                    sizeof(stgm_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(stgm_code) - 1,
                            0, 0) == UC_ERR_WRITE_UNMAPPED);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, stgm_code,
                    sizeof(stgm_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_READ));
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(stgm_code) - 1,
                            0, 0) == UC_ERR_WRITE_PROT);
    OK(uc_close(uc));
}

static void test_arm64_mte_enable_sve_vq(uc_engine *uc, uint64_t zcr_len)
{
    const uint32_t CPACR_EL1[5] = { 3, 0, 1, 0, 2 };
    const uint32_t CPTR_EL3[5] = { 3, 6, 1, 1, 2 };
    const uint32_t ZCR_EL1[5] = { 3, 0, 1, 2, 0 };
    const uint32_t ZCR_EL2[5] = { 3, 4, 1, 2, 0 };
    const uint32_t ZCR_EL3[5] = { 3, 6, 1, 2, 0 };

    test_arm64_pauth_cp_reg_write(uc, CPACR_EL1,
                                  (3ULL << 16) | (3ULL << 20));
    TEST_CHECK(test_arm64_pauth_cp_reg_update(uc, CPTR_EL3, 0, 1ULL << 8));
    test_arm64_pauth_cp_reg_write(uc, ZCR_EL1, zcr_len);
    test_arm64_pauth_cp_reg_write(uc, ZCR_EL2, zcr_len);
    test_arm64_pauth_cp_reg_write(uc, ZCR_EL3, zcr_len);
}

static void test_arm64_mte_enable_sve(uc_engine *uc)
{
    test_arm64_mte_enable_sve_vq(uc, 0);
}

static void test_arm64_sve2_non_temporal_gather_scatter(void)
{
    uc_engine *uc;
    const char load_code[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\xe2\xa0\x40\xa5" /* ld1w { z2.s },p0/z,[x7] */
        "\x41\xa0\x04\x84" /* ldnt1b { z1.s },p0/z,[z2.s,x4] */
        "\xc1\xe0\x40\xe5"; /* st1w { z1.s },p0,[x6] */
    const char store_code[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\xc1\xa0\x40\xa5" /* ld1w { z1.s },p0/z,[x6] */
        "\xe2\xa0\x40\xa5" /* ld1w { z2.s },p0/z,[x7] */
        "\x41\x20\x44\xe4"; /* stnt1b { z1.s },p0,[z2.s,x4] */
    uint64_t x4 = 0x40000;
    uint64_t x6 = 0x40100;
    uint64_t x7 = 0x40200;
    uint8_t mem[16];
    uint8_t expected[16];
    uint32_t offsets[4];
    uint32_t words[4];
    int i;

    for (i = 0; i < (int)sizeof(expected); i++) {
        expected[i] = (uint8_t)(0x20 + i);
    }
    for (i = 0; i < 4; i++) {
        offsets[i] = (uint32_t)i;
        words[i] = 0;
    }

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, load_code,
                    sizeof(load_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    OK(uc_mem_write(uc, 0x40100, words, sizeof(words)));
    OK(uc_mem_write(uc, 0x40200, offsets, sizeof(offsets)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(load_code) - 1,
                    0, 0));
    OK(uc_mem_read(uc, 0x40100, words, sizeof(words)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(words[i] == expected[i]);
    }
    OK(uc_close(uc));

    memset(expected, 0xa5, sizeof(expected));
    for (i = 0; i < 4; i++) {
        offsets[i] = (uint32_t)i;
        words[i] = (uint32_t)(0x90 + i);
    }

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, store_code,
                    sizeof(store_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    OK(uc_mem_write(uc, 0x40100, words, sizeof(words)));
    OK(uc_mem_write(uc, 0x40200, offsets, sizeof(offsets)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(store_code) - 1,
                    0, 0));
    OK(uc_mem_read(uc, 0x40000, mem, sizeof(mem)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(mem[i] == (uint8_t)words[i]);
    }
    for (i = 4; i < (int)sizeof(mem); i++) {
        TEST_CHECK(mem[i] == 0xa5);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_bitwise_ternary(void)
{
    uc_engine *uc;
    const char code[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\xe1\xa0\x40\xa5" /* ld1w { z1.s },p0/z,[x7] */
        "\x02\xa1\x40\xa5" /* ld1w { z2.s },p0/z,[x8] */
        "\xca\xa0\x40\xa5" /* ld1w { z10.s },p0/z,[x6] */
        "\xcb\xa0\x40\xa5" /* ld1w { z11.s },p0/z,[x6] */
        "\xcc\xa0\x40\xa5" /* ld1w { z12.s },p0/z,[x6] */
        "\xcd\xa0\x40\xa5" /* ld1w { z13.s },p0/z,[x6] */
        "\xce\xa0\x40\xa5" /* ld1w { z14.s },p0/z,[x6] */
        "\xcf\xa0\x40\xa5" /* ld1w { z15.s },p0/z,[x6] */
        "\x4a\x38\x21\x04" /* eor3 z10.d,z10.d,z1.d,z2.d */
        "\x4b\x3c\x21\x04" /* bsl z11.d,z11.d,z1.d,z2.d */
        "\x4c\x38\x61\x04" /* bcax z12.d,z12.d,z1.d,z2.d */
        "\x4d\x3c\x61\x04" /* bsl1n z13.d,z13.d,z1.d,z2.d */
        "\x4e\x3c\xa1\x04" /* bsl2n z14.d,z14.d,z1.d,z2.d */
        "\x4f\x3c\xe1\x04" /* nbsl z15.d,z15.d,z1.d,z2.d */
        "\x2a\xe1\x40\xe5" /* st1w { z10.s },p0,[x9] */
        "\x4b\xe1\x40\xe5" /* st1w { z11.s },p0,[x10] */
        "\x6c\xe1\x40\xe5" /* st1w { z12.s },p0,[x11] */
        "\x8d\xe1\x40\xe5" /* st1w { z13.s },p0,[x12] */
        "\xae\xe1\x40\xe5" /* st1w { z14.s },p0,[x13] */
        "\xcf\xe1\x40\xe5"; /* st1w { z15.s },p0,[x14] */
    uint32_t n[4] = {
        0x01234567, 0x89abcdef, 0x10203040, 0xfedcba98
    };
    uint32_t m[4] = {
        0xf0f0aa55, 0x00ff00ff, 0x87654321, 0x13579bdf
    };
    uint32_t k[4] = {
        0xff00ff00, 0x0f0f0f0f, 0xaaaaaaaa, 0x55555555
    };
    uint32_t expected[6][4];
    uint32_t got[4];
    uint64_t x6 = 0x40000;
    uint64_t x7 = 0x40100;
    uint64_t x8 = 0x40200;
    uint64_t out[6] = {
        0x40300, 0x40320, 0x40340, 0x40360, 0x40380, 0x403a0
    };
    int i, j;

    for (i = 0; i < 4; i++) {
        expected[0][i] = n[i] ^ m[i] ^ k[i];
        expected[1][i] = (n[i] & k[i]) | (m[i] & ~k[i]);
        expected[2][i] = n[i] ^ (m[i] & ~k[i]);
        expected[3][i] = (~n[i] & k[i]) | (m[i] & ~k[i]);
        expected[4][i] = (n[i] & k[i]) | (~m[i] & ~k[i]);
        expected[5][i] = ~((n[i] & k[i]) | (m[i] & ~k[i]));
    }

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, n, sizeof(n)));
    OK(uc_mem_write(uc, 0x40100, m, sizeof(m)));
    OK(uc_mem_write(uc, 0x40200, k, sizeof(k)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_reg_write(uc, UC_ARM64_REG_X9, &out[0]));
    OK(uc_reg_write(uc, UC_ARM64_REG_X10, &out[1]));
    OK(uc_reg_write(uc, UC_ARM64_REG_X11, &out[2]));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &out[3]));
    OK(uc_reg_write(uc, UC_ARM64_REG_X13, &out[4]));
    OK(uc_reg_write(uc, UC_ARM64_REG_X14, &out[5]));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    for (i = 0; i < 6; i++) {
        OK(uc_mem_read(uc, out[i], got, sizeof(got)));
        for (j = 0; j < 4; j++) {
            TEST_CHECK(got[j] == expected[i][j]);
        }
    }

    OK(uc_close(uc));
}

static uint8_t test_arm64_ror8(uint8_t value, unsigned int shift)
{
    return (uint8_t)((value >> shift) | (value << (8 - shift)));
}

static uint16_t test_arm64_ror16(uint16_t value, unsigned int shift)
{
    return (uint16_t)((value >> shift) | (value << (16 - shift)));
}

static uint32_t test_arm64_ror32(uint32_t value, unsigned int shift)
{
    return (value >> shift) | (value << (32 - shift));
}

static uint64_t test_arm64_ror64(uint64_t value, unsigned int shift)
{
    return (value >> shift) | (value << (64 - shift));
}

static uint16_t test_arm64_pmull8(uint8_t op1, uint8_t op2)
{
    uint16_t result = 0;
    int i;

    for (i = 0; i < 8; i++) {
        if ((op1 >> i) & 1) {
            result ^= (uint16_t)op2 << i;
        }
    }
    return result;
}

static uint64_t test_arm64_pmull32(uint32_t op1, uint32_t op2)
{
    uint64_t result = 0;
    int i;

    for (i = 0; i < 32; i++) {
        if ((op1 >> i) & 1) {
            result ^= (uint64_t)op2 << i;
        }
    }
    return result;
}

static void test_arm64_pmull64(uint64_t op1, uint64_t op2, uint64_t *lo,
                               uint64_t *hi)
{
    uint64_t result_lo = 0;
    uint64_t result_hi = 0;
    int i;

    for (i = 0; i < 64; i++) {
        if ((op1 >> i) & 1) {
            result_lo ^= op2 << i;
            if (i != 0) {
                result_hi ^= op2 >> (64 - i);
            }
        }
    }
    *lo = result_lo;
    *hi = result_hi;
}

static uint64_t test_arm64_bitextract(uint64_t data, uint64_t mask, int n)
{
    uint64_t result = 0;
    int db, rb = 0;

    for (db = 0; db < n; db++) {
        if ((mask >> db) & 1) {
            result |= ((data >> db) & 1) << rb;
            rb++;
        }
    }
    return result;
}

static uint64_t test_arm64_bitdeposit(uint64_t data, uint64_t mask, int n)
{
    uint64_t result = 0;
    int rb, db = 0;

    for (rb = 0; rb < n; rb++) {
        if ((mask >> rb) & 1) {
            result |= ((data >> db) & 1) << rb;
            db++;
        }
    }
    return result;
}

static uint64_t test_arm64_bitgroup(uint64_t data, uint64_t mask, int n)
{
    uint64_t masked = 0, unmasked = 0;
    int db, rbm = 0, rbu = 0;

    for (db = 0; db < n; db++) {
        uint64_t bit = (data >> db) & 1;

        if ((mask >> db) & 1) {
            masked |= bit << rbm++;
        } else {
            unmasked |= bit << rbu++;
        }
    }
    return rbm == 64 ? masked : masked | (unmasked << rbm);
}

static bool test_arm64_has_u8(const uint8_t *values, int count, uint8_t needle)
{
    int i;

    for (i = 0; i < count; i++) {
        if (values[i] == needle) {
            return true;
        }
    }
    return false;
}

static bool test_arm64_has_u16(const uint16_t *values, int count,
                               uint16_t needle)
{
    int i;

    for (i = 0; i < count; i++) {
        if (values[i] == needle) {
            return true;
        }
    }
    return false;
}

static void test_arm64_sve2_xar(void)
{
    uc_engine *uc;
    const char code_b[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x80\xa0\x00\xa4" /* ld1b { z0.b },p0/z,[x4] */
        "\xa1\xa0\x00\xa4" /* ld1b { z1.b },p0/z,[x5] */
        "\x20\x34\x2d\x04" /* xar z0.b,z0.b,z1.b,#3 */
        "\xc0\xe0\x00\xe4" /* st1b { z0.b },p0,[x6] */
        "\x82\xa0\x00\xa4" /* ld1b { z2.b },p0/z,[x4] */
        "\xa3\xa0\x00\xa4" /* ld1b { z3.b },p0/z,[x5] */
        "\x62\x34\x28\x04" /* xar z2.b,z2.b,z3.b,#8 */
        "\xe2\xe0\x00\xe4"; /* st1b { z2.b },p0,[x7] */
    const char code_h[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x80\xa0\xa0\xa4" /* ld1h { z0.h },p0/z,[x4] */
        "\xa1\xa0\xa0\xa4" /* ld1h { z1.h },p0/z,[x5] */
        "\x20\x34\x3b\x04" /* xar z0.h,z0.h,z1.h,#5 */
        "\xc0\xe0\xa0\xe4"; /* st1h { z0.h },p0,[x6] */
    const char code_s[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x80\xa0\x40\xa5" /* ld1w { z0.s },p0/z,[x4] */
        "\xa1\xa0\x40\xa5" /* ld1w { z1.s },p0/z,[x5] */
        "\x20\x34\x73\x04" /* xar z0.s,z0.s,z1.s,#13 */
        "\xc0\xe0\x40\xe5"; /* st1w { z0.s },p0,[x6] */
    const char code_d[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x80\xa0\xe0\xa5" /* ld1d { z0.d },p0/z,[x4] */
        "\xa1\xa0\xe0\xa5" /* ld1d { z1.d },p0/z,[x5] */
        "\x20\x34\xe3\x04" /* xar z0.d,z0.d,z1.d,#29 */
        "\xc0\xe0\xe0\xe5"; /* st1d { z0.d },p0,[x6] */
    uint8_t n_b[16], m_b[16], exp_b[16], exp_b_xor[16], got_b[16];
    uint16_t n_h[8], m_h[8], exp_h[8], got_h[8];
    uint32_t n_s[4], m_s[4], exp_s[4], got_s[4];
    uint64_t n_d[2], m_d[2], exp_d[2], got_d[2];
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40100;
    uint64_t x6 = 0x40200;
    uint64_t x7 = 0x40300;
    int i;

    for (i = 0; i < 16; i++) {
        n_b[i] = (uint8_t)(0x11 + i * 7);
        m_b[i] = (uint8_t)(0xc3 - i * 5);
        exp_b[i] = test_arm64_ror8((uint8_t)(n_b[i] ^ m_b[i]), 3);
        exp_b_xor[i] = n_b[i] ^ m_b[i];
    }
    for (i = 0; i < 8; i++) {
        n_h[i] = (uint16_t)(0x1234 + i * 0x101);
        m_h[i] = (uint16_t)(0xf0e1 - i * 0x111);
        exp_h[i] = test_arm64_ror16((uint16_t)(n_h[i] ^ m_h[i]), 5);
    }
    for (i = 0; i < 4; i++) {
        n_s[i] = 0x10203040u + (uint32_t)i * 0x11111111u;
        m_s[i] = 0xfedcba98u - (uint32_t)i * 0x01020304u;
        exp_s[i] = test_arm64_ror32(n_s[i] ^ m_s[i], 13);
    }
    n_d[0] = 0x0123456789abcdefull;
    n_d[1] = 0xfedcba9876543210ull;
    m_d[0] = 0x0f1e2d3c4b5a6978ull;
    m_d[1] = 0x8877665544332211ull;
    for (i = 0; i < 2; i++) {
        exp_d[i] = test_arm64_ror64(n_d[i] ^ m_d[i], 29);
    }

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_b,
                    sizeof(code_b) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_b, sizeof(n_b)));
    OK(uc_mem_write(uc, x5, m_b, sizeof(m_b)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_b) - 1, 0, 0));
    OK(uc_mem_read(uc, x6, got_b, sizeof(got_b)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got_b[i] == exp_b[i]);
    }
    OK(uc_mem_read(uc, x7, got_b, sizeof(got_b)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got_b[i] == exp_b_xor[i]);
    }
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_h,
                    sizeof(code_h) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_h, sizeof(n_h)));
    OK(uc_mem_write(uc, x5, m_h, sizeof(m_h)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_h) - 1, 0, 0));
    OK(uc_mem_read(uc, x6, got_h, sizeof(got_h)));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(got_h[i] == exp_h[i]);
    }
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_s,
                    sizeof(code_s) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_s, sizeof(n_s)));
    OK(uc_mem_write(uc, x5, m_s, sizeof(m_s)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_s) - 1, 0, 0));
    OK(uc_mem_read(uc, x6, got_s, sizeof(got_s)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(got_s[i] == exp_s[i]);
    }
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_d,
                    sizeof(code_d) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_d, sizeof(n_d)));
    OK(uc_mem_write(uc, x5, m_d, sizeof(m_d)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_d) - 1, 0, 0));
    OK(uc_mem_read(uc, x6, got_d, sizeof(got_d)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_d[i] == exp_d[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_pmull(void)
{
    uc_engine *uc;
    const char code_h[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x00\xa4" /* ld1b { z1.b },p0/z,[x4] */
        "\xa2\xa0\x00\xa4" /* ld1b { z2.b },p0/z,[x5] */
        "\x20\x68\x42\x45" /* pmullb z0.h,z1.b,z2.b */
        "\x23\x6c\x42\x45" /* pmullt z3.h,z1.b,z2.b */
        "\xc0\xe0\xa0\xe4" /* st1h { z0.h },p0,[x6] */
        "\xe3\xe0\xa0\xe4"; /* st1h { z3.h },p0,[x7] */
    const char code_d[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x40\xa5" /* ld1w { z1.s },p0/z,[x4] */
        "\xa2\xa0\x40\xa5" /* ld1w { z2.s },p0/z,[x5] */
        "\x20\x68\xc2\x45" /* pmullb z0.d,z1.s,z2.s */
        "\x23\x6c\xc2\x45" /* pmullt z3.d,z1.s,z2.s */
        "\xc0\xe0\xe0\xe5" /* st1d { z0.d },p0,[x6] */
        "\xe3\xe0\xe0\xe5"; /* st1d { z3.d },p0,[x7] */
    const char code_q[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\xe0\xa5" /* ld1d { z1.d },p0/z,[x4] */
        "\xa2\xa0\xe0\xa5" /* ld1d { z2.d },p0/z,[x5] */
        "\x20\x68\x02\x45" /* pmullb z0.q,z1.d,z2.d */
        "\x23\x6c\x02\x45" /* pmullt z3.q,z1.d,z2.d */
        "\xc0\xe0\xe0\xe5" /* st1d { z0.d },p0,[x6] */
        "\xe3\xe0\xe0\xe5"; /* st1d { z3.d },p0,[x7] */
    uint8_t n_b[16], m_b[16];
    uint16_t exp_h_b[8], exp_h_t[8], got_h[8];
    uint32_t n_s[4], m_s[4];
    uint64_t exp_d_b[2], exp_d_t[2], got_d[2];
    uint64_t n_d[2], m_d[2];
    uint64_t exp_q_b[2], exp_q_t[2], got_q[2];
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40100;
    uint64_t x6 = 0x40200;
    uint64_t x7 = 0x40300;
    int i;

    for (i = 0; i < 16; i++) {
        n_b[i] = (uint8_t)(0x21 + i * 9);
        m_b[i] = (uint8_t)(0xf3 - i * 7);
    }
    for (i = 0; i < 8; i++) {
        exp_h_b[i] = test_arm64_pmull8(n_b[2 * i], m_b[2 * i]);
        exp_h_t[i] = test_arm64_pmull8(n_b[2 * i + 1], m_b[2 * i + 1]);
    }
    for (i = 0; i < 4; i++) {
        n_s[i] = 0x13579bdfu + (uint32_t)i * 0x01010101u;
        m_s[i] = 0xfdb97531u - (uint32_t)i * 0x02020202u;
    }
    for (i = 0; i < 2; i++) {
        exp_d_b[i] = test_arm64_pmull32(n_s[2 * i], m_s[2 * i]);
        exp_d_t[i] = test_arm64_pmull32(n_s[2 * i + 1],
                                        m_s[2 * i + 1]);
    }
    n_d[0] = 0x0123456789abcdefull;
    n_d[1] = 0xfedcba9876543210ull;
    m_d[0] = 0x0f1e2d3c4b5a6978ull;
    m_d[1] = 0x8877665544332211ull;
    test_arm64_pmull64(n_d[0], m_d[0], &exp_q_b[0], &exp_q_b[1]);
    test_arm64_pmull64(n_d[1], m_d[1], &exp_q_t[0], &exp_q_t[1]);

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_h,
                    sizeof(code_h) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_b, sizeof(n_b)));
    OK(uc_mem_write(uc, x5, m_b, sizeof(m_b)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_h) - 1, 0, 0));
    OK(uc_mem_read(uc, x6, got_h, sizeof(got_h)));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(got_h[i] == exp_h_b[i]);
    }
    OK(uc_mem_read(uc, x7, got_h, sizeof(got_h)));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(got_h[i] == exp_h_t[i]);
    }
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_d,
                    sizeof(code_d) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_s, sizeof(n_s)));
    OK(uc_mem_write(uc, x5, m_s, sizeof(m_s)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_d) - 1, 0, 0));
    OK(uc_mem_read(uc, x6, got_d, sizeof(got_d)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_d[i] == exp_d_b[i]);
    }
    OK(uc_mem_read(uc, x7, got_d, sizeof(got_d)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_d[i] == exp_d_t[i]);
    }
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_q,
                    sizeof(code_q) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_d, sizeof(n_d)));
    OK(uc_mem_write(uc, x5, m_d, sizeof(m_d)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_q) - 1, 0, 0));
    OK(uc_mem_read(uc, x6, got_q, sizeof(got_q)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_q[i] == exp_q_b[i]);
    }
    OK(uc_mem_read(uc, x7, got_q, sizeof(got_q)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_q[i] == exp_q_t[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_emit32(uint8_t *code, int offset, uint32_t insn)
{
    code[offset] = (uint8_t)insn;
    code[offset + 1] = (uint8_t)(insn >> 8);
    code[offset + 2] = (uint8_t)(insn >> 16);
    code[offset + 3] = (uint8_t)(insn >> 24);
}

static void test_arm64_mte_simd_fp_single_access(void)
{
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    const uint64_t tag0 = 0x0c00000000000000ull;
    const uint64_t tag1 = 0x0d00000000000000ull;
    uint8_t load_code[8];
    uint8_t store_code[8];
    uint8_t mem[64];
    uint8_t actual[64];
    uint64_t q0_initial[2] = {
        0x1111222233334444ull, 0x5555666677778888ull
    };
    uint64_t q0_store[2] = {
        0x1021324354657687ull, 0x98a9bacbdcedfe0full
    };
    uint64_t q0[2];
    uint64_t x4 = 0x0c00000000040008ull;
    uc_engine *uc;
    size_t i;

    for (i = 0; i < sizeof(mem); i++) {
        mem[i] = (uint8_t)(0x40 + i);
    }
    test_arm64_emit32(load_code, 0, 0xd9200822);  /* stg x2,[x1] */
    test_arm64_emit32(load_code, 4, 0x3dc00080); /* ldr q0,[x4] */
    test_arm64_emit32(store_code, 0, 0xd9200822);  /* stg x2,[x1] */
    test_arm64_emit32(store_code, 4, 0x3d800080); /* str q0,[x4] */

    memcpy(q0, q0_initial, sizeof(q0));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)load_code, sizeof(load_code),
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, mem, sizeof(mem)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_store_tag_at(uc, 0x40000, tag0);
    test_arm64_mte_store_tag_at(uc, 0x40010, tag1);
    OK(uc_reg_write(uc, UC_ARM64_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    TEST_CHECK(uc_emu_start(uc, code_start + 4,
                            code_start + sizeof(load_code), 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_ARM64_REG_Q0, q0));
    TEST_CHECK(memcmp(q0, q0_initial, sizeof(q0)) == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)store_code, sizeof(store_code),
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, mem, sizeof(mem)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    test_arm64_mte_store_tag_at(uc, 0x40000, tag0);
    test_arm64_mte_store_tag_at(uc, 0x40010, tag1);
    OK(uc_reg_write(uc, UC_ARM64_REG_Q0, q0_store));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_emu_start(uc, code_start + 4, code_start + sizeof(store_code),
                    0, 0));
    OK(uc_mem_read(uc, 0x40000, actual, sizeof(actual)));
    TEST_CHECK(memcmp(actual, mem, 8) == 0);
    TEST_CHECK(memcmp(actual + 8, q0_store, sizeof(q0_store)) == 0);
    TEST_CHECK(memcmp(actual + 24, mem + 24, sizeof(actual) - 24) == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 1);
    OK(uc_close(uc));
}

static void test_arm64_mte_advsimd_struct_range(void)
{
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    const uint64_t tag0 = 0x0c00000000000000ull;
    const uint64_t tag1 = 0x0d00000000000000ull;
    uint8_t load_code[8];
    uint8_t store_code[8];
    uint8_t mem[64];
    uint8_t actual[64];
    uint8_t expected[64];
    uint64_t q0_initial[2] = {
        0x0102030405060708ull, 0x1112131415161718ull
    };
    uint64_t q1_initial[2] = {
        0x2122232425262728ull, 0x3132333435363738ull
    };
    uint64_t q0_store[2] = {
        0x405162738495a6b7ull, 0xc8d9eafb0c1d2e3full
    };
    uint64_t q1_store[2] = {
        0x1020304050607080ull, 0x90a0b0c0d0e0f000ull
    };
    uint64_t q0[2];
    uint64_t q1[2];
    uint64_t x4 = 0x0c00000000040000ull;
    uc_engine *uc;
    size_t i;

    for (i = 0; i < sizeof(mem); i++) {
        mem[i] = (uint8_t)(0x80 + i);
    }
    test_arm64_emit32(load_code, 0, 0xd9200822);  /* stg x2,[x1] */
    test_arm64_emit32(load_code, 4, 0x4c40a080);
    test_arm64_emit32(store_code, 0, 0xd9200822);  /* stg x2,[x1] */
    test_arm64_emit32(store_code, 4, 0x4c00a080);

    memcpy(q0, q0_initial, sizeof(q0));
    memcpy(q1, q1_initial, sizeof(q1));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)load_code, sizeof(load_code),
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, mem, sizeof(mem)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_store_tag_at(uc, 0x40000, tag0);
    test_arm64_mte_store_tag_at(uc, 0x40010, tag1);
    OK(uc_reg_write(uc, UC_ARM64_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM64_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    TEST_CHECK(uc_emu_start(uc, code_start + 4,
                            code_start + sizeof(load_code), 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_reg_read(uc, UC_ARM64_REG_Q0, q0));
    OK(uc_reg_read(uc, UC_ARM64_REG_Q1, q1));
    TEST_CHECK(memcmp(q0, q0_initial, sizeof(q0)) == 0);
    TEST_CHECK(memcmp(q1, q1_initial, sizeof(q1)) == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));

    memcpy(expected, mem, sizeof(expected));
    memcpy(expected, q0_store, sizeof(q0_store));
    memcpy(expected + sizeof(q0_store), q1_store, sizeof(q1_store));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)store_code, sizeof(store_code),
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, mem, sizeof(mem)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    test_arm64_mte_store_tag_at(uc, 0x40000, tag0);
    test_arm64_mte_store_tag_at(uc, 0x40010, tag1);
    OK(uc_reg_write(uc, UC_ARM64_REG_Q0, q0_store));
    OK(uc_reg_write(uc, UC_ARM64_REG_Q1, q1_store));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_emu_start(uc, code_start + 4, code_start + sizeof(store_code),
                    0, 0));
    OK(uc_mem_read(uc, 0x40000, actual, sizeof(actual)));
    TEST_CHECK(memcmp(actual, expected, sizeof(actual)) == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 1);
    OK(uc_close(uc));
}

static void test_arm64_i8mm_q_run(uint32_t insn, const uint8_t *initial,
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

    test_arm64_emit32(code, 0, insn);
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    memcpy(q0, initial, 16);
    memcpy(q1, n, 16);
    memcpy(q2, m, 16);
    OK(uc_reg_write(uc, UC_ARM64_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM64_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM64_REG_Q2, q2));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_Q0, q0));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got[i] == expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_i8mm_expect_exception(uint32_t insn,
                                             uc_cpu_arm64 cpu)
{
    uc_engine *uc;
    uint8_t code[4];

    test_arm64_emit32(code, 0, insn);
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), cpu);
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_close(uc));
}

static void test_arm64_i8mm_advsimd(void)
{
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
    const uint8_t exp_sudot_idx[16] = {
        0x19, 0x43, 0x00, 0x00, 0xb1, 0xea, 0xff, 0xff,
        0x78, 0xb7, 0xff, 0xff, 0x08, 0x92, 0xff, 0xff,
    };
    const uint8_t exp_usdot_idx[16] = {
        0x19, 0xc4, 0xff, 0xff, 0xb1, 0xa5, 0xff, 0xff,
        0x78, 0xd5, 0xff, 0xff, 0x08, 0x99, 0xff, 0xff,
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

    test_arm64_i8mm_q_run(0x4e829c20, initial, n, m, exp_usdot);
    test_arm64_i8mm_q_run(0x4f02f820, initial, n, m, exp_sudot_idx);
    test_arm64_i8mm_q_run(0x4f82f820, initial, n, m, exp_usdot_idx);
    test_arm64_i8mm_q_run(0x4e82a420, initial, n, m, exp_smmla);
    test_arm64_i8mm_q_run(0x6e82a420, initial, n, m, exp_ummla);
    test_arm64_i8mm_q_run(0x4e82ac20, initial, n, m, exp_usmmla);

    test_arm64_i8mm_expect_exception(0x4e829c20, UC_CPU_ARM64_A72);
    test_arm64_i8mm_expect_exception(0x0e82a420, UC_CPU_ARM64_MAX);
}

static void test_arm64_bf16_scalar_convert(void)
{
    uc_engine *uc;
    uint8_t code[4];
    uint32_t s0;
    uint32_t s1 = 0x3fc00000u;

    test_arm64_emit32(code, 0, 0x1e634020);
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_reg_write(uc, UC_ARM64_REG_S1, &s1));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_S0, &s0));
    TEST_CHECK(s0 == 0x00003fc0u);
    OK(uc_close(uc));
}

static void test_arm64_bf16_vector_convert_run(uint32_t insn,
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

    test_arm64_emit32(code, 0, insn);
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    memcpy(q0, initial, 16);
    memcpy(q1, source, 16);
    OK(uc_reg_write(uc, UC_ARM64_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM64_REG_Q1, q1));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_Q0, q0));
    for (i = 0; i < 8; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn %08x lane %zu got %04x expected %04x",
                    insn, i, got[i], expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_bf16_q_run(uint32_t insn, const uint32_t *initial,
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

    test_arm64_emit32(code, 0, insn);
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    memcpy(q0, initial, 16);
    memcpy(q1, n, 16);
    memcpy(q2, m, 16);
    OK(uc_reg_write(uc, UC_ARM64_REG_Q0, q0));
    OK(uc_reg_write(uc, UC_ARM64_REG_Q1, q1));
    OK(uc_reg_write(uc, UC_ARM64_REG_Q2, q2));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_Q0, q0));
    for (i = 0; i < 4; i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn %08x lane %zu got %08x expected %08x",
                    insn, i, got[i], expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_bf16_advsimd(void)
{
    const uint16_t init_h[8] = {
        0x1111, 0x2222, 0x3333, 0x4444,
        0xaaaa, 0xbbbb, 0xcccc, 0xdddd,
    };
    const uint32_t fp32_source[4] = {
        0x3f800000u, 0xc0000000u, 0x40400000u, 0x40800000u,
    };
    const uint16_t exp_bfcvtn[8] = {
        0x3f80, 0xc000, 0x4040, 0x4080,
        0x0000, 0x0000, 0x0000, 0x0000,
    };
    const uint16_t exp_bfcvtn2[8] = {
        0x1111, 0x2222, 0x3333, 0x4444,
        0x3f80, 0xc000, 0x4040, 0x4080,
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

    test_arm64_bf16_scalar_convert();
    test_arm64_bf16_vector_convert_run(0x0ea16820, init_h, fp32_source,
                                       exp_bfcvtn);
    test_arm64_bf16_vector_convert_run(0x4ea16820, init_h, fp32_source,
                                       exp_bfcvtn2);
    test_arm64_bf16_q_run(0x6e42fc20, init_s, n_pair, m_pair, exp_bfdot);
    test_arm64_bf16_q_run(0x4f42f020, init_s, n_pair, m_pair,
                          exp_bfdot_idx);
    test_arm64_bf16_q_run(0x6e42ec20, init_s, n_mmla, m_mmla, exp_bfmmla);
    test_arm64_bf16_q_run(0x2ec2fc20, init_s, n_long, m_long, exp_bfmlalb);
    test_arm64_bf16_q_run(0x6ec2fc20, init_s, n_long, m_long, exp_bfmlalt);
    test_arm64_bf16_q_run(0x0fc2f020, init_s, n_long, m_long,
                          exp_bfmlalb_idx);
    test_arm64_bf16_q_run(0x4fc2f020, init_s, n_long, m_long,
                          exp_bfmlalt_idx);

    test_arm64_i8mm_expect_exception(0x1e634020, UC_CPU_ARM64_A72);
    test_arm64_i8mm_expect_exception(0x6e42fc20, UC_CPU_ARM64_A72);
    test_arm64_i8mm_expect_exception(0x2e42ec20, UC_CPU_ARM64_MAX);
}

static void test_arm64_sve2_mul_run(uint32_t insn, int esz, const void *n,
                                    const void *m, const void *expected,
                                    size_t size)
{
    static const uint32_t ld1_z1[4] = {
        0xa400a081, 0xa4a0a081, 0xa540a081, 0xa5e0a081,
    };
    static const uint32_t ld1_z2[4] = {
        0xa400a0a2, 0xa4a0a0a2, 0xa540a0a2, 0xa5e0a0a2,
    };
    static const uint32_t st1_z0[4] = {
        0xe400e0c0, 0xe4a0e0c0, 0xe540e0c0, 0xe5e0e0c0,
    };
    uc_engine *uc;
    uint8_t code[20];
    uint8_t got[32];
    const uint8_t *exp = expected;
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40100;
    uint64_t x6 = 0x40200;
    size_t i;

    test_arm64_emit32(code, 0, 0x2518e3e0);
    test_arm64_emit32(code, 4, ld1_z1[esz]);
    test_arm64_emit32(code, 8, ld1_z2[esz]);
    test_arm64_emit32(code, 12, insn);
    test_arm64_emit32(code, 16, st1_z0[esz]);

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n, size));
    OK(uc_mem_write(uc, x5, m, size));
    if (size > 16) {
        test_arm64_mte_enable_sve_vq(uc, 1);
    } else {
        test_arm64_mte_enable_sve(uc);
    }
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x6, got, size));
    for (i = 0; i < size; i++) {
        TEST_CHECK(got[i] == exp[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_widen_run(uint32_t insn, int dst_esz,
                                      int src1_esz, int src2_esz,
                                      const void *n, size_t n_size,
                                      const void *m, size_t m_size,
                                      const void *expected, size_t out_size)
{
    static const uint32_t ld1_z1[4] = {
        0xa400a081, 0xa4a0a081, 0xa540a081, 0xa5e0a081,
    };
    static const uint32_t ld1_z2[4] = {
        0xa400a0a2, 0xa4a0a0a2, 0xa540a0a2, 0xa5e0a0a2,
    };
    static const uint32_t st1_z0[4] = {
        0xe400e0c0, 0xe4a0e0c0, 0xe540e0c0, 0xe5e0e0c0,
    };
    uc_engine *uc;
    uint8_t code[28];
    uint8_t got[32];
    const uint8_t *exp = expected;
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40100;
    uint64_t x6 = 0x40200;
    size_t code_size = 0;
    size_t i;

    test_arm64_emit32(code, code_size, 0x2518e3e0);
    code_size += 4;
    test_arm64_emit32(code, code_size, ld1_z1[src1_esz]);
    code_size += 4;
    if (m != NULL) {
        test_arm64_emit32(code, code_size, ld1_z2[src2_esz]);
        code_size += 4;
    }
    test_arm64_emit32(code, code_size, insn);
    code_size += 4;
    test_arm64_emit32(code, code_size, st1_z0[dst_esz]);
    code_size += 4;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    code_size, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n, n_size));
    if (m != NULL) {
        OK(uc_mem_write(uc, x5, m, m_size));
    }
    if (out_size > 16 || n_size > 16 || m_size > 16) {
        test_arm64_mte_enable_sve_vq(uc, 1);
    } else {
        test_arm64_mte_enable_sve(uc);
    }
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
    OK(uc_mem_read(uc, x6, got, out_size));
    for (i = 0; i < out_size; i++) {
        TEST_CHECK(got[i] == exp[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_narrow_run(uint32_t insn, int dst_esz,
                                       int src_esz, const void *initial,
                                       const void *n, const void *m,
                                       const void *expected, size_t size)
{
    static const uint32_t ld1_z0[4] = {
        0xa400a060, 0xa4a0a060, 0xa540a060, 0xa5e0a060,
    };
    static const uint32_t ld1_z1[4] = {
        0xa400a081, 0xa4a0a081, 0xa540a081, 0xa5e0a081,
    };
    static const uint32_t ld1_z2[4] = {
        0xa400a0a2, 0xa4a0a0a2, 0xa540a0a2, 0xa5e0a0a2,
    };
    static const uint32_t st1_z0[4] = {
        0xe400e0c0, 0xe4a0e0c0, 0xe540e0c0, 0xe5e0e0c0,
    };
    uc_engine *uc;
    uint8_t code[24];
    uint8_t got[32];
    const uint8_t *exp = expected;
    uint64_t x3 = 0x40000;
    uint64_t x4 = 0x40100;
    uint64_t x5 = 0x40200;
    uint64_t x6 = 0x40300;
    size_t i;

    test_arm64_emit32(code, 0, 0x2518e3e0);
    test_arm64_emit32(code, 4, ld1_z0[dst_esz]);
    test_arm64_emit32(code, 8, ld1_z1[src_esz]);
    test_arm64_emit32(code, 12, ld1_z2[src_esz]);
    test_arm64_emit32(code, 16, insn);
    test_arm64_emit32(code, 20, st1_z0[dst_esz]);

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x3, initial, size));
    OK(uc_mem_write(uc, x4, n, size));
    OK(uc_mem_write(uc, x5, m, size));
    if (size > 16) {
        test_arm64_mte_enable_sve_vq(uc, 1);
    } else {
        test_arm64_mte_enable_sve(uc);
    }
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x6, got, size));
    for (i = 0; i < size; i++) {
        TEST_CHECK(got[i] == exp[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_fp_convert_run(uint32_t ptrue, uint32_t insn,
                                           int dst_esz, int src_esz,
                                           const void *initial,
                                           const void *source,
                                           const void *expected,
                                           size_t size)
{
    static const uint32_t ld1_z0[4] = {
        0xa400a060, 0xa4a0a060, 0xa540a060, 0xa5e0a060,
    };
    static const uint32_t ld1_z1[4] = {
        0xa400a081, 0xa4a0a081, 0xa540a081, 0xa5e0a081,
    };
    static const uint32_t st1_z0[4] = {
        0xe400e0c0, 0xe4a0e0c0, 0xe540e0c0, 0xe5e0e0c0,
    };
    uc_engine *uc;
    uint8_t code[28];
    uint8_t got[32];
    const uint8_t *exp = expected;
    uint64_t x3 = 0x40000;
    uint64_t x4 = 0x40100;
    uint64_t x6 = 0x40200;
    size_t i;

    test_arm64_emit32(code, 0, 0x2518e3e0);
    test_arm64_emit32(code, 4, ld1_z0[dst_esz]);
    test_arm64_emit32(code, 8, ld1_z1[src_esz]);
    test_arm64_emit32(code, 12, ptrue);
    test_arm64_emit32(code, 16, insn);
    test_arm64_emit32(code, 20, 0x2518e3e0);
    test_arm64_emit32(code, 24, st1_z0[dst_esz]);

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x3, initial, size));
    OK(uc_mem_write(uc, x4, source, size));
    if (size > 16) {
        test_arm64_mte_enable_sve_vq(uc, 1);
    } else {
        test_arm64_mte_enable_sve(uc);
    }
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x6, got, size));
    for (i = 0; i < size; i++) {
        TEST_CHECK_(got[i] == exp[i],
                    "insn %08x byte %zu got %02x expected %02x",
                    insn, i, got[i], exp[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_fp_convert(void)
{
    const uint32_t ptrue_b = 0x2518e3e0;
    const uint32_t ptrue_s_vl2 = 0x2598e040;
    const uint16_t init_h[8] = {
        0x1110, 0xaaaa, 0x1111, 0xbbbb,
        0x1112, 0xcccc, 0x1113, 0xdddd,
    };
    const uint16_t exp_fcvtnt_sh[8] = {
        0x1110, 0x3c00, 0x1111, 0xc000,
        0x1112, 0xcccc, 0x1113, 0xdddd,
    };
    const uint16_t src_h[8] = {
        0xaaaa, 0x3c00, 0xbbbb, 0xc000,
        0xcccc, 0x3800, 0xdddd, 0x4400,
    };
    const uint32_t src_s[4] = {
        0x3f800000u, 0xc0000000u, 0x3f000000u, 0x40800000u,
    };
    const uint32_t src_s_top[4] = {
        0xdeadbeefu, 0x3f800000u, 0xcafebabeu, 0xc0000000u,
    };
    const uint32_t init_s[4] = {
        0x11111111u, 0xaaaaaaaau, 0x22222222u, 0xbbbbbbbbu,
    };
    const uint32_t exp_fcvtlt_hs[4] = {
        0x3f800000u, 0xc0000000u, 0x3f000000u, 0x40800000u,
    };
    const uint32_t exp_fcvtnt_ds[4] = {
        0x11111111u, 0x3fc00000u, 0x22222222u, 0xc0000000u,
    };
    const uint32_t exp_fcvtx_ds[4] = {
        0x3f800001u, 0x00000000u, 0xc0000000u, 0x00000000u,
    };
    const uint32_t exp_fcvtxnt_ds[4] = {
        0x11111111u, 0x3f800001u, 0x22222222u, 0xc0000000u,
    };
    const uint64_t src_d[2] = {
        0x3ff8000000000000ull, 0xc000000000000000ull,
    };
    const uint64_t src_d_odd[2] = {
        0x3ff0000010000000ull, 0xc000000000000000ull,
    };
    const uint64_t exp_fcvtlt_sd[2] = {
        0x3ff0000000000000ull, 0xc000000000000000ull,
    };
    const uint64_t init_d[2] = {
        0xaaaaaaaaaaaaaaaaull, 0xbbbbbbbbbbbbbbbbull,
    };

    test_arm64_sve2_fp_convert_run(ptrue_s_vl2, 0x6488a020, 1, 2,
                                   init_h, src_s, exp_fcvtnt_sh,
                                   sizeof(exp_fcvtnt_sh));
    test_arm64_sve2_fp_convert_run(ptrue_b, 0x6489a020, 2, 1,
                                   init_s, src_h, exp_fcvtlt_hs,
                                   sizeof(exp_fcvtlt_hs));
    test_arm64_sve2_fp_convert_run(ptrue_b, 0x64caa020, 2, 3,
                                   init_s, src_d, exp_fcvtnt_ds,
                                   sizeof(exp_fcvtnt_ds));
    test_arm64_sve2_fp_convert_run(ptrue_b, 0x64cba020, 3, 2,
                                   init_d, src_s_top, exp_fcvtlt_sd,
                                   sizeof(exp_fcvtlt_sd));
    test_arm64_sve2_fp_convert_run(ptrue_b, 0x650aa020, 2, 3,
                                   init_s, src_d_odd, exp_fcvtx_ds,
                                   sizeof(exp_fcvtx_ds));
    test_arm64_sve2_fp_convert_run(ptrue_b, 0x640aa020, 2, 3,
                                   init_s, src_d_odd, exp_fcvtxnt_ds,
                                   sizeof(exp_fcvtxnt_ds));
}

static void test_arm64_sve2_fp_pairwise_run(uint32_t ptrue, uint32_t insn,
                                            int esz, const void *n,
                                            const void *m,
                                            const void *expected,
                                            size_t size)
{
    static const uint32_t ld1_z0[4] = {
        0xa400a060, 0xa4a0a060, 0xa540a060, 0xa5e0a060,
    };
    static const uint32_t ld1_z1[4] = {
        0xa400a081, 0xa4a0a081, 0xa540a081, 0xa5e0a081,
    };
    static const uint32_t st1_z0[4] = {
        0xe400e0c0, 0xe4a0e0c0, 0xe540e0c0, 0xe5e0e0c0,
    };
    uc_engine *uc;
    uint8_t code[28];
    uint8_t got[32];
    const uint8_t *exp = expected;
    uint64_t x3 = 0x40000;
    uint64_t x4 = 0x40100;
    uint64_t x6 = 0x40200;
    size_t i;

    test_arm64_emit32(code, 0, 0x2518e3e0);
    test_arm64_emit32(code, 4, ld1_z0[esz]);
    test_arm64_emit32(code, 8, ld1_z1[esz]);
    test_arm64_emit32(code, 12, ptrue);
    test_arm64_emit32(code, 16, insn);
    test_arm64_emit32(code, 20, 0x2518e3e0);
    test_arm64_emit32(code, 24, st1_z0[esz]);

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x3, n, size));
    OK(uc_mem_write(uc, x4, m, size));
    if (size > 16) {
        test_arm64_mte_enable_sve_vq(uc, 1);
    } else {
        test_arm64_mte_enable_sve(uc);
    }
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x6, got, size));
    for (i = 0; i < size; i++) {
        TEST_CHECK_(got[i] == exp[i],
                    "insn %08x byte %zu got %02x expected %02x",
                    insn, i, got[i], exp[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_flogb_run(uint32_t ptrue, uint32_t insn, int esz,
                                      const void *initial, const void *source,
                                      const void *expected, size_t size,
                                      uint32_t fpcr)
{
    static const uint32_t ld1_z0[4] = {
        0xa400a060, 0xa4a0a060, 0xa540a060, 0xa5e0a060,
    };
    static const uint32_t ld1_z1[4] = {
        0xa400a081, 0xa4a0a081, 0xa540a081, 0xa5e0a081,
    };
    static const uint32_t st1_z0[4] = {
        0xe400e0c0, 0xe4a0e0c0, 0xe540e0c0, 0xe5e0e0c0,
    };
    uc_engine *uc;
    uint8_t code[28];
    uint8_t got[32];
    const uint8_t *exp = expected;
    uint64_t x3 = 0x40000;
    uint64_t x4 = 0x40100;
    uint64_t x6 = 0x40200;
    size_t i;

    test_arm64_emit32(code, 0, 0x2518e3e0);
    test_arm64_emit32(code, 4, ld1_z0[esz]);
    test_arm64_emit32(code, 8, ld1_z1[esz]);
    test_arm64_emit32(code, 12, ptrue);
    test_arm64_emit32(code, 16, insn);
    test_arm64_emit32(code, 20, 0x2518e3e0);
    test_arm64_emit32(code, 24, st1_z0[esz]);

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x3, initial, size));
    OK(uc_mem_write(uc, x4, source, size));
    if (size > 16) {
        test_arm64_mte_enable_sve_vq(uc, 1);
    } else {
        test_arm64_mte_enable_sve(uc);
    }
    if (fpcr != 0) {
        OK(uc_reg_write(uc, UC_ARM64_REG_FPCR, &fpcr));
    }
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x6, got, size));
    for (i = 0; i < size; i++) {
        TEST_CHECK_(got[i] == exp[i],
                    "insn %08x byte %zu got %02x expected %02x",
                    insn, i, got[i], exp[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_fp_pairwise_flogb(void)
{
    const uint32_t ptrue_b = 0x2518e3e0;
    const uint32_t ptrue_s_vl2 = 0x2598e040;
    const uint16_t n_h[8] = {
        0x3c00, 0x4000, 0xbc00, 0xc000,
        0x3800, 0x4400, 0x4200, 0xb800,
    };
    const uint16_t m_h[8] = {
        0x4000, 0x4200, 0x4400, 0xbc00,
        0xc000, 0x3800, 0xbc00, 0x4400,
    };
    const uint16_t exp_faddp_h[8] = {
        0x4200, 0x4500, 0xc200, 0x4200,
        0x4480, 0xbe00, 0x4100, 0x4200,
    };
    const uint16_t exp_fmaxnmp_h[8] = {
        0x4000, 0x4200, 0xbc00, 0x4400,
        0x4400, 0x3800, 0x4200, 0x4400,
    };
    const uint16_t exp_fminnmp_h[8] = {
        0x3c00, 0x4000, 0xc000, 0xbc00,
        0x3800, 0xc000, 0xb800, 0xbc00,
    };
    const uint16_t exp_fmaxp_h[8] = {
        0x4000, 0x4200, 0xbc00, 0x4400,
        0x4400, 0x3800, 0x4200, 0x4400,
    };
    const uint16_t exp_fminp_h[8] = {
        0x3c00, 0x4000, 0xc000, 0xbc00,
        0x3800, 0xc000, 0xb800, 0xbc00,
    };
    const uint32_t n_s[4] = {
        0x3f800000u, 0x40000000u, 0xc0800000u, 0x40a00000u,
    };
    const uint32_t m_s[4] = {
        0x41200000u, 0xc0400000u, 0x40e00000u, 0x41000000u,
    };
    const uint32_t exp_faddp_s[4] = {
        0x40400000u, 0x40e00000u, 0x3f800000u, 0x41700000u,
    };
    const uint32_t exp_fmaxnmp_s[4] = {
        0x40000000u, 0x41200000u, 0x40a00000u, 0x41000000u,
    };
    const uint32_t exp_fminnmp_s[4] = {
        0x3f800000u, 0xc0400000u, 0xc0800000u, 0x40e00000u,
    };
    const uint64_t n_d[2] = {
        0x3ff8000000000000ull, 0xc000000000000000ull,
    };
    const uint64_t m_d[2] = {
        0x4008000000000000ull, 0x3ff0000000000000ull,
    };
    const uint64_t exp_faddp_d[2] = {
        0xbfe0000000000000ull, 0x4010000000000000ull,
    };
    const uint64_t exp_fmaxnmp_d[2] = {
        0x3ff8000000000000ull, 0x4008000000000000ull,
    };
    const uint64_t exp_fminnmp_d[2] = {
        0xc000000000000000ull, 0x3ff0000000000000ull,
    };
    const uint32_t n_nan_s[4] = {
        0x7fc00000u, 0x3f800000u, 0x40000000u, 0x40400000u,
    };
    const uint32_t m_nan_s[4] = {
        0x7fc00000u, 0x40000000u, 0x40800000u, 0x40a00000u,
    };
    const uint32_t exp_fmaxnmp_nan_s[4] = {
        0x3f800000u, 0x40000000u, 0x40400000u, 0x40a00000u,
    };
    const uint32_t exp_fmaxp_nan_s[4] = {
        0x7fc00000u, 0x7fc00000u, 0x40400000u, 0x40a00000u,
    };
    const uint32_t init_s[4] = {
        0x11111111u, 0x22222222u, 0x33333333u, 0x44444444u,
    };
    const uint32_t exp_faddp_s_vl2[4] = {
        0x40400000u, 0x40e00000u, 0xc0800000u, 0x40a00000u,
    };
    const uint16_t init_h[8] = {
        0x1111, 0x2222, 0x3333, 0x4444,
        0x5555, 0x6666, 0x7777, 0x8888,
    };
    const uint16_t flogb_h[8] = {
        0x3c00, 0x4000, 0x3800, 0x0001,
        0x0000, 0x7c00, 0x7e00, 0xc000,
    };
    const uint16_t exp_flogb_h[8] = {
        0x0000, 0x0001, 0xffff, 0xffe8,
        0x8000, 0x7fff, 0x8000, 0x0001,
    };
    const uint16_t exp_flogb_h_fz[8] = {
        0x0000, 0x0001, 0xffff, 0x8000,
        0x8000, 0x7fff, 0x8000, 0x0001,
    };
    const uint32_t flogb_s[4] = {
        0x3f800000u, 0x40000000u, 0x3f400000u, 0x00000001u,
    };
    const uint32_t exp_flogb_s[4] = {
        0x00000000u, 0x00000001u, 0xffffffffu, 0xffffff6bu,
    };
    const uint64_t flogb_d[2] = {
        0x3ff0000000000000ull, 0x7ff0000000000000ull,
    };
    const uint64_t exp_flogb_d[2] = {
        0x0000000000000000ull, 0x7fffffffffffffffull,
    };
    const uint32_t fpcr_fz16 = 1u << 19;

    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64508020, 1, n_h, m_h,
                                    exp_faddp_h, sizeof(exp_faddp_h));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64548020, 1, n_h, m_h,
                                    exp_fmaxnmp_h, sizeof(exp_fmaxnmp_h));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64558020, 1, n_h, m_h,
                                    exp_fminnmp_h, sizeof(exp_fminnmp_h));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64568020, 1, n_h, m_h,
                                    exp_fmaxp_h, sizeof(exp_fmaxp_h));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64578020, 1, n_h, m_h,
                                    exp_fminp_h, sizeof(exp_fminp_h));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64908020, 2, n_s, m_s,
                                    exp_faddp_s, sizeof(exp_faddp_s));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64948020, 2, n_s, m_s,
                                    exp_fmaxnmp_s, sizeof(exp_fmaxnmp_s));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64958020, 2, n_s, m_s,
                                    exp_fminnmp_s, sizeof(exp_fminnmp_s));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64968020, 2, n_s, m_s,
                                    exp_fmaxnmp_s, sizeof(exp_fmaxnmp_s));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64978020, 2, n_s, m_s,
                                    exp_fminnmp_s, sizeof(exp_fminnmp_s));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64d08020, 3, n_d, m_d,
                                    exp_faddp_d, sizeof(exp_faddp_d));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64d48020, 3, n_d, m_d,
                                    exp_fmaxnmp_d, sizeof(exp_fmaxnmp_d));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64d58020, 3, n_d, m_d,
                                    exp_fminnmp_d, sizeof(exp_fminnmp_d));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64d68020, 3, n_d, m_d,
                                    exp_fmaxnmp_d, sizeof(exp_fmaxnmp_d));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64d78020, 3, n_d, m_d,
                                    exp_fminnmp_d, sizeof(exp_fminnmp_d));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64948020, 2, n_nan_s,
                                    m_nan_s, exp_fmaxnmp_nan_s,
                                    sizeof(exp_fmaxnmp_nan_s));
    test_arm64_sve2_fp_pairwise_run(ptrue_b, 0x64968020, 2, n_nan_s,
                                    m_nan_s, exp_fmaxp_nan_s,
                                    sizeof(exp_fmaxp_nan_s));
    test_arm64_sve2_fp_pairwise_run(ptrue_s_vl2, 0x64908020, 2, n_s, m_s,
                                    exp_faddp_s_vl2,
                                    sizeof(exp_faddp_s_vl2));

    test_arm64_sve2_flogb_run(ptrue_b, 0x651aa020, 1, init_h, flogb_h,
                              exp_flogb_h, sizeof(exp_flogb_h), 0);
    test_arm64_sve2_flogb_run(ptrue_b, 0x651aa020, 1, init_h, flogb_h,
                              exp_flogb_h_fz, sizeof(exp_flogb_h_fz),
                              fpcr_fz16);
    test_arm64_sve2_flogb_run(ptrue_b, 0x651ca020, 2, init_s, flogb_s,
                              exp_flogb_s, sizeof(exp_flogb_s), 0);
    test_arm64_sve2_flogb_run(ptrue_b, 0x651ea020, 3, n_d, flogb_d,
                              exp_flogb_d, sizeof(exp_flogb_d), 0);

    test_arm64_i8mm_expect_exception(0x64908020, UC_CPU_ARM64_A72);
    test_arm64_i8mm_expect_exception(0x651ca020, UC_CPU_ARM64_A72);
}

static void test_arm64_sve2_fmlal_run(uint32_t insn, const uint32_t *initial,
                                      const uint16_t *n, const uint16_t *m,
                                      const uint32_t *expected, size_t size,
                                      uint32_t fpcr)
{
    uc_engine *uc;
    uint8_t code[24];
    uint8_t got[32];
    const uint8_t *exp = (const uint8_t *)expected;
    uint64_t x3 = 0x40000;
    uint64_t x4 = 0x40100;
    uint64_t x5 = 0x40200;
    uint64_t x6 = 0x40300;
    size_t i;

    test_arm64_emit32(code, 0, 0x2518e3e0);
    test_arm64_emit32(code, 4, 0xa540a060);
    test_arm64_emit32(code, 8, 0xa4a0a081);
    test_arm64_emit32(code, 12, 0xa4a0a0a2);
    test_arm64_emit32(code, 16, insn);
    test_arm64_emit32(code, 20, 0xe540e0c0);

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x3, initial, size));
    OK(uc_mem_write(uc, x4, n, size));
    OK(uc_mem_write(uc, x5, m, size));
    if (size > 16) {
        test_arm64_mte_enable_sve_vq(uc, 1);
    } else {
        test_arm64_mte_enable_sve(uc);
    }
    if (fpcr != 0) {
        OK(uc_reg_write(uc, UC_ARM64_REG_FPCR, &fpcr));
    }
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x6, got, size));
    for (i = 0; i < size; i++) {
        TEST_CHECK_(got[i] == exp[i],
                    "insn %08x byte %zu got %02x expected %02x",
                    insn, i, got[i], exp[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_fmlal(void)
{
    const uint32_t init_s[4] = {
        0x3f800000u, 0x41200000u, 0xc0000000u, 0x3f000000u,
    };
    const uint16_t n_h[8] = {
        0x3c00, 0x4000, 0xbc00, 0xc000,
        0x3800, 0x4400, 0x4200, 0xb800,
    };
    const uint16_t m_h[8] = {
        0x4000, 0x4200, 0x4400, 0xbc00,
        0xc000, 0x3800, 0xbc00, 0x4400,
    };
    const uint32_t exp_fmlalb[4] = {
        0x40400000u, 0x40c00000u, 0xc0400000u, 0xc0200000u,
    };
    const uint32_t exp_fmlalt[4] = {
        0x40e00000u, 0x41400000u, 0x00000000u, 0xbfc00000u,
    };
    const uint32_t exp_fmlslb[4] = {
        0xbf800000u, 0x41600000u, 0xbf800000u, 0x40600000u,
    };
    const uint32_t exp_fmlslt[4] = {
        0xc0a00000u, 0x41000000u, 0xc0800000u, 0x40200000u,
    };
    const uint32_t init_idx_s[8] = {
        0x3f800000u, 0x41200000u, 0xc0000000u, 0x3f000000u,
        0xbf800000u, 0x40400000u, 0x40800000u, 0xbf000000u,
    };
    const uint16_t n_idx_h[16] = {
        0x3c00, 0x4000, 0xbc00, 0xc000,
        0x3800, 0x4400, 0x4200, 0xb800,
        0x4000, 0x3c00, 0x4200, 0x4400,
        0xbc00, 0x3800, 0xc000, 0xb800,
    };
    const uint16_t m_idx_h[16] = {
        0x0000, 0x0000, 0x0000, 0x4000,
        0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0xc000,
        0x0000, 0x0000, 0x0000, 0x0000,
    };
    const uint32_t exp_fmlalb_idx[8] = {
        0x40400000u, 0x41000000u, 0xbf800000u, 0x40d00000u,
        0xc0a00000u, 0xc0400000u, 0x40c00000u, 0x40600000u,
    };
    const uint32_t exp_fmlalt_idx[8] = {
        0x40a00000u, 0x40c00000u, 0x40c00000u, 0xbf000000u,
        0xc0400000u, 0xc0a00000u, 0x40400000u, 0x3f000000u,
    };
    const uint32_t exp_fmlslb_idx[8] = {
        0xbf800000u, 0x41400000u, 0xc0400000u, 0xc0b00000u,
        0x40400000u, 0x41100000u, 0x40000000u, 0xc0900000u,
    };
    const uint32_t exp_fmlslt_idx[8] = {
        0xc0400000u, 0x41600000u, 0xc1200000u, 0x3fc00000u,
        0x3f800000u, 0x41300000u, 0x40a00000u, 0xbfc00000u,
    };
    const uint32_t zero_s[4] = { 0, 0, 0, 0 };
    const uint16_t subnormal_h[8] = {
        0x0001, 0x3c00, 0x0002, 0x3c00,
        0x0003, 0x3c00, 0x0004, 0x3c00,
    };
    const uint16_t one_bottom_h[8] = {
        0x3c00, 0x0000, 0x3c00, 0x0000,
        0x3c00, 0x0000, 0x3c00, 0x0000,
    };
    const uint32_t fpcr_fz16 = 1u << 19;

    test_arm64_sve2_fmlal_run(0x64a28020, init_s, n_h, m_h,
                              exp_fmlalb, sizeof(exp_fmlalb), 0);
    test_arm64_sve2_fmlal_run(0x64a28420, init_s, n_h, m_h,
                              exp_fmlalt, sizeof(exp_fmlalt), 0);
    test_arm64_sve2_fmlal_run(0x64a2a020, init_s, n_h, m_h,
                              exp_fmlslb, sizeof(exp_fmlslb), 0);
    test_arm64_sve2_fmlal_run(0x64a2a420, init_s, n_h, m_h,
                              exp_fmlslt, sizeof(exp_fmlslt), 0);
    test_arm64_sve2_fmlal_run(0x64aa4820, init_idx_s, n_idx_h, m_idx_h,
                              exp_fmlalb_idx, sizeof(exp_fmlalb_idx), 0);
    test_arm64_sve2_fmlal_run(0x64aa4c20, init_idx_s, n_idx_h, m_idx_h,
                              exp_fmlalt_idx, sizeof(exp_fmlalt_idx), 0);
    test_arm64_sve2_fmlal_run(0x64aa6820, init_idx_s, n_idx_h, m_idx_h,
                              exp_fmlslb_idx, sizeof(exp_fmlslb_idx), 0);
    test_arm64_sve2_fmlal_run(0x64aa6c20, init_idx_s, n_idx_h, m_idx_h,
                              exp_fmlslt_idx, sizeof(exp_fmlslt_idx), 0);
    test_arm64_sve2_fmlal_run(0x64a28020, zero_s, subnormal_h,
                              one_bottom_h, zero_s, sizeof(zero_s),
                              fpcr_fz16);

    test_arm64_i8mm_expect_exception(0x64a28020, UC_CPU_ARM64_A72);
}

static void test_arm64_sve2_mul_base(void)
{
    uc_engine *uc;
    uint8_t invalid_code[8];
    const uint8_t n_b[16] = {
        0x80, 0x7f, 0xf0, 0x11, 0x22, 0xdd, 0x33, 0xcc,
        0x44, 0xbb, 0x55, 0xaa, 0x66, 0x99, 0x77, 0x88,
    };
    const uint8_t m_b[16] = {
        0x02, 0xfe, 0x10, 0xf1, 0x80, 0x03, 0x7f, 0x81,
        0x55, 0xaa, 0x66, 0x99, 0x77, 0x88, 0xff, 0x01,
    };
    const uint8_t exp_mul_b[16] = {
        0x00, 0x02, 0x00, 0x01, 0x00, 0x97, 0x4d, 0xcc,
        0x94, 0x2e, 0xde, 0x9a, 0x6a, 0x48, 0x89, 0x88,
    };
    const uint8_t exp_smulh_b[16] = {
        0xff, 0xff, 0xff, 0xff, 0xef, 0xff, 0x19, 0x19,
        0x16, 0x17, 0x21, 0x22, 0x2f, 0x30, 0xff, 0xff,
    };
    const uint8_t exp_umulh_b[16] = {
        0x01, 0x7e, 0x0f, 0x10, 0x11, 0x02, 0x19, 0x66,
        0x16, 0x7c, 0x21, 0x65, 0x2f, 0x51, 0x76, 0x00,
    };
    const uint8_t exp_pmul_b[16] = {
        0x00, 0xaa, 0x00, 0xe1, 0x00, 0x67, 0x91, 0xcc,
        0x14, 0x4e, 0x1e, 0x5a, 0x12, 0x48, 0x2d, 0x88,
    };
    const uint16_t n_h[8] = {
        0x8001, 0x7fff, 0xf123, 0x1234,
        0xaaaa, 0x5555, 0x0101, 0xfefe,
    };
    const uint16_t m_h[8] = {
        0x0002, 0xfffe, 0x1357, 0x8000,
        0x2222, 0xdddd, 0x7fff, 0x8001,
    };
    const uint16_t exp_mul_h[8] = {
        0x0002, 0x0002, 0x8be5, 0x0000,
        0x3e94, 0x0b61, 0x7eff, 0xfefe,
    };
    const uint16_t exp_smulh_h[8] = {
        0xffff, 0xffff, 0xfee0, 0xf6e6,
        0xf49f, 0xf49f, 0x0080, 0x0080,
    };
    const uint16_t exp_umulh_h[8] = {
        0x0001, 0x7ffe, 0x1237, 0x091a,
        0x16c1, 0x49f4, 0x0080, 0x7f7f,
    };
    const uint32_t n_s[4] = {
        0x80000001u, 0x7fffffffu, 0xf1234567u, 0x12345678u,
    };
    const uint32_t m_s[4] = {
        0x00000002u, 0xfffffffeu, 0x13579bdfu, 0x80000000u,
    };
    const uint32_t exp_mul_s[4] = {
        0x00000002u, 0x00000002u, 0xa3bfd1b9u, 0x00000000u,
    };
    const uint32_t exp_smulh_s[4] = {
        0xffffffffu, 0xffffffffu, 0xfee08816u, 0xf6e5d4c4u,
    };
    const uint32_t exp_umulh_s[4] = {
        0x00000001u, 0x7ffffffeu, 0x123823f5u, 0x091a2b3cu,
    };
    const uint64_t n_d[2] = {
        0x8000000000000001ull, 0x7fffffffffffffffull,
    };
    const uint64_t m_d[2] = {
        0x0000000000000002ull, 0xfffffffffffffffeull,
    };
    const uint64_t exp_mul_d[2] = {
        0x0000000000000002ull, 0x0000000000000002ull,
    };
    const uint64_t exp_smulh_d[2] = {
        0xffffffffffffffffull, 0xffffffffffffffffull,
    };
    const uint64_t exp_umulh_d[2] = {
        0x0000000000000001ull, 0x7ffffffffffffffeull,
    };
    const uint8_t sq_n_b[16] = {
        0x80, 0x7f, 0x40, 0xc0, 0x20, 0xe0, 0x55, 0xab,
        0x10, 0xf0, 0x33, 0xcd, 0x01, 0xff, 0x7e, 0x82,
    };
    const uint8_t sq_m_b[16] = {
        0x80, 0x7f, 0x40, 0x40, 0xe0, 0x20, 0x55, 0xab,
        0x7f, 0x81, 0xcd, 0x33, 0x80, 0x80, 0x02, 0xfe,
    };
    const uint8_t exp_sqdmulh_b[16] = {
        0x7f, 0x7e, 0x20, 0xe0, 0xf8, 0xf8, 0x38, 0x38,
        0x0f, 0x0f, 0xeb, 0xeb, 0xff, 0x01, 0x01, 0x01,
    };
    const uint8_t exp_sqrdmulh_b[16] = {
        0x7f, 0x7e, 0x20, 0xe0, 0xf8, 0xf8, 0x38, 0x38,
        0x10, 0x10, 0xec, 0xec, 0xff, 0x01, 0x02, 0x02,
    };
    const uint16_t sq_n_h[8] = {
        0x8000, 0x7fff, 0x4000, 0xc000,
        0x2000, 0xe000, 0x5555, 0x0001,
    };
    const uint16_t sq_m_h[8] = {
        0x8000, 0x7fff, 0x4000, 0x4000,
        0xe000, 0x2000, 0x5555, 0x4000,
    };
    const uint16_t exp_sqdmulh_h[8] = {
        0x7fff, 0x7ffe, 0x2000, 0xe000,
        0xf800, 0xf800, 0x38e3, 0x0000,
    };
    const uint16_t exp_sqrdmulh_h[8] = {
        0x7fff, 0x7ffe, 0x2000, 0xe000,
        0xf800, 0xf800, 0x38e3, 0x0001,
    };
    const uint32_t sq_n_s[4] = {
        0x80000000u, 0x7fffffffu, 0x40000000u, 0x00000001u,
    };
    const uint32_t sq_m_s[4] = {
        0x80000000u, 0x7fffffffu, 0x40000000u, 0x40000000u,
    };
    const uint32_t exp_sqdmulh_s[4] = {
        0x7fffffffu, 0x7ffffffeu, 0x20000000u, 0x00000000u,
    };
    const uint32_t exp_sqrdmulh_s[4] = {
        0x7fffffffu, 0x7ffffffeu, 0x20000000u, 0x00000001u,
    };
    const uint64_t sq_n_d[2] = {
        0x8000000000000000ull, 0x0000000000000001ull,
    };
    const uint64_t sq_m_d[2] = {
        0x8000000000000000ull, 0x4000000000000000ull,
    };
    const uint64_t exp_sqdmulh_d[2] = {
        0x7fffffffffffffffull, 0x0000000000000000ull,
    };
    const uint64_t exp_sqrdmulh_d[2] = {
        0x7fffffffffffffffull, 0x0000000000000001ull,
    };

    test_arm64_sve2_mul_run(0x04226020, 0, n_b, m_b, exp_mul_b,
                            sizeof(n_b));
    test_arm64_sve2_mul_run(0x04226820, 0, n_b, m_b, exp_smulh_b,
                            sizeof(n_b));
    test_arm64_sve2_mul_run(0x04226c20, 0, n_b, m_b, exp_umulh_b,
                            sizeof(n_b));
    test_arm64_sve2_mul_run(0x04226420, 0, n_b, m_b, exp_pmul_b,
                            sizeof(n_b));
    test_arm64_sve2_mul_run(0x04626020, 1, n_h, m_h, exp_mul_h,
                            sizeof(n_h));
    test_arm64_sve2_mul_run(0x04626820, 1, n_h, m_h, exp_smulh_h,
                            sizeof(n_h));
    test_arm64_sve2_mul_run(0x04626c20, 1, n_h, m_h, exp_umulh_h,
                            sizeof(n_h));
    test_arm64_sve2_mul_run(0x04a26020, 2, n_s, m_s, exp_mul_s,
                            sizeof(n_s));
    test_arm64_sve2_mul_run(0x04a26820, 2, n_s, m_s, exp_smulh_s,
                            sizeof(n_s));
    test_arm64_sve2_mul_run(0x04a26c20, 2, n_s, m_s, exp_umulh_s,
                            sizeof(n_s));
    test_arm64_sve2_mul_run(0x04e26020, 3, n_d, m_d, exp_mul_d,
                            sizeof(n_d));
    test_arm64_sve2_mul_run(0x04e26820, 3, n_d, m_d, exp_smulh_d,
                            sizeof(n_d));
    test_arm64_sve2_mul_run(0x04e26c20, 3, n_d, m_d, exp_umulh_d,
                            sizeof(n_d));
    test_arm64_sve2_mul_run(0x04227020, 0, sq_n_b, sq_m_b,
                            exp_sqdmulh_b, sizeof(sq_n_b));
    test_arm64_sve2_mul_run(0x04227420, 0, sq_n_b, sq_m_b,
                            exp_sqrdmulh_b, sizeof(sq_n_b));
    test_arm64_sve2_mul_run(0x04627020, 1, sq_n_h, sq_m_h,
                            exp_sqdmulh_h, sizeof(sq_n_h));
    test_arm64_sve2_mul_run(0x04627420, 1, sq_n_h, sq_m_h,
                            exp_sqrdmulh_h, sizeof(sq_n_h));
    test_arm64_sve2_mul_run(0x04a27020, 2, sq_n_s, sq_m_s,
                            exp_sqdmulh_s, sizeof(sq_n_s));
    test_arm64_sve2_mul_run(0x04a27420, 2, sq_n_s, sq_m_s,
                            exp_sqrdmulh_s, sizeof(sq_n_s));
    test_arm64_sve2_mul_run(0x04e27020, 3, sq_n_d, sq_m_d,
                            exp_sqdmulh_d, sizeof(sq_n_d));
    test_arm64_sve2_mul_run(0x04e27420, 3, sq_n_d, sq_m_d,
                            exp_sqrdmulh_d, sizeof(sq_n_d));

    test_arm64_emit32(invalid_code, 0, 0x2518e3e0);
    test_arm64_emit32(invalid_code, 4, 0x04626420);
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)invalid_code, sizeof(invalid_code),
                    UC_CPU_ARM64_MAX);
    test_arm64_mte_enable_sve(uc);
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(invalid_code), 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_close(uc));
}

static void test_arm64_sve2_mul_indexed(void)
{
    const uint16_t n_h[16] = {
        0x8001, 0x7fff, 0x4000, 0xc000, 0x1111, 0xeeee, 0x5555, 0xaaaa,
        0x1234, 0xedcc, 0x0101, 0xfefe, 0x7000, 0x9000, 0x2222, 0xdddd,
    };
    const uint16_t m_h[16] = {
        0x0002, 0x7fff, 0x4000, 0xc000, 0x3333, 0x2000, 0x5555, 0xaaaa,
        0x1111, 0xeeee, 0x0100, 0xff00, 0x6000, 0xe000, 0x4444, 0xbbbb,
    };
    const uint16_t exp_mul_h[16] = {
        0x2000, 0xe000, 0x0000, 0x0000, 0x2000, 0xc000, 0xa000, 0x4000,
        0x8000, 0x8000, 0xe000, 0x4000, 0x0000, 0x0000, 0xc000, 0x6000,
    };
    const uint16_t exp_sqdmulh_h[16] = {
        0xe000, 0x1fff, 0x1000, 0xf000, 0x0444, 0xfbbb, 0x1555, 0xeaaa,
        0xfb73, 0x048d, 0xffbf, 0x0040, 0xe400, 0x1c00, 0xf777, 0x0888,
    };
    const uint16_t exp_sqrdmulh_h[16] = {
        0xe000, 0x2000, 0x1000, 0xf000, 0x0444, 0xfbbc, 0x1555, 0xeaab,
        0xfb73, 0x048d, 0xffc0, 0x0041, 0xe400, 0x1c00, 0xf778, 0x0889,
    };
    const uint32_t n_s[8] = {
        0x80000001u, 0x7fffffffu, 0x40000000u, 0xc0000000u,
        0x11111111u, 0xeeeeeeeeu, 0x00000001u, 0xffffffffu,
    };
    const uint32_t m_s[8] = {
        0x00000002u, 0x7fffffffu, 0x40000000u, 0xc0000000u,
        0x22222222u, 0xddddddddu, 0x40000000u, 0x80000000u,
    };
    const uint32_t exp_mul_s[8] = {
        0x40000000u, 0xc0000000u, 0x00000000u, 0x00000000u,
        0x40000000u, 0x80000000u, 0x40000000u, 0xc0000000u,
    };
    const uint32_t exp_sqdmulh_s[8] = {
        0xc0000000u, 0x3fffffffu, 0x20000000u, 0xe0000000u,
        0x08888888u, 0xf7777777u, 0x00000000u, 0xffffffffu,
    };
    const uint32_t exp_sqrdmulh_s[8] = {
        0xc0000001u, 0x40000000u, 0x20000000u, 0xe0000000u,
        0x08888889u, 0xf7777777u, 0x00000001u, 0x00000000u,
    };
    const uint64_t n_d[4] = {
        0x8000000000000001ull, 0x7fffffffffffffffull,
        0x4000000000000000ull, 0xc000000000000000ull,
    };
    const uint64_t m_d[4] = {
        0x0000000000000002ull, 0x4000000000000000ull,
        0x2222222222222222ull, 0x8000000000000000ull,
    };
    const uint64_t exp_mul_d[4] = {
        0x4000000000000000ull, 0xc000000000000000ull,
        0x0000000000000000ull, 0x0000000000000000ull,
    };
    const uint64_t exp_sqdmulh_d[4] = {
        0xc000000000000000ull, 0x3fffffffffffffffull,
        0xc000000000000000ull, 0x4000000000000000ull,
    };
    const uint64_t exp_sqrdmulh_d[4] = {
        0xc000000000000001ull, 0x4000000000000000ull,
        0xc000000000000000ull, 0x4000000000000000ull,
    };

    test_arm64_sve2_mul_run(0x446af820, 1, n_h, m_h, exp_mul_h,
                            sizeof(n_h));
    test_arm64_sve2_mul_run(0x446af020, 1, n_h, m_h, exp_sqdmulh_h,
                            sizeof(n_h));
    test_arm64_sve2_mul_run(0x446af420, 1, n_h, m_h, exp_sqrdmulh_h,
                            sizeof(n_h));
    test_arm64_sve2_mul_run(0x44b2f820, 2, n_s, m_s, exp_mul_s,
                            sizeof(n_s));
    test_arm64_sve2_mul_run(0x44b2f020, 2, n_s, m_s, exp_sqdmulh_s,
                            sizeof(n_s));
    test_arm64_sve2_mul_run(0x44b2f420, 2, n_s, m_s, exp_sqrdmulh_s,
                            sizeof(n_s));
    test_arm64_sve2_mul_run(0x44f2f820, 3, n_d, m_d, exp_mul_d,
                            sizeof(n_d));
    test_arm64_sve2_mul_run(0x44f2f020, 3, n_d, m_d, exp_sqdmulh_d,
                            sizeof(n_d));
    test_arm64_sve2_mul_run(0x44f2f420, 3, n_d, m_d, exp_sqrdmulh_d,
                            sizeof(n_d));
}

static void test_arm64_sve2_widen_indexed(void)
{
    const uint16_t n_h[16] = {
        0x8001, 0x7fff, 0x4000, 0xc000, 0x1111, 0xeeee, 0x5555, 0xaaaa,
        0x1234, 0xedcc, 0x0101, 0xfefe, 0x7000, 0x9000, 0x2222, 0xdddd,
    };
    const uint16_t m_h[16] = {
        0x0002, 0x7fff, 0x4000, 0xc000, 0x3333, 0x2000, 0x5555, 0xaaaa,
        0x1111, 0xeeee, 0x0100, 0xff00, 0x6000, 0xe000, 0x4444, 0xbbbb,
    };
    const uint32_t n_s[8] = {
        0x80000001u, 0x7fffffffu, 0x40000000u, 0xc0000000u,
        0x11111111u, 0xeeeeeeeeu, 0x00000001u, 0xffffffffu,
    };
    const uint32_t m_s[8] = {
        0x00000002u, 0x7fffffffu, 0x40000000u, 0xc0000000u,
        0x22222222u, 0xddddddddu, 0x40000000u, 0x80000000u,
    };
    const uint32_t exp_smullb_s[8] = {
        0xf0002000u, 0x08000000u, 0x02222000u, 0x0aaaa000u,
        0xfdb98000u, 0xffdfe000u, 0xf2000000u, 0xfbbbc000u,
    };
    const uint32_t exp_sqdmullt_s[8] = {
        0x1fffc000u, 0xf0000000u, 0xfbbb8000u, 0xeaaa8000u,
        0x048d0000u, 0x00408000u, 0x1c000000u, 0x0888c000u,
    };
    const uint64_t exp_umullt_d[4] = {
        0x5fffffff40000000ull, 0x9000000000000000ull,
        0x7777777700000000ull, 0x7fffffff80000000ull,
    };
    const uint32_t init_s[8] = {
        0x00000010u, 0x7ffffff0u, 0x80000020u, 0x12345678u,
        0xfffffff0u, 0x80000010u, 0x7fffff00u, 0x01020304u,
    };
    const uint64_t init_d[4] = {
        0x0000000000000010ull, 0x7ffffffffffffff0ull,
        0x8000000000000020ull, 0x0123456789abcdefull,
    };
    const uint32_t exp_smlalb_s[8] = {
        0xf0002010u, 0x87fffff0u, 0x82222020u, 0x1cdef678u,
        0xfdb97ff0u, 0x7fdfe010u, 0x71ffff00u, 0xfcbdc304u,
    };
    const uint32_t exp_sqdmlalb_s[8] = {
        0xe0004010u, 0x7fffffffu, 0x84444020u, 0x27899678u,
        0xfb72fff0u, 0x80000000u, 0x63ffff00u, 0xf8798304u,
    };
    const uint64_t exp_umlslt_d[4] = {
        0xa0000000c0000010ull, 0xeffffffffffffff0ull,
        0x0888888900000020ull, 0x8123456809abcdefull,
    };
    const uint64_t exp_sqdmlslt_d[4] = {
        0x3fffffff80000010ull, 0x5ffffffffffffff0ull,
        0x8000000000000000ull, 0x0123456689abcdefull,
    };

    test_arm64_sve2_widen_run(0x44b2c820, 2, 1, 1, n_h, sizeof(n_h),
                              m_h, sizeof(m_h), exp_smullb_s,
                              sizeof(exp_smullb_s));
    test_arm64_sve2_widen_run(0x44b2ec20, 2, 1, 1, n_h, sizeof(n_h),
                              m_h, sizeof(m_h), exp_sqdmullt_s,
                              sizeof(exp_sqdmullt_s));
    test_arm64_sve2_widen_run(0x44f2dc20, 3, 2, 2, n_s, sizeof(n_s),
                              m_s, sizeof(m_s), exp_umullt_d,
                              sizeof(exp_umullt_d));
    test_arm64_sve2_narrow_run(0x44b28820, 2, 1, init_s, n_h, m_h,
                               exp_smlalb_s, sizeof(exp_smlalb_s));
    test_arm64_sve2_narrow_run(0x44b22820, 2, 1, init_s, n_h, m_h,
                               exp_sqdmlalb_s, sizeof(exp_sqdmlalb_s));
    test_arm64_sve2_narrow_run(0x44f2bc20, 3, 2, init_d, n_s, m_s,
                               exp_umlslt_d, sizeof(exp_umlslt_d));
    test_arm64_sve2_narrow_run(0x44f23c20, 3, 2, init_d, n_s, m_s,
                               exp_sqdmlslt_d, sizeof(exp_sqdmlslt_d));
}

static void test_arm64_sve2_widen_accumulate(void)
{
    const uint8_t n_b[16] = {
        0x80, 0x7f, 0x40, 0xc0, 0x11, 0xee, 0x55, 0xaa,
        0x10, 0xf0, 0x33, 0xcd, 0x01, 0xff, 0x7e, 0x82,
    };
    const uint8_t m_b[16] = {
        0x02, 0x7f, 0x40, 0xc0, 0x33, 0x20, 0x55, 0xaa,
        0x7f, 0x81, 0xcd, 0x33, 0x80, 0x80, 0x02, 0xfe,
    };
    const uint16_t n_h[16] = {
        0x8001, 0x7fff, 0x4000, 0xc000, 0x1111, 0xeeee, 0x5555, 0xaaaa,
        0x1234, 0xedcc, 0x0101, 0xfefe, 0x7000, 0x9000, 0x2222, 0xdddd,
    };
    const uint16_t m_h[16] = {
        0x0002, 0x7fff, 0x4000, 0xc000, 0x3333, 0x2000, 0x5555, 0xaaaa,
        0x1111, 0xeeee, 0x0100, 0xff00, 0x6000, 0xe000, 0x4444, 0xbbbb,
    };
    const uint32_t n_s[8] = {
        0x80000001u, 0x7fffffffu, 0x40000000u, 0xc0000000u,
        0x11111111u, 0xeeeeeeeeu, 0x00000001u, 0xffffffffu,
    };
    const uint32_t m_s[8] = {
        0x00000002u, 0x7fffffffu, 0x40000000u, 0xc0000000u,
        0x22222222u, 0xddddddddu, 0x40000000u, 0x80000000u,
    };
    const uint16_t init_h[8] = {
        0x0010, 0x7ff0, 0x8020, 0x5678,
        0xfff0, 0x8010, 0x7f00, 0x0304,
    };
    const uint32_t init_s[8] = {
        0x00000010u, 0x7ffffff0u, 0x80000020u, 0x12345678u,
        0xfffffff0u, 0x80000010u, 0x7fffff00u, 0x01020304u,
    };
    const uint64_t init_d[4] = {
        0x0000000000000010ull, 0x7ffffffffffffff0ull,
        0x8000000000000020ull, 0x0123456789abcdefull,
    };
    const uint16_t exp_smlalb_h[8] = {
        0xff10, 0x8ff0, 0x8383, 0x72b1,
        0x07e0, 0x75e7, 0x7e80, 0x0400,
    };
    const uint32_t exp_umlalt_s[8] = {
        0x3fff0011u, 0x0ffffff0u, 0x9dddc020u, 0x83fa8f5cu,
        0xddf0bb98u, 0x7dff0210u, 0xfdffff00u, 0xa3b48273u,
    };
    const uint64_t exp_smlslt_d[4] = {
        0xc00000010000000full, 0x6ffffffffffffff0ull,
        0x7db97530be0246aaull, 0x0123456709abcdefull,
    };
    const uint32_t exp_sqdmlalb_s[8] = {
        0xfffe0014u, 0x7fffffffu, 0x86d392e6u, 0x4b1772eau,
        0x026d52d8u, 0x80020210u, 0x7fffffffu, 0x13363514u,
    };
    const uint32_t exp_sqdmlalbt_s[8] = {
        0x8002000eu, 0x5ffffff0u, 0x84444020u, 0xd9508f5cu,
        0xfd9288a0u, 0x80000000u, 0x63ffff00u, 0xeecd8cb0u,
    };
    const uint64_t exp_sqdmlslt_d[4] = {
        0x800000020000000eull, 0x5ffffffffffffff0ull,
        0x8000000000000000ull, 0x0123456689abcdefull,
    };

    test_arm64_sve2_narrow_run(0x44424020, 1, 0, init_h, n_b, m_b,
                               exp_smlalb_h, sizeof(exp_smlalb_h));
    test_arm64_sve2_narrow_run(0x44824c20, 2, 1, init_s, n_h, m_h,
                               exp_umlalt_s, sizeof(exp_umlalt_s));
    test_arm64_sve2_narrow_run(0x44c25420, 3, 2, init_d, n_s, m_s,
                               exp_smlslt_d, sizeof(exp_smlslt_d));
    test_arm64_sve2_narrow_run(0x44826020, 2, 1, init_s, n_h, m_h,
                               exp_sqdmlalb_s, sizeof(exp_sqdmlalb_s));
    test_arm64_sve2_narrow_run(0x44820820, 2, 1, init_s, n_h, m_h,
                               exp_sqdmlalbt_s, sizeof(exp_sqdmlalbt_s));
    test_arm64_sve2_narrow_run(0x44c26c20, 3, 2, init_d, n_s, m_s,
                               exp_sqdmlslt_d, sizeof(exp_sqdmlslt_d));
}

static void test_arm64_sve2_abs_accumulate(void)
{
    const uint8_t aba_n_b[16] = {
        0x80, 0x7f, 0x40, 0xc0, 0x11, 0xee, 0x55, 0xaa,
        0x10, 0xf0, 0x33, 0xcd, 0x01, 0xff, 0x7e, 0x82,
    };
    const uint8_t aba_m_b[16] = {
        0x02, 0x7f, 0x40, 0xc0, 0x33, 0x20, 0x55, 0xaa,
        0x7f, 0x81, 0xcd, 0x33, 0x80, 0x80, 0x02, 0xfe,
    };
    const uint16_t aba_n_h[8] = {
        0x8001, 0x7fff, 0x4000, 0xc000,
        0x1111, 0xeeee, 0x5555, 0xaaaa,
    };
    const uint16_t aba_m_h[8] = {
        0x0002, 0x7fff, 0x4000, 0xc000,
        0x3333, 0x2000, 0x5555, 0xaaaa,
    };
    const uint32_t aba_n_s[4] = {
        0x80000001u, 0x7fffffffu, 0x40000000u, 0xc0000000u,
    };
    const uint32_t aba_m_s[4] = {
        0x00000002u, 0x7fffffffu, 0x40000000u, 0xc0000000u,
    };
    const uint64_t aba_n_d[2] = {
        0x8000000000000000ull, 0x7fffffffffffffffull,
    };
    const uint64_t aba_m_d[2] = {
        0x7fffffffffffffffull, 0x8000000000000000ull,
    };
    const uint8_t aba_init_b[16] = {
        0x10, 0x80, 0xff, 0x01, 0x7f, 0x00, 0xaa, 0x55,
        0xfe, 0x02, 0x40, 0xc0, 0x11, 0xee, 0x33, 0xcd,
    };
    const uint16_t aba_init_h[8] = {
        0x0010, 0x7ff0, 0x8020, 0x5678,
        0xfff0, 0x8010, 0x7f00, 0x0304,
    };
    const uint32_t aba_init_s[4] = {
        0x00000010u, 0x7ffffff0u, 0x80000020u, 0x12345678u,
    };
    const uint64_t aba_init_d[2] = {
        0x0000000000000010ull, 0x7ffffffffffffff0ull,
    };
    const uint16_t exp_sabalb_h[8] = {
        0x0092, 0x7ff0, 0x8042, 0x5678,
        0x005f, 0x8076, 0x7f81, 0x0380,
    };
    const uint16_t exp_sabalt_h[8] = {
        0x0010, 0x7ff0, 0x8052, 0x5678,
        0x005f, 0x8076, 0x7f7f, 0x0380,
    };
    const uint16_t exp_uabalb_h[8] = {
        0x008e, 0x7ff0, 0x8042, 0x5678,
        0x005f, 0x80aa, 0x7f7f, 0x0380,
    };
    const uint16_t exp_uabalt_h[8] = {
        0x0010, 0x7ff0, 0x80ee, 0x5678,
        0x005f, 0x80aa, 0x7f7f, 0x0380,
    };
    const uint32_t exp_sabalb_s[4] = {
        0x00008011u, 0x7ffffff0u, 0x80002242u, 0x12345678u,
    };
    const uint32_t exp_sabalt_s[4] = {
        0x00000010u, 0x7ffffff0u, 0x80003132u, 0x12345678u,
    };
    const uint32_t exp_uabalb_s[4] = {
        0x0000800fu, 0x7ffffff0u, 0x80002242u, 0x12345678u,
    };
    const uint32_t exp_uabalt_s[4] = {
        0x00000010u, 0x7ffffff0u, 0x8000cf0eu, 0x12345678u,
    };
    const uint64_t exp_sabalb_d[2] = {
        0x0000000080000011ull, 0x7ffffffffffffff0ull,
    };
    const uint64_t exp_sabalt_d[2] = {
        0x0000000000000010ull, 0x7ffffffffffffff0ull,
    };
    const uint64_t exp_uabalb_d[2] = {
        0x000000008000000full, 0x7ffffffffffffff0ull,
    };
    const uint64_t exp_uabalt_d[2] = {
        0x0000000000000010ull, 0x7ffffffffffffff0ull,
    };
    const uint8_t exp_saba_b[16] = {
        0x92, 0x80, 0xff, 0x01, 0xa1, 0x32, 0xaa, 0x55,
        0x6d, 0x71, 0xa6, 0x26, 0x92, 0x6d, 0xaf, 0x49,
    };
    const uint8_t exp_uaba_b[16] = {
        0x8e, 0x80, 0xff, 0x01, 0xa1, 0xce, 0xaa, 0x55,
        0x6d, 0x71, 0xda, 0x5a, 0x90, 0x6d, 0xaf, 0x49,
    };
    const uint16_t exp_saba_h[8] = {
        0x8011, 0x7ff0, 0x8020, 0x5678,
        0x2212, 0xb122, 0x7f00, 0x0304,
    };
    const uint16_t exp_uaba_h[8] = {
        0x800f, 0x7ff0, 0x8020, 0x5678,
        0x2212, 0x4efe, 0x7f00, 0x0304,
    };
    const uint32_t exp_saba_s[4] = {
        0x80000011u, 0x7ffffff0u, 0x80000020u, 0x12345678u,
    };
    const uint32_t exp_uaba_s[4] = {
        0x8000000fu, 0x7ffffff0u, 0x80000020u, 0x12345678u,
    };
    const uint64_t exp_saba_d[2] = {
        0x000000000000000full, 0x7fffffffffffffefull,
    };
    const uint64_t exp_uaba_d[2] = {
        0x0000000000000011ull, 0x7ffffffffffffff1ull,
    };

    test_arm64_sve2_narrow_run(0x4542c020, 1, 0, aba_init_h, aba_n_b,
                               aba_m_b, exp_sabalb_h,
                               sizeof(exp_sabalb_h));
    test_arm64_sve2_narrow_run(0x4542c420, 1, 0, aba_init_h, aba_n_b,
                               aba_m_b, exp_sabalt_h,
                               sizeof(exp_sabalt_h));
    test_arm64_sve2_narrow_run(0x4542c820, 1, 0, aba_init_h, aba_n_b,
                               aba_m_b, exp_uabalb_h,
                               sizeof(exp_uabalb_h));
    test_arm64_sve2_narrow_run(0x4542cc20, 1, 0, aba_init_h, aba_n_b,
                               aba_m_b, exp_uabalt_h,
                               sizeof(exp_uabalt_h));
    test_arm64_sve2_narrow_run(0x4582c020, 2, 1, aba_init_s, aba_n_h,
                               aba_m_h, exp_sabalb_s,
                               sizeof(exp_sabalb_s));
    test_arm64_sve2_narrow_run(0x4582c420, 2, 1, aba_init_s, aba_n_h,
                               aba_m_h, exp_sabalt_s,
                               sizeof(exp_sabalt_s));
    test_arm64_sve2_narrow_run(0x4582c820, 2, 1, aba_init_s, aba_n_h,
                               aba_m_h, exp_uabalb_s,
                               sizeof(exp_uabalb_s));
    test_arm64_sve2_narrow_run(0x4582cc20, 2, 1, aba_init_s, aba_n_h,
                               aba_m_h, exp_uabalt_s,
                               sizeof(exp_uabalt_s));
    test_arm64_sve2_narrow_run(0x45c2c020, 3, 2, aba_init_d, aba_n_s,
                               aba_m_s, exp_sabalb_d,
                               sizeof(exp_sabalb_d));
    test_arm64_sve2_narrow_run(0x45c2c420, 3, 2, aba_init_d, aba_n_s,
                               aba_m_s, exp_sabalt_d,
                               sizeof(exp_sabalt_d));
    test_arm64_sve2_narrow_run(0x45c2c820, 3, 2, aba_init_d, aba_n_s,
                               aba_m_s, exp_uabalb_d,
                               sizeof(exp_uabalb_d));
    test_arm64_sve2_narrow_run(0x45c2cc20, 3, 2, aba_init_d, aba_n_s,
                               aba_m_s, exp_uabalt_d,
                               sizeof(exp_uabalt_d));

    test_arm64_sve2_narrow_run(0x4502f820, 0, 0, aba_init_b, aba_n_b,
                               aba_m_b, exp_saba_b, sizeof(exp_saba_b));
    test_arm64_sve2_narrow_run(0x4542f820, 1, 1, aba_init_h, aba_n_h,
                               aba_m_h, exp_saba_h, sizeof(exp_saba_h));
    test_arm64_sve2_narrow_run(0x4582f820, 2, 2, aba_init_s, aba_n_s,
                               aba_m_s, exp_saba_s, sizeof(exp_saba_s));
    test_arm64_sve2_narrow_run(0x45c2f820, 3, 3, aba_init_d, aba_n_d,
                               aba_m_d, exp_saba_d, sizeof(exp_saba_d));
    test_arm64_sve2_narrow_run(0x4502fc20, 0, 0, aba_init_b, aba_n_b,
                               aba_m_b, exp_uaba_b, sizeof(exp_uaba_b));
    test_arm64_sve2_narrow_run(0x4542fc20, 1, 1, aba_init_h, aba_n_h,
                               aba_m_h, exp_uaba_h, sizeof(exp_uaba_h));
    test_arm64_sve2_narrow_run(0x4582fc20, 2, 2, aba_init_s, aba_n_s,
                               aba_m_s, exp_uaba_s, sizeof(exp_uaba_s));
    test_arm64_sve2_narrow_run(0x45c2fc20, 3, 3, aba_init_d, aba_n_d,
                               aba_m_d, exp_uaba_d, sizeof(exp_uaba_d));
}

static void test_arm64_sve2_cadd_sqcadd(void)
{
    const uint8_t cadd_n_b[16] = {
        0x10, 0x20, 0x7f, 0x7e, 0x80, 0x81, 0xff, 0x01,
        0x40, 0xc0, 0x7f, 0x80, 0x01, 0xfe, 0x55, 0xaa,
    };
    const uint8_t cadd_m_b[16] = {
        0x01, 0x02, 0x7f, 0x01, 0x80, 0x80, 0x7f, 0xff,
        0xc0, 0x40, 0x01, 0x7f, 0xff, 0x02, 0xaa, 0x55,
    };
    const uint16_t cadd_n_h[8] = {
        0x0010, 0x0020, 0x7fff, 0x7ffe,
        0x8000, 0x8001, 0xffff, 0x0001,
    };
    const uint16_t cadd_m_h[8] = {
        0x0001, 0x0002, 0x7fff, 0x0001,
        0x8000, 0x8000, 0x7fff, 0xffff,
    };
    const uint32_t cadd_n_s[4] = {
        0x00000010u, 0x00000020u, 0x7fffffffu, 0x80000000u,
    };
    const uint32_t cadd_m_s[4] = {
        0x00000001u, 0x00000002u, 0x7fffffffu, 0x80000000u,
    };
    const uint64_t cadd_n_d[2] = {
        0x7fffffffffffffffull, 0x8000000000000000ull,
    };
    const uint64_t cadd_m_d[2] = {
        0x0000000000000001ull, 0xffffffffffffffffull,
    };
    const uint8_t exp_cadd90_b[16] = {
        0x0e, 0x21, 0x7e, 0xfd, 0x00, 0x01, 0x00, 0x80,
        0x00, 0x80, 0x00, 0x81, 0xff, 0xfd, 0x00, 0x54,
    };
    const uint8_t exp_cadd270_b[16] = {
        0x12, 0x1f, 0x80, 0xff, 0x00, 0x01, 0xfe, 0x82,
        0x80, 0x00, 0xfe, 0x7f, 0x03, 0xff, 0xaa, 0x00,
    };
    const uint8_t exp_sqcadd90_b[16] = {
        0x0e, 0x21, 0x7e, 0x7f, 0x00, 0x80, 0x00, 0x7f,
        0x00, 0x80, 0x00, 0x81, 0xff, 0xfd, 0x00, 0x80,
    };
    const uint8_t exp_sqcadd270_b[16] = {
        0x12, 0x1f, 0x7f, 0xff, 0x80, 0x01, 0xfe, 0x82,
        0x7f, 0x00, 0x7f, 0x80, 0x03, 0xff, 0x7f, 0x00,
    };
    const uint16_t exp_cadd90_h[8] = {
        0x000e, 0x0021, 0x7ffe, 0xfffd,
        0x0000, 0x0001, 0x0000, 0x8000,
    };
    const uint16_t exp_cadd270_h[8] = {
        0x0012, 0x001f, 0x8000, 0xffff,
        0x0000, 0x0001, 0xfffe, 0x8002,
    };
    const uint16_t exp_sqcadd90_h[8] = {
        0x000e, 0x0021, 0x7ffe, 0x7fff,
        0x0000, 0x8000, 0x0000, 0x7fff,
    };
    const uint16_t exp_sqcadd270_h[8] = {
        0x0012, 0x001f, 0x7fff, 0xffff,
        0x8000, 0x0001, 0xfffe, 0x8002,
    };
    const uint32_t exp_cadd90_s[4] = {
        0x0000000eu, 0x00000021u, 0xffffffffu, 0xffffffffu,
    };
    const uint32_t exp_cadd270_s[4] = {
        0x00000012u, 0x0000001fu, 0xffffffffu, 0x00000001u,
    };
    const uint32_t exp_sqcadd90_s[4] = {
        0x0000000eu, 0x00000021u, 0x7fffffffu, 0xffffffffu,
    };
    const uint32_t exp_sqcadd270_s[4] = {
        0x00000012u, 0x0000001fu, 0xffffffffu, 0x80000000u,
    };
    const uint64_t exp_cadd90_d[2] = {
        0x8000000000000000ull, 0x8000000000000001ull,
    };
    const uint64_t exp_cadd270_d[2] = {
        0x7ffffffffffffffeull, 0x7fffffffffffffffull,
    };
    const uint64_t exp_sqcadd90_d[2] = {
        0x7fffffffffffffffull, 0x8000000000000001ull,
    };
    const uint64_t exp_sqcadd270_d[2] = {
        0x7ffffffffffffffeull, 0x8000000000000000ull,
    };

    test_arm64_sve2_narrow_run(0x4500d840, 0, 0, cadd_n_b, cadd_n_b,
                               cadd_m_b, exp_cadd90_b,
                               sizeof(exp_cadd90_b));
    test_arm64_sve2_narrow_run(0x4500dc40, 0, 0, cadd_n_b, cadd_n_b,
                               cadd_m_b, exp_cadd270_b,
                               sizeof(exp_cadd270_b));
    test_arm64_sve2_narrow_run(0x4501d840, 0, 0, cadd_n_b, cadd_n_b,
                               cadd_m_b, exp_sqcadd90_b,
                               sizeof(exp_sqcadd90_b));
    test_arm64_sve2_narrow_run(0x4501dc40, 0, 0, cadd_n_b, cadd_n_b,
                               cadd_m_b, exp_sqcadd270_b,
                               sizeof(exp_sqcadd270_b));

    test_arm64_sve2_narrow_run(0x4540d840, 1, 1, cadd_n_h, cadd_n_h,
                               cadd_m_h, exp_cadd90_h,
                               sizeof(exp_cadd90_h));
    test_arm64_sve2_narrow_run(0x4540dc40, 1, 1, cadd_n_h, cadd_n_h,
                               cadd_m_h, exp_cadd270_h,
                               sizeof(exp_cadd270_h));
    test_arm64_sve2_narrow_run(0x4541d840, 1, 1, cadd_n_h, cadd_n_h,
                               cadd_m_h, exp_sqcadd90_h,
                               sizeof(exp_sqcadd90_h));
    test_arm64_sve2_narrow_run(0x4541dc40, 1, 1, cadd_n_h, cadd_n_h,
                               cadd_m_h, exp_sqcadd270_h,
                               sizeof(exp_sqcadd270_h));

    test_arm64_sve2_narrow_run(0x4580d840, 2, 2, cadd_n_s, cadd_n_s,
                               cadd_m_s, exp_cadd90_s,
                               sizeof(exp_cadd90_s));
    test_arm64_sve2_narrow_run(0x4580dc40, 2, 2, cadd_n_s, cadd_n_s,
                               cadd_m_s, exp_cadd270_s,
                               sizeof(exp_cadd270_s));
    test_arm64_sve2_narrow_run(0x4581d840, 2, 2, cadd_n_s, cadd_n_s,
                               cadd_m_s, exp_sqcadd90_s,
                               sizeof(exp_sqcadd90_s));
    test_arm64_sve2_narrow_run(0x4581dc40, 2, 2, cadd_n_s, cadd_n_s,
                               cadd_m_s, exp_sqcadd270_s,
                               sizeof(exp_sqcadd270_s));

    test_arm64_sve2_narrow_run(0x45c0d840, 3, 3, cadd_n_d, cadd_n_d,
                               cadd_m_d, exp_cadd90_d,
                               sizeof(exp_cadd90_d));
    test_arm64_sve2_narrow_run(0x45c0dc40, 3, 3, cadd_n_d, cadd_n_d,
                               cadd_m_d, exp_cadd270_d,
                               sizeof(exp_cadd270_d));
    test_arm64_sve2_narrow_run(0x45c1d840, 3, 3, cadd_n_d, cadd_n_d,
                               cadd_m_d, exp_sqcadd90_d,
                               sizeof(exp_sqcadd90_d));
    test_arm64_sve2_narrow_run(0x45c1dc40, 3, 3, cadd_n_d, cadd_n_d,
                               cadd_m_d, exp_sqcadd270_d,
                               sizeof(exp_sqcadd270_d));
}

static void test_arm64_sve2_sqrdmla(void)
{
    const uint8_t sqrd_n_b[16] = {
        0x80, 0x7f, 0x40, 0xc0, 0x11, 0xee, 0x55, 0xaa,
        0x10, 0xf0, 0x33, 0xcd, 0x01, 0xff, 0x7e, 0x82,
    };
    const uint8_t sqrd_m_b[16] = {
        0x80, 0x7f, 0x40, 0xc0, 0x33, 0x20, 0x55, 0xaa,
        0x7f, 0x81, 0xcd, 0x33, 0x80, 0x80, 0x02, 0xfe,
    };
    const uint8_t sqrd_a_b[16] = {
        0x7f, 0x80, 0x10, 0xf0, 0x01, 0xff, 0x55, 0xaa,
        0x40, 0xc0, 0x02, 0xfe, 0x7e, 0x82, 0x00, 0xff,
    };
    const uint16_t sqrd_n_h[16] = {
        0x8001, 0x7fff, 0x4000, 0xc000,
        0x1111, 0xeeee, 0x5555, 0xaaaa,
        0x1234, 0xedcc, 0x0101, 0xfefe,
        0x7000, 0x9000, 0x2222, 0xdddd,
    };
    const uint16_t sqrd_m_h[16] = {
        0x0002, 0x7fff, 0x4000, 0xc000,
        0x3333, 0x2000, 0x5555, 0xaaaa,
        0x1111, 0xeeee, 0x0100, 0xff00,
        0x6000, 0xe000, 0x4444, 0xbbbb,
    };
    const uint16_t sqrd_a_h[16] = {
        0x7fff, 0x8000, 0x0010, 0xfff0,
        0x4000, 0xc000, 0x0001, 0xffff,
        0x1357, 0x2468, 0x9753, 0xeca9,
        0x4000, 0xc000, 0x7fff, 0x8000,
    };
    const uint32_t sqrd_n_s[8] = {
        0x80000001u, 0x7fffffffu, 0x40000000u, 0xc0000000u,
        0x11111111u, 0xeeeeeeeeu, 0x00000001u, 0xffffffffu,
    };
    const uint32_t sqrd_m_s[8] = {
        0x00000002u, 0x7fffffffu, 0x40000000u, 0xc0000000u,
        0x22222222u, 0xddddddddu, 0x40000000u, 0x80000000u,
    };
    const uint32_t sqrd_a_s[8] = {
        0x7fffffffu, 0x80000000u, 0x00000010u, 0xfffffff0u,
        0xfffffff0u, 0x80000010u, 0x7fffff00u, 0x01020304u,
    };
    const uint64_t sqrd_n_d[4] = {
        0x8000000000000001ull, 0x7fffffffffffffffull,
        0x4000000000000000ull, 0xc000000000000000ull,
    };
    const uint64_t sqrd_m_d[4] = {
        0x0000000000000002ull, 0x7fffffffffffffffull,
        0x2222222222222222ull, 0x8000000000000000ull,
    };
    const uint64_t sqrd_a_d[4] = {
        0x7fffffffffffffffull, 0x8000000000000000ull,
        0x8000000000000020ull, 0x0123456789abcdefull,
    };
    const uint8_t exp_sqrdmlah_b[16] = {
        0x7f, 0xfe, 0x30, 0x10, 0x08, 0xfb, 0x7f, 0xe4,
        0x50, 0xd0, 0xee, 0xea, 0x7d, 0x83, 0x02, 0x01,
    };
    const uint8_t exp_sqrdmlsh_b[16] = {
        0xff, 0x80, 0xf0, 0xd0, 0xfa, 0x04, 0x1d, 0x80,
        0x30, 0xb0, 0x16, 0x12, 0x7f, 0x81, 0xfe, 0xfd,
    };
    const uint16_t exp_sqrdmlah_h[8] = {
        0x7ffd, 0xfffe, 0x2010, 0x1ff0,
        0x46d4, 0xbbbc, 0x38e4, 0x38e3,
    };
    const uint16_t exp_sqrdmlsh_h[8] = {
        0x7fff, 0x8000, 0xe010, 0xdff0,
        0x392c, 0xc445, 0xc71e, 0xc71b,
    };
    const uint32_t exp_sqrdmlah_s[4] = {
        0x7ffffffdu, 0xfffffffeu, 0x20000010u, 0x1ffffff0u,
    };
    const uint32_t exp_sqrdmlsh_s[4] = {
        0x7fffffffu, 0x80000000u, 0xe0000010u, 0xdffffff0u,
    };
    const uint64_t exp_sqrdmlah_d[2] = {
        0x7ffffffffffffffdull, 0xfffffffffffffffeull,
    };
    const uint64_t exp_sqrdmlsh_d[2] = {
        0x7fffffffffffffffull, 0x8000000000000000ull,
    };
    const uint16_t exp_sqrdmlah_idx_h[16] = {
        0x5fff, 0xa000, 0x1010, 0xeff0,
        0x4444, 0xbbbc, 0x1556, 0xeaaa,
        0x0eca, 0x28f5, 0x9713, 0xecea,
        0x2400, 0xdc00, 0x7777, 0x8889,
    };
    const uint16_t exp_sqrdmlsh_idx_h[16] = {
        0x7fff, 0x8000, 0xf010, 0x0ff0,
        0x3bbc, 0xc445, 0xeaac, 0x1555,
        0x17e4, 0x1fdb, 0x9793, 0xec69,
        0x5c00, 0xa400, 0x7fff, 0x8000,
    };
    const uint32_t exp_sqrdmlah_idx_s[8] = {
        0x40000000u, 0xc0000000u, 0x20000010u, 0xdffffff0u,
        0x08888879u, 0x80000000u, 0x7fffff01u, 0x01020304u,
    };
    const uint32_t exp_sqrdmlsh_idx_s[8] = {
        0x7fffffffu, 0x80000000u, 0xe0000010u, 0x1ffffff0u,
        0xf7777768u, 0x88888899u, 0x7fffff00u, 0x01020305u,
    };
    const uint64_t exp_sqrdmlah_idx_d[4] = {
        0x0000000000000001ull, 0xfffffffffffffffeull,
        0x8000000000000000ull, 0x4123456789abcdefull,
    };
    const uint64_t exp_sqrdmlsh_idx_d[4] = {
        0x7fffffffffffffffull, 0x8000000000000000ull,
        0xc000000000000020ull, 0xc123456789abcdefull,
    };

    test_arm64_sve2_narrow_run(0x44027020, 0, 0, sqrd_a_b, sqrd_n_b,
                               sqrd_m_b, exp_sqrdmlah_b,
                               sizeof(exp_sqrdmlah_b));
    test_arm64_sve2_narrow_run(0x44027420, 0, 0, sqrd_a_b, sqrd_n_b,
                               sqrd_m_b, exp_sqrdmlsh_b,
                               sizeof(exp_sqrdmlsh_b));
    test_arm64_sve2_narrow_run(0x44427020, 1, 1, sqrd_a_h, sqrd_n_h,
                               sqrd_m_h, exp_sqrdmlah_h,
                               sizeof(exp_sqrdmlah_h));
    test_arm64_sve2_narrow_run(0x44427420, 1, 1, sqrd_a_h, sqrd_n_h,
                               sqrd_m_h, exp_sqrdmlsh_h,
                               sizeof(exp_sqrdmlsh_h));
    test_arm64_sve2_narrow_run(0x44827020, 2, 2, sqrd_a_s, sqrd_n_s,
                               sqrd_m_s, exp_sqrdmlah_s,
                               sizeof(exp_sqrdmlah_s));
    test_arm64_sve2_narrow_run(0x44827420, 2, 2, sqrd_a_s, sqrd_n_s,
                               sqrd_m_s, exp_sqrdmlsh_s,
                               sizeof(exp_sqrdmlsh_s));
    test_arm64_sve2_narrow_run(0x44c27020, 3, 3, sqrd_a_d, sqrd_n_d,
                               sqrd_m_d, exp_sqrdmlah_d,
                               sizeof(exp_sqrdmlah_d));
    test_arm64_sve2_narrow_run(0x44c27420, 3, 3, sqrd_a_d, sqrd_n_d,
                               sqrd_m_d, exp_sqrdmlsh_d,
                               sizeof(exp_sqrdmlsh_d));

    test_arm64_sve2_narrow_run(0x446a1020, 1, 1, sqrd_a_h, sqrd_n_h,
                               sqrd_m_h, exp_sqrdmlah_idx_h,
                               sizeof(exp_sqrdmlah_idx_h));
    test_arm64_sve2_narrow_run(0x446a1420, 1, 1, sqrd_a_h, sqrd_n_h,
                               sqrd_m_h, exp_sqrdmlsh_idx_h,
                               sizeof(exp_sqrdmlsh_idx_h));
    test_arm64_sve2_narrow_run(0x44b21020, 2, 2, sqrd_a_s, sqrd_n_s,
                               sqrd_m_s, exp_sqrdmlah_idx_s,
                               sizeof(exp_sqrdmlah_idx_s));
    test_arm64_sve2_narrow_run(0x44b21420, 2, 2, sqrd_a_s, sqrd_n_s,
                               sqrd_m_s, exp_sqrdmlsh_idx_s,
                               sizeof(exp_sqrdmlsh_idx_s));
    test_arm64_sve2_narrow_run(0x44f21020, 3, 3, sqrd_a_d, sqrd_n_d,
                               sqrd_m_d, exp_sqrdmlah_idx_d,
                               sizeof(exp_sqrdmlah_idx_d));
    test_arm64_sve2_narrow_run(0x44f21420, 3, 3, sqrd_a_d, sqrd_n_d,
                               sqrd_m_d, exp_sqrdmlsh_idx_d,
                               sizeof(exp_sqrdmlsh_idx_d));
}

static void test_arm64_sve2_complex_dot(void)
{
    const uint8_t n_b[16] = {
        0x02, 0x03, 0xfe, 0x05, 0x7f, 0x80, 0x10, 0xf0,
        0x11, 0xee, 0x40, 0xc0, 0x55, 0xaa, 0x01, 0xff,
    };
    const uint8_t m_b[16] = {
        0x04, 0xfd, 0x06, 0xfa, 0x80, 0x7f, 0xf0, 0x10,
        0x22, 0xdd, 0xc0, 0x40, 0xaa, 0x55, 0xff, 0x02,
    };
    const uint8_t a_b[16] = {
        0x10, 0x20, 0x30, 0x40, 0x7f, 0x80, 0x01, 0xff,
        0x55, 0xaa, 0x00, 0x7f, 0x80, 0x01, 0xfe, 0x02,
    };
    const uint16_t n_h[16] = {
        0x0002, 0xfffd, 0x1234, 0xedcc,
        0x7fff, 0x8000, 0x1111, 0xeeee,
        0x4000, 0xc000, 0x0101, 0xfefe,
        0x5555, 0xaaaa, 0x0001, 0xffff,
    };
    const uint16_t m_h[16] = {
        0x0004, 0xfffb, 0x0100, 0xff00,
        0x8000, 0x7fff, 0x2222, 0xdddd,
        0x2000, 0xe000, 0x3333, 0xcccc,
        0xaaaa, 0x5555, 0xffff, 0x0002,
    };
    const uint16_t a_h[16] = {
        0x0010, 0xfff0, 0x1234, 0xedcc,
        0x7fff, 0x8000, 0x0101, 0xfefe,
        0x4000, 0xc000, 0x1357, 0xeca9,
        0x8000, 0x7fff, 0x00ff, 0xff00,
    };
    const uint32_t n_s[8] = {
        0x00000002u, 0xfffffffdu, 0x12345678u, 0xedcba988u,
        0x7fffffffu, 0x80000000u, 0x11111111u, 0xeeeeeeeeu,
    };
    const uint32_t m_s[8] = {
        0x00000004u, 0xfffffffbu, 0x01010101u, 0xfefefeffu,
        0x80000000u, 0x7fffffffu, 0x22222222u, 0xddddddddu,
    };
    const uint32_t a_s[8] = {
        0x00000010u, 0xfffffff0u, 0x12345678u, 0xedcba988u,
        0x7fffffffu, 0x80000000u, 0x01020304u, 0xfefdfcfcu,
    };
    const uint64_t n_d[4] = {
        0x0000000000000002ull, 0xfffffffffffffffdull,
        0x123456789abcdef0ull, 0xedcba98765432110ull,
    };
    const uint64_t m_d[4] = {
        0x0000000000000004ull, 0xfffffffffffffffbull,
        0x0102030405060708ull, 0xfefdfcfbfaf9f8f7ull,
    };
    const uint64_t a_d[4] = {
        0x0000000000000010ull, 0xfffffffffffffff0ull,
        0x123456789abcdef0ull, 0xedcba98765432110ull,
    };
    const uint8_t exp_cmla_b_rot0[16] = {
        0x18, 0x1a, 0x24, 0x4c, 0xff, 0x81, 0x01, 0xff,
        0x97, 0x57, 0x00, 0x7f, 0xf2, 0x3a, 0xfd, 0x04,
    };
    const uint16_t exp_cmla_h_rot90[16] = {
        0x0001, 0xffe4, 0xde34, 0xb9cc,
        0xffff, 0x8000, 0x478b, 0x569a,
        0x4000, 0xc000, 0x78ef, 0x5343,
        0x638e, 0xb8e3, 0x0101, 0xff01,
    };
    const uint32_t exp_cmla_s_rot180[8] = {
        0x00000008u, 0xfffffffau, 0xfd318800u, 0x02ce7800u,
        0xffffffffu, 0x7fffffffu, 0xf2377cc2u, 0x1ed9944fu,
    };
    const uint64_t exp_cmla_d_rot270[4] = {
        0x000000000000001full, 0xfffffffffffffffcull,
        0xd5b249791f194560ull, 0x9f15460f4ee2a890ull,
    };
    const uint8_t exp_sqrdcmlah_b_rot0[16] = {
        0x10, 0x20, 0x30, 0x40, 0x00, 0xfe, 0xff, 0x01,
        0x5a, 0xa5, 0xe0, 0x7f, 0x80, 0x39, 0xfe, 0x02,
    };
    const uint16_t exp_sqrdcmlah_h_rot90[16] = {
        0x0010, 0xfff0, 0x1210, 0xeda8,
        0x7fff, 0x0000, 0xfc74, 0xfa71,
        0x3000, 0xb000, 0x12f0, 0xec42,
        0xb8e4, 0x7fff, 0x00ff, 0xff00,
    };
    const uint32_t exp_sqrdcmlah_s_rot180[8] = {
        0x00000010u, 0xfffffff0u, 0x120fc93eu, 0xedf036c2u,
        0x7fffffffu, 0x80000000u, 0xfc74ed66u, 0x038b129au,
    };
    const uint64_t exp_sqrdcmlah_d_rot270[4] = {
        0x0000000000000010ull, 0xfffffffffffffff0ull,
        0x12590864b23531dcull, 0xedf05b737cbb73fbull,
    };
    const uint32_t exp_cdot_s_rot0[8] = {
        0x00000018u, 0xfffffffeu, 0x123456bcu, 0xedcba996u,
        0x80003f7fu, 0x80003f80u, 0x01020304u, 0xfefdfcfcu,
    };
    const uint64_t exp_cdot_d_rot90[4] = {
        0x0000000000000010ull, 0xfffffffffffffffaull,
        0x1234567897dccc30ull, 0xedcba9876262fbb9ull,
    };
    const uint16_t exp_cmla_idx_h[16] = {
        0x99a7, 0x998a, 0xad18, 0x9ae4,
        0xffff, 0x8000, 0x478b, 0x569a,
        0xc000, 0x0000, 0x155b, 0xedab,
        0x2aac, 0xd555, 0x0101, 0xff01,
    };
    const uint32_t exp_cmla_idx_s[8] = {
        0x03030313u, 0x030302f3u, 0x273724f0u, 0x02ce7800u,
        0xffffffffu, 0x80000000u, 0x42ffbc7au, 0x2feaa560u,
    };
    const uint16_t exp_sqrdcmlah_idx_h[16] = {
        0x0012, 0xffee, 0x2468, 0xdb98,
        0x7fff, 0x8000, 0x1212, 0xeded,
        0x6aab, 0x9556, 0x1402, 0xebfe,
        0xb8e4, 0x471c, 0x0100, 0xfeff,
    };
    const uint32_t exp_sqrdcmlah_idx_s[8] = {
        0x00000010u, 0xfffffff0u, 0x120fc93eu, 0xeda71c4eu,
        0x5ddddddcu, 0x80000000u, 0xfc74ed65u, 0xfa70e75eu,
    };
    const uint32_t exp_cdot_idx_s[8] = {
        0x0000000eu, 0xfffffff1u, 0x12345668u, 0xedcba996u,
        0x8000117fu, 0x7fffee80u, 0x01020304u, 0xfefdfcfcu,
    };
    const uint64_t exp_cdot_idx_d[4] = {
        0x000000000000000eull, 0xffffffffffffffeeull,
        0x12345678987a2698ull, 0xedcba9876785d05dull,
    };

    test_arm64_sve2_narrow_run(0x44022020, 0, 0, a_b, n_b, m_b,
                               exp_cmla_b_rot0, sizeof(exp_cmla_b_rot0));
    test_arm64_sve2_narrow_run(0x44422420, 1, 1, a_h, n_h, m_h,
                               exp_cmla_h_rot90,
                               sizeof(exp_cmla_h_rot90));
    test_arm64_sve2_narrow_run(0x44822820, 2, 2, a_s, n_s, m_s,
                               exp_cmla_s_rot180,
                               sizeof(exp_cmla_s_rot180));
    test_arm64_sve2_narrow_run(0x44c22c20, 3, 3, a_d, n_d, m_d,
                               exp_cmla_d_rot270,
                               sizeof(exp_cmla_d_rot270));

    test_arm64_sve2_narrow_run(0x44023020, 0, 0, a_b, n_b, m_b,
                               exp_sqrdcmlah_b_rot0,
                               sizeof(exp_sqrdcmlah_b_rot0));
    test_arm64_sve2_narrow_run(0x44423420, 1, 1, a_h, n_h, m_h,
                               exp_sqrdcmlah_h_rot90,
                               sizeof(exp_sqrdcmlah_h_rot90));
    test_arm64_sve2_narrow_run(0x44823820, 2, 2, a_s, n_s, m_s,
                               exp_sqrdcmlah_s_rot180,
                               sizeof(exp_sqrdcmlah_s_rot180));
    test_arm64_sve2_narrow_run(0x44c23c20, 3, 3, a_d, n_d, m_d,
                               exp_sqrdcmlah_d_rot270,
                               sizeof(exp_sqrdcmlah_d_rot270));

    test_arm64_sve2_narrow_run(0x44821020, 2, 2, a_s, n_s, m_s,
                               exp_cdot_s_rot0, sizeof(exp_cdot_s_rot0));
    test_arm64_sve2_narrow_run(0x44c21420, 3, 3, a_d, n_d, m_d,
                               exp_cdot_d_rot90, sizeof(exp_cdot_d_rot90));

    test_arm64_sve2_narrow_run(0x44ba6420, 1, 1, a_h, n_h, m_h,
                               exp_cmla_idx_h, sizeof(exp_cmla_idx_h));
    test_arm64_sve2_narrow_run(0x44f26c20, 2, 2, a_s, n_s, m_s,
                               exp_cmla_idx_s, sizeof(exp_cmla_idx_s));
    test_arm64_sve2_narrow_run(0x44b27820, 1, 1, a_h, n_h, m_h,
                               exp_sqrdcmlah_idx_h,
                               sizeof(exp_sqrdcmlah_idx_h));
    test_arm64_sve2_narrow_run(0x44f27420, 2, 2, a_s, n_s, m_s,
                               exp_sqrdcmlah_idx_s,
                               sizeof(exp_sqrdcmlah_idx_s));
    test_arm64_sve2_narrow_run(0x44ba4020, 2, 2, a_s, n_s, m_s,
                               exp_cdot_idx_s, sizeof(exp_cdot_idx_s));
    test_arm64_sve2_narrow_run(0x44f24c20, 3, 3, a_d, n_d, m_d,
                               exp_cdot_idx_d, sizeof(exp_cdot_idx_d));
}

static void test_arm64_sve_i8mm(void)
{
    uc_engine *uc;
    uint8_t invalid_code[8];
    const uint8_t initial[32] = {
        0x10, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff,
        0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff,
        0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    };
    const uint8_t n[32] = {
        0x01, 0x7f, 0x80, 0xff, 0x10, 0xf0, 0x22, 0xdd,
        0x40, 0xc0, 0x55, 0xaa, 0x7e, 0x82, 0x01, 0xff,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x7f, 0x80, 0x01, 0xff, 0xaa, 0x55, 0x10, 0xf0,
    };
    const uint8_t m[32] = {
        0x02, 0xfe, 0x03, 0xfd, 0x80, 0x7f, 0x04, 0xfc,
        0x11, 0xef, 0x66, 0x99, 0x08, 0xf8, 0x01, 0xff,
        0x01, 0x02, 0x03, 0x04, 0x80, 0x81, 0x7e, 0x7f,
        0x11, 0x22, 0xdd, 0xee, 0xff, 0x00, 0x55, 0xaa,
    };
    const uint8_t exp_usdot[32] = {
        0x97, 0xfd, 0xff, 0xff, 0x14, 0x6c, 0x00, 0x00,
        0x78, 0xd5, 0xff, 0xff, 0x61, 0xfe, 0xff, 0xff,
        0x5d, 0x03, 0x00, 0x00, 0x12, 0x3a, 0x00, 0x00,
        0x61, 0x07, 0x00, 0x00, 0x0a, 0xb4, 0xff, 0xff,
    };
    const uint8_t exp_sudot_idx[32] = {
        0x19, 0x43, 0x00, 0x00, 0xb1, 0xea, 0xff, 0xff,
        0x78, 0xb7, 0xff, 0xff, 0x08, 0x92, 0xff, 0xff,
        0xe9, 0xc1, 0x00, 0x00, 0xfa, 0xc3, 0xff, 0xff,
        0x61, 0xf7, 0xff, 0xff, 0x88, 0x04, 0x00, 0x00,
    };
    const uint8_t exp_usdot_idx[32] = {
        0x19, 0xc4, 0xff, 0xff, 0xb1, 0xa5, 0xff, 0xff,
        0x78, 0xd5, 0xff, 0xff, 0x08, 0x99, 0xff, 0xff,
        0xe9, 0xf3, 0xff, 0xff, 0xfa, 0xf3, 0xff, 0xff,
        0x61, 0x07, 0x00, 0x00, 0x88, 0x03, 0x00, 0x00,
    };
    const uint8_t exp_smmla[32] = {
        0xbb, 0xee, 0xff, 0xff, 0x3e, 0xc6, 0xff, 0xff,
        0x07, 0x86, 0xff, 0xff, 0x59, 0x54, 0x00, 0x00,
        0x6d, 0x3f, 0x00, 0x00, 0x66, 0xee, 0xff, 0xff,
        0x46, 0x00, 0x00, 0x00, 0x68, 0x02, 0x00, 0x00,
    };
    const uint8_t exp_ummla[32] = {
        0xbb, 0xd4, 0x02, 0x00, 0x3e, 0x07, 0x03, 0x00,
        0x07, 0xe3, 0x02, 0x00, 0x59, 0xbe, 0x02, 0x00,
        0x6d, 0x93, 0x01, 0x00, 0x66, 0x44, 0x02, 0x00,
        0x46, 0x04, 0x01, 0x00, 0x68, 0x55, 0x02, 0x00,
    };
    const uint8_t exp_usmmla[32] = {
        0xbb, 0x69, 0x00, 0x00, 0x3e, 0xbc, 0xff, 0xff,
        0x07, 0xfc, 0xff, 0xff, 0x59, 0xd3, 0xff, 0xff,
        0x6d, 0x3d, 0x00, 0x00, 0x66, 0xec, 0xff, 0xff,
        0x46, 0x05, 0x00, 0x00, 0x68, 0xbb, 0xff, 0xff,
    };

    test_arm64_sve2_narrow_run(0x44827820, 2, 2, initial, n, m,
                               exp_usdot, sizeof(exp_usdot));
    test_arm64_sve2_narrow_run(0x44b21c20, 2, 2, initial, n, m,
                               exp_sudot_idx, sizeof(exp_sudot_idx));
    test_arm64_sve2_narrow_run(0x44b21820, 2, 2, initial, n, m,
                               exp_usdot_idx, sizeof(exp_usdot_idx));
    test_arm64_sve2_narrow_run(0x45029820, 2, 2, initial, n, m,
                               exp_smmla, sizeof(exp_smmla));
    test_arm64_sve2_narrow_run(0x45c29820, 2, 2, initial, n, m,
                               exp_ummla, sizeof(exp_ummla));
    test_arm64_sve2_narrow_run(0x45829820, 2, 2, initial, n, m,
                               exp_usmmla, sizeof(exp_usmmla));

    test_arm64_emit32(invalid_code, 0, 0x2518e3e0);
    test_arm64_emit32(invalid_code, 4, 0x44427820);
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)invalid_code, sizeof(invalid_code),
                    UC_CPU_ARM64_MAX);
    test_arm64_mte_enable_sve(uc);
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(invalid_code), 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_close(uc));
}

static void test_arm64_sve_bf16(void)
{
    const uint32_t ptrue_b = 0x2518e3e0;
    const uint16_t init_h[8] = {
        0x1110, 0xaaaa, 0x1111, 0xbbbb,
        0x1112, 0xcccc, 0x1113, 0xdddd,
    };
    const uint32_t source_s[4] = {
        0x3f800000u, 0xc0000000u, 0x40400000u, 0x40800000u,
    };
    const uint32_t exp_bfcvt[4] = {
        0x00003f80u, 0x0000c000u, 0x00004040u, 0x00004080u,
    };
    const uint16_t exp_bfcvtnt[8] = {
        0x1110, 0x3f80, 0x1111, 0xc000,
        0x1112, 0x4040, 0x1113, 0x4080,
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

    test_arm64_sve2_fp_convert_run(ptrue_b, 0x658aa020, 2, 2,
                                   init_s, source_s, exp_bfcvt,
                                   sizeof(exp_bfcvt));
    test_arm64_sve2_fp_convert_run(ptrue_b, 0x648aa020, 1, 2,
                                   init_h, source_s, exp_bfcvtnt,
                                   sizeof(exp_bfcvtnt));
    test_arm64_sve2_narrow_run(0x64628020, 2, 2, init_s, n_pair,
                               m_pair, exp_bfdot, sizeof(exp_bfdot));
    test_arm64_sve2_narrow_run(0x64624020, 2, 2, init_s, n_pair,
                               m_pair, exp_bfdot_idx,
                               sizeof(exp_bfdot_idx));
    test_arm64_sve2_narrow_run(0x6462e420, 2, 2, init_s, n_mmla,
                               m_mmla, exp_bfmmla, sizeof(exp_bfmmla));
    test_arm64_sve2_narrow_run(0x64e28020, 2, 1, init_s, n_long,
                               m_long, exp_bfmlalb, sizeof(exp_bfmlalb));
    test_arm64_sve2_narrow_run(0x64e28420, 2, 1, init_s, n_long,
                               m_long, exp_bfmlalt, sizeof(exp_bfmlalt));
    test_arm64_sve2_narrow_run(0x64e24020, 2, 1, init_s, n_long,
                               m_long, exp_bfmlalb_idx,
                               sizeof(exp_bfmlalb_idx));
    test_arm64_sve2_narrow_run(0x64e24420, 2, 1, init_s, n_long,
                               m_long, exp_bfmlalt_idx,
                               sizeof(exp_bfmlalt_idx));

    test_arm64_i8mm_expect_exception(0x658aa020, UC_CPU_ARM64_A72);
}

static void test_arm64_sve_qperm_run(uint32_t insn, uint64_t zcr_len,
                                     const uint8_t *n, const uint8_t *m,
                                     const uint8_t *expected, size_t size)
{
    uc_engine *uc;
    uint8_t code[20];
    uint8_t got[64];
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40100;
    uint64_t x6 = 0x40200;
    size_t i;

    test_arm64_emit32(code, 0, 0x2518e3e0);
    test_arm64_emit32(code, 4, 0xa400a081);
    test_arm64_emit32(code, 8, 0xa400a0a2);
    test_arm64_emit32(code, 12, insn);
    test_arm64_emit32(code, 16, 0xe400e0c0);

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n, size));
    OK(uc_mem_write(uc, x5, m, size));
    test_arm64_mte_enable_sve_vq(uc, zcr_len);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x6, got, size));
    for (i = 0; i < size; i++) {
        TEST_CHECK(got[i] == expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve_qperm_expect_exception(uint32_t insn,
                                                  uint64_t zcr_len)
{
    uc_engine *uc;
    uint8_t code[8];

    test_arm64_emit32(code, 0, 0x2518e3e0);
    test_arm64_emit32(code, 4, insn);
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    test_arm64_mte_enable_sve_vq(uc, zcr_len);
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code),
                            0, 0) == UC_ERR_EXCEPTION);
    OK(uc_close(uc));
}

static void test_arm64_sve_f32mm_f64mm(void)
{
    const uint32_t init_s[8] = {
        0x41200000u, 0x41a00000u, 0x41f00000u, 0x42200000u,
        0x3f800000u, 0x40000000u, 0x40400000u, 0x40800000u,
    };
    const uint32_t n_s[8] = {
        0x3f800000u, 0x40000000u, 0x40400000u, 0x40800000u,
        0xbf800000u, 0x3f000000u, 0x40000000u, 0xbf000000u,
    };
    const uint32_t m_s[8] = {
        0x40a00000u, 0x40c00000u, 0x40e00000u, 0x41000000u,
        0x40800000u, 0xc0000000u, 0x3f800000u, 0x40400000u,
    };
    const uint32_t exp_s[8] = {
        0x41d80000u, 0x422c0000u, 0x428a0000u, 0x42ba0000u,
        0xc0800000u, 0x40200000u, 0x41400000u, 0x40900000u,
    };
    const uint64_t init_d[4] = {
        0x4024000000000000ull, 0x4034000000000000ull,
        0x403e000000000000ull, 0x4044000000000000ull,
    };
    const uint64_t n_d[4] = {
        0x3ff0000000000000ull, 0x4000000000000000ull,
        0x4008000000000000ull, 0x4010000000000000ull,
    };
    const uint64_t m_d[4] = {
        0x4014000000000000ull, 0x4018000000000000ull,
        0x401c000000000000ull, 0x4020000000000000ull,
    };
    const uint64_t exp_d[4] = {
        0x403b000000000000ull, 0x4045800000000000ull,
        0x4051400000000000ull, 0x4057400000000000ull,
    };
    uint8_t n_q[64];
    uint8_t m_q[64];
    uint8_t exp_q[64];
    int q, i;

    test_arm64_sve2_narrow_run(0x64a2e420, 2, 2, init_s, n_s, m_s,
                               exp_s, sizeof(exp_s));
    test_arm64_sve2_narrow_run(0x64e2e420, 3, 3, init_d, n_d, m_d,
                               exp_d, sizeof(exp_d));

    for (q = 0; q < 4; q++) {
        for (i = 0; i < 16; i++) {
            n_q[q * 16 + i] = 0x10 + q * 0x10 + i;
            m_q[q * 16 + i] = 0x80 + q * 0x10 + i;
        }
    }

    memcpy(exp_q, n_q + 0x00, 16);
    memcpy(exp_q + 0x10, m_q + 0x00, 16);
    memcpy(exp_q + 0x20, n_q + 0x10, 16);
    memcpy(exp_q + 0x30, m_q + 0x10, 16);
    test_arm64_sve_qperm_run(0x05a20020, 3, n_q, m_q, exp_q, 64);

    memcpy(exp_q, n_q + 0x20, 16);
    memcpy(exp_q + 0x10, m_q + 0x20, 16);
    memcpy(exp_q + 0x20, n_q + 0x30, 16);
    memcpy(exp_q + 0x30, m_q + 0x30, 16);
    test_arm64_sve_qperm_run(0x05a20420, 3, n_q, m_q, exp_q, 64);

    memcpy(exp_q, n_q + 0x00, 16);
    memcpy(exp_q + 0x10, n_q + 0x20, 16);
    memcpy(exp_q + 0x20, m_q + 0x00, 16);
    memcpy(exp_q + 0x30, m_q + 0x20, 16);
    test_arm64_sve_qperm_run(0x05a20820, 3, n_q, m_q, exp_q, 64);

    memcpy(exp_q, n_q + 0x10, 16);
    memcpy(exp_q + 0x10, n_q + 0x30, 16);
    memcpy(exp_q + 0x20, m_q + 0x10, 16);
    memcpy(exp_q + 0x30, m_q + 0x30, 16);
    test_arm64_sve_qperm_run(0x05a20c20, 3, n_q, m_q, exp_q, 64);

    memcpy(exp_q, n_q + 0x00, 16);
    memcpy(exp_q + 0x10, m_q + 0x00, 16);
    memcpy(exp_q + 0x20, n_q + 0x20, 16);
    memcpy(exp_q + 0x30, m_q + 0x20, 16);
    test_arm64_sve_qperm_run(0x05a21820, 3, n_q, m_q, exp_q, 64);

    memcpy(exp_q, n_q + 0x10, 16);
    memcpy(exp_q + 0x10, m_q + 0x10, 16);
    memcpy(exp_q + 0x20, n_q + 0x30, 16);
    memcpy(exp_q + 0x30, m_q + 0x30, 16);
    test_arm64_sve_qperm_run(0x05a21c20, 3, n_q, m_q, exp_q, 64);

    memset(exp_q, 0, sizeof(exp_q));
    memcpy(exp_q, n_q + 0x10, 16);
    memcpy(exp_q + 0x10, m_q + 0x10, 16);
    test_arm64_sve_qperm_run(0x05a20420, 2, n_q, m_q, exp_q, 48);

    memset(exp_q, 0, sizeof(exp_q));
    memcpy(exp_q, n_q + 0x00, 16);
    memcpy(exp_q + 0x10, n_q + 0x20, 16);
    memcpy(exp_q + 0x20, m_q + 0x10, 16);
    test_arm64_sve_qperm_run(0x05a20820, 2, n_q, m_q, exp_q, 48);

    memset(exp_q, 0, sizeof(exp_q));
    memcpy(exp_q, n_q + 0x10, 16);
    memcpy(exp_q + 0x10, m_q + 0x10, 16);
    test_arm64_sve_qperm_run(0x05a21c20, 2, n_q, m_q, exp_q, 48);

    test_arm64_sve_qperm_expect_exception(0x05a20020, 0);
    test_arm64_i8mm_expect_exception(0x64a2e420, UC_CPU_ARM64_A72);
    test_arm64_i8mm_expect_exception(0x64e2e420, UC_CPU_ARM64_A72);
    test_arm64_i8mm_expect_exception(0x05a20020, UC_CPU_ARM64_A72);
}

static void test_arm64_sme_foundation(void)
{
    const uint32_t SVCR[5] = { 3, 3, 4, 2, 2 };
    const uint32_t SMCR_EL1[5] = { 3, 0, 1, 2, 6 };
    const uint32_t TPIDR2_EL0[5] = { 3, 3, 13, 0, 5 };
    uint8_t code[52];
    uc_engine *uc;
    uint64_t x0;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
    uint64_t x4;
    uint64_t x5;
    uint64_t x6;
    uint64_t value;

    test_arm64_emit32(code, 0, 0xd51812c4);  /* msr smcr_el1, x4 */
    test_arm64_emit32(code, 4, 0xd53812c0);  /* mrs x0, smcr_el1 */
    test_arm64_emit32(code, 8, 0xd51b4244);  /* msr svcr, x4 */
    test_arm64_emit32(code, 12, 0xd53b4241); /* mrs x1, svcr */
    test_arm64_emit32(code, 16, 0xd503467f); /* smstop smza */
    test_arm64_emit32(code, 20, 0xd503437f); /* smstart sm */
    test_arm64_emit32(code, 24, 0xd53b4242); /* mrs x2, svcr */
    test_arm64_emit32(code, 28, 0xd503457f); /* smstart za */
    test_arm64_emit32(code, 32, 0xd53b4243); /* mrs x3, svcr */
    test_arm64_emit32(code, 36, 0xd503427f); /* smstop sm */
    test_arm64_emit32(code, 40, 0xd53b4245); /* mrs x5, svcr */
    test_arm64_emit32(code, 44, 0xd503447f); /* smstop za */
    test_arm64_emit32(code, 48, 0xd53b4246); /* mrs x6, svcr */

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, SVCR) == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, SMCR_EL1) == 0x80000001);
    value = 0x123456789abcdef0ULL;
    test_arm64_pauth_cp_reg_write(uc, TPIDR2_EL0, value);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TPIDR2_EL0) == value);
    x4 = 0xffffffffffffffffULL;
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &x0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_read(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_read(uc, UC_ARM64_REG_X6, &x6));
    TEST_CHECK(x0 == 0x8000000f);
    TEST_CHECK(x1 == 3);
    TEST_CHECK(x2 == 1);
    TEST_CHECK(x3 == 3);
    TEST_CHECK(x5 == 2);
    TEST_CHECK(x6 == 0);
    OK(uc_close(uc));

    test_arm64_i8mm_expect_exception(0xd503437f, UC_CPU_ARM64_A72);
}

static void test_arm64_sme_svlength(void)
{
    const uint32_t SVCR[5] = { 3, 3, 4, 2, 2 };
    const uint32_t SMCR_EL1[5] = { 3, 0, 1, 2, 6 };
    const uint32_t SMCR_EL2[5] = { 3, 4, 1, 2, 6 };
    const uint32_t SMCR_EL3[5] = { 3, 6, 1, 2, 6 };
    uint8_t code[28];
    uint8_t no_fa64_code[20];
    uc_engine *uc;
    uint64_t x0;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
    uint64_t x4;
    uint64_t x5;
    uint64_t x6;
    uint64_t pc;
    uint64_t smcr_el1;
    uint64_t svcr;
    uc_err err;

    test_arm64_emit32(code, 0, 0xd51812c4);  /* msr smcr_el1, x4 */
    test_arm64_emit32(code, 4, 0x04bf5820);  /* rdsvl x0, #1 */
    test_arm64_emit32(code, 8, 0x04bf5fe1);  /* rdsvl x1, #-1 */
    test_arm64_emit32(code, 12, 0x04235842); /* addsvl x2, x3, #2 */
    test_arm64_emit32(code, 16, 0x04635845); /* addspl x5, x3, #2 */
    test_arm64_emit32(code, 20, 0xd503437f); /* smstart sm */
    test_arm64_emit32(code, 24, 0x04bf5026); /* rdvl x6, #1 */

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    x3 = 0x1000;
    x4 = 0x80000003;
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, x4);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, x4);
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    OK(uc_reg_read(uc, UC_ARM64_REG_PC, &pc));
    smcr_el1 = test_arm64_pauth_cp_reg_read(uc, SMCR_EL1);
    svcr = test_arm64_pauth_cp_reg_read(uc, SVCR);
    TEST_CHECK_(err == UC_ERR_OK,
                "err=%u pc=0x%llx smcr_el1=0x%llx svcr=0x%llx",
                (unsigned)err, (unsigned long long)pc,
                (unsigned long long)smcr_el1, (unsigned long long)svcr);
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &x0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_read(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_read(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_read(uc, UC_ARM64_REG_X6, &x6));
    TEST_CHECK(x0 == 64);
    TEST_CHECK(x1 == (uint64_t)-64);
    TEST_CHECK(x2 == 0x1080);
    TEST_CHECK(x5 == 0x1010);
    TEST_CHECK_(x6 == 64, "x6 = 0x%llx", (unsigned long long)x6);
    OK(uc_close(uc));

    test_arm64_emit32(no_fa64_code, 0, 0xd51812c4);  /* msr smcr_el1, x4 */
    test_arm64_emit32(no_fa64_code, 4, 0xd503437f);  /* smstart sm */
    test_arm64_emit32(no_fa64_code, 8, 0x04bf5020);  /* rdvl x0, #1 */
    test_arm64_emit32(no_fa64_code, 12, 0x0e013c01); /* umov w1, v0.b[0] */
    test_arm64_emit32(no_fa64_code, 16, 0x4e010c00); /* dup v0.16b, w0 */

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)no_fa64_code, sizeof(no_fa64_code),
                    UC_CPU_ARM64_MAX);
    x4 = 3;
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, x4);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, x4);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    err = uc_emu_start(uc, code_start,
                       code_start + sizeof(no_fa64_code), 0, 0);
    OK(uc_reg_read(uc, UC_ARM64_REG_PC, &pc));
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &x0));
    TEST_CHECK_(err == UC_ERR_EXCEPTION, "err=%u pc=0x%llx",
                (unsigned)err, (unsigned long long)pc);
    TEST_CHECK(x0 == 64);
    TEST_CHECK(pc == code_start + 16);
    OK(uc_close(uc));

    test_arm64_i8mm_expect_exception(0x04bf5820, UC_CPU_ARM64_A72);
}

static void test_arm64_sme_nonstreaming_sve_ffr_one(uint32_t insn)
{
    const uint32_t CPACR_EL1[5] = { 3, 0, 1, 0, 2 };
    const uint32_t SMCR_EL2[5] = { 3, 4, 1, 2, 6 };
    const uint32_t SMCR_EL3[5] = { 3, 6, 1, 2, 6 };
    uint8_t code[4];
    uint8_t streaming_code[12];
    uc_engine *uc;
    uint64_t x4;
    uint64_t pc;
    uc_err err;

    test_arm64_emit32(code, 0, insn);
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    test_arm64_mte_enable_sve(uc);
    test_arm64_pauth_cp_reg_write(uc, CPACR_EL1,
                                  (3ULL << 16) | (3ULL << 20) |
                                  (3ULL << 24));
    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    TEST_CHECK_(err == UC_ERR_OK, "insn=0x%x err=%u", insn, (unsigned)err);
    OK(uc_close(uc));

    test_arm64_emit32(streaming_code, 0, 0xd51812c4);  /* msr smcr_el1, x4 */
    test_arm64_emit32(streaming_code, 4, 0xd503437f);  /* smstart sm */
    test_arm64_emit32(streaming_code, 8, insn);

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)streaming_code, sizeof(streaming_code),
                    UC_CPU_ARM64_MAX);
    test_arm64_mte_enable_sve(uc);
    test_arm64_pauth_cp_reg_write(uc, CPACR_EL1,
                                  (3ULL << 16) | (3ULL << 20) |
                                  (3ULL << 24));
    x4 = 3;
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, x4);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, x4);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    err = uc_emu_start(uc, code_start, code_start + sizeof(streaming_code),
                       0, 0);
    OK(uc_reg_read(uc, UC_ARM64_REG_PC, &pc));
    TEST_CHECK_(err == UC_ERR_EXCEPTION, "insn=0x%x err=%u pc=0x%llx",
                insn, (unsigned)err, (unsigned long long)pc);
    TEST_CHECK_(pc == code_start + 8,
                "insn=0x%x pc=0x%llx", insn, (unsigned long long)pc);
    OK(uc_close(uc));
}

static void test_arm64_sme_nonstreaming_sve_ffr(void)
{
    test_arm64_sme_nonstreaming_sve_ffr_one(0x252c9000); /* setffr */
    test_arm64_sme_nonstreaming_sve_ffr_one(0x2518f000); /* rdffr p0.b,p0/z */
    test_arm64_sme_nonstreaming_sve_ffr_one(0x2519f000); /* rdffr p0.b */
    test_arm64_sme_nonstreaming_sve_ffr_one(0x25289000); /* wrffr p0.b */
}

static void test_arm64_sme_nonstreaming_sve_setup(uc_engine *uc,
                                                  uint64_t zcr_len,
                                                  bool memory)
{
    const uint32_t CPACR_EL1[5] = { 3, 0, 1, 0, 2 };
    uint8_t mem[0x400];
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0;
    uint64_t x6 = 0x40000;
    uint64_t x7 = 8;
    uint64_t x8 = 0x40100;
    uint64_t x9 = 0x40200;
    uint64_t x10 = 3;
    int i;

    test_arm64_mte_enable_sve_vq(uc, zcr_len);
    test_arm64_pauth_cp_reg_write(uc, CPACR_EL1,
                                  (3ULL << 16) | (3ULL << 20) |
                                  (3ULL << 24));

    if (memory) {
        for (i = 0; i < (int)sizeof(mem); i++) {
            mem[i] = (uint8_t)i;
        }
        OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
        OK(uc_mem_write(uc, 0x40000, mem, sizeof(mem)));
    }

    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_reg_write(uc, UC_ARM64_REG_X9, &x9));
    OK(uc_reg_write(uc, UC_ARM64_REG_X10, &x10));
}

static void test_arm64_sme_nonstreaming_sve_one(const char *name,
                                                uint32_t insn,
                                                uint64_t zcr_len,
                                                bool ptrue, bool memory,
                                                bool streaming_ok)
{
    const uint32_t SMCR_EL2[5] = { 3, 4, 1, 2, 6 };
    const uint32_t SMCR_EL3[5] = { 3, 6, 1, 2, 6 };
    uint8_t code[8];
    uint8_t streaming_code[20];
    uint64_t smcr = 3;
    uint64_t pc;
    size_t off = 0;
    size_t target_off;
    uc_engine *uc;
    uc_err err;

    if (ptrue) {
        test_arm64_emit32(code, off, 0x2518e3e0); /* ptrue p0.b */
        off += 4;
    }
    test_arm64_emit32(code, off, insn);
    off += 4;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    off, UC_CPU_ARM64_MAX);
    test_arm64_sme_nonstreaming_sve_setup(uc, zcr_len, memory);
    err = uc_emu_start(uc, code_start, code_start + off, 0, 0);
    TEST_CHECK_(err == UC_ERR_OK, "%s insn=0x%x err=%u", name, insn,
                (unsigned)err);
    OK(uc_close(uc));

    off = 0;
    if (ptrue) {
        test_arm64_emit32(streaming_code, off, 0x2518e3e0); /* ptrue p0.b */
        off += 4;
    }
    test_arm64_emit32(streaming_code, off, 0xd51812ca); /* msr smcr_el1,x10 */
    off += 4;
    test_arm64_emit32(streaming_code, off, 0xd503437f); /* smstart sm */
    off += 4;
    target_off = off;
    test_arm64_emit32(streaming_code, off, insn);
    off += 4;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)streaming_code, off, UC_CPU_ARM64_MAX);
    test_arm64_sme_nonstreaming_sve_setup(uc, zcr_len, memory);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
    err = uc_emu_start(uc, code_start, code_start + off, 0, 0);
    OK(uc_reg_read(uc, UC_ARM64_REG_PC, &pc));
    if (streaming_ok) {
        TEST_CHECK_(err == UC_ERR_OK, "%s insn=0x%x err=%u pc=0x%llx",
                    name, insn, (unsigned)err, (unsigned long long)pc);
    } else {
        TEST_CHECK_(err == UC_ERR_EXCEPTION,
                    "%s insn=0x%x err=%u pc=0x%llx", name, insn,
                    (unsigned)err, (unsigned long long)pc);
        TEST_CHECK_(pc == code_start + target_off,
                    "%s insn=0x%x pc=0x%llx", name, insn,
                    (unsigned long long)pc);
    }
    OK(uc_close(uc));
}

static void test_arm64_sme_nonstreaming_sve_misc(void)
{
    static const struct {
        const char *name;
        uint32_t insn;
        uint64_t zcr_len;
        bool ptrue;
        bool memory;
    } nonstreaming[] = {
        { "bext", 0x4502b020, 0, true, false },
        { "adr_s32", 0x0420a000, 0, false, false },
        { "fexpa_s", 0x04a0b800, 0, false, false },
        { "ftssel_s", 0x04a0b000, 0, false, false },
        { "zip1_q", 0x05a20020, 3, false, false },
        { "compact_s", 0x05a18000, 0, true, false },
        { "histcnt_s", 0x45a2c020, 0, true, false },
        { "histseg", 0x4522a020, 0, false, false },
        { "aese", 0x4522e040, 0, false, false },
        { "smmla", 0x45029820, 0, false, false },
        { "bfmmla", 0x6462e420, 0, false, false },
        { "fmmla_s", 0x64a2e420, 0, false, false },
        { "ftmad_s", 0x65908000, 0, false, false },
        { "fadda_s", 0x65982000, 0, true, false },
        { "ftsmul_s", 0x65800c00, 0, false, false },
        { "ldff1b", 0xa4056081, 0, true, true },
        { "ldnf1b", 0xa410a081, 0, true, true },
        { "ld1row", 0xa52120c1, 3, true, true },
        { "ldnt1b", 0x8404a041, 0, true, true },
        { "stnt1b", 0xe4442041, 0, true, true },
        { "prf_ns", 0x8400e000, 0, false, false },
    };
    size_t i;

    for (i = 0; i < sizeof(nonstreaming) / sizeof(nonstreaming[0]); i++) {
        test_arm64_sme_nonstreaming_sve_one(nonstreaming[i].name,
                                            nonstreaming[i].insn,
                                            nonstreaming[i].zcr_len,
                                            nonstreaming[i].ptrue,
                                            nonstreaming[i].memory, false);
    }

    test_arm64_sme_nonstreaming_sve_one("prf_contiguous", 0x85c00000,
                                        0, false, false, true);
}

enum {
    TEST_ARM64_SME_OP_S = 2,
    TEST_ARM64_SME_OP_D = 3,
    TEST_ARM64_SME_OP_Q = 4,
};

static uint32_t test_arm64_sme_mova_esz_imm_insn(int esz, bool to_vec,
                                                 bool vertical, int zr,
                                                 int za_imm)
{
    uint32_t insn = 0xc0000000;

    if (esz == TEST_ARM64_SME_OP_Q) {
        insn |= 3U << 22;
        insn |= 1U << 16;
    } else {
        insn |= (uint32_t)esz << 22;
    }
    if (to_vec) {
        insn |= 1U << 17;
        insn |= (uint32_t)za_imm << 5;
        insn |= (uint32_t)zr;
    } else {
        insn |= (uint32_t)zr << 5;
        insn |= (uint32_t)za_imm;
    }
    if (vertical) {
        insn |= 1U << 15;
    }
    return insn;
}

static uint32_t test_arm64_sme_mova_esz_insn(int esz, bool to_vec,
                                             bool vertical, int zr)
{
    return test_arm64_sme_mova_esz_imm_insn(esz, to_vec, vertical, zr, 0);
}

static uint32_t test_arm64_sme_mova_insn(bool to_vec, bool vertical, int zr)
{
    return test_arm64_sme_mova_esz_insn(0, to_vec, vertical, zr);
}

static uint32_t test_arm64_sme_adda_insn(int esz, bool vertical)
{
    uint32_t insn;

    if (esz == 2) {
        insn = 0xc0900000;
    } else {
        insn = 0xc0d00000;
    }
    if (vertical) {
        insn |= 1U << 16;
    }
    insn |= 1U << 5;
    return insn;
}

static uint32_t test_arm64_sme_ldstr_insn(bool store, int rv, int rn, int imm)
{
    uint32_t insn = 0xe1000000;

    if (store) {
        insn |= 1U << 21;
    }
    insn |= (uint32_t)(rv - 12) << 13;
    insn |= (uint32_t)rn << 5;
    insn |= (uint32_t)imm;
    return insn;
}

enum {
    TEST_ARM64_SME_FMOPA_S,
    TEST_ARM64_SME_FMOPA_D,
    TEST_ARM64_SME_BFMOPA,
    TEST_ARM64_SME_FMOPA_H,
};

static uint32_t test_arm64_sme_imopa_insn(int esz, int kind, bool sub)
{
    uint32_t insn = 0xa0000000;

    insn |= (uint32_t)esz << 22;
    if (kind & 2) {
        insn |= 1U << 24;
    }
    if (kind & 1) {
        insn |= 1U << 21;
    }
    insn |= 2U << 16;
    insn |= 1U << 5;
    if (sub) {
        insn |= 1U << 4;
    }
    return insn;
}

static uint32_t test_arm64_sme_fpout_insn(int kind, bool sub)
{
    uint32_t insn;

    switch (kind) {
    case TEST_ARM64_SME_FMOPA_S:
        insn = 0x80800000;
        break;
    case TEST_ARM64_SME_FMOPA_D:
        insn = 0x80c00000;
        break;
    case TEST_ARM64_SME_BFMOPA:
        insn = 0x81800000;
        break;
    default:
        insn = 0x81a00000;
        break;
    }

    insn |= 2U << 16;
    insn |= 1U << 5;
    if (sub) {
        insn |= 1U << 4;
    }
    return insn;
}

static uint32_t test_arm64_sme_ldst1_insn(int esz, bool store, bool vertical,
                                          int rn, int rm, int za_imm)
{
    uint32_t insn;

    if (esz == TEST_ARM64_SME_OP_Q) {
        insn = 0xe1c00000;
    } else {
        insn = 0xe0000000 | ((uint32_t)esz << 22);
    }
    if (store) {
        insn |= 1U << 21;
    }
    if (vertical) {
        insn |= 1U << 15;
    }
    insn |= (uint32_t)rm << 16;
    insn |= (uint32_t)rn << 5;
    insn |= (uint32_t)za_imm;
    return insn;
}

static uint32_t test_arm64_sve_ldr_p_insn(int pd, int rn)
{
    return 0x85800000 | ((uint32_t)rn << 5) | (uint32_t)pd;
}

static uint32_t test_arm64_sve_str_p_insn(int pd, int rn)
{
    return 0xe5800000 | ((uint32_t)rn << 5) | (uint32_t)pd;
}

static uint32_t test_arm64_sme_psel_insn(int esz, int pd, int pn, int pm,
                                         int rv, int imm)
{
    uint32_t insn = 0x25000000 | (1U << 21) | (1U << 14);

    insn |= (uint32_t)pd;
    insn |= (uint32_t)pm << 5;
    insn |= (uint32_t)pn << 10;
    insn |= (uint32_t)(rv - 12) << 16;

    switch (esz) {
    case 0:
        insn |= 1U << 18;
        insn |= (uint32_t)(imm >> 2) << 22;
        insn |= (uint32_t)(imm & 3) << 19;
        break;
    case 1:
        insn |= 1U << 19;
        insn |= (uint32_t)(imm >> 1) << 22;
        insn |= (uint32_t)(imm & 1) << 20;
        break;
    case 2:
        insn |= 1U << 20;
        insn |= (uint32_t)imm << 22;
        break;
    default:
        insn |= 1U << 22;
        insn |= (uint32_t)imm << 23;
        break;
    }
    return insn;
}

static void test_arm64_sme_za_only_expect_exception(uint32_t insn)
{
    const uint32_t SVCR[5] = { 3, 3, 4, 2, 2 };
    uint8_t code[8];
    uc_engine *uc;
    uc_err err;

    test_arm64_emit32(code, 0, 0xd503457f); /* smstart za */
    test_arm64_emit32(code, 4, insn);

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    TEST_CHECK(err == UC_ERR_EXCEPTION);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, SVCR) == 2);
    OK(uc_close(uc));
}

static void test_arm64_sme_zero_mova(void)
{
    const uint32_t SVCR[5] = { 3, 3, 4, 2, 2 };
    const uint32_t SMCR_EL1[5] = { 3, 0, 1, 2, 6 };
    const uint32_t SMCR_EL2[5] = { 3, 4, 1, 2, 6 };
    const uint32_t SMCR_EL3[5] = { 3, 6, 1, 2, 6 };
    uint8_t roundtrip_code[24];
    uint8_t zero_code[28];
    uint8_t partial_zero_code[24];
    uint8_t input[32];
    uint8_t partial_input[64];
    uint8_t output[32];
    uint8_t partial_output[64];
    uint8_t expected_zero[32];
    uint8_t expected_partial[64];
    uc_engine *uc;
    uint64_t x4 = 0x40000;
    uint64_t x6 = 0x40200;
    uint64_t x12 = 0;
    uint64_t smcr = 0x80000001;
    size_t i;

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(i * 7 + 3);
    }
    for (i = 0; i < sizeof(partial_input); i++) {
        partial_input[i] = (uint8_t)(i * 5 + 1);
    }
    memset(expected_zero, 0, sizeof(expected_zero));
    memcpy(expected_partial, partial_input, sizeof(expected_partial));
    memset(expected_partial, 0, sizeof(input));

    test_arm64_emit32(roundtrip_code, 0, 0xd503477f);  /* smstart smza */
    test_arm64_emit32(roundtrip_code, 4, 0x2518e3e0);  /* ptrue p0.b */
    test_arm64_emit32(roundtrip_code, 8, 0xa400a081);  /* ld1b z1.b */
    test_arm64_emit32(roundtrip_code, 12,
                      test_arm64_sme_mova_insn(false, true, 1));
    test_arm64_emit32(roundtrip_code, 16,
                      test_arm64_sme_mova_insn(true, true, 0));
    test_arm64_emit32(roundtrip_code, 20, 0xe400e0c0); /* st1b z0.b */

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)roundtrip_code, sizeof(roundtrip_code),
                    UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(roundtrip_code),
                    0, 0));
    OK(uc_mem_read(uc, x6, output, sizeof(output)));
    TEST_CHECK(memcmp(output, input, sizeof(output)) == 0);
    OK(uc_close(uc));

    test_arm64_emit32(zero_code, 0, 0xd503477f);  /* smstart smza */
    test_arm64_emit32(zero_code, 4, 0x2518e3e0);  /* ptrue p0.b */
    test_arm64_emit32(zero_code, 8, 0xa400a081);  /* ld1b z1.b */
    test_arm64_emit32(zero_code, 12,
                      test_arm64_sme_mova_insn(false, true, 1));
    test_arm64_emit32(zero_code, 16, 0xc00800ff); /* zero {za} */
    test_arm64_emit32(zero_code, 20,
                      test_arm64_sme_mova_insn(true, true, 0));
    test_arm64_emit32(zero_code, 24, 0xe400e0c0); /* st1b z0.b */

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)zero_code, sizeof(zero_code),
                    UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(zero_code), 0, 0));
    OK(uc_mem_read(uc, x6, output, sizeof(output)));
    TEST_CHECK(memcmp(output, expected_zero, sizeof(output)) == 0);
    OK(uc_close(uc));

    test_arm64_emit32(partial_zero_code, 0, 0xd503457f);  /* smstart za */
    test_arm64_emit32(partial_zero_code, 4,
                      test_arm64_sme_ldstr_insn(false, 12, 4, 0));
    test_arm64_emit32(partial_zero_code, 8,
                      test_arm64_sme_ldstr_insn(false, 12, 4, 1));
    test_arm64_emit32(partial_zero_code, 12, 0xc0080001); /* zero {za0.h} */
    test_arm64_emit32(partial_zero_code, 16,
                      test_arm64_sme_ldstr_insn(true, 12, 6, 0));
    test_arm64_emit32(partial_zero_code, 20,
                      test_arm64_sme_ldstr_insn(true, 12, 6, 1));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)partial_zero_code,
                    sizeof(partial_zero_code), UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, partial_input, sizeof(partial_input)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));
    OK(uc_emu_start(uc, code_start,
                    code_start + sizeof(partial_zero_code), 0, 0));
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, SVCR) == 2);
    OK(uc_mem_read(uc, x6, partial_output, sizeof(partial_output)));
    TEST_CHECK(memcmp(partial_output, expected_partial,
                      sizeof(partial_output)) == 0);
    OK(uc_close(uc));

    test_arm64_sme_za_only_expect_exception(
        test_arm64_sme_mova_insn(false, true, 1));

    test_arm64_i8mm_expect_exception(0xc00800ff, UC_CPU_ARM64_A72);
}

static void test_arm64_sme_context_save_restore(void)
{
    const uint32_t SVCR[5] = { 3, 3, 4, 2, 2 };
    const uint32_t SMCR_EL1[5] = { 3, 0, 1, 2, 6 };
    const uint32_t SMCR_EL2[5] = { 3, 4, 1, 2, 6 };
    const uint32_t SMCR_EL3[5] = { 3, 6, 1, 2, 6 };
    const uint32_t TPIDR2_EL0[5] = { 3, 3, 13, 0, 5 };
    const uint32_t ZCR_EL1[5] = { 3, 0, 1, 2, 0 };
    const uint32_t ZCR_EL2[5] = { 3, 4, 1, 2, 0 };
    const uint32_t ZCR_EL3[5] = { 3, 6, 1, 2, 0 };
    uint8_t code[40];
    uint8_t input[32];
    uint8_t output[32];
    uc_engine *uc;
    uc_context *ctx;
    uint64_t x4 = 0x40000;
    uint64_t x6 = 0x40200;
    uint64_t x12 = 0;
    uint64_t smcr = 0x80000001;
    uint64_t zcr = 1;
    uint64_t saved_tpidr2 = 0x0123456789abcdefULL;
    uint64_t mutated_tpidr2 = 0xfedcba9876543210ULL;
    size_t i;

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(0x23 + i * 9);
    }
    memset(output, 0xa5, sizeof(output));

    test_arm64_emit32(code, 0, 0xd503477f);  /* smstart smza */
    test_arm64_emit32(code, 4, 0x2518e3e0);  /* ptrue p0.b */
    test_arm64_emit32(code, 8, 0xa400a081);  /* ld1b z1.b */
    test_arm64_emit32(code, 12,
                      test_arm64_sme_mova_insn(false, true, 1));
    test_arm64_emit32(code, 16, 0xd503477f); /* smstart smza */
    test_arm64_emit32(code, 20, 0xc00800ff); /* zero {za} */
    test_arm64_emit32(code, 24, 0xd503467f); /* smstop smza */
    test_arm64_emit32(code, 28, 0x2518e3e0); /* ptrue p0.b */
    test_arm64_emit32(code, 32,
                      test_arm64_sme_mova_insn(true, true, 0));
    test_arm64_emit32(code, 36, 0xe400e0c0); /* st1b z0.b */

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_context_alloc(uc, &ctx));
    OK(uc_ctl_context_mode(uc, UC_CTL_CONTEXT_CPU));
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
    test_arm64_pauth_cp_reg_write(uc, TPIDR2_EL0, saved_tpidr2);
    test_arm64_pauth_cp_reg_write(uc, ZCR_EL1, zcr);
    test_arm64_pauth_cp_reg_write(uc, ZCR_EL2, zcr);
    test_arm64_pauth_cp_reg_write(uc, ZCR_EL3, zcr);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, input, sizeof(input)));
    OK(uc_mem_write(uc, x6, output, sizeof(output)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));

    OK(uc_emu_start(uc, code_start, code_start + 16, 0, 0));
    OK(uc_context_save(uc, ctx));

    OK(uc_emu_start(uc, code_start + 16, code_start + 28, 0, 0));

    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, 0);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, 0);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, 0);
    test_arm64_pauth_cp_reg_write(uc, TPIDR2_EL0, mutated_tpidr2);
    test_arm64_pauth_cp_reg_write(uc, ZCR_EL1, 0);
    test_arm64_pauth_cp_reg_write(uc, ZCR_EL2, 0);
    test_arm64_pauth_cp_reg_write(uc, ZCR_EL3, 0);
    OK(uc_context_restore(uc, ctx));
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, SVCR) == 3);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, SMCR_EL1) == smcr);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, SMCR_EL2) == smcr);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, SMCR_EL3) == smcr);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TPIDR2_EL0) == saved_tpidr2);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, ZCR_EL1) == zcr);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, ZCR_EL2) == zcr);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, ZCR_EL3) == zcr);

    OK(uc_emu_start(uc, code_start + 28, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x6, output, sizeof(output)));
    TEST_CHECK(memcmp(output, input, sizeof(output)) == 0);

    OK(uc_context_free(ctx));
    OK(uc_close(uc));
}

static void test_arm64_sme_mova_q_horizontal(void)
{
    const uint32_t SMCR_EL1[5] = { 3, 0, 1, 2, 6 };
    const uint32_t SMCR_EL2[5] = { 3, 4, 1, 2, 6 };
    const uint32_t SMCR_EL3[5] = { 3, 6, 1, 2, 6 };
    uint8_t code[24];
    uint8_t input[32];
    uint8_t output[32];
    uc_engine *uc;
    uint64_t x4 = 0x40000;
    uint64_t x6 = 0x40200;
    uint64_t x12 = 0;
    uint64_t smcr = 0x80000001;
    size_t i;

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(0x5a + i * 11);
    }

    test_arm64_emit32(code, 0, 0xd503477f);  /* smstart smza */
    test_arm64_emit32(code, 4, 0x2518e3e0);  /* ptrue p0.b */
    test_arm64_emit32(code, 8, 0xa400a081);  /* ld1b z1.b */
    test_arm64_emit32(code, 12,
                      test_arm64_sme_mova_esz_insn(TEST_ARM64_SME_OP_Q,
                                                   false, false, 1));
    test_arm64_emit32(code, 16,
                      test_arm64_sme_mova_esz_insn(TEST_ARM64_SME_OP_Q,
                                                   true, false, 0));
    test_arm64_emit32(code, 20, 0xe400e0c0); /* st1b z0.b */

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x6, output, sizeof(output)));
    TEST_CHECK(memcmp(output, input, sizeof(output)) == 0);
    OK(uc_close(uc));

    test_arm64_i8mm_expect_exception(
        test_arm64_sme_mova_esz_insn(TEST_ARM64_SME_OP_Q, false, false, 1),
        UC_CPU_ARM64_A72);
}

static void test_arm64_sme_adda_run(int esz, bool vertical, const void *input,
                                    const void *expected, size_t size)
{
    static const uint32_t ptrue[4] = {
        0x2518e3e0, 0x2558e3e0, 0x2598e3e0, 0x25d8e3e0,
    };
    static const uint32_t ld1_z1[4] = {
        0xa400a081, 0xa4a0a081, 0xa540a081, 0xa5e0a081,
    };
    static const uint32_t st1_z0[4] = {
        0xe400e0c0, 0xe4a0e0c0, 0xe540e0c0, 0xe5e0e0c0,
    };
    const uint32_t SMCR_EL1[5] = { 3, 0, 1, 2, 6 };
    const uint32_t SMCR_EL2[5] = { 3, 4, 1, 2, 6 };
    const uint32_t SMCR_EL3[5] = { 3, 6, 1, 2, 6 };
    uint8_t code[28];
    uint8_t output[32];
    uc_engine *uc;
    uint64_t x4 = 0x40000;
    uint64_t x6 = 0x40200;
    uint64_t x12 = 0;
    uint64_t smcr = 0x80000001;

    test_arm64_emit32(code, 0, 0xd503477f); /* smstart smza */
    test_arm64_emit32(code, 4, ptrue[esz]);
    test_arm64_emit32(code, 8, ld1_z1[esz]);
    test_arm64_emit32(code, 12,
                      test_arm64_sme_mova_esz_insn(esz, false, true, 1));
    test_arm64_emit32(code, 16, test_arm64_sme_adda_insn(esz, vertical));
    test_arm64_emit32(code, 20,
                      test_arm64_sme_mova_esz_insn(esz, true, true, 0));
    test_arm64_emit32(code, 24, st1_z0[esz]);

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, input, size));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x6, output, size));
    TEST_CHECK(memcmp(output, expected, size) == 0);
    OK(uc_close(uc));
}

static void test_arm64_sme_adda(void)
{
    const uint32_t input_s[8] = {
        1, 3, 5, 7, 11, 13, 17, 19,
    };
    const uint32_t exp_addha_s[8] = {
        2, 4, 6, 8, 12, 14, 18, 20,
    };
    const uint32_t exp_addva_s[8] = {
        2, 6, 10, 14, 22, 26, 34, 38,
    };
    const uint64_t input_d[4] = {
        0x100000000ULL, 0x100000003ULL,
        0x100000005ULL, 0x100000007ULL,
    };
    const uint64_t exp_addha_d[4] = {
        0x200000000ULL, 0x200000003ULL,
        0x200000005ULL, 0x200000007ULL,
    };
    const uint64_t exp_addva_d[4] = {
        0x200000000ULL, 0x200000006ULL,
        0x20000000aULL, 0x20000000eULL,
    };

    test_arm64_sme_adda_run(2, false, input_s, exp_addha_s, sizeof(input_s));
    test_arm64_sme_adda_run(2, true, input_s, exp_addva_s, sizeof(input_s));
    test_arm64_sme_adda_run(3, false, input_d, exp_addha_d, sizeof(input_d));
    test_arm64_sme_adda_run(3, true, input_d, exp_addva_d, sizeof(input_d));

    test_arm64_sme_za_only_expect_exception(
        test_arm64_sme_adda_insn(TEST_ARM64_SME_OP_S, false));

    test_arm64_i8mm_expect_exception(test_arm64_sme_adda_insn(2, false),
                                     UC_CPU_ARM64_A72);
}

static void test_arm64_sme_ldstr(void)
{
    const uint32_t SMCR_EL1[5] = { 3, 0, 1, 2, 6 };
    const uint32_t SMCR_EL2[5] = { 3, 4, 1, 2, 6 };
    const uint32_t SMCR_EL3[5] = { 3, 6, 1, 2, 6 };
    uint8_t ldr_code[20];
    uint8_t str_code[20];
    uint8_t input[32];
    uint8_t output[32];
    uint8_t store_mem[64];
    uc_engine *uc;
    uint64_t x4 = 0x40000;
    uint64_t x6 = 0x40200;
    uint64_t x12 = 0;
    uint64_t smcr = 0x80000001;
    size_t i;

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(0x80 + i * 5);
    }
    memset(store_mem, 0xa5, sizeof(store_mem));

    test_arm64_emit32(ldr_code, 0, 0xd503477f);  /* smstart smza */
    test_arm64_emit32(ldr_code, 4,
                      test_arm64_sme_ldstr_insn(false, 12, 4, 0));
    test_arm64_emit32(ldr_code, 8, 0x2518e3e0);  /* ptrue p0.b */
    test_arm64_emit32(ldr_code, 12,
                      test_arm64_sme_mova_insn(true, false, 0));
    test_arm64_emit32(ldr_code, 16, 0xe400e0c0); /* st1b z0.b */

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)ldr_code, sizeof(ldr_code),
                    UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(ldr_code), 0, 0));
    OK(uc_mem_read(uc, x6, output, sizeof(output)));
    TEST_CHECK(memcmp(output, input, sizeof(output)) == 0);
    OK(uc_close(uc));

    test_arm64_emit32(str_code, 0, 0xd503477f);  /* smstart smza */
    test_arm64_emit32(str_code, 4, 0x2518e3e0);  /* ptrue p0.b */
    test_arm64_emit32(str_code, 8, 0xa400a081);  /* ld1b z1.b */
    test_arm64_emit32(str_code, 12,
                      test_arm64_sme_mova_esz_imm_insn(0, false,
                                                       false, 1, 1));
    test_arm64_emit32(str_code, 16,
                      test_arm64_sme_ldstr_insn(true, 12, 6, 1));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)str_code, sizeof(str_code),
                    UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, input, sizeof(input)));
    OK(uc_mem_write(uc, x6, store_mem, sizeof(store_mem)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(str_code), 0, 0));
    OK(uc_mem_read(uc, x6, store_mem, sizeof(store_mem)));
    for (i = 0; i < 32; i++) {
        TEST_CHECK(store_mem[i] == 0xa5);
    }
    TEST_CHECK(memcmp(store_mem + 32, input, sizeof(input)) == 0);
    OK(uc_close(uc));

    test_arm64_i8mm_expect_exception(
        test_arm64_sme_ldstr_insn(false, 12, 4, 0), UC_CPU_ARM64_A72);
}

static void test_arm64_sme_ldst1_run(int esz, bool vertical)
{
    static const uint32_t ptrue[4] = {
        0x2518e3e0, 0x2558e3e0, 0x2598e3e0, 0x25d8e3e0,
    };
    static const uint32_t st1_z0[4] = {
        0xe400e0c0, 0xe4a0e0c0, 0xe540e0c0, 0xe5e0e0c0,
    };
    const uint32_t SMCR_EL1[5] = { 3, 0, 1, 2, 6 };
    const uint32_t SMCR_EL2[5] = { 3, 4, 1, 2, 6 };
    const uint32_t SMCR_EL3[5] = { 3, 6, 1, 2, 6 };
    uint8_t code[24];
    uint8_t input[80];
    uint8_t expected[32];
    uint8_t vec_output[32];
    uint8_t za_output[32];
    uc_engine *uc;
    uint64_t x4 = 0x40000;
    uint64_t x5 = 1;
    uint64_t x6 = 0x40200;
    uint64_t x7 = 0x40300;
    uint64_t x12 = 0;
    uint64_t smcr = 0x80000001;
    size_t addr_off = (size_t)1 << esz;
    size_t code_off = 0;
    int pred_esz = esz == TEST_ARM64_SME_OP_Q ? TEST_ARM64_SME_OP_D : esz;
    bool can_mova_to_vec = esz != TEST_ARM64_SME_OP_Q;
    size_t i;

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(0x31 + i * 13);
    }
    memcpy(expected, input + addr_off, sizeof(expected));

    test_arm64_emit32(code, code_off, 0xd503477f);  /* smstart smza */
    code_off += 4;
    test_arm64_emit32(code, code_off, ptrue[pred_esz]);
    code_off += 4;
    test_arm64_emit32(code, code_off,
                      test_arm64_sme_ldst1_insn(esz, false, vertical,
                                                4, 5, 0));
    code_off += 4;
    if (can_mova_to_vec) {
        test_arm64_emit32(code, code_off,
                          test_arm64_sme_mova_esz_insn(esz, true,
                                                       vertical, 0));
        code_off += 4;
        test_arm64_emit32(code, code_off, st1_z0[esz]);
        code_off += 4;
    }
    test_arm64_emit32(code, code_off,
                      test_arm64_sme_ldst1_insn(esz, true, vertical,
                                                7, 31, 0));
    code_off += 4;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    code_off, UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
    OK(uc_mem_map(uc, 0x40000, 0x4000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));
    OK(uc_emu_start(uc, code_start, code_start + code_off, 0, 0));
    OK(uc_mem_read(uc, x7, za_output, sizeof(za_output)));
    TEST_CHECK(memcmp(za_output, expected, sizeof(expected)) == 0);
    if (can_mova_to_vec) {
        OK(uc_mem_read(uc, x6, vec_output, sizeof(vec_output)));
        TEST_CHECK(memcmp(vec_output, expected, sizeof(expected)) == 0);
    }
    OK(uc_close(uc));
}

static void test_arm64_sme_ldst1(void)
{
    const uint32_t SVCR[5] = { 3, 3, 4, 2, 2 };
    uint8_t za_only_code[12];
    uc_engine *uc;
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0;
    uint64_t x12 = 0;
    uc_err err;
    int esz;

    for (esz = 0; esz <= TEST_ARM64_SME_OP_Q; esz++) {
        test_arm64_sme_ldst1_run(esz, false);
        test_arm64_sme_ldst1_run(esz, true);
    }

    test_arm64_emit32(za_only_code, 0, 0xd503457f); /* smstart za */
    test_arm64_emit32(za_only_code, 4, 0x2518e3e0); /* ptrue p0.b */
    test_arm64_emit32(za_only_code, 8,
                      test_arm64_sme_ldst1_insn(0, false, false,
                                                4, 5, 0));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)za_only_code, sizeof(za_only_code),
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, x4, 0x1000, UC_PROT_ALL));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));
    err = uc_emu_start(uc, code_start, code_start + sizeof(za_only_code),
                       0, 0);
    TEST_CHECK(err == UC_ERR_EXCEPTION);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, SVCR) == 2);
    OK(uc_close(uc));

    test_arm64_i8mm_expect_exception(
        test_arm64_sme_ldst1_insn(0, false, false, 4, 5, 0),
        UC_CPU_ARM64_A72);
}

static void test_arm64_sme_ldst1_fault_no_partial(void)
{
    const uint32_t SMCR_EL1[5] = { 3, 0, 1, 2, 6 };
    const uint32_t SMCR_EL2[5] = { 3, 4, 1, 2, 6 };
    const uint32_t SMCR_EL3[5] = { 3, 6, 1, 2, 6 };
    uint8_t code[20];
    uint8_t initial[32];
    uint8_t fault_src[8];
    uint8_t before[8];
    uint8_t output[32];
    uc_engine *uc;
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40ff8;
    uint64_t x7 = 0x40200;
    uint64_t smcr = 0x80000001;
    uc_err err;
    size_t i;

    for (i = 0; i < sizeof(initial); i++) {
        initial[i] = (uint8_t)(0x60 + i);
    }
    for (i = 0; i < sizeof(fault_src); i++) {
        fault_src[i] = (uint8_t)(0xb0 + i);
        before[i] = (uint8_t)(0xc0 + i);
    }

    test_arm64_emit32(code, 0, 0xd503477f);  /* smstart smza */
    test_arm64_emit32(code, 4, 0x2518e3e0);  /* ptrue p0.b */
    test_arm64_emit32(code, 8,
                      test_arm64_sme_ldst1_insn(0, false, false,
                                                4, 31, 0));
    test_arm64_emit32(code, 12,
                      test_arm64_sme_ldst1_insn(0, false, false,
                                                5, 31, 0));
    test_arm64_emit32(code, 16,
                      test_arm64_sme_ldst1_insn(0, true, false,
                                                7, 31, 0));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, initial, sizeof(initial)));
    OK(uc_mem_write(uc, x5, fault_src, sizeof(fault_src)));
    memset(output, 0xa5, sizeof(output));
    OK(uc_mem_write(uc, x7, output, sizeof(output)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));

    err = uc_emu_start(uc, code_start, code_start + 16, 0, 0);
    TEST_CHECK_(err == UC_ERR_READ_UNMAPPED, "err=%u", err);
    OK(uc_emu_start(uc, code_start + 16, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x7, output, sizeof(output)));
    TEST_CHECK(memcmp(output, initial, sizeof(output)) == 0);
    OK(uc_close(uc));

    test_arm64_emit32(code, 0, 0xd503477f);  /* smstart smza */
    test_arm64_emit32(code, 4, 0x2518e3e0);  /* ptrue p0.b */
    test_arm64_emit32(code, 8,
                      test_arm64_sme_ldst1_insn(0, false, false,
                                                4, 31, 0));
    test_arm64_emit32(code, 12,
                      test_arm64_sme_ldst1_insn(0, true, false,
                                                5, 31, 0));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code, 16,
                    UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, initial, sizeof(initial)));
    OK(uc_mem_write(uc, x5, before, sizeof(before)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));

    err = uc_emu_start(uc, code_start, code_start + 16, 0, 0);
    TEST_CHECK_(err == UC_ERR_WRITE_UNMAPPED, "err=%u", err);
    OK(uc_mem_read(uc, x5, output, sizeof(before)));
    TEST_CHECK(memcmp(output, before, sizeof(before)) == 0);
    OK(uc_close(uc));
}

static void test_arm64_sme_psel_run(int esz, uint64_t x12, int imm,
                                    uint16_t pm_mask, bool copy)
{
    uc_engine *uc;
    uint8_t code[16];
    const uint8_t pn[2] = { 0xb5, 0x4a };
    uint8_t pm[2];
    uint8_t expected[2];
    uint8_t out[2];
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40100;
    uint64_t x6 = 0x40200;

    pm[0] = (uint8_t)pm_mask;
    pm[1] = (uint8_t)(pm_mask >> 8);
    if (copy) {
        memcpy(expected, pn, sizeof(expected));
    } else {
        memset(expected, 0, sizeof(expected));
    }
    memset(out, 0xa5, sizeof(out));

    test_arm64_emit32(code, 0, test_arm64_sve_ldr_p_insn(1, 4));
    test_arm64_emit32(code, 4, test_arm64_sve_ldr_p_insn(2, 5));
    test_arm64_emit32(code, 8,
                      test_arm64_sme_psel_insn(esz, 0, 1, 2, 12, imm));
    test_arm64_emit32(code, 12, test_arm64_sve_str_p_insn(0, 6));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, pn, sizeof(pn)));
    OK(uc_mem_write(uc, x5, pm, sizeof(pm)));
    OK(uc_mem_write(uc, x6, out, sizeof(out)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x6, out, sizeof(out)));
    TEST_CHECK(memcmp(out, expected, sizeof(out)) == 0);

    OK(uc_close(uc));
}

static void test_arm64_sme_psel(void)
{
    test_arm64_sme_psel_run(0, 14, 5, 1U << 3, true);
    test_arm64_sme_psel_run(0, 14, 5, 0, false);
    test_arm64_sme_psel_run(1, 7, 3, 1U << 4, true);
    test_arm64_sme_psel_run(1, 7, 3, 0, false);
    test_arm64_sme_psel_run(2, 3, 3, 1U << 8, true);
    test_arm64_sme_psel_run(2, 3, 3, 0, false);
    test_arm64_sme_psel_run(3, 4, 1, 1U << 8, true);
    test_arm64_sme_psel_run(3, 4, 1, 0, false);

    test_arm64_i8mm_expect_exception(
        test_arm64_sme_psel_insn(0, 0, 1, 2, 12, 0), UC_CPU_ARM64_A72);
}

static void test_arm64_sme_ldst1_mte_enable_tcf(uc_engine *uc, uint64_t tcf)
{
    const uint32_t CPACR_EL1[5] = { 3, 0, 1, 0, 2 };
    const uint32_t CPTR_EL3[5] = { 3, 6, 1, 1, 2 };
    const uint32_t SMCR_EL1[5] = { 3, 0, 1, 2, 6 };
    const uint32_t SMCR_EL2[5] = { 3, 4, 1, 2, 6 };
    const uint32_t SMCR_EL3[5] = { 3, 6, 1, 2, 6 };
    uint64_t smcr = 0x80000001;

    test_arm64_mte_enable_checks(uc, tcf);
    test_arm64_mte_enable_sve(uc);
    TEST_CHECK(test_arm64_pauth_cp_reg_update(
        uc, CPACR_EL1, 0, (3ULL << 16) | (3ULL << 20) | (3ULL << 24)));
    TEST_CHECK(test_arm64_pauth_cp_reg_update(
        uc, CPTR_EL3, 0, (1ULL << 8) | (1ULL << 12)));
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
}

static void test_arm64_sme_ldst1_mte_enable(uc_engine *uc)
{
    test_arm64_sme_ldst1_mte_enable_tcf(uc, 1ULL << 40);
}

static void test_arm64_sme_ldst1_mte_seed_tag_pair(uc_engine *uc,
                                                   uint64_t addr,
                                                   uint64_t tag0,
                                                   uint64_t tag1)
{
    test_arm64_mte_store_tag_at(uc, addr, tag0);
    test_arm64_mte_store_tag_at(uc, addr + 0x10, tag1);
}

static void test_arm64_sme_ldst1_mte_seed_tags(uc_engine *uc,
                                               uint64_t input_addr,
                                               uint64_t output_addr,
                                               uint64_t tag)
{
    test_arm64_sme_ldst1_mte_seed_tag_pair(uc, input_addr, tag, tag);
    test_arm64_sme_ldst1_mte_seed_tag_pair(uc, output_addr, tag, tag);
}

static void test_arm64_sme_ldst1_mte_run(uint64_t load_addr,
                                         uint64_t store_addr, bool tco,
                                         uc_err expected_err,
                                         bool expect_store,
                                         uint64_t input_tag1,
                                         uint64_t output_tag1)
{
    const uint32_t SMCR_EL1[5] = { 3, 0, 1, 2, 6 };
    const uint32_t SVCR[5] = { 3, 3, 4, 2, 2 };
    const uint32_t TCO[5] = { 3, 3, 4, 2, 7 };
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    const uint64_t pstate_tco = 1ULL << 25;
    uint8_t code[24];
    uint8_t input[32];
    uint8_t initial_output[32];
    uint8_t output[32];
    uc_engine *uc;
    uc_err err;
    uint64_t pc = 0;
    uint64_t svcr = 0;
    uint64_t smcr_el1 = 0;
    uint64_t x4 = load_addr;
    uint64_t x7 = store_addr;
    uint64_t x12 = 0;
    uint64_t tag = 0x0c00000000000000ull;
    uint64_t tag_probe = 0;
    size_t i;

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(0x70 + i);
        initial_output[i] = 0xa5;
    }

    test_arm64_emit32(code, 0, 0xd9200822);  /* stg x2,[x1] */
    test_arm64_emit32(code, 4, 0xd9600023);  /* ldg x3,[x1] */
    test_arm64_emit32(code, 8, 0xd503477f);  /* smstart smza */
    test_arm64_emit32(code, 12, 0x2518e3e0); /* ptrue p0.b */
    test_arm64_emit32(code, 16,
                      test_arm64_sme_ldst1_insn(0, false, false,
                                                4, 31, 0));
    test_arm64_emit32(code, 20,
                      test_arm64_sme_ldst1_insn(0, true, false,
                                                7, 31, 0));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, input, sizeof(input)));
    OK(uc_mem_write(uc, 0x40100, initial_output, sizeof(initial_output)));
    test_arm64_sme_ldst1_mte_enable(uc);
    test_arm64_sme_ldst1_mte_seed_tag_pair(uc, 0x40000, tag, input_tag1);
    test_arm64_sme_ldst1_mte_seed_tag_pair(uc, 0x40100, tag, output_tag1);
    tag_probe = test_arm64_mte_load_tag_at(uc, 0x40000, 0);
    TEST_CHECK_(tag_probe == tag, "tag=0x%llx",
                (unsigned long long)tag_probe);
    tag_probe = test_arm64_mte_load_tag_at(uc, 0x40010, 0);
    TEST_CHECK_(tag_probe == input_tag1, "tag=0x%llx",
                (unsigned long long)tag_probe);
    tag_probe = test_arm64_mte_load_tag_at(uc, 0x40100, 0);
    TEST_CHECK_(tag_probe == tag, "tag=0x%llx",
                (unsigned long long)tag_probe);
    tag_probe = test_arm64_mte_load_tag_at(uc, 0x40110, 0);
    TEST_CHECK_(tag_probe == output_tag1, "tag=0x%llx",
                (unsigned long long)tag_probe);
    if (tco) {
        test_arm64_pauth_cp_reg_write(uc, TCO, pstate_tco);
    }
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));

    err = uc_emu_start(uc, code_start + 8, code_start + sizeof(code), 0, 0);
    OK(uc_reg_read(uc, UC_ARM64_REG_PC, &pc));
    svcr = test_arm64_pauth_cp_reg_read(uc, SVCR);
    smcr_el1 = test_arm64_pauth_cp_reg_read(uc, SMCR_EL1);
    TEST_CHECK_(err == expected_err,
                "err=%u expected=%u pc=0x%llx svcr=0x%llx smcr=0x%llx",
                (unsigned)err, (unsigned)expected_err,
                (unsigned long long)pc, (unsigned long long)svcr,
                (unsigned long long)smcr_el1);
    OK(uc_mem_read(uc, 0x40100, output, sizeof(output)));
    if (expect_store) {
        TEST_CHECK(memcmp(output, input, sizeof(output)) == 0);
    } else {
        TEST_CHECK(memcmp(output, initial_output, sizeof(output)) == 0);
    }
    if (tco) {
        TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    }
    OK(uc_close(uc));
}

static void test_arm64_sme_ldst1_mte_load_fault_preserve(void)
{
    uint8_t code[28];
    uint8_t input[32];
    uint8_t output[32];
    uc_engine *uc;
    uc_err err;
    uint64_t x4 = 0x0c00000000040000ull;
    uint64_t x5 = 0x0d00000000040000ull;
    uint64_t x7 = 0x0c00000000040100ull;
    uint64_t x12 = 0;
    uint64_t tag = 0x0c00000000000000ull;
    size_t i;

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(0x90 + i);
        output[i] = 0xa5;
    }

    test_arm64_emit32(code, 0, 0xd9200822);  /* stg x2,[x1] */
    test_arm64_emit32(code, 4, 0xd9600023);  /* ldg x3,[x1] */
    test_arm64_emit32(code, 8, 0xd503477f);  /* smstart smza */
    test_arm64_emit32(code, 12, 0x2518e3e0); /* ptrue p0.b */
    test_arm64_emit32(code, 16,
                      test_arm64_sme_ldst1_insn(0, false, false,
                                                4, 31, 0));
    test_arm64_emit32(code, 20,
                      test_arm64_sme_ldst1_insn(0, false, false,
                                                5, 31, 0));
    test_arm64_emit32(code, 24,
                      test_arm64_sme_ldst1_insn(0, true, false,
                                                7, 31, 0));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, input, sizeof(input)));
    OK(uc_mem_write(uc, 0x40100, output, sizeof(output)));
    test_arm64_sme_ldst1_mte_enable(uc);
    test_arm64_sme_ldst1_mte_seed_tags(uc, 0x40000, 0x40100, tag);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));

    err = uc_emu_start(uc, code_start + 8, code_start + 24, 0, 0);
    TEST_CHECK(err == UC_ERR_EXCEPTION);
    OK(uc_emu_start(uc, code_start + 24, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, 0x40100, output, sizeof(output)));
    TEST_CHECK(memcmp(output, input, sizeof(output)) == 0);
    OK(uc_close(uc));
}

static void test_arm64_sme_ldst1_mte_store_fault_priority(void)
{
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    uint8_t code[20];
    uint8_t initial[16];
    uint8_t actual[16];
    uc_engine *uc;
    uc_err err;
    uint64_t x5 = 0x0d00000000040ff8ull;
    uint64_t x12 = 0;
    uint64_t tag = 0x0c00000000000000ull;
    size_t i;

    for (i = 0; i < sizeof(initial); i++) {
        initial[i] = (uint8_t)(0xe0 + i);
    }

    test_arm64_emit32(code, 0, 0xd9200822);  /* stg x2,[x1] */
    test_arm64_emit32(code, 4, 0xd503477f);  /* smstart smza */
    test_arm64_emit32(code, 8, 0xc00800ff);  /* zero {za} */
    test_arm64_emit32(code, 12, 0x2518e3e0); /* ptrue p0.b */
    test_arm64_emit32(code, 16,
                      test_arm64_sme_ldst1_insn(0, true, false,
                                                5, 31, 0));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40ff0, initial, sizeof(initial)));
    test_arm64_sme_ldst1_mte_enable_tcf(uc, 3ULL << 40);
    test_arm64_mte_store_tag_at(uc, 0x40ff0, tag);
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));

    err = uc_emu_start(uc, code_start + 4, code_start + sizeof(code), 0, 0);
    TEST_CHECK_(err == UC_ERR_WRITE_UNMAPPED, "err=%u", (unsigned)err);
    OK(uc_mem_read(uc, 0x40ff0, actual, sizeof(actual)));
    TEST_CHECK(memcmp(actual, initial, sizeof(initial)) == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));
}

static void test_arm64_sme_ldst1_mte(void)
{
    uint64_t tag = 0x0c00000000000000ull;
    uint64_t other_tag = 0x0e00000000000000ull;

    test_arm64_sme_ldst1_mte_load_fault_preserve();
    test_arm64_sme_ldst1_mte_store_fault_priority();

    test_arm64_sme_ldst1_mte_run(0x0c00000000040000ull,
                                 0x0c00000000040100ull,
                                 false, UC_ERR_OK, true, tag, tag);
    test_arm64_sme_ldst1_mte_run(0x0d00000000040000ull,
                                 0x0c00000000040100ull,
                                 false, UC_ERR_EXCEPTION, false, tag, tag);
    test_arm64_sme_ldst1_mte_run(0x0c00000000040000ull,
                                 0x0c00000000040100ull,
                                 false, UC_ERR_EXCEPTION, false,
                                 other_tag, tag);
    test_arm64_sme_ldst1_mte_run(0x0c00000000040000ull,
                                 0x0d00000000040100ull,
                                 false, UC_ERR_EXCEPTION, false, tag, tag);
    test_arm64_sme_ldst1_mte_run(0x0c00000000040000ull,
                                 0x0c00000000040100ull,
                                 false, UC_ERR_EXCEPTION, false,
                                 tag, other_tag);
    test_arm64_sme_ldst1_mte_run(0x0d00000000040000ull,
                                 0x0d00000000040100ull,
                                 true, UC_ERR_OK, true, tag, tag);
}

static int64_t test_arm64_sme_byte_value(uint8_t value, bool is_unsigned)
{
    if (is_unsigned) {
        return value;
    }
    return (int8_t)value;
}

static int64_t test_arm64_sme_half_value(uint16_t value, bool is_unsigned)
{
    if (is_unsigned) {
        return value;
    }
    return (int16_t)value;
}

static void test_arm64_sme_imopa_s_expected(uint32_t *expected,
                                            const uint8_t *n,
                                            const uint8_t *m,
                                            int kind, bool sub)
{
    bool n_unsigned = (kind & 2) != 0;
    bool m_unsigned = (kind & 1) != 0;
    int col;

    for (col = 0; col < 4; col++) {
        int lane;
        int64_t sum0 = 0;
        int64_t sum1 = 0;

        for (lane = 0; lane < 4; lane++) {
            sum0 += test_arm64_sme_byte_value(n[lane], n_unsigned) *
                    test_arm64_sme_byte_value(m[col * 8 + lane],
                                              m_unsigned);
            sum1 += test_arm64_sme_byte_value(n[lane + 4], n_unsigned) *
                    test_arm64_sme_byte_value(m[col * 8 + lane + 4],
                                              m_unsigned);
        }
        expected[col * 2] = (uint32_t)(sub ? -sum0 : sum0);
        expected[col * 2 + 1] = (uint32_t)(sub ? -sum1 : sum1);
    }
}

static void test_arm64_sme_imopa_d_expected(uint64_t *expected,
                                            const uint16_t *n,
                                            const uint16_t *m,
                                            int kind, bool sub)
{
    bool n_unsigned = (kind & 2) != 0;
    bool m_unsigned = (kind & 1) != 0;
    int col;

    for (col = 0; col < 4; col++) {
        int lane;
        int64_t sum = 0;

        for (lane = 0; lane < 4; lane++) {
            sum += test_arm64_sme_half_value(n[lane], n_unsigned) *
                   test_arm64_sme_half_value(m[col * 4 + lane], m_unsigned);
        }
        expected[col] = (uint64_t)(sub ? -sum : sum);
    }
}

static void test_arm64_sme_imopa_run(int esz, int kind, bool sub,
                                     const void *input_n,
                                     const void *input_m,
                                     const void *expected, size_t size)
{
    static const uint32_t ptrue[2] = {
        0x2518e3e0, 0x2558e3e0,
    };
    static const uint32_t ld1_z1[2] = {
        0xa400a081, 0xa4a0a081,
    };
    static const uint32_t ld1_z2[2] = {
        0xa400a0a2, 0xa4a0a0a2,
    };
    const uint32_t SMCR_EL1[5] = { 3, 0, 1, 2, 6 };
    const uint32_t SMCR_EL2[5] = { 3, 4, 1, 2, 6 };
    const uint32_t SMCR_EL3[5] = { 3, 6, 1, 2, 6 };
    uint8_t code[28];
    uint8_t output[32];
    uc_engine *uc;
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40100;
    uint64_t x6 = 0x40200;
    uint64_t x12 = 0;
    uint64_t smcr = 0x80000001;
    int load_esz = esz == TEST_ARM64_SME_OP_D ? 1 : 0;

    test_arm64_emit32(code, 0, 0xd503477f);  /* smstart smza */
    test_arm64_emit32(code, 4, 0xc00800ff);  /* zero {za} */
    test_arm64_emit32(code, 8, ptrue[load_esz]);
    test_arm64_emit32(code, 12, ld1_z1[load_esz]);
    test_arm64_emit32(code, 16, ld1_z2[load_esz]);
    test_arm64_emit32(code, 20, test_arm64_sme_imopa_insn(esz, kind, sub));
    test_arm64_emit32(code, 24,
                      test_arm64_sme_ldstr_insn(true, 12, 6, 0));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, input_n, size));
    OK(uc_mem_write(uc, x5, input_m, size));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x6, output, size));
    TEST_CHECK(memcmp(output, expected, size) == 0);
    OK(uc_close(uc));
}

static void test_arm64_sme_imopa(void)
{
    uint8_t n_b[32] = {
        0x7f, 0x80, 0x02, 0xff, 0x10, 0xf0, 0x04, 0x81,
    };
    uint8_t m_b[32] = {
        0x02, 0x7e, 0x80, 0xff, 0x11, 0xef, 0x40, 0xc0,
        0x01, 0x02, 0x03, 0x04, 0x80, 0x7f, 0xfe, 0x10,
        0xf0, 0x10, 0x08, 0xf8, 0x20, 0xe0, 0x55, 0xaa,
        0x7f, 0x81, 0x33, 0xcd, 0x12, 0x34, 0x56, 0x78,
    };
    uint16_t n_h[16] = {
        0x7fff, 0x8000, 0x0002, 0xffff,
    };
    uint16_t m_h[16] = {
        0x0002, 0x7ffe, 0x8000, 0xffff,
        0x0001, 0x0002, 0x0003, 0x0004,
        0x8000, 0x7fff, 0xfffe, 0x0010,
        0x1234, 0xedcc, 0x0101, 0xf0f0,
    };
    uint32_t expected_s[8];
    uint64_t expected_d[4];
    int kind;

    for (kind = 0; kind < 4; kind++) {
        test_arm64_sme_imopa_s_expected(expected_s, n_b, m_b, kind, false);
        test_arm64_sme_imopa_run(TEST_ARM64_SME_OP_S, kind, false,
                                 n_b, m_b, expected_s,
                                 sizeof(expected_s));
        test_arm64_sme_imopa_s_expected(expected_s, n_b, m_b, kind, true);
        test_arm64_sme_imopa_run(TEST_ARM64_SME_OP_S, kind, true,
                                 n_b, m_b, expected_s,
                                 sizeof(expected_s));

        test_arm64_sme_imopa_d_expected(expected_d, n_h, m_h, kind, false);
        test_arm64_sme_imopa_run(TEST_ARM64_SME_OP_D, kind, false,
                                 n_h, m_h, expected_d,
                                 sizeof(expected_d));
        test_arm64_sme_imopa_d_expected(expected_d, n_h, m_h, kind, true);
        test_arm64_sme_imopa_run(TEST_ARM64_SME_OP_D, kind, true,
                                 n_h, m_h, expected_d,
                                 sizeof(expected_d));
    }

    test_arm64_sme_za_only_expect_exception(
        test_arm64_sme_imopa_insn(TEST_ARM64_SME_OP_S, 0, false));

    test_arm64_i8mm_expect_exception(
        test_arm64_sme_imopa_insn(TEST_ARM64_SME_OP_S, 0, false),
        UC_CPU_ARM64_A72);
}

static void test_arm64_sme_fpout_run(int kind, bool sub, int pred_esz,
                                     const void *input_n,
                                     const void *input_m,
                                     const void *expected)
{
    static const uint32_t ptrue[4] = {
        0x2518e3e0, 0x2558e3e0, 0x2598e3e0, 0x25d8e3e0,
    };
    const uint32_t SMCR_EL1[5] = { 3, 0, 1, 2, 6 };
    const uint32_t SMCR_EL2[5] = { 3, 4, 1, 2, 6 };
    const uint32_t SMCR_EL3[5] = { 3, 6, 1, 2, 6 };
    uint8_t code[32];
    uint8_t output[32];
    uc_engine *uc;
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40100;
    uint64_t x6 = 0x40200;
    uint64_t x12 = 0;
    uint64_t smcr = 0x80000001;

    test_arm64_emit32(code, 0, 0xd503477f);  /* smstart smza */
    test_arm64_emit32(code, 4, 0xc00800ff);  /* zero {za} */
    test_arm64_emit32(code, 8, ptrue[0]);
    test_arm64_emit32(code, 12, 0xa400a081); /* ld1b z1.b */
    test_arm64_emit32(code, 16, 0xa400a0a2); /* ld1b z2.b */
    test_arm64_emit32(code, 20, ptrue[pred_esz]);
    test_arm64_emit32(code, 24, test_arm64_sme_fpout_insn(kind, sub));
    test_arm64_emit32(code, 28,
                      test_arm64_sme_ldstr_insn(true, 12, 6, 0));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, smcr);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL3, smcr);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, input_n, sizeof(output)));
    OK(uc_mem_write(uc, x5, input_m, sizeof(output)));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x6, output, sizeof(output)));
    TEST_CHECK(memcmp(output, expected, sizeof(output)) == 0);
    OK(uc_close(uc));
}

static void test_arm64_sme_fpout(void)
{
    const uint32_t n_s[8] = {
        0x40000000u, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint32_t m_s[8] = {
        0x40400000u, 0x40800000u, 0xbf800000u, 0x3f000000u,
        0x40000000u, 0xc0400000u, 0x41000000u, 0xbe800000u,
    };
    const uint32_t exp_s_add[8] = {
        0x40c00000u, 0x41000000u, 0xc0000000u, 0x3f800000u,
        0x40800000u, 0xc0c00000u, 0x41800000u, 0xbf000000u,
    };
    const uint32_t exp_s_sub[8] = {
        0xc0c00000u, 0xc1000000u, 0x40000000u, 0xbf800000u,
        0xc0800000u, 0x40c00000u, 0xc1800000u, 0x3f000000u,
    };
    const uint64_t n_d[4] = {
        0x4000000000000000ull, 0, 0, 0,
    };
    const uint64_t m_d[4] = {
        0x4008000000000000ull, 0x4010000000000000ull,
        0xbff0000000000000ull, 0x3fe0000000000000ull,
    };
    const uint64_t exp_d_add[4] = {
        0x4018000000000000ull, 0x4020000000000000ull,
        0xc000000000000000ull, 0x3ff0000000000000ull,
    };
    const uint64_t exp_d_sub[4] = {
        0xc018000000000000ull, 0xc020000000000000ull,
        0x4000000000000000ull, 0xbff0000000000000ull,
    };
    const uint32_t n_h[8] = {
        0x40003c00u, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint32_t m_h[8] = {
        0x44004200u, 0x3c003c00u, 0x42004000u, 0x3c00bc00u,
        0x38003800u, 0xbc004400u, 0x38004800u, 0xbc00c400u,
    };
    const uint32_t exp_pair_add[8] = {
        0x41300000u, 0x40400000u, 0x41000000u, 0x3f800000u,
        0x3fc00000u, 0x40000000u, 0x41100000u, 0xc0c00000u,
    };
    const uint32_t exp_pair_sub[8] = {
        0xc1300000u, 0xc0400000u, 0xc1000000u, 0xbf800000u,
        0xbfc00000u, 0xc0000000u, 0xc1100000u, 0x40c00000u,
    };
    const uint32_t n_bf[8] = {
        0x40003f80u, 0, 0, 0, 0, 0, 0, 0,
    };
    const uint32_t m_bf[8] = {
        0x40804040u, 0x3f803f80u, 0x40404000u, 0x3f80bf80u,
        0x3f003f00u, 0xbf804080u, 0x3f004100u, 0xbf80c080u,
    };

    test_arm64_sme_fpout_run(TEST_ARM64_SME_FMOPA_S, false,
                             TEST_ARM64_SME_OP_S, n_s, m_s, exp_s_add);
    test_arm64_sme_fpout_run(TEST_ARM64_SME_FMOPA_S, true,
                             TEST_ARM64_SME_OP_S, n_s, m_s, exp_s_sub);
    test_arm64_sme_fpout_run(TEST_ARM64_SME_FMOPA_D, false,
                             TEST_ARM64_SME_OP_D, n_d, m_d, exp_d_add);
    test_arm64_sme_fpout_run(TEST_ARM64_SME_FMOPA_D, true,
                             TEST_ARM64_SME_OP_D, n_d, m_d, exp_d_sub);
    test_arm64_sme_fpout_run(TEST_ARM64_SME_FMOPA_H, false, 1,
                             n_h, m_h, exp_pair_add);
    test_arm64_sme_fpout_run(TEST_ARM64_SME_FMOPA_H, true, 1,
                             n_h, m_h, exp_pair_sub);
    test_arm64_sme_fpout_run(TEST_ARM64_SME_BFMOPA, false, 1,
                             n_bf, m_bf, exp_pair_add);
    test_arm64_sme_fpout_run(TEST_ARM64_SME_BFMOPA, true, 1,
                             n_bf, m_bf, exp_pair_sub);

    test_arm64_sme_za_only_expect_exception(
        test_arm64_sme_fpout_insn(TEST_ARM64_SME_FMOPA_S, false));
    test_arm64_sme_za_only_expect_exception(
        test_arm64_sme_fpout_insn(TEST_ARM64_SME_BFMOPA, false));

    test_arm64_i8mm_expect_exception(
        test_arm64_sme_fpout_insn(TEST_ARM64_SME_FMOPA_S, false),
        UC_CPU_ARM64_A72);
}

static void test_arm64_sve2_widen_add_shift(void)
{
    const uint8_t n_b[16] = {
        0x80, 0x7f, 0x40, 0xc0, 0x11, 0xee, 0x55, 0xaa,
        0x10, 0xf0, 0x33, 0xcd, 0x01, 0xff, 0x7e, 0x82,
    };
    const uint8_t m_b[16] = {
        0x02, 0x7f, 0x40, 0xc0, 0x33, 0x20, 0x55, 0xaa,
        0x7f, 0x81, 0xcd, 0x33, 0x80, 0x80, 0x02, 0xfe,
    };
    const uint8_t sq_n_b[16] = {
        0x80, 0x7f, 0x40, 0xc0, 0x20, 0xe0, 0x55, 0xab,
        0x10, 0xf0, 0x33, 0xcd, 0x01, 0xff, 0x7e, 0x82,
    };
    const uint8_t sq_m_b[16] = {
        0x80, 0x7f, 0x40, 0x40, 0xe0, 0x20, 0x55, 0xab,
        0x7f, 0x81, 0xcd, 0x33, 0x80, 0x80, 0x02, 0xfe,
    };
    const uint16_t n_h[8] = {
        0x8001, 0x7fff, 0x4000, 0xc000,
        0x1111, 0xeeee, 0x5555, 0xaaaa,
    };
    const uint16_t m_h[8] = {
        0x0002, 0x7fff, 0x4000, 0xc000,
        0x3333, 0x2000, 0x5555, 0xaaaa,
    };
    const uint32_t n_s[4] = {
        0x80000001u, 0x7fffffffu, 0x40000000u, 0xc0000000u,
    };
    const uint32_t m_s[4] = {
        0x00000002u, 0x7fffffffu, 0x40000000u, 0xc0000000u,
    };
    const uint64_t n_d[2] = {
        0x8000000000000001ull, 0x7fffffffffffffffull,
    };
    const uint16_t exp_saddlb[8] = {
        0xff82, 0x0080, 0x0044, 0x00aa,
        0x008f, 0x0000, 0xff81, 0x0080,
    };
    const uint16_t exp_uaddlb[8] = {
        0x0082, 0x0080, 0x0044, 0x00aa,
        0x008f, 0x0100, 0x0081, 0x0080,
    };
    const uint16_t exp_ssublb[8] = {
        0xff7e, 0x0000, 0xffde, 0x0000,
        0xff91, 0x0066, 0x0081, 0x007c,
    };
    const uint16_t exp_usublb[8] = {
        0x007e, 0x0000, 0xffde, 0x0000,
        0xff91, 0xff66, 0xff81, 0x007c,
    };
    const uint16_t exp_saddlt[8] = {
        0x00fe, 0xff80, 0x000e, 0xff54,
        0xff71, 0x0000, 0xff7f, 0xff80,
    };
    const uint16_t exp_uaddlt[8] = {
        0x00fe, 0x0180, 0x010e, 0x0154,
        0x0171, 0x0100, 0x017f, 0x0180,
    };
    const uint16_t exp_ssublt[8] = {
        0x0000, 0x0000, 0xffce, 0x0000,
        0x006f, 0xff9a, 0x007f, 0xff84,
    };
    const uint16_t exp_usublt[8] = {
        0x0000, 0x0000, 0x00ce, 0x0000,
        0x006f, 0x009a, 0x007f, 0xff84,
    };
    const uint16_t exp_saddwb[8] = {
        0x8003, 0x803f, 0x4033, 0xc055,
        0x1190, 0xeebb, 0x54d5, 0xaaac,
    };
    const uint16_t exp_uaddwb[8] = {
        0x8003, 0x803f, 0x4033, 0xc055,
        0x1190, 0xefbb, 0x55d5, 0xaaac,
    };
    const uint16_t exp_ssubwb[8] = {
        0x7fff, 0x7fbf, 0x3fcd, 0xbfab,
        0x1092, 0xef21, 0x55d5, 0xaaa8,
    };
    const uint16_t exp_usubwb[8] = {
        0x7fff, 0x7fbf, 0x3fcd, 0xbfab,
        0x1092, 0xee21, 0x54d5, 0xaaa8,
    };
    const uint16_t exp_saddwt[8] = {
        0x8080, 0x7fbf, 0x4020, 0xbfaa,
        0x1092, 0xef21, 0x54d5, 0xaaa8,
    };
    const uint16_t exp_uaddwt[8] = {
        0x8080, 0x80bf, 0x4020, 0xc0aa,
        0x1192, 0xef21, 0x55d5, 0xaba8,
    };
    const uint16_t exp_ssubwt[8] = {
        0x7f82, 0x803f, 0x3fe0, 0xc056,
        0x1190, 0xeebb, 0x55d5, 0xaaac,
    };
    const uint16_t exp_usubwt[8] = {
        0x7f82, 0x7f3f, 0x3fe0, 0xbf56,
        0x1090, 0xeebb, 0x54d5, 0xa9ac,
    };
    const uint16_t exp_sshllb[8] = {
        0xff80, 0x0040, 0x0011, 0x0055,
        0x0010, 0x0033, 0x0001, 0x007e,
    };
    const uint16_t exp_ushllb[8] = {
        0x0080, 0x0040, 0x0011, 0x0055,
        0x0010, 0x0033, 0x0001, 0x007e,
    };
    const uint16_t exp_sshllt[8] = {
        0x007f, 0xffc0, 0xffee, 0xffaa,
        0xfff0, 0xffcd, 0xffff, 0xff82,
    };
    const uint16_t exp_ushllt[8] = {
        0x007f, 0x00c0, 0x00ee, 0x00aa,
        0x00f0, 0x00cd, 0x00ff, 0x0082,
    };
    const uint32_t exp_saddlb_s[4] = {
        0xffff8003u, 0x00008000u, 0x00004444u, 0x0000aaaau,
    };
    const uint32_t exp_uaddlt_s[4] = {
        0x0000fffeu, 0x00018000u, 0x00010eeeu, 0x00015554u,
    };
    const uint32_t exp_ssublb_s[4] = {
        0xffff7fffu, 0x00000000u, 0xffffdddeu, 0x00000000u,
    };
    const uint32_t exp_usublt_s[4] = {
        0x00000000u, 0x00000000u, 0x0000ceeeu, 0x00000000u,
    };
    const uint64_t exp_saddlt_d[2] = {
        0x00000000fffffffeull, 0xffffffff80000000ull,
    };
    const uint64_t exp_uaddlb_d[2] = {
        0x0000000080000003ull, 0x0000000080000000ull,
    };
    const uint64_t exp_ssublt_d[2] = {
        0x0000000000000000ull, 0x0000000000000000ull,
    };
    const uint64_t exp_usublb_d[2] = {
        0x000000007fffffffull, 0x0000000000000000ull,
    };
    const uint32_t exp_saddwb_s[4] = {
        0x80000003u, 0x80003fffu, 0x40003333u, 0xc0005555u,
    };
    const uint32_t exp_uaddwt_s[4] = {
        0x80008000u, 0x8000bfffu, 0x40002000u, 0xc000aaaau,
    };
    const uint32_t exp_ssubwt_s[4] = {
        0x7fff8002u, 0x80003fffu, 0x3fffe000u, 0xc0005556u,
    };
    const uint32_t exp_usubwb_s[4] = {
        0x7fffffffu, 0x7fffbfffu, 0x3fffcccdu, 0xbfffaaabu,
    };
    const uint64_t exp_saddwt_d[2] = {
        0x8000000080000000ull, 0x7fffffffbfffffffull,
    };
    const uint64_t exp_uaddwb_d[2] = {
        0x8000000000000003ull, 0x800000003fffffffull,
    };
    const uint64_t exp_ssubwb_d[2] = {
        0x7fffffffffffffffull, 0x7fffffffbfffffffull,
    };
    const uint64_t exp_usubwt_d[2] = {
        0x7fffffff80000002ull, 0x7fffffff3fffffffull,
    };
    const uint32_t exp_sshllb_s4[4] = {
        0xfff80010u, 0x00040000u, 0x00011110u, 0x00055550u,
    };
    const uint64_t exp_ushllt_d7[2] = {
        0x0000003fffffff80ull, 0x0000006000000000ull,
    };
    const uint32_t exp_saddlbt_s[4] = {
        0x00000000u, 0x00000000u, 0x00003111u, 0xffffffffu,
    };
    const uint64_t exp_ssubltb_d[2] = {
        0x000000007ffffffdull, 0xffffffff80000000ull,
    };
    const uint32_t exp_sabdlb_s[4] = {
        0x00008001u, 0x00000000u, 0x00002222u, 0x00000000u,
    };
    const uint64_t exp_uabdlb_d[2] = {
        0x000000007fffffffull, 0x0000000000000000ull,
    };
    const uint32_t exp_smullb_s[4] = {
        0xffff0002u, 0x10000000u, 0x0369c963u, 0x1c718e39u,
    };
    const uint64_t exp_umullt_d[2] = {
        0x3fffffff00000001ull, 0x9000000000000000ull,
    };
    const uint16_t exp_sqdmullb_h[8] = {
        0x7fff, 0x2000, 0xf800, 0x3872,
        0x0fe0, 0xebae, 0xff00, 0x01f8,
    };

    test_arm64_sve2_widen_run(0x45420020, 1, 0, 0, n_b, sizeof(n_b),
                              m_b, sizeof(m_b), exp_saddlb,
                              sizeof(exp_saddlb));
    test_arm64_sve2_widen_run(0x45420820, 1, 0, 0, n_b, sizeof(n_b),
                              m_b, sizeof(m_b), exp_uaddlb,
                              sizeof(exp_uaddlb));
    test_arm64_sve2_widen_run(0x45421020, 1, 0, 0, n_b, sizeof(n_b),
                              m_b, sizeof(m_b), exp_ssublb,
                              sizeof(exp_ssublb));
    test_arm64_sve2_widen_run(0x45421820, 1, 0, 0, n_b, sizeof(n_b),
                              m_b, sizeof(m_b), exp_usublb,
                              sizeof(exp_usublb));
    test_arm64_sve2_widen_run(0x45420420, 1, 0, 0, n_b, sizeof(n_b),
                              m_b, sizeof(m_b), exp_saddlt,
                              sizeof(exp_saddlt));
    test_arm64_sve2_widen_run(0x45420c20, 1, 0, 0, n_b, sizeof(n_b),
                              m_b, sizeof(m_b), exp_uaddlt,
                              sizeof(exp_uaddlt));
    test_arm64_sve2_widen_run(0x45421420, 1, 0, 0, n_b, sizeof(n_b),
                              m_b, sizeof(m_b), exp_ssublt,
                              sizeof(exp_ssublt));
    test_arm64_sve2_widen_run(0x45421c20, 1, 0, 0, n_b, sizeof(n_b),
                              m_b, sizeof(m_b), exp_usublt,
                              sizeof(exp_usublt));

    test_arm64_sve2_widen_run(0x45424020, 1, 1, 0, n_h, sizeof(n_h),
                              m_b, sizeof(m_b), exp_saddwb,
                              sizeof(exp_saddwb));
    test_arm64_sve2_widen_run(0x45424820, 1, 1, 0, n_h, sizeof(n_h),
                              m_b, sizeof(m_b), exp_uaddwb,
                              sizeof(exp_uaddwb));
    test_arm64_sve2_widen_run(0x45425020, 1, 1, 0, n_h, sizeof(n_h),
                              m_b, sizeof(m_b), exp_ssubwb,
                              sizeof(exp_ssubwb));
    test_arm64_sve2_widen_run(0x45425820, 1, 1, 0, n_h, sizeof(n_h),
                              m_b, sizeof(m_b), exp_usubwb,
                              sizeof(exp_usubwb));
    test_arm64_sve2_widen_run(0x45424420, 1, 1, 0, n_h, sizeof(n_h),
                              m_b, sizeof(m_b), exp_saddwt,
                              sizeof(exp_saddwt));
    test_arm64_sve2_widen_run(0x45424c20, 1, 1, 0, n_h, sizeof(n_h),
                              m_b, sizeof(m_b), exp_uaddwt,
                              sizeof(exp_uaddwt));
    test_arm64_sve2_widen_run(0x45425420, 1, 1, 0, n_h, sizeof(n_h),
                              m_b, sizeof(m_b), exp_ssubwt,
                              sizeof(exp_ssubwt));
    test_arm64_sve2_widen_run(0x45425c20, 1, 1, 0, n_h, sizeof(n_h),
                              m_b, sizeof(m_b), exp_usubwt,
                              sizeof(exp_usubwt));

    test_arm64_sve2_widen_run(0x4508a020, 1, 0, 0, n_b, sizeof(n_b),
                              NULL, 0, exp_sshllb, sizeof(exp_sshllb));
    test_arm64_sve2_widen_run(0x4508a820, 1, 0, 0, n_b, sizeof(n_b),
                              NULL, 0, exp_ushllb, sizeof(exp_ushllb));
    test_arm64_sve2_widen_run(0x4508a420, 1, 0, 0, n_b, sizeof(n_b),
                              NULL, 0, exp_sshllt, sizeof(exp_sshllt));
    test_arm64_sve2_widen_run(0x4508ac20, 1, 0, 0, n_b, sizeof(n_b),
                              NULL, 0, exp_ushllt, sizeof(exp_ushllt));

    test_arm64_sve2_widen_run(0x45820020, 2, 1, 1, n_h, sizeof(n_h),
                              m_h, sizeof(m_h), exp_saddlb_s,
                              sizeof(exp_saddlb_s));
    test_arm64_sve2_widen_run(0x45820c20, 2, 1, 1, n_h, sizeof(n_h),
                              m_h, sizeof(m_h), exp_uaddlt_s,
                              sizeof(exp_uaddlt_s));
    test_arm64_sve2_widen_run(0x45821020, 2, 1, 1, n_h, sizeof(n_h),
                              m_h, sizeof(m_h), exp_ssublb_s,
                              sizeof(exp_ssublb_s));
    test_arm64_sve2_widen_run(0x45821c20, 2, 1, 1, n_h, sizeof(n_h),
                              m_h, sizeof(m_h), exp_usublt_s,
                              sizeof(exp_usublt_s));
    test_arm64_sve2_widen_run(0x45c20420, 3, 2, 2, n_s, sizeof(n_s),
                              m_s, sizeof(m_s), exp_saddlt_d,
                              sizeof(exp_saddlt_d));
    test_arm64_sve2_widen_run(0x45c20820, 3, 2, 2, n_s, sizeof(n_s),
                              m_s, sizeof(m_s), exp_uaddlb_d,
                              sizeof(exp_uaddlb_d));
    test_arm64_sve2_widen_run(0x45c21420, 3, 2, 2, n_s, sizeof(n_s),
                              m_s, sizeof(m_s), exp_ssublt_d,
                              sizeof(exp_ssublt_d));
    test_arm64_sve2_widen_run(0x45c21820, 3, 2, 2, n_s, sizeof(n_s),
                              m_s, sizeof(m_s), exp_usublb_d,
                              sizeof(exp_usublb_d));

    test_arm64_sve2_widen_run(0x45824020, 2, 2, 1, n_s, sizeof(n_s),
                              m_h, sizeof(m_h), exp_saddwb_s,
                              sizeof(exp_saddwb_s));
    test_arm64_sve2_widen_run(0x45824c20, 2, 2, 1, n_s, sizeof(n_s),
                              m_h, sizeof(m_h), exp_uaddwt_s,
                              sizeof(exp_uaddwt_s));
    test_arm64_sve2_widen_run(0x45825420, 2, 2, 1, n_s, sizeof(n_s),
                              m_h, sizeof(m_h), exp_ssubwt_s,
                              sizeof(exp_ssubwt_s));
    test_arm64_sve2_widen_run(0x45825820, 2, 2, 1, n_s, sizeof(n_s),
                              m_h, sizeof(m_h), exp_usubwb_s,
                              sizeof(exp_usubwb_s));
    test_arm64_sve2_widen_run(0x45c24420, 3, 3, 2, n_d, sizeof(n_d),
                              m_s, sizeof(m_s), exp_saddwt_d,
                              sizeof(exp_saddwt_d));
    test_arm64_sve2_widen_run(0x45c24820, 3, 3, 2, n_d, sizeof(n_d),
                              m_s, sizeof(m_s), exp_uaddwb_d,
                              sizeof(exp_uaddwb_d));
    test_arm64_sve2_widen_run(0x45c25020, 3, 3, 2, n_d, sizeof(n_d),
                              m_s, sizeof(m_s), exp_ssubwb_d,
                              sizeof(exp_ssubwb_d));
    test_arm64_sve2_widen_run(0x45c25c20, 3, 3, 2, n_d, sizeof(n_d),
                              m_s, sizeof(m_s), exp_usubwt_d,
                              sizeof(exp_usubwt_d));

    test_arm64_sve2_widen_run(0x4514a020, 2, 1, 0, n_h, sizeof(n_h),
                              NULL, 0, exp_sshllb_s4,
                              sizeof(exp_sshllb_s4));
    test_arm64_sve2_widen_run(0x4547ac20, 3, 2, 0, n_s, sizeof(n_s),
                              NULL, 0, exp_ushllt_d7,
                              sizeof(exp_ushllt_d7));

    test_arm64_sve2_widen_run(0x45828020, 2, 1, 1, n_h, sizeof(n_h),
                              m_h, sizeof(m_h), exp_saddlbt_s,
                              sizeof(exp_saddlbt_s));
    test_arm64_sve2_widen_run(0x45c28c20, 3, 2, 2, n_s, sizeof(n_s),
                              m_s, sizeof(m_s), exp_ssubltb_d,
                              sizeof(exp_ssubltb_d));
    test_arm64_sve2_widen_run(0x45823020, 2, 1, 1, n_h, sizeof(n_h),
                              m_h, sizeof(m_h), exp_sabdlb_s,
                              sizeof(exp_sabdlb_s));
    test_arm64_sve2_widen_run(0x45c23820, 3, 2, 2, n_s, sizeof(n_s),
                              m_s, sizeof(m_s), exp_uabdlb_d,
                              sizeof(exp_uabdlb_d));
    test_arm64_sve2_widen_run(0x45827020, 2, 1, 1, n_h, sizeof(n_h),
                              m_h, sizeof(m_h), exp_smullb_s,
                              sizeof(exp_smullb_s));
    test_arm64_sve2_widen_run(0x45c27c20, 3, 2, 2, n_s, sizeof(n_s),
                              m_s, sizeof(m_s), exp_umullt_d,
                              sizeof(exp_umullt_d));
    test_arm64_sve2_widen_run(0x45426020, 1, 0, 0, sq_n_b, sizeof(sq_n_b),
                              sq_m_b, sizeof(sq_m_b), exp_sqdmullb_h,
                              sizeof(exp_sqdmullb_h));
}

static void test_arm64_sve2_addhn(void)
{
    const uint8_t init_b[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const uint16_t init_h[8] = {
        0xa000, 0xa001, 0xa002, 0xa003,
        0xa004, 0xa005, 0xa006, 0xa007,
    };
    const uint32_t init_s[4] = {
        0xa0000000u, 0xa0000001u, 0xa0000002u, 0xa0000003u,
    };
    const uint16_t n_h[8] = {
        0x1200, 0x12ff, 0x8000, 0x7fff,
        0xffff, 0x0001, 0x00ff, 0xff00,
    };
    const uint16_t m_h[8] = {
        0x0100, 0x0002, 0x8000, 0x0001,
        0x0002, 0xffff, 0xff00, 0x0100,
    };
    const uint32_t n_s[4] = {
        0x12000000u, 0x12ff0001u, 0x80000000u, 0x7fffffffu,
    };
    const uint32_t m_s[4] = {
        0x01000000u, 0x00020000u, 0x80000000u, 0x00000001u,
    };
    const uint64_t n_d[2] = {
        0x1200000000000000ull, 0x7fffffffffffffffull,
    };
    const uint64_t m_d[2] = {
        0x0100000000000000ull, 0x0000000100000001ull,
    };
    const uint8_t exp_addhnb_h[16] = {
        0x13, 0x00, 0x13, 0x00, 0x00, 0x00, 0x80, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00,
    };
    const uint8_t exp_subhnb_h[16] = {
        0x11, 0x00, 0x12, 0x00, 0x00, 0x00, 0x7f, 0x00,
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0xfe, 0x00,
    };
    const uint8_t exp_rsubhnt_h[16] = {
        0xa0, 0x11, 0xa2, 0x13, 0xa4, 0x00, 0xa6, 0x80,
        0xa8, 0x00, 0xaa, 0x00, 0xac, 0x02, 0xae, 0xfe,
    };
    const uint16_t exp_addhnt_s[8] = {
        0xa000, 0x1300, 0xa002, 0x1301,
        0xa004, 0x0000, 0xa006, 0x8000,
    };
    const uint16_t exp_raddhnb_s[8] = {
        0x1300, 0x0000, 0x1301, 0x0000,
        0x0000, 0x0000, 0x8000, 0x0000,
    };
    const uint16_t exp_subhnt_s[8] = {
        0xa000, 0x1100, 0xa002, 0x12fd,
        0xa004, 0x0000, 0xa006, 0x7fff,
    };
    const uint32_t exp_raddhnt_d[4] = {
        0xa0000000u, 0x13000000u, 0xa0000002u, 0x80000001u,
    };
    const uint32_t exp_rsubhnb_d[4] = {
        0x11000000u, 0x00000000u, 0x7fffffffu, 0x00000000u,
    };

    test_arm64_sve2_narrow_run(0x45626020, 0, 1, init_b, n_h, m_h,
                               exp_addhnb_h, sizeof(exp_addhnb_h));
    test_arm64_sve2_narrow_run(0x45627020, 0, 1, init_b, n_h, m_h,
                               exp_subhnb_h, sizeof(exp_subhnb_h));
    test_arm64_sve2_narrow_run(0x45627c20, 0, 1, init_b, n_h, m_h,
                               exp_rsubhnt_h, sizeof(exp_rsubhnt_h));
    test_arm64_sve2_narrow_run(0x45a26420, 1, 2, init_h, n_s, m_s,
                               exp_addhnt_s, sizeof(exp_addhnt_s));
    test_arm64_sve2_narrow_run(0x45a26820, 1, 2, init_h, n_s, m_s,
                               exp_raddhnb_s, sizeof(exp_raddhnb_s));
    test_arm64_sve2_narrow_run(0x45a27420, 1, 2, init_h, n_s, m_s,
                               exp_subhnt_s, sizeof(exp_subhnt_s));
    test_arm64_sve2_narrow_run(0x45e26c20, 2, 3, init_s, n_d, m_d,
                               exp_raddhnt_d, sizeof(exp_raddhnt_d));
    test_arm64_sve2_narrow_run(0x45e27820, 2, 3, init_s, n_d, m_d,
                               exp_rsubhnb_d, sizeof(exp_rsubhnb_d));
}

static void test_arm64_sve2_xtn(void)
{
    const uint8_t init_b[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const uint16_t init_h[8] = {
        0xa000, 0xa001, 0xa002, 0xa003,
        0xa004, 0xa005, 0xa006, 0xa007,
    };
    const uint32_t init_s[4] = {
        0xa0000000u, 0xa0000001u, 0xa0000002u, 0xa0000003u,
    };
    const uint16_t src_h[8] = {
        0x007f, 0x0080, 0xff80, 0xff7f,
        0x0000, 0xffff, 0x1234, 0x8000,
    };
    const uint32_t src_s[4] = {
        0x00007fffu, 0x00008000u, 0xffff8000u, 0xffff7fffu,
    };
    const uint64_t src_d[2] = {
        0x000000007fffffffull, 0x0000000080000000ull,
    };
    const uint8_t exp_sqxtnb_h[16] = {
        0x7f, 0x00, 0x7f, 0x00, 0x80, 0x00, 0x80, 0x00,
        0x00, 0x00, 0xff, 0x00, 0x7f, 0x00, 0x80, 0x00,
    };
    const uint8_t exp_sqxtnt_h[16] = {
        0xa0, 0x7f, 0xa2, 0x7f, 0xa4, 0x80, 0xa6, 0x80,
        0xa8, 0x00, 0xaa, 0xff, 0xac, 0x7f, 0xae, 0x80,
    };
    const uint16_t exp_uqxtnb_s[8] = {
        0x7fff, 0x0000, 0x8000, 0x0000,
        0xffff, 0x0000, 0xffff, 0x0000,
    };
    const uint8_t exp_sqxtunb_h[16] = {
        0x7f, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00,
    };
    const uint16_t exp_sqxtunt_s[8] = {
        0xa000, 0x7fff, 0xa002, 0x8000,
        0xa004, 0x0000, 0xa006, 0x0000,
    };
    const uint32_t exp_uqxtnt_d[4] = {
        0xa0000000u, 0x7fffffffu, 0xa0000002u, 0x80000000u,
    };

    test_arm64_sve2_narrow_run(0x45284020, 0, 1, init_b, src_h, src_h,
                               exp_sqxtnb_h, sizeof(exp_sqxtnb_h));
    test_arm64_sve2_narrow_run(0x45284420, 0, 1, init_b, src_h, src_h,
                               exp_sqxtnt_h, sizeof(exp_sqxtnt_h));
    test_arm64_sve2_narrow_run(0x45304820, 1, 2, init_h, src_s, src_s,
                               exp_uqxtnb_s, sizeof(exp_uqxtnb_s));
    test_arm64_sve2_narrow_run(0x45285020, 0, 1, init_b, src_h, src_h,
                               exp_sqxtunb_h, sizeof(exp_sqxtunb_h));
    test_arm64_sve2_narrow_run(0x45305420, 1, 2, init_h, src_s, src_s,
                               exp_sqxtunt_s, sizeof(exp_sqxtunt_s));
    test_arm64_sve2_narrow_run(0x45604c20, 2, 3, init_s, src_d, src_d,
                               exp_uqxtnt_d, sizeof(exp_uqxtnt_d));
}

static void test_arm64_sve2_shift_narrow(void)
{
    const uint8_t init_b[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const uint16_t init_h[8] = {
        0xa000, 0xa001, 0xa002, 0xa003,
        0xa004, 0xa005, 0xa006, 0xa007,
    };
    const uint32_t init_s[4] = {
        0xa0000000u, 0xa0000001u, 0xa0000002u, 0xa0000003u,
    };
    const uint16_t src_h[8] = {
        0x0000, 0x00ff, 0x0100, 0x7fff,
        0x8000, 0xff00, 0xffff, 0x1234,
    };
    const uint32_t src_s[4] = {
        0x00000000u, 0x0000ffffu, 0x00010000u, 0xffffffffu,
    };
    const uint32_t src_s_signed[4] = {
        0x00010000u, 0x7fffffffu, 0x80000000u, 0xffff0000u,
    };
    const uint64_t src_d[2] = {
        0x00000000ffffffffull, 0xffffffff00000000ull,
    };
    const uint64_t src_d_signed[2] = {
        0x0000000100000000ull, 0x8000000000000000ull,
    };
    const uint8_t exp_shrnb_h[16] = {
        0x00, 0x00, 0x1f, 0x00, 0x20, 0x00, 0xff, 0x00,
        0x00, 0x00, 0xe0, 0x00, 0xff, 0x00, 0x46, 0x00,
    };
    const uint8_t exp_shrnt_h[16] = {
        0xa0, 0x00, 0xa2, 0x0f, 0xa4, 0x10, 0xa6, 0xff,
        0xa8, 0x00, 0xaa, 0xf0, 0xac, 0xff, 0xae, 0x23,
    };
    const uint16_t exp_rshrnb_s[8] = {
        0x0000, 0x0000, 0x0800, 0x0000,
        0x0800, 0x0000, 0x0000, 0x0000,
    };
    const uint16_t exp_rshrnt_s[8] = {
        0xa000, 0x0000, 0xa002, 0x0400,
        0xa004, 0x0400, 0xa006, 0x0000,
    };
    const uint16_t exp_sqshrunb_s[8] = {
        0x1000, 0x0000, 0xffff, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000,
    };
    const uint32_t exp_sqrshrunt_d[4] = {
        0xa0000000u, 0x00000002u,
        0xa0000002u, 0x00000000u,
    };
    const uint32_t exp_sqrshrnt_d[4] = {
        0xa0000000u, 0x00000002u,
        0xa0000002u, 0x80000000u,
    };
    const uint8_t exp_sqshrnb_h[16] = {
        0x00, 0x00, 0x3f, 0x00, 0x40, 0x00, 0x7f, 0x00,
        0x80, 0x00, 0xc0, 0x00, 0xff, 0x00, 0x7f, 0x00,
    };
    const uint8_t exp_sqrshrunb_h[16] = {
        0x00, 0x00, 0x80, 0x00, 0x80, 0x00, 0xff, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00,
    };
    const uint32_t exp_uqshrnb_d[4] = {
        0x0fffffffu, 0x00000000u, 0xffffffffu, 0x00000000u,
    };
    const uint16_t exp_uqshrnt_s[8] = {
        0xa000, 0x0000, 0xa002, 0x1fff,
        0xa004, 0x2000, 0xa006, 0xffff,
    };
    const uint8_t exp_uqrshrnb_h[16] = {
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
        0x80, 0x00, 0xff, 0x00, 0xff, 0x00, 0x12, 0x00,
    };
    const uint8_t exp_uqrshrnt_h[16] = {
        0xa0, 0x00, 0xa2, 0x01, 0xa4, 0x01, 0xa6, 0x80,
        0xa8, 0x80, 0xaa, 0xff, 0xac, 0xff, 0xae, 0x12,
    };

    test_arm64_sve2_narrow_run(0x452d1020, 0, 1, init_b, src_h, src_h,
                               exp_shrnb_h, sizeof(exp_shrnb_h));
    test_arm64_sve2_narrow_run(0x452c1420, 0, 1, init_b, src_h, src_h,
                               exp_shrnt_h, sizeof(exp_shrnt_h));
    test_arm64_sve2_narrow_run(0x453b1820, 1, 2, init_h, src_s, src_s,
                               exp_rshrnb_s, sizeof(exp_rshrnb_s));
    test_arm64_sve2_narrow_run(0x453a1c20, 1, 2, init_h, src_s, src_s,
                               exp_rshrnt_s, sizeof(exp_rshrnt_s));
    test_arm64_sve2_narrow_run(0x453c0020, 1, 2, init_h, src_s_signed,
                               src_s_signed, exp_sqshrunb_s,
                               sizeof(exp_sqshrunb_s));
    test_arm64_sve2_narrow_run(0x45610c20, 2, 3, init_s, src_d_signed,
                               src_d_signed, exp_sqrshrunt_d,
                               sizeof(exp_sqrshrunt_d));
    test_arm64_sve2_narrow_run(0x45612c20, 2, 3, init_s, src_d_signed,
                               src_d_signed, exp_sqrshrnt_d,
                               sizeof(exp_sqrshrnt_d));
    test_arm64_sve2_narrow_run(0x452e2020, 0, 1, init_b, src_h, src_h,
                               exp_sqshrnb_h, sizeof(exp_sqshrnb_h));
    test_arm64_sve2_narrow_run(0x452f0820, 0, 1, init_b, src_h, src_h,
                               exp_sqrshrunb_h, sizeof(exp_sqrshrunb_h));
    test_arm64_sve2_narrow_run(0x457c3020, 2, 3, init_s, src_d, src_d,
                               exp_uqshrnb_d, sizeof(exp_uqshrnb_d));
    test_arm64_sve2_narrow_run(0x453d3420, 1, 2, init_h, src_s, src_s,
                               exp_uqshrnt_s, sizeof(exp_uqshrnt_s));
    test_arm64_sve2_narrow_run(0x45283820, 0, 1, init_b, src_h, src_h,
                               exp_uqrshrnb_h, sizeof(exp_uqrshrnb_h));
    test_arm64_sve2_narrow_run(0x45283c20, 0, 1, init_b, src_h, src_h,
                               exp_uqrshrnt_h, sizeof(exp_uqrshrnt_h));
}

static void test_arm64_sve2_shift_accumulate(void)
{
    const uint8_t init_b[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const uint8_t src_b[16] = {
        0x80, 0x7f, 0xff, 0x01, 0x40, 0xc0, 0x00, 0xfe,
        0x55, 0xaa, 0x08, 0xf8, 0x81, 0x7e, 0x02, 0x00,
    };
    const uint8_t exp_ssra_b[16] = {
        0x0f, 0x11, 0x11, 0x13, 0x14, 0x14, 0x16, 0x16,
        0x18, 0x18, 0x1a, 0x1a, 0x1b, 0x1d, 0x1e, 0x1f,
    };
    const uint16_t init_h[8] = {
        0x1000, 0x1001, 0x1002, 0x1003,
        0x1004, 0x1005, 0x1006, 0x1007,
    };
    const uint16_t src_h[8] = {
        0x00f0, 0xffff, 0x8000, 0x0001,
        0x1234, 0xf000, 0x0ff0, 0x7000,
    };
    const uint16_t exp_usra_h[8] = {
        0x100f, 0x2000, 0x1802, 0x1003,
        0x1127, 0x1f05, 0x1105, 0x1707,
    };
    const uint32_t init_s[4] = {
        0x10000000u, 0x10000001u, 0x10000002u, 0x10000003u,
    };
    const uint32_t src_s[4] = {
        0x0000001fu, 0xfffffff1u, 0x80000000u, 0x7ffffff8u,
    };
    const uint32_t exp_srsra_s[4] = {
        0x10000002u, 0x10000000u, 0x08000002u, 0x18000003u,
    };
    const uint64_t init_d[2] = {
        0x1000000000000000ull, 0x1000000000000001ull,
    };
    const uint64_t src_d[2] = {
        0x8000000000000000ull, 0x7fffffffffffffffull,
    };
    const uint64_t exp_ursra_d[2] = {
        0x1000000000000001ull, 0x1000000000000001ull,
    };

    test_arm64_sve2_narrow_run(0x4508e020, 0, 0, init_b, src_b, src_b,
                               exp_ssra_b, sizeof(exp_ssra_b));
    test_arm64_sve2_narrow_run(0x451ce420, 1, 1, init_h, src_h, src_h,
                               exp_usra_h, sizeof(exp_usra_h));
    test_arm64_sve2_narrow_run(0x455ce820, 2, 2, init_s, src_s, src_s,
                               exp_srsra_s, sizeof(exp_srsra_s));
    test_arm64_sve2_narrow_run(0x4580ec20, 3, 3, init_d, src_d, src_d,
                               exp_ursra_d, sizeof(exp_ursra_d));
}

static uint64_t test_arm64_sve2_load_elem(const uint8_t *data, size_t offset,
                                          int esz)
{
    uint64_t value = 0;
    unsigned bytes = 1u << esz;
    unsigned i;

    for (i = 0; i < bytes; i++) {
        value |= (uint64_t)data[offset + i] << (i * 8);
    }
    return value;
}

static void test_arm64_sve2_store_elem(uint8_t *data, size_t offset, int esz,
                                       uint64_t value)
{
    unsigned bytes = 1u << esz;
    unsigned i;

    for (i = 0; i < bytes; i++) {
        data[offset + i] = (uint8_t)(value >> (i * 8));
    }
}

static uint64_t test_arm64_sve2_elem_mask(int esz)
{
    unsigned bits = 8u << esz;

    return bits == 64 ? ~0ull : ((1ull << bits) - 1);
}

static uint64_t test_arm64_sve2_shift_insert_expected(uint64_t old,
                                                      uint64_t src,
                                                      int esz,
                                                      unsigned shift,
                                                      bool left)
{
    unsigned bits = 8u << esz;
    uint64_t mask = test_arm64_sve2_elem_mask(esz);

    old &= mask;
    src &= mask;
    if (left) {
        uint64_t low_mask;

        if (shift == 0) {
            return src;
        }
        low_mask = (1ull << shift) - 1;
        return (old & low_mask) | ((src << shift) & mask);
    } else {
        uint64_t low_mask;

        if (shift == bits) {
            return old;
        }
        low_mask = (1ull << (bits - shift)) - 1;
        return (old & (mask & ~low_mask)) | ((src >> shift) & low_mask);
    }
}

static void test_arm64_sve2_shift_insert_run(uint32_t insn, int esz,
                                             unsigned shift, bool left)
{
    static const uint32_t ld1_z0[4] = {
        0xa400a060, 0xa4a0a060, 0xa540a060, 0xa5e0a060,
    };
    static const uint32_t ld1_z1[4] = {
        0xa400a081, 0xa4a0a081, 0xa540a081, 0xa5e0a081,
    };
    static const uint32_t st1_z0[4] = {
        0xe400e0c0, 0xe4a0e0c0, 0xe540e0c0, 0xe5e0e0c0,
    };
    uc_engine *uc;
    uint8_t code[20];
    uint8_t initial[32];
    uint8_t source[32];
    uint8_t expected[32];
    uint8_t got[32];
    uint64_t x3 = 0x40000;
    uint64_t x4 = 0x40100;
    uint64_t x6 = 0x40200;
    unsigned bytes = 1u << esz;
    size_t i;

    for (i = 0; i < sizeof(initial); i++) {
        initial[i] = (uint8_t)(0xa5u + i * 13u);
        source[i] = (uint8_t)(0x3cu + i * 29u);
    }
    memcpy(expected, initial, sizeof(expected));
    for (i = 0; i < sizeof(expected); i += bytes) {
        uint64_t old = test_arm64_sve2_load_elem(initial, i, esz);
        uint64_t src = test_arm64_sve2_load_elem(source, i, esz);
        uint64_t res;

        res = test_arm64_sve2_shift_insert_expected(old, src, esz,
                                                    shift, left);
        test_arm64_sve2_store_elem(expected, i, esz, res);
    }

    test_arm64_emit32(code, 0, 0x2518e3e0);
    test_arm64_emit32(code, 4, ld1_z0[esz]);
    test_arm64_emit32(code, 8, ld1_z1[esz]);
    test_arm64_emit32(code, 12, insn);
    test_arm64_emit32(code, 16, st1_z0[esz]);

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x3, initial, sizeof(initial)));
    OK(uc_mem_write(uc, x4, source, sizeof(source)));
    test_arm64_mte_enable_sve_vq(uc, 1);
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, x6, got, sizeof(got)));
    for (i = 0; i < sizeof(got); i++) {
        TEST_CHECK_(got[i] == expected[i],
                    "insn %08x byte %zu got %02x expected %02x",
                    insn, i, got[i], expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_shift_insert(void)
{
    test_arm64_sve2_shift_insert_run(0x450df020, 0, 3, false);
    test_arm64_sve2_shift_insert_run(0x451cf020, 1, 4, false);
    test_arm64_sve2_shift_insert_run(0x455bf020, 2, 5, false);
    test_arm64_sve2_shift_insert_run(0x45d8f020, 3, 8, false);
    test_arm64_sve2_shift_insert_run(0x4508f020, 0, 8, false);

    test_arm64_sve2_shift_insert_run(0x450bf420, 0, 3, true);
    test_arm64_sve2_shift_insert_run(0x4514f420, 1, 4, true);
    test_arm64_sve2_shift_insert_run(0x4545f420, 2, 5, true);
    test_arm64_sve2_shift_insert_run(0x4588f420, 3, 8, true);
    test_arm64_sve2_shift_insert_run(0x4508f420, 0, 0, true);
}

static void test_arm64_sve2_sat_unary(void)
{
    uc_engine *uc;
    const char code_sqabs_b[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x60\xa0\x00\xa4" /* ld1b { z0.b },p0/z,[x3] */
        "\x81\xa0\x00\xa4" /* ld1b { z1.b },p0/z,[x4] */
        "\x80\xe0\x18\x25" /* ptrue p0.b,vl4 */
        "\x20\xa0\x08\x44" /* sqabs z0.b,p0/m,z1.b */
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\xc0\xe0\x00\xe4"; /* st1b { z0.b },p0,[x6] */
    const char code_sqneg_d[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\xe0\xa5" /* ld1d { z1.d },p0/z,[x4] */
        "\x20\xa0\xc9\x44" /* sqneg z0.d,p0/m,z1.d */
        "\xc0\xe0\xe0\xe5"; /* st1d { z0.d },p0,[x6] */
    const uint8_t init_b[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const uint8_t src_b[16] = {
        0x80, 0x81, 0xff, 0x7f, 0x01, 0xfe, 0x40, 0xc0,
        0x00, 0x55, 0xaa, 0x02, 0xfd, 0x10, 0xf0, 0x7e,
    };
    const uint8_t exp_sqabs_b[16] = {
        0x7f, 0x7f, 0x01, 0x7f, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const uint64_t src_d[2] = {
        0x8000000000000000ull, 0xffffffffffffffffull,
    };
    const uint64_t exp_sqneg_d[2] = {
        0x7fffffffffffffffull, 0x0000000000000001ull,
    };
    uint8_t got_b[16];
    uint64_t got_d[2];
    uint64_t x3 = 0x40000;
    uint64_t x4 = 0x40100;
    uint64_t x6 = 0x40200;
    int i;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_sqabs_b,
                    sizeof(code_sqabs_b) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x3, init_b, sizeof(init_b)));
    OK(uc_mem_write(uc, x4, src_b, sizeof(src_b)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_sqabs_b) - 1,
                    0, 0));
    OK(uc_mem_read(uc, x6, got_b, sizeof(got_b)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got_b[i] == exp_sqabs_b[i]);
    }
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_sqneg_d,
                    sizeof(code_sqneg_d) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, src_d, sizeof(src_d)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_sqneg_d) - 1,
                    0, 0));
    OK(uc_mem_read(uc, x6, got_d, sizeof(got_d)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_d[i] == exp_sqneg_d[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_adalp(void)
{
    const uint16_t init_h[8] = {
        0x0100, 0x0101, 0x0102, 0x0103,
        0x0104, 0x0105, 0x0106, 0x0107,
    };
    const uint32_t init_s[4] = {
        0x01000000u, 0x01000001u,
        0x01000002u, 0x01000003u,
    };
    const uint64_t init_d[2] = {
        0x0100000000000000ull, 0x0100000000000001ull,
    };
    const uint8_t src_b[16] = {
        0x02, 0x01, 0x80, 0xff, 0x81, 0x7f, 0x80, 0x80,
        0x01, 0x00, 0xf0, 0x10, 0x0f, 0xf0, 0xff, 0xff,
    };
    const uint16_t src_h[8] = {
        0x0001, 0xffff, 0x8000, 0x7fff,
        0xff00, 0x0100, 0x1234, 0xedcc,
    };
    const uint32_t src_s[4] = {
        0x00000001u, 0xffffffffu, 0x80000000u, 0x7fffffffu,
    };
    const uint32_t src_s_unsigned[4] = {
        0x00000001u, 0x00000002u, 0x80000000u, 0xffffffffu,
    };
    const uint16_t exp_sadalp_h[8] = {
        0x0103, 0x0080, 0x0102, 0x0003,
        0x0105, 0x0105, 0x0105, 0x0105,
    };
    const uint32_t exp_sadalp_s[4] = {
        0x01000000u, 0x01000000u,
        0x01000002u, 0x01000003u,
    };
    const uint64_t exp_sadalp_d[2] = {
        0x0100000000000000ull, 0x0100000000000000ull,
    };
    const uint16_t exp_uadalp_h[8] = {
        0x0103, 0x0280, 0x0202, 0x0203,
        0x0105, 0x0205, 0x0205, 0x0305,
    };
    const uint32_t exp_uadalp_s[4] = {
        0x01010000u, 0x01010000u,
        0x01010002u, 0x01010003u,
    };
    const uint64_t exp_uadalp_d[2] = {
        0x0100000000000003ull, 0x0100000180000000ull,
    };

    test_arm64_sve2_narrow_run(0x4444a020, 1, 0, init_h, src_b, src_b,
                               exp_sadalp_h, sizeof(exp_sadalp_h));
    test_arm64_sve2_narrow_run(0x4484a020, 2, 1, init_s, src_h, src_h,
                               exp_sadalp_s, sizeof(exp_sadalp_s));
    test_arm64_sve2_narrow_run(0x44c4a020, 3, 2, init_d, src_s, src_s,
                               exp_sadalp_d, sizeof(exp_sadalp_d));
    test_arm64_sve2_narrow_run(0x4445a020, 1, 0, init_h, src_b, src_b,
                               exp_uadalp_h, sizeof(exp_uadalp_h));
    test_arm64_sve2_narrow_run(0x4485a020, 2, 1, init_s, src_h, src_h,
                               exp_uadalp_s, sizeof(exp_uadalp_s));
    test_arm64_sve2_narrow_run(0x44c5a020, 3, 2, init_d, src_s_unsigned,
                               src_s_unsigned, exp_uadalp_d,
                               sizeof(exp_uadalp_d));
}

static void test_arm64_sve2_halving_add_sub(void)
{
    const uint8_t n_b[16] = {
        0x80, 0x7f, 0xff, 0x01, 0x40, 0xc0, 0x00, 0xfe,
        0x55, 0xaa, 0x08, 0xf8, 0x81, 0x7e, 0x02, 0x00,
    };
    const uint8_t m_b[16] = {
        0x80, 0x01, 0x02, 0xff, 0xc0, 0x40, 0xff, 0x02,
        0xaa, 0x55, 0xf8, 0x08, 0x7f, 0x82, 0xfe, 0x00,
    };
    const uint16_t n_h[8] = {
        0x8000, 0x7fff, 0xffff, 0x0001,
        0x4000, 0xc000, 0x0000, 0xfffe,
    };
    const uint16_t m_h[8] = {
        0x8000, 0x0001, 0x0002, 0xffff,
        0xc000, 0x4000, 0xffff, 0x0002,
    };
    const uint32_t n_s[4] = {
        0x80000000u, 0x7fffffffu, 0xffffffffu, 0x00000001u,
    };
    const uint32_t m_s[4] = {
        0x80000000u, 0x00000001u, 0x00000002u, 0xffffffffu,
    };
    const uint64_t n_d[2] = {
        0xffffffffffffffffull, 0x8000000000000000ull,
    };
    const uint64_t m_d[2] = {
        0x0000000000000001ull, 0x7fffffffffffffffull,
    };
    const uint8_t exp_shadd_b[16] = {
        0x80, 0x40, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00,
        0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t exp_uhadd_b[16] = {
        0x80, 0x40, 0x80, 0x80, 0x80, 0x80, 0x7f, 0x80,
        0x7f, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
    };
    const uint8_t exp_shsub_b[16] = {
        0x00, 0x3f, 0xfe, 0x01, 0x40, 0xc0, 0x00, 0xfe,
        0x55, 0xaa, 0x08, 0xf8, 0x81, 0x7e, 0x02, 0x00,
    };
    const uint8_t exp_uhsub_b[16] = {
        0x00, 0x3f, 0x7e, 0x81, 0xc0, 0x40, 0x80, 0x7e,
        0xd5, 0x2a, 0x88, 0x78, 0x01, 0xfe, 0x82, 0x00,
    };
    const uint8_t exp_srhadd_b[16] = {
        0x80, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t exp_urhadd_b[16] = {
        0x80, 0x40, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
    };
    const uint8_t exp_shsubr_b[16] = {
        0x00, 0xc1, 0x01, 0xff, 0xc0, 0x40, 0xff, 0x02,
        0xaa, 0x55, 0xf8, 0x08, 0x7f, 0x82, 0xfe, 0x00,
    };
    const uint16_t exp_shadd_h[8] = {
        0x8000, 0x4000, 0x0000, 0x0000,
        0x0000, 0x0000, 0xffff, 0x0000,
    };
    const uint16_t exp_uhadd_h[8] = {
        0x8000, 0x4000, 0x8000, 0x8000,
        0x8000, 0x8000, 0x7fff, 0x8000,
    };
    const uint16_t exp_shsub_h[8] = {
        0x0000, 0x3fff, 0xfffe, 0x0001,
        0x4000, 0xc000, 0x0000, 0xfffe,
    };
    const uint16_t exp_uhsub_h[8] = {
        0x0000, 0x3fff, 0x7ffe, 0x8001,
        0xc000, 0x4000, 0x8000, 0x7ffe,
    };
    const uint16_t exp_srhadd_h[8] = {
        0x8000, 0x4000, 0x0001, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000,
    };
    const uint16_t exp_urhadd_h[8] = {
        0x8000, 0x4000, 0x8001, 0x8000,
        0x8000, 0x8000, 0x8000, 0x8000,
    };
    const uint16_t exp_uhsubr_h[8] = {
        0x0000, 0xc001, 0x8001, 0x7fff,
        0x4000, 0xc000, 0x7fff, 0x8002,
    };
    const uint32_t exp_shadd_s[4] = {
        0x80000000u, 0x40000000u, 0x00000000u, 0x00000000u,
    };
    const uint32_t exp_uhadd_s[4] = {
        0x80000000u, 0x40000000u, 0x80000000u, 0x80000000u,
    };
    const uint32_t exp_shsub_s[4] = {
        0x00000000u, 0x3fffffffu, 0xfffffffeu, 0x00000001u,
    };
    const uint32_t exp_uhsub_s[4] = {
        0x00000000u, 0x3fffffffu, 0x7ffffffeu, 0x80000001u,
    };
    const uint32_t exp_srhadd_s[4] = {
        0x80000000u, 0x40000000u, 0x00000001u, 0x00000000u,
    };
    const uint32_t exp_urhadd_s[4] = {
        0x80000000u, 0x40000000u, 0x80000001u, 0x80000000u,
    };
    const uint64_t exp_shadd_d[2] = {
        0x0000000000000000ull, 0xffffffffffffffffull,
    };
    const uint64_t exp_uhadd_d[2] = {
        0x8000000000000000ull, 0x7fffffffffffffffull,
    };
    const uint64_t exp_shsub_d[2] = {
        0xffffffffffffffffull, 0x8000000000000000ull,
    };
    const uint64_t exp_uhsub_d[2] = {
        0x7fffffffffffffffull, 0x0000000000000000ull,
    };
    const uint64_t exp_srhadd_d[2] = {
        0x0000000000000000ull, 0x0000000000000000ull,
    };
    const uint64_t exp_urhadd_d[2] = {
        0x8000000000000000ull, 0x8000000000000000ull,
    };

    test_arm64_sve2_narrow_run(0x44108020, 0, 0, n_b, m_b, m_b,
                               exp_shadd_b, sizeof(exp_shadd_b));
    test_arm64_sve2_narrow_run(0x44508020, 1, 1, n_h, m_h, m_h,
                               exp_shadd_h, sizeof(exp_shadd_h));
    test_arm64_sve2_narrow_run(0x44908020, 2, 2, n_s, m_s, m_s,
                               exp_shadd_s, sizeof(exp_shadd_s));
    test_arm64_sve2_narrow_run(0x44d08020, 3, 3, n_d, m_d, m_d,
                               exp_shadd_d, sizeof(exp_shadd_d));
    test_arm64_sve2_narrow_run(0x44118020, 0, 0, n_b, m_b, m_b,
                               exp_uhadd_b, sizeof(exp_uhadd_b));
    test_arm64_sve2_narrow_run(0x44518020, 1, 1, n_h, m_h, m_h,
                               exp_uhadd_h, sizeof(exp_uhadd_h));
    test_arm64_sve2_narrow_run(0x44918020, 2, 2, n_s, m_s, m_s,
                               exp_uhadd_s, sizeof(exp_uhadd_s));
    test_arm64_sve2_narrow_run(0x44d18020, 3, 3, n_d, m_d, m_d,
                               exp_uhadd_d, sizeof(exp_uhadd_d));
    test_arm64_sve2_narrow_run(0x44128020, 0, 0, n_b, m_b, m_b,
                               exp_shsub_b, sizeof(exp_shsub_b));
    test_arm64_sve2_narrow_run(0x44528020, 1, 1, n_h, m_h, m_h,
                               exp_shsub_h, sizeof(exp_shsub_h));
    test_arm64_sve2_narrow_run(0x44928020, 2, 2, n_s, m_s, m_s,
                               exp_shsub_s, sizeof(exp_shsub_s));
    test_arm64_sve2_narrow_run(0x44d28020, 3, 3, n_d, m_d, m_d,
                               exp_shsub_d, sizeof(exp_shsub_d));
    test_arm64_sve2_narrow_run(0x44138020, 0, 0, n_b, m_b, m_b,
                               exp_uhsub_b, sizeof(exp_uhsub_b));
    test_arm64_sve2_narrow_run(0x44538020, 1, 1, n_h, m_h, m_h,
                               exp_uhsub_h, sizeof(exp_uhsub_h));
    test_arm64_sve2_narrow_run(0x44938020, 2, 2, n_s, m_s, m_s,
                               exp_uhsub_s, sizeof(exp_uhsub_s));
    test_arm64_sve2_narrow_run(0x44d38020, 3, 3, n_d, m_d, m_d,
                               exp_uhsub_d, sizeof(exp_uhsub_d));
    test_arm64_sve2_narrow_run(0x44148020, 0, 0, n_b, m_b, m_b,
                               exp_srhadd_b, sizeof(exp_srhadd_b));
    test_arm64_sve2_narrow_run(0x44548020, 1, 1, n_h, m_h, m_h,
                               exp_srhadd_h, sizeof(exp_srhadd_h));
    test_arm64_sve2_narrow_run(0x44948020, 2, 2, n_s, m_s, m_s,
                               exp_srhadd_s, sizeof(exp_srhadd_s));
    test_arm64_sve2_narrow_run(0x44d48020, 3, 3, n_d, m_d, m_d,
                               exp_srhadd_d, sizeof(exp_srhadd_d));
    test_arm64_sve2_narrow_run(0x44158020, 0, 0, n_b, m_b, m_b,
                               exp_urhadd_b, sizeof(exp_urhadd_b));
    test_arm64_sve2_narrow_run(0x44558020, 1, 1, n_h, m_h, m_h,
                               exp_urhadd_h, sizeof(exp_urhadd_h));
    test_arm64_sve2_narrow_run(0x44958020, 2, 2, n_s, m_s, m_s,
                               exp_urhadd_s, sizeof(exp_urhadd_s));
    test_arm64_sve2_narrow_run(0x44d58020, 3, 3, n_d, m_d, m_d,
                               exp_urhadd_d, sizeof(exp_urhadd_d));
    test_arm64_sve2_narrow_run(0x44168020, 0, 0, n_b, m_b, m_b,
                               exp_shsubr_b, sizeof(exp_shsubr_b));
    test_arm64_sve2_narrow_run(0x44578020, 1, 1, n_h, m_h, m_h,
                               exp_uhsubr_h, sizeof(exp_uhsubr_h));
}

static void test_arm64_sve2_pairwise_pred(void)
{
    const uint8_t n_b[16] = {
        0x80, 0x7f, 0xff, 0x01, 0x40, 0xc0, 0x00, 0xfe,
        0x55, 0xaa, 0x08, 0xf8, 0x81, 0x7e, 0x02, 0x00,
    };
    const uint8_t m_b[16] = {
        0x80, 0x01, 0x02, 0xff, 0xc0, 0x40, 0xff, 0x02,
        0xaa, 0x55, 0xf8, 0x08, 0x7f, 0x82, 0xfe, 0x00,
    };
    const uint16_t n_h[8] = {
        0x8000, 0x7fff, 0xffff, 0x0001,
        0x4000, 0xc000, 0x0000, 0xfffe,
    };
    const uint16_t m_h[8] = {
        0x8000, 0x0001, 0x0002, 0xffff,
        0xc000, 0x4000, 0xffff, 0x0002,
    };
    const uint32_t n_s[4] = {
        0x80000000u, 0x7fffffffu, 0xffffffffu, 0x00000001u,
    };
    const uint32_t m_s[4] = {
        0x80000000u, 0x00000001u, 0x00000002u, 0xffffffffu,
    };
    const uint64_t n_d[2] = {
        0x8000000000000000ull, 0x7fffffffffffffffull,
    };
    const uint64_t m_d[2] = {
        0xffffffffffffffffull, 0x0000000000000001ull,
    };
    const uint8_t exp_addp_b[16] = {
        0xff, 0x81, 0x00, 0x01, 0x00, 0x00, 0xfe, 0x01,
        0xff, 0xff, 0x00, 0x00, 0xff, 0x01, 0x02, 0xfe,
    };
    const uint8_t exp_smaxp_b[16] = {
        0x7f, 0x01, 0x01, 0x02, 0x40, 0x40, 0x00, 0x02,
        0x55, 0x55, 0x08, 0x08, 0x7e, 0x7f, 0x02, 0x00,
    };
    const uint8_t exp_umaxp_b[16] = {
        0x80, 0x80, 0xff, 0xff, 0xc0, 0xc0, 0xfe, 0xff,
        0xaa, 0xaa, 0xf8, 0xf8, 0x81, 0x82, 0x02, 0xfe,
    };
    const uint8_t exp_sminp_b[16] = {
        0x80, 0x80, 0xff, 0xff, 0xc0, 0xc0, 0xfe, 0xff,
        0xaa, 0xaa, 0xf8, 0xf8, 0x81, 0x82, 0x00, 0xfe,
    };
    const uint8_t exp_uminp_b[16] = {
        0x7f, 0x01, 0x01, 0x02, 0x40, 0x40, 0x00, 0x02,
        0x55, 0x55, 0x08, 0x08, 0x7e, 0x7f, 0x00, 0x00,
    };
    const uint16_t exp_addp_h[8] = {
        0xffff, 0x8001, 0x0000, 0x0001,
        0x0000, 0x0000, 0xfffe, 0x0001,
    };
    const uint16_t exp_smaxp_h[8] = {
        0x7fff, 0x0001, 0x0001, 0x0002,
        0x4000, 0x4000, 0x0000, 0x0002,
    };
    const uint16_t exp_umaxp_h[8] = {
        0x8000, 0x8000, 0xffff, 0xffff,
        0xc000, 0xc000, 0xfffe, 0xffff,
    };
    const uint16_t exp_sminp_h[8] = {
        0x8000, 0x8000, 0xffff, 0xffff,
        0xc000, 0xc000, 0xfffe, 0xffff,
    };
    const uint16_t exp_uminp_h[8] = {
        0x7fff, 0x0001, 0x0001, 0x0002,
        0x4000, 0x4000, 0x0000, 0x0002,
    };
    const uint32_t exp_addp_s[4] = {
        0xffffffffu, 0x80000001u, 0x00000000u, 0x00000001u,
    };
    const uint32_t exp_smaxp_s[4] = {
        0x7fffffffu, 0x00000001u, 0x00000001u, 0x00000002u,
    };
    const uint32_t exp_umaxp_s[4] = {
        0x80000000u, 0x80000000u, 0xffffffffu, 0xffffffffu,
    };
    const uint32_t exp_sminp_s[4] = {
        0x80000000u, 0x80000000u, 0xffffffffu, 0xffffffffu,
    };
    const uint32_t exp_uminp_s[4] = {
        0x7fffffffu, 0x00000001u, 0x00000001u, 0x00000002u,
    };
    const uint64_t exp_addp_d[2] = {
        0xffffffffffffffffull, 0x0000000000000000ull,
    };
    const uint64_t exp_smaxp_d[2] = {
        0x7fffffffffffffffull, 0x0000000000000001ull,
    };
    const uint64_t exp_umaxp_d[2] = {
        0x8000000000000000ull, 0xffffffffffffffffull,
    };
    const uint64_t exp_sminp_d[2] = {
        0x8000000000000000ull, 0xffffffffffffffffull,
    };
    const uint64_t exp_uminp_d[2] = {
        0x7fffffffffffffffull, 0x0000000000000001ull,
    };

    test_arm64_sve2_narrow_run(0x4411a020, 0, 0, n_b, m_b, m_b,
                               exp_addp_b, sizeof(exp_addp_b));
    test_arm64_sve2_narrow_run(0x4451a020, 1, 1, n_h, m_h, m_h,
                               exp_addp_h, sizeof(exp_addp_h));
    test_arm64_sve2_narrow_run(0x4491a020, 2, 2, n_s, m_s, m_s,
                               exp_addp_s, sizeof(exp_addp_s));
    test_arm64_sve2_narrow_run(0x44d1a020, 3, 3, n_d, m_d, m_d,
                               exp_addp_d, sizeof(exp_addp_d));
    test_arm64_sve2_narrow_run(0x4414a020, 0, 0, n_b, m_b, m_b,
                               exp_smaxp_b, sizeof(exp_smaxp_b));
    test_arm64_sve2_narrow_run(0x4454a020, 1, 1, n_h, m_h, m_h,
                               exp_smaxp_h, sizeof(exp_smaxp_h));
    test_arm64_sve2_narrow_run(0x4494a020, 2, 2, n_s, m_s, m_s,
                               exp_smaxp_s, sizeof(exp_smaxp_s));
    test_arm64_sve2_narrow_run(0x44d4a020, 3, 3, n_d, m_d, m_d,
                               exp_smaxp_d, sizeof(exp_smaxp_d));
    test_arm64_sve2_narrow_run(0x4415a020, 0, 0, n_b, m_b, m_b,
                               exp_umaxp_b, sizeof(exp_umaxp_b));
    test_arm64_sve2_narrow_run(0x4455a020, 1, 1, n_h, m_h, m_h,
                               exp_umaxp_h, sizeof(exp_umaxp_h));
    test_arm64_sve2_narrow_run(0x4495a020, 2, 2, n_s, m_s, m_s,
                               exp_umaxp_s, sizeof(exp_umaxp_s));
    test_arm64_sve2_narrow_run(0x44d5a020, 3, 3, n_d, m_d, m_d,
                               exp_umaxp_d, sizeof(exp_umaxp_d));
    test_arm64_sve2_narrow_run(0x4416a020, 0, 0, n_b, m_b, m_b,
                               exp_sminp_b, sizeof(exp_sminp_b));
    test_arm64_sve2_narrow_run(0x4456a020, 1, 1, n_h, m_h, m_h,
                               exp_sminp_h, sizeof(exp_sminp_h));
    test_arm64_sve2_narrow_run(0x4496a020, 2, 2, n_s, m_s, m_s,
                               exp_sminp_s, sizeof(exp_sminp_s));
    test_arm64_sve2_narrow_run(0x44d6a020, 3, 3, n_d, m_d, m_d,
                               exp_sminp_d, sizeof(exp_sminp_d));
    test_arm64_sve2_narrow_run(0x4417a020, 0, 0, n_b, m_b, m_b,
                               exp_uminp_b, sizeof(exp_uminp_b));
    test_arm64_sve2_narrow_run(0x4457a020, 1, 1, n_h, m_h, m_h,
                               exp_uminp_h, sizeof(exp_uminp_h));
    test_arm64_sve2_narrow_run(0x4497a020, 2, 2, n_s, m_s, m_s,
                               exp_uminp_s, sizeof(exp_uminp_s));
    test_arm64_sve2_narrow_run(0x44d7a020, 3, 3, n_d, m_d, m_d,
                               exp_uminp_d, sizeof(exp_uminp_d));
}

static void test_arm64_sve2_saturating_add_sub(void)
{
    uc_engine *uc;
    const char code_pred[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x60\xa0\x00\xa4" /* ld1b { z0.b },p0/z,[x3] */
        "\x81\xa0\x00\xa4" /* ld1b { z1.b },p0/z,[x4] */
        "\x80\xe0\x18\x25" /* ptrue p0.b,vl4 */
        "\x20\x80\x18\x44" /* sqadd z0.b,p0/m,z0.b,z1.b */
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\xc0\xe0\x00\xe4"; /* st1b { z0.b },p0,[x6] */
    const uint8_t n_b[16] = {
        0x80, 0x7f, 0xff, 0x01, 0x40, 0xc0, 0x00, 0xfe,
        0x55, 0xaa, 0x08, 0xf8, 0x81, 0x7e, 0x02, 0x00,
    };
    const uint8_t m_b[16] = {
        0x80, 0x01, 0x02, 0xff, 0xc0, 0x40, 0xff, 0x02,
        0xaa, 0x55, 0xf8, 0x08, 0x7f, 0x82, 0xfe, 0x00,
    };
    const uint16_t n_h[8] = {
        0x8000, 0x7fff, 0xffff, 0x0001,
        0x4000, 0xc000, 0x0000, 0xfffe,
    };
    const uint16_t m_h[8] = {
        0x8000, 0x0001, 0x0002, 0xffff,
        0xc000, 0x4000, 0xffff, 0x0002,
    };
    const uint32_t n_s[4] = {
        0x80000000u, 0x7fffffffu, 0xffffffffu, 0x00000001u,
    };
    const uint32_t m_s[4] = {
        0x80000000u, 0x00000001u, 0x00000002u, 0xffffffffu,
    };
    const uint64_t n_d[2] = {
        0x7fffffffffffffffull, 0x8000000000000000ull,
    };
    const uint64_t m_d[2] = {
        0x0000000000000001ull, 0xffffffffffffffffull,
    };
    const uint8_t exp_pred_b[16] = {
        0x80, 0x7f, 0x01, 0x00, 0x40, 0xc0, 0x00, 0xfe,
        0x55, 0xaa, 0x08, 0xf8, 0x81, 0x7e, 0x02, 0x00,
    };
    const uint8_t exp_sqadd_b[16] = {
        0x80, 0x7f, 0x01, 0x00, 0x00, 0x00, 0xff, 0x00,
        0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t exp_uqadd_b[16] = {
        0xff, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
    };
    const uint8_t exp_sqsub_b[16] = {
        0x00, 0x7e, 0xfd, 0x02, 0x7f, 0x80, 0x01, 0xfc,
        0x7f, 0x80, 0x10, 0xf0, 0x80, 0x7f, 0x04, 0x00,
    };
    const uint8_t exp_uqsub_b[16] = {
        0x00, 0x7e, 0xfd, 0x00, 0x00, 0x80, 0x00, 0xfc,
        0x00, 0x55, 0x00, 0xf0, 0x02, 0x00, 0x00, 0x00,
    };
    const uint8_t exp_suqadd_b[16] = {
        0x00, 0x7f, 0x01, 0x7f, 0x7f, 0x00, 0x7f, 0x00,
        0x7f, 0xff, 0x7f, 0x00, 0x00, 0x7f, 0x7f, 0x00,
    };
    const uint8_t exp_usqadd_b[16] = {
        0x00, 0x80, 0xff, 0x00, 0x00, 0xff, 0x00, 0xff,
        0x00, 0xff, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00,
    };
    const uint8_t exp_sqsubr_b[16] = {
        0x00, 0x82, 0x03, 0xfe, 0x80, 0x7f, 0xff, 0x04,
        0x80, 0x7f, 0xf0, 0x10, 0x7f, 0x80, 0xfc, 0x00,
    };
    const uint16_t exp_sqadd_h[8] = {
        0x8000, 0x7fff, 0x0001, 0x0000,
        0x0000, 0x0000, 0xffff, 0x0000,
    };
    const uint16_t exp_uqadd_h[8] = {
        0xffff, 0x8000, 0xffff, 0xffff,
        0xffff, 0xffff, 0xffff, 0xffff,
    };
    const uint16_t exp_sqsub_h[8] = {
        0x0000, 0x7ffe, 0xfffd, 0x0002,
        0x7fff, 0x8000, 0x0001, 0xfffc,
    };
    const uint16_t exp_uqsub_h[8] = {
        0x0000, 0x7ffe, 0xfffd, 0x0000,
        0x0000, 0x8000, 0x0000, 0xfffc,
    };
    const uint16_t exp_suqadd_h[8] = {
        0x0000, 0x7fff, 0x0001, 0x7fff,
        0x7fff, 0x0000, 0x7fff, 0x0000,
    };
    const uint16_t exp_usqadd_h[8] = {
        0x0000, 0x8000, 0xffff, 0x0000,
        0x0000, 0xffff, 0x0000, 0xffff,
    };
    const uint16_t exp_uqsubr_h[8] = {
        0x0000, 0x0000, 0x0000, 0xfffe,
        0x8000, 0x0000, 0xffff, 0x0000,
    };
    const uint32_t exp_sqadd_s[4] = {
        0x80000000u, 0x7fffffffu, 0x00000001u, 0x00000000u,
    };
    const uint32_t exp_uqadd_s[4] = {
        0xffffffffu, 0x80000000u, 0xffffffffu, 0xffffffffu,
    };
    const uint32_t exp_sqsub_s[4] = {
        0x00000000u, 0x7ffffffeu, 0xfffffffdu, 0x00000002u,
    };
    const uint32_t exp_uqsub_s[4] = {
        0x00000000u, 0x7ffffffeu, 0xfffffffdu, 0x00000000u,
    };
    const uint32_t exp_suqadd_s[4] = {
        0x00000000u, 0x7fffffffu, 0x00000001u, 0x7fffffffu,
    };
    const uint32_t exp_usqadd_s[4] = {
        0x00000000u, 0x80000000u, 0xffffffffu, 0x00000000u,
    };
    const uint64_t exp_sqadd_d[2] = {
        0x7fffffffffffffffull, 0x8000000000000000ull,
    };
    const uint64_t exp_uqadd_d[2] = {
        0x8000000000000000ull, 0xffffffffffffffffull,
    };
    const uint64_t exp_sqsub_d[2] = {
        0x7ffffffffffffffeull, 0x8000000000000001ull,
    };
    const uint64_t exp_uqsub_d[2] = {
        0x7ffffffffffffffeull, 0x0000000000000000ull,
    };
    const uint64_t exp_suqadd_d[2] = {
        0x7fffffffffffffffull, 0x7fffffffffffffffull,
    };
    const uint64_t exp_usqadd_d[2] = {
        0x8000000000000000ull, 0x7fffffffffffffffull,
    };
    const uint64_t exp_sqsubr_d[2] = {
        0x8000000000000002ull, 0x7fffffffffffffffull,
    };
    const uint64_t exp_uqsubr_d[2] = {
        0x0000000000000000ull, 0x7fffffffffffffffull,
    };
    uint8_t got_b[16];
    uint64_t x3 = 0x40000;
    uint64_t x4 = 0x40100;
    uint64_t x6 = 0x40200;
    int i;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_pred,
                    sizeof(code_pred) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x3, n_b, sizeof(n_b)));
    OK(uc_mem_write(uc, x4, m_b, sizeof(m_b)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_pred) - 1,
                    0, 0));
    OK(uc_mem_read(uc, x6, got_b, sizeof(got_b)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got_b[i] == exp_pred_b[i]);
    }
    OK(uc_close(uc));

    test_arm64_sve2_narrow_run(0x44188020, 0, 0, n_b, m_b, m_b,
                               exp_sqadd_b, sizeof(exp_sqadd_b));
    test_arm64_sve2_narrow_run(0x44588020, 1, 1, n_h, m_h, m_h,
                               exp_sqadd_h, sizeof(exp_sqadd_h));
    test_arm64_sve2_narrow_run(0x44988020, 2, 2, n_s, m_s, m_s,
                               exp_sqadd_s, sizeof(exp_sqadd_s));
    test_arm64_sve2_narrow_run(0x44d88020, 3, 3, n_d, m_d, m_d,
                               exp_sqadd_d, sizeof(exp_sqadd_d));
    test_arm64_sve2_narrow_run(0x44198020, 0, 0, n_b, m_b, m_b,
                               exp_uqadd_b, sizeof(exp_uqadd_b));
    test_arm64_sve2_narrow_run(0x44598020, 1, 1, n_h, m_h, m_h,
                               exp_uqadd_h, sizeof(exp_uqadd_h));
    test_arm64_sve2_narrow_run(0x44998020, 2, 2, n_s, m_s, m_s,
                               exp_uqadd_s, sizeof(exp_uqadd_s));
    test_arm64_sve2_narrow_run(0x44d98020, 3, 3, n_d, m_d, m_d,
                               exp_uqadd_d, sizeof(exp_uqadd_d));
    test_arm64_sve2_narrow_run(0x441a8020, 0, 0, n_b, m_b, m_b,
                               exp_sqsub_b, sizeof(exp_sqsub_b));
    test_arm64_sve2_narrow_run(0x445a8020, 1, 1, n_h, m_h, m_h,
                               exp_sqsub_h, sizeof(exp_sqsub_h));
    test_arm64_sve2_narrow_run(0x449a8020, 2, 2, n_s, m_s, m_s,
                               exp_sqsub_s, sizeof(exp_sqsub_s));
    test_arm64_sve2_narrow_run(0x44da8020, 3, 3, n_d, m_d, m_d,
                               exp_sqsub_d, sizeof(exp_sqsub_d));
    test_arm64_sve2_narrow_run(0x441b8020, 0, 0, n_b, m_b, m_b,
                               exp_uqsub_b, sizeof(exp_uqsub_b));
    test_arm64_sve2_narrow_run(0x445b8020, 1, 1, n_h, m_h, m_h,
                               exp_uqsub_h, sizeof(exp_uqsub_h));
    test_arm64_sve2_narrow_run(0x449b8020, 2, 2, n_s, m_s, m_s,
                               exp_uqsub_s, sizeof(exp_uqsub_s));
    test_arm64_sve2_narrow_run(0x44db8020, 3, 3, n_d, m_d, m_d,
                               exp_uqsub_d, sizeof(exp_uqsub_d));
    test_arm64_sve2_narrow_run(0x441c8020, 0, 0, n_b, m_b, m_b,
                               exp_suqadd_b, sizeof(exp_suqadd_b));
    test_arm64_sve2_narrow_run(0x445c8020, 1, 1, n_h, m_h, m_h,
                               exp_suqadd_h, sizeof(exp_suqadd_h));
    test_arm64_sve2_narrow_run(0x449c8020, 2, 2, n_s, m_s, m_s,
                               exp_suqadd_s, sizeof(exp_suqadd_s));
    test_arm64_sve2_narrow_run(0x44dc8020, 3, 3, n_d, m_d, m_d,
                               exp_suqadd_d, sizeof(exp_suqadd_d));
    test_arm64_sve2_narrow_run(0x441d8020, 0, 0, n_b, m_b, m_b,
                               exp_usqadd_b, sizeof(exp_usqadd_b));
    test_arm64_sve2_narrow_run(0x445d8020, 1, 1, n_h, m_h, m_h,
                               exp_usqadd_h, sizeof(exp_usqadd_h));
    test_arm64_sve2_narrow_run(0x449d8020, 2, 2, n_s, m_s, m_s,
                               exp_usqadd_s, sizeof(exp_usqadd_s));
    test_arm64_sve2_narrow_run(0x44dd8020, 3, 3, n_d, m_d, m_d,
                               exp_usqadd_d, sizeof(exp_usqadd_d));
    test_arm64_sve2_narrow_run(0x441e8020, 0, 0, n_b, m_b, m_b,
                               exp_sqsubr_b, sizeof(exp_sqsubr_b));
    test_arm64_sve2_narrow_run(0x445f8020, 1, 1, n_h, m_h, m_h,
                               exp_uqsubr_h, sizeof(exp_uqsubr_h));
    test_arm64_sve2_narrow_run(0x44de8020, 3, 3, n_d, m_d, m_d,
                               exp_sqsubr_d, sizeof(exp_sqsubr_d));
    test_arm64_sve2_narrow_run(0x44df8020, 3, 3, n_d, m_d, m_d,
                               exp_uqsubr_d, sizeof(exp_uqsubr_d));
}

static void test_arm64_sve2_int_estimate(void)
{
    uc_engine *uc;
    uint8_t invalid_code[8];
    const uint32_t src_s[4] = {
        0x00000000u, 0x40000000u, 0x80000000u, 0xffffffffu,
    };
    const uint32_t exp_urecpe_s[4] = {
        0xffffffffu, 0xffffffffu, 0xff800000u, 0x80000000u,
    };
    const uint32_t exp_ursqrte_s[4] = {
        0xffffffffu, 0xff800000u, 0xb4800000u, 0x80000000u,
    };

    test_arm64_sve2_narrow_run(0x4480a020, 2, 2, src_s, src_s, src_s,
                               exp_urecpe_s, sizeof(exp_urecpe_s));
    test_arm64_sve2_narrow_run(0x4481a020, 2, 2, src_s, src_s, src_s,
                               exp_ursqrte_s, sizeof(exp_ursqrte_s));

    test_arm64_emit32(invalid_code, 0, 0x2518e3e0);
    test_arm64_emit32(invalid_code, 4, 0x4440a020);
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM,
                    (const char *)invalid_code, sizeof(invalid_code),
                    UC_CPU_ARM64_MAX);
    test_arm64_mte_enable_sve(uc);
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(invalid_code), 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_close(uc));
}

static void test_arm64_sve2_variable_shift(void)
{
    const uint8_t var_n_b[16] = {
        0x7f, 0x40, 0x81, 0x80, 0x55, 0xaa, 0x01, 0xff,
        0x10, 0xf0, 0x7e, 0x02, 0xfe, 0x00, 0x33, 0xcc,
    };
    const uint8_t var_shift_b[16] = {
        0x01, 0x02, 0x01, 0x01, 0xff, 0xfe, 0x07, 0x08,
        0xf8, 0xf7, 0x00, 0x04, 0x84, 0x7f, 0xfc, 0x03,
    };
    const uint8_t exp_srshl_b[16] = {
        0xfe, 0x00, 0x02, 0x00, 0x2b, 0xeb, 0x80, 0x00,
        0x00, 0x00, 0x7e, 0x20, 0x00, 0x00, 0x03, 0x60,
    };
    const uint8_t exp_urshl_b[16] = {
        0xfe, 0x00, 0x02, 0x00, 0x2b, 0x2b, 0x80, 0x00,
        0x00, 0x00, 0x7e, 0x20, 0x00, 0x00, 0x03, 0x60,
    };
    const uint8_t exp_sqshl_b[16] = {
        0x7f, 0x7f, 0x80, 0x80, 0x2a, 0xea, 0x7f, 0x80,
        0x00, 0xff, 0x7e, 0x20, 0xff, 0x00, 0x03, 0x80,
    };
    const uint8_t exp_uqshl_b[16] = {
        0xfe, 0xff, 0xff, 0xff, 0x2a, 0x2a, 0x80, 0xff,
        0x00, 0x00, 0x7e, 0x20, 0x00, 0x00, 0x03, 0xff,
    };
    const uint8_t exp_sqrshl_b[16] = {
        0x7f, 0x7f, 0x80, 0x80, 0x2b, 0xeb, 0x7f, 0x80,
        0x00, 0x00, 0x7e, 0x20, 0x00, 0x00, 0x03, 0x80,
    };
    const uint8_t exp_uqrshl_b[16] = {
        0xfe, 0xff, 0xff, 0xff, 0x2b, 0x2b, 0x80, 0xff,
        0x00, 0x00, 0x7e, 0x20, 0x00, 0x00, 0x03, 0xff,
    };
    const uint16_t var_n_h[8] = {
        0x7fff, 0x4000, 0x8001, 0x8000,
        0x1234, 0xedcc, 0x0001, 0xffff,
    };
    const uint16_t var_shift_h[8] = {
        0x0001, 0x0002, 0x0001, 0x0001,
        0xffff, 0xfffe, 0x000f, 0x0010,
    };
    const uint16_t exp_srshl_h[8] = {
        0xfffe, 0x0000, 0x0002, 0x0000,
        0x091a, 0xfb73, 0x8000, 0x0000,
    };
    const uint16_t exp_urshl_h[8] = {
        0xfffe, 0x0000, 0x0002, 0x0000,
        0x091a, 0x3b73, 0x8000, 0x0000,
    };
    const uint16_t exp_sqshl_h[8] = {
        0x7fff, 0x7fff, 0x8000, 0x8000,
        0x091a, 0xfb73, 0x7fff, 0x8000,
    };
    const uint16_t exp_uqshl_h[8] = {
        0xfffe, 0xffff, 0xffff, 0xffff,
        0x091a, 0x3b73, 0x8000, 0xffff,
    };
    const uint16_t exp_sqrshl_h[8] = {
        0x7fff, 0x7fff, 0x8000, 0x8000,
        0x091a, 0xfb73, 0x7fff, 0x8000,
    };
    const uint16_t exp_uqrshl_h[8] = {
        0xfffe, 0xffff, 0xffff, 0xffff,
        0x091a, 0x3b73, 0x8000, 0xffff,
    };
    const uint32_t var_n_s[4] = {
        0x7fffffffu, 0x40000000u, 0x80000001u, 0x80000000u,
    };
    const uint32_t var_shift_s[4] = {
        0x00000001u, 0x00000002u, 0xffffffffu, 0x00000020u,
    };
    const uint32_t exp_srshl_s[4] = {
        0xfffffffeu, 0x00000000u, 0xc0000001u, 0x00000000u,
    };
    const uint32_t exp_urshl_s[4] = {
        0xfffffffeu, 0x00000000u, 0x40000001u, 0x00000000u,
    };
    const uint32_t exp_sqshl_s[4] = {
        0x7fffffffu, 0x7fffffffu, 0xc0000000u, 0x80000000u,
    };
    const uint32_t exp_uqshl_s[4] = {
        0xfffffffeu, 0xffffffffu, 0x40000000u, 0xffffffffu,
    };
    const uint32_t exp_sqrshl_s[4] = {
        0x7fffffffu, 0x7fffffffu, 0xc0000001u, 0x80000000u,
    };
    const uint32_t exp_uqrshl_s[4] = {
        0xfffffffeu, 0xffffffffu, 0x40000001u, 0xffffffffu,
    };
    const uint64_t var_n_d[2] = {
        0x7fffffffffffffffull, 0x8000000000000000ull,
    };
    const uint64_t var_shift_d[2] = {
        0x0000000000000001ull, 0xffffffffffffffffull,
    };
    const uint64_t exp_srshl_d[2] = {
        0xfffffffffffffffeull, 0xc000000000000000ull,
    };
    const uint64_t exp_urshl_d[2] = {
        0xfffffffffffffffeull, 0x4000000000000000ull,
    };
    const uint64_t exp_sqshl_d[2] = {
        0x7fffffffffffffffull, 0xc000000000000000ull,
    };
    const uint64_t exp_uqshl_d[2] = {
        0xfffffffffffffffeull, 0x4000000000000000ull,
    };
    const uint64_t exp_sqrshl_d[2] = {
        0x7fffffffffffffffull, 0xc000000000000000ull,
    };
    const uint64_t exp_uqrshl_d[2] = {
        0xfffffffffffffffeull, 0x4000000000000000ull,
    };

    test_arm64_sve2_narrow_run(0x44028020, 0, 0, var_n_b, var_shift_b,
                               var_shift_b, exp_srshl_b,
                               sizeof(exp_srshl_b));
    test_arm64_sve2_narrow_run(0x44428020, 1, 1, var_n_h, var_shift_h,
                               var_shift_h, exp_srshl_h,
                               sizeof(exp_srshl_h));
    test_arm64_sve2_narrow_run(0x44828020, 2, 2, var_n_s, var_shift_s,
                               var_shift_s, exp_srshl_s,
                               sizeof(exp_srshl_s));
    test_arm64_sve2_narrow_run(0x44c28020, 3, 3, var_n_d, var_shift_d,
                               var_shift_d, exp_srshl_d,
                               sizeof(exp_srshl_d));
    test_arm64_sve2_narrow_run(0x44038020, 0, 0, var_n_b, var_shift_b,
                               var_shift_b, exp_urshl_b,
                               sizeof(exp_urshl_b));
    test_arm64_sve2_narrow_run(0x44438020, 1, 1, var_n_h, var_shift_h,
                               var_shift_h, exp_urshl_h,
                               sizeof(exp_urshl_h));
    test_arm64_sve2_narrow_run(0x44838020, 2, 2, var_n_s, var_shift_s,
                               var_shift_s, exp_urshl_s,
                               sizeof(exp_urshl_s));
    test_arm64_sve2_narrow_run(0x44c38020, 3, 3, var_n_d, var_shift_d,
                               var_shift_d, exp_urshl_d,
                               sizeof(exp_urshl_d));
    test_arm64_sve2_narrow_run(0x44088020, 0, 0, var_n_b, var_shift_b,
                               var_shift_b, exp_sqshl_b,
                               sizeof(exp_sqshl_b));
    test_arm64_sve2_narrow_run(0x44488020, 1, 1, var_n_h, var_shift_h,
                               var_shift_h, exp_sqshl_h,
                               sizeof(exp_sqshl_h));
    test_arm64_sve2_narrow_run(0x44888020, 2, 2, var_n_s, var_shift_s,
                               var_shift_s, exp_sqshl_s,
                               sizeof(exp_sqshl_s));
    test_arm64_sve2_narrow_run(0x44c88020, 3, 3, var_n_d, var_shift_d,
                               var_shift_d, exp_sqshl_d,
                               sizeof(exp_sqshl_d));
    test_arm64_sve2_narrow_run(0x44098020, 0, 0, var_n_b, var_shift_b,
                               var_shift_b, exp_uqshl_b,
                               sizeof(exp_uqshl_b));
    test_arm64_sve2_narrow_run(0x44498020, 1, 1, var_n_h, var_shift_h,
                               var_shift_h, exp_uqshl_h,
                               sizeof(exp_uqshl_h));
    test_arm64_sve2_narrow_run(0x44898020, 2, 2, var_n_s, var_shift_s,
                               var_shift_s, exp_uqshl_s,
                               sizeof(exp_uqshl_s));
    test_arm64_sve2_narrow_run(0x44c98020, 3, 3, var_n_d, var_shift_d,
                               var_shift_d, exp_uqshl_d,
                               sizeof(exp_uqshl_d));
    test_arm64_sve2_narrow_run(0x440a8020, 0, 0, var_n_b, var_shift_b,
                               var_shift_b, exp_sqrshl_b,
                               sizeof(exp_sqrshl_b));
    test_arm64_sve2_narrow_run(0x444a8020, 1, 1, var_n_h, var_shift_h,
                               var_shift_h, exp_sqrshl_h,
                               sizeof(exp_sqrshl_h));
    test_arm64_sve2_narrow_run(0x448a8020, 2, 2, var_n_s, var_shift_s,
                               var_shift_s, exp_sqrshl_s,
                               sizeof(exp_sqrshl_s));
    test_arm64_sve2_narrow_run(0x44ca8020, 3, 3, var_n_d, var_shift_d,
                               var_shift_d, exp_sqrshl_d,
                               sizeof(exp_sqrshl_d));
    test_arm64_sve2_narrow_run(0x440b8020, 0, 0, var_n_b, var_shift_b,
                               var_shift_b, exp_uqrshl_b,
                               sizeof(exp_uqrshl_b));
    test_arm64_sve2_narrow_run(0x444b8020, 1, 1, var_n_h, var_shift_h,
                               var_shift_h, exp_uqrshl_h,
                               sizeof(exp_uqrshl_h));
    test_arm64_sve2_narrow_run(0x448b8020, 2, 2, var_n_s, var_shift_s,
                               var_shift_s, exp_uqrshl_s,
                               sizeof(exp_uqrshl_s));
    test_arm64_sve2_narrow_run(0x44cb8020, 3, 3, var_n_d, var_shift_d,
                               var_shift_d, exp_uqrshl_d,
                               sizeof(exp_uqrshl_d));

    test_arm64_sve2_narrow_run(0x44068020, 0, 0, var_shift_b, var_n_b,
                               var_n_b, exp_srshl_b, sizeof(exp_srshl_b));
    test_arm64_sve2_narrow_run(0x44478020, 1, 1, var_shift_h, var_n_h,
                               var_n_h, exp_urshl_h, sizeof(exp_urshl_h));
    test_arm64_sve2_narrow_run(0x448c8020, 2, 2, var_shift_s, var_n_s,
                               var_n_s, exp_sqshl_s, sizeof(exp_sqshl_s));
    test_arm64_sve2_narrow_run(0x44cd8020, 3, 3, var_shift_d, var_n_d,
                               var_n_d, exp_uqshl_d, sizeof(exp_uqshl_d));
    test_arm64_sve2_narrow_run(0x440e8020, 0, 0, var_shift_b, var_n_b,
                               var_n_b, exp_sqrshl_b,
                               sizeof(exp_sqrshl_b));
    test_arm64_sve2_narrow_run(0x444f8020, 1, 1, var_shift_h, var_n_h,
                               var_n_h, exp_uqrshl_h,
                               sizeof(exp_uqrshl_h));
}

static void test_arm64_sve2_eor_adcl(void)
{
    uc_engine *uc;
    const char code_eor_b[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x60\xa0\x00\xa4" /* ld1b { z0.b },p0/z,[x3] */
        "\x81\xa0\x00\xa4" /* ld1b { z1.b },p0/z,[x4] */
        "\xa2\xa0\x00\xa4" /* ld1b { z2.b },p0/z,[x5] */
        "\x20\x90\x02\x45" /* eorbt z0.b,z1.b,z2.b */
        "\xc0\xe0\x00\xe4" /* st1b { z0.b },p0,[x6] */
        "\xe3\xa0\x00\xa4" /* ld1b { z3.b },p0/z,[x7] */
        "\x23\x94\x02\x45" /* eortb z3.b,z1.b,z2.b */
        "\x03\xe1\x00\xe4"; /* st1b { z3.b },p0,[x8] */
    const char code_eor_h[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x60\xa0\xa0\xa4" /* ld1h { z0.h },p0/z,[x3] */
        "\x81\xa0\xa0\xa4" /* ld1h { z1.h },p0/z,[x4] */
        "\xa2\xa0\xa0\xa4" /* ld1h { z2.h },p0/z,[x5] */
        "\x20\x90\x42\x45" /* eorbt z0.h,z1.h,z2.h */
        "\xc0\xe0\xa0\xe4" /* st1h { z0.h },p0,[x6] */
        "\xe3\xa0\xa0\xa4" /* ld1h { z3.h },p0/z,[x7] */
        "\x23\x94\x42\x45" /* eortb z3.h,z1.h,z2.h */
        "\x03\xe1\xa0\xe4"; /* st1h { z3.h },p0,[x8] */
    const char code_eor_s[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x60\xa0\x40\xa5" /* ld1w { z0.s },p0/z,[x3] */
        "\x81\xa0\x40\xa5" /* ld1w { z1.s },p0/z,[x4] */
        "\xa2\xa0\x40\xa5" /* ld1w { z2.s },p0/z,[x5] */
        "\x20\x90\x82\x45" /* eorbt z0.s,z1.s,z2.s */
        "\xc0\xe0\x40\xe5" /* st1w { z0.s },p0,[x6] */
        "\xe3\xa0\x40\xa5" /* ld1w { z3.s },p0/z,[x7] */
        "\x23\x94\x82\x45" /* eortb z3.s,z1.s,z2.s */
        "\x03\xe1\x40\xe5"; /* st1w { z3.s },p0,[x8] */
    const char code_eor_d[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x60\xa0\xe0\xa5" /* ld1d { z0.d },p0/z,[x3] */
        "\x81\xa0\xe0\xa5" /* ld1d { z1.d },p0/z,[x4] */
        "\xa2\xa0\xe0\xa5" /* ld1d { z2.d },p0/z,[x5] */
        "\x20\x90\xc2\x45" /* eorbt z0.d,z1.d,z2.d */
        "\xc0\xe0\xe0\xe5" /* st1d { z0.d },p0,[x6] */
        "\xe3\xa0\xe0\xa5" /* ld1d { z3.d },p0/z,[x7] */
        "\x23\x94\xc2\x45" /* eortb z3.d,z1.d,z2.d */
        "\x03\xe1\xe0\xe5"; /* st1d { z3.d },p0,[x8] */
    const char code_adcl_s[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x60\xa0\xe0\xa5" /* ld1d { z0.d },p0/z,[x3] */
        "\x81\xa0\x40\xa5" /* ld1w { z1.s },p0/z,[x4] */
        "\xa2\xa0\xe0\xa5" /* ld1d { z2.d },p0/z,[x5] */
        "\x20\xd0\x02\x45" /* adclb z0.d,z1.s,z2.d */
        "\xc0\xe0\xe0\xe5" /* st1d { z0.d },p0,[x6] */
        "\xe3\xa0\xe0\xa5" /* ld1d { z3.d },p0/z,[x7] */
        "\x23\xd4\x02\x45" /* adclt z3.d,z1.s,z2.d */
        "\x03\xe1\xe0\xe5"; /* st1d { z3.d },p0,[x8] */
    const char code_adcl_d[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x60\xa0\xe0\xa5" /* ld1d { z0.d },p0/z,[x3] */
        "\x81\xa0\xe0\xa5" /* ld1d { z1.d },p0/z,[x4] */
        "\xa2\xa0\xe0\xa5" /* ld1d { z2.d },p0/z,[x5] */
        "\x20\xd0\x42\x45" /* adclb z0.d,z1.d,z2.d */
        "\xc0\xe0\xe0\xe5" /* st1d { z0.d },p0,[x6] */
        "\xe3\xa0\xe0\xa5" /* ld1d { z3.d },p0/z,[x7] */
        "\x23\xd4\x42\x45" /* adclt z3.d,z1.d,z2.d */
        "\x03\xe1\xe0\xe5"; /* st1d { z3.d },p0,[x8] */
    uint8_t init_b[16], init2_b[16], n_b[16], m_b[16];
    uint8_t exp_eorbt_b[16], exp_eortb_b[16], got_b[16];
    uint16_t init_h[8], init2_h[8], n_h[8], m_h[8];
    uint16_t exp_eorbt_h[8], exp_eortb_h[8], got_h[8];
    uint32_t init_s[4], init2_s[4], n_s[4], m_s[4];
    uint32_t exp_eorbt_s[4], exp_eortb_s[4], got_s[4];
    uint64_t init_d[2], init2_d[2], n_d[2], m_d[2];
    uint64_t exp_eorbt_d[2], exp_eortb_d[2], got_d[2];
    uint64_t adcl_acc_b[2], adcl_acc_t[2], adcl_m_s[2];
    uint32_t adcl_n_s[4];
    uint64_t exp_adclb_s[2], exp_adclt_s[2], got_adcl_s[2];
    uint64_t adcl_acc_b_d[2], adcl_acc_t_d[2], adcl_n_d[2], adcl_m_d[2];
    uint64_t exp_adclb_d[2], exp_adclt_d[2], got_adcl_d[2];
    uint64_t x3 = 0x40000;
    uint64_t x4 = 0x40100;
    uint64_t x5 = 0x40200;
    uint64_t x6 = 0x40300;
    uint64_t x7 = 0x40400;
    uint64_t x8 = 0x40500;
    int i;

    for (i = 0; i < 16; i++) {
        init_b[i] = (uint8_t)(0x80 + i);
        init2_b[i] = (uint8_t)(0xa0 + i);
        n_b[i] = (uint8_t)(0x11 + i * 3);
        m_b[i] = (uint8_t)(0xf0 - i * 5);
        exp_eorbt_b[i] = init_b[i];
        exp_eortb_b[i] = init2_b[i];
    }
    for (i = 0; i < 8; i++) {
        exp_eorbt_b[2 * i] = n_b[2 * i] ^ m_b[2 * i + 1];
        exp_eortb_b[2 * i + 1] = n_b[2 * i + 1] ^ m_b[2 * i];
    }

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_eor_b,
                    sizeof(code_eor_b) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x3, init_b, sizeof(init_b)));
    OK(uc_mem_write(uc, x4, n_b, sizeof(n_b)));
    OK(uc_mem_write(uc, x5, m_b, sizeof(m_b)));
    OK(uc_mem_write(uc, x7, init2_b, sizeof(init2_b)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_eor_b) - 1,
                    0, 0));
    OK(uc_mem_read(uc, x6, got_b, sizeof(got_b)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got_b[i] == exp_eorbt_b[i]);
    }
    OK(uc_mem_read(uc, x8, got_b, sizeof(got_b)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got_b[i] == exp_eortb_b[i]);
    }
    OK(uc_close(uc));

    for (i = 0; i < 8; i++) {
        init_h[i] = (uint16_t)(0x8000 + i);
        init2_h[i] = (uint16_t)(0xa000 + i);
        n_h[i] = (uint16_t)(0x1100 + i * 0x21);
        m_h[i] = (uint16_t)(0xf000 - i * 0x31);
        exp_eorbt_h[i] = init_h[i];
        exp_eortb_h[i] = init2_h[i];
    }
    for (i = 0; i < 4; i++) {
        exp_eorbt_h[2 * i] = n_h[2 * i] ^ m_h[2 * i + 1];
        exp_eortb_h[2 * i + 1] = n_h[2 * i + 1] ^ m_h[2 * i];
    }

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_eor_h,
                    sizeof(code_eor_h) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x3, init_h, sizeof(init_h)));
    OK(uc_mem_write(uc, x4, n_h, sizeof(n_h)));
    OK(uc_mem_write(uc, x5, m_h, sizeof(m_h)));
    OK(uc_mem_write(uc, x7, init2_h, sizeof(init2_h)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_eor_h) - 1,
                    0, 0));
    OK(uc_mem_read(uc, x6, got_h, sizeof(got_h)));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(got_h[i] == exp_eorbt_h[i]);
    }
    OK(uc_mem_read(uc, x8, got_h, sizeof(got_h)));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(got_h[i] == exp_eortb_h[i]);
    }
    OK(uc_close(uc));

    for (i = 0; i < 4; i++) {
        init_s[i] = 0x80000000u + (uint32_t)i;
        init2_s[i] = 0xa0000000u + (uint32_t)i;
        n_s[i] = 0x11110000u + (uint32_t)i * 0x1111u;
        m_s[i] = 0xf0000000u - (uint32_t)i * 0x10101u;
        exp_eorbt_s[i] = init_s[i];
        exp_eortb_s[i] = init2_s[i];
    }
    for (i = 0; i < 2; i++) {
        exp_eorbt_s[2 * i] = n_s[2 * i] ^ m_s[2 * i + 1];
        exp_eortb_s[2 * i + 1] = n_s[2 * i + 1] ^ m_s[2 * i];
    }

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_eor_s,
                    sizeof(code_eor_s) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x3, init_s, sizeof(init_s)));
    OK(uc_mem_write(uc, x4, n_s, sizeof(n_s)));
    OK(uc_mem_write(uc, x5, m_s, sizeof(m_s)));
    OK(uc_mem_write(uc, x7, init2_s, sizeof(init2_s)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_eor_s) - 1,
                    0, 0));
    OK(uc_mem_read(uc, x6, got_s, sizeof(got_s)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(got_s[i] == exp_eorbt_s[i]);
    }
    OK(uc_mem_read(uc, x8, got_s, sizeof(got_s)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(got_s[i] == exp_eortb_s[i]);
    }
    OK(uc_close(uc));

    init_d[0] = 0x8000000000000000ull;
    init_d[1] = 0x8000000000000001ull;
    init2_d[0] = 0xa000000000000000ull;
    init2_d[1] = 0xa000000000000001ull;
    n_d[0] = 0x0123456789abcdefull;
    n_d[1] = 0xfedcba9876543210ull;
    m_d[0] = 0x1111111111111111ull;
    m_d[1] = 0x2222222222222222ull;
    exp_eorbt_d[0] = n_d[0] ^ m_d[1];
    exp_eorbt_d[1] = init_d[1];
    exp_eortb_d[0] = init2_d[0];
    exp_eortb_d[1] = n_d[1] ^ m_d[0];

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_eor_d,
                    sizeof(code_eor_d) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x3, init_d, sizeof(init_d)));
    OK(uc_mem_write(uc, x4, n_d, sizeof(n_d)));
    OK(uc_mem_write(uc, x5, m_d, sizeof(m_d)));
    OK(uc_mem_write(uc, x7, init2_d, sizeof(init2_d)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_eor_d) - 1,
                    0, 0));
    OK(uc_mem_read(uc, x6, got_d, sizeof(got_d)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_d[i] == exp_eorbt_d[i]);
    }
    OK(uc_mem_read(uc, x8, got_d, sizeof(got_d)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_d[i] == exp_eortb_d[i]);
    }
    OK(uc_close(uc));

    adcl_acc_b[0] = 0x00000000fffffffeull;
    adcl_acc_b[1] = 0x0000000000000010ull;
    adcl_acc_t[0] = 0x0000000000000020ull;
    adcl_acc_t[1] = 0x0000000000000030ull;
    adcl_n_s[0] = 5;
    adcl_n_s[1] = 0x7fffffffu;
    adcl_n_s[2] = 0xffffffffu;
    adcl_n_s[3] = 0x80000000u;
    adcl_m_s[0] = 0x0000000100000000ull;
    adcl_m_s[1] = 0;
    exp_adclb_s[0] = 0x0000000100000004ull;
    exp_adclb_s[1] = 0x000000010000000full;
    exp_adclt_s[0] = 0x0000000080000020ull;
    exp_adclt_s[1] = 0x0000000080000030ull;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_adcl_s,
                    sizeof(code_adcl_s) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x3, adcl_acc_b, sizeof(adcl_acc_b)));
    OK(uc_mem_write(uc, x4, adcl_n_s, sizeof(adcl_n_s)));
    OK(uc_mem_write(uc, x5, adcl_m_s, sizeof(adcl_m_s)));
    OK(uc_mem_write(uc, x7, adcl_acc_t, sizeof(adcl_acc_t)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_adcl_s) - 1,
                    0, 0));
    OK(uc_mem_read(uc, x6, got_adcl_s, sizeof(got_adcl_s)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_adcl_s[i] == exp_adclb_s[i]);
    }
    OK(uc_mem_read(uc, x8, got_adcl_s, sizeof(got_adcl_s)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_adcl_s[i] == exp_adclt_s[i]);
    }
    OK(uc_close(uc));

    adcl_acc_b_d[0] = 0xffffffffffffffffull;
    adcl_acc_b_d[1] = 0;
    adcl_acc_t_d[0] = 0x10;
    adcl_acc_t_d[1] = 0;
    adcl_n_d[0] = 2;
    adcl_n_d[1] = 0xfffffffffffffff0ull;
    adcl_m_d[0] = 0;
    adcl_m_d[1] = 1;
    exp_adclb_d[0] = 2;
    exp_adclb_d[1] = 1;
    exp_adclt_d[0] = 1;
    exp_adclt_d[1] = 1;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_adcl_d,
                    sizeof(code_adcl_d) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x3, adcl_acc_b_d, sizeof(adcl_acc_b_d)));
    OK(uc_mem_write(uc, x4, adcl_n_d, sizeof(adcl_n_d)));
    OK(uc_mem_write(uc, x5, adcl_m_d, sizeof(adcl_m_d)));
    OK(uc_mem_write(uc, x7, adcl_acc_t_d, sizeof(adcl_acc_t_d)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_adcl_d) - 1,
                    0, 0));
    OK(uc_mem_read(uc, x6, got_adcl_d, sizeof(got_adcl_d)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_adcl_d[i] == exp_adclb_d[i]);
    }
    OK(uc_mem_read(uc, x8, got_adcl_d, sizeof(got_adcl_d)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_adcl_d[i] == exp_adclt_d[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_bitperm(void)
{
    uc_engine *uc;
    const char code_b[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x00\xa4" /* ld1b { z1.b },p0/z,[x4] */
        "\xa2\xa0\x00\xa4" /* ld1b { z2.b },p0/z,[x5] */
        "\x20\xb0\x02\x45" /* bext z0.b,z1.b,z2.b */
        "\xc0\xe0\x00\xe4" /* st1b { z0.b },p0,[x6] */
        "\x23\xb4\x02\x45" /* bdep z3.b,z1.b,z2.b */
        "\xe3\xe0\x00\xe4" /* st1b { z3.b },p0,[x7] */
        "\x24\xb8\x02\x45" /* bgrp z4.b,z1.b,z2.b */
        "\x04\xe1\x00\xe4"; /* st1b { z4.b },p0,[x8] */
    const char code_h[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\xa0\xa4" /* ld1h { z1.h },p0/z,[x4] */
        "\xa2\xa0\xa0\xa4" /* ld1h { z2.h },p0/z,[x5] */
        "\x20\xb0\x42\x45" /* bext z0.h,z1.h,z2.h */
        "\xc0\xe0\xa0\xe4" /* st1h { z0.h },p0,[x6] */
        "\x23\xb4\x42\x45" /* bdep z3.h,z1.h,z2.h */
        "\xe3\xe0\xa0\xe4" /* st1h { z3.h },p0,[x7] */
        "\x24\xb8\x42\x45" /* bgrp z4.h,z1.h,z2.h */
        "\x04\xe1\xa0\xe4"; /* st1h { z4.h },p0,[x8] */
    const char code_s[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x40\xa5" /* ld1w { z1.s },p0/z,[x4] */
        "\xa2\xa0\x40\xa5" /* ld1w { z2.s },p0/z,[x5] */
        "\x20\xb0\x82\x45" /* bext z0.s,z1.s,z2.s */
        "\xc0\xe0\x40\xe5" /* st1w { z0.s },p0,[x6] */
        "\x23\xb4\x82\x45" /* bdep z3.s,z1.s,z2.s */
        "\xe3\xe0\x40\xe5" /* st1w { z3.s },p0,[x7] */
        "\x24\xb8\x82\x45" /* bgrp z4.s,z1.s,z2.s */
        "\x04\xe1\x40\xe5"; /* st1w { z4.s },p0,[x8] */
    const char code_d[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\xe0\xa5" /* ld1d { z1.d },p0/z,[x4] */
        "\xa2\xa0\xe0\xa5" /* ld1d { z2.d },p0/z,[x5] */
        "\x20\xb0\xc2\x45" /* bext z0.d,z1.d,z2.d */
        "\xc0\xe0\xe0\xe5" /* st1d { z0.d },p0,[x6] */
        "\x23\xb4\xc2\x45" /* bdep z3.d,z1.d,z2.d */
        "\xe3\xe0\xe0\xe5" /* st1d { z3.d },p0,[x7] */
        "\x24\xb8\xc2\x45" /* bgrp z4.d,z1.d,z2.d */
        "\x04\xe1\xe0\xe5"; /* st1d { z4.d },p0,[x8] */
    uint8_t n_b[16], m_b[16], exp_bext_b[16], exp_bdep_b[16];
    uint8_t exp_bgrp_b[16], got_b[16];
    uint16_t n_h[8], m_h[8], exp_bext_h[8], exp_bdep_h[8];
    uint16_t exp_bgrp_h[8], got_h[8];
    uint32_t n_s[4], m_s[4], exp_bext_s[4], exp_bdep_s[4];
    uint32_t exp_bgrp_s[4], got_s[4];
    uint64_t n_d[2], m_d[2], exp_bext_d[2], exp_bdep_d[2];
    uint64_t exp_bgrp_d[2], got_d[2];
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40100;
    uint64_t x6 = 0x40200;
    uint64_t x7 = 0x40300;
    uint64_t x8 = 0x40400;
    int i;

    for (i = 0; i < 16; i++) {
        n_b[i] = (uint8_t)(0x35 + i * 13);
        m_b[i] = (uint8_t)(0x5a ^ (i * 17));
        exp_bext_b[i] = (uint8_t)test_arm64_bitextract(n_b[i], m_b[i], 8);
        exp_bdep_b[i] = (uint8_t)test_arm64_bitdeposit(n_b[i], m_b[i], 8);
        exp_bgrp_b[i] = (uint8_t)test_arm64_bitgroup(n_b[i], m_b[i], 8);
    }

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_b,
                    sizeof(code_b) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_b, sizeof(n_b)));
    OK(uc_mem_write(uc, x5, m_b, sizeof(m_b)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_b) - 1, 0, 0));
    OK(uc_mem_read(uc, x6, got_b, sizeof(got_b)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got_b[i] == exp_bext_b[i]);
    }
    OK(uc_mem_read(uc, x7, got_b, sizeof(got_b)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got_b[i] == exp_bdep_b[i]);
    }
    OK(uc_mem_read(uc, x8, got_b, sizeof(got_b)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got_b[i] == exp_bgrp_b[i]);
    }
    OK(uc_close(uc));

    for (i = 0; i < 8; i++) {
        n_h[i] = (uint16_t)(0x1357 + i * 0x1111);
        m_h[i] = (uint16_t)(0xa55a ^ (i * 0x1234));
        exp_bext_h[i] = (uint16_t)test_arm64_bitextract(n_h[i], m_h[i], 16);
        exp_bdep_h[i] = (uint16_t)test_arm64_bitdeposit(n_h[i], m_h[i], 16);
        exp_bgrp_h[i] = (uint16_t)test_arm64_bitgroup(n_h[i], m_h[i], 16);
    }

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_h,
                    sizeof(code_h) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_h, sizeof(n_h)));
    OK(uc_mem_write(uc, x5, m_h, sizeof(m_h)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_h) - 1, 0, 0));
    OK(uc_mem_read(uc, x6, got_h, sizeof(got_h)));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(got_h[i] == exp_bext_h[i]);
    }
    OK(uc_mem_read(uc, x7, got_h, sizeof(got_h)));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(got_h[i] == exp_bdep_h[i]);
    }
    OK(uc_mem_read(uc, x8, got_h, sizeof(got_h)));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(got_h[i] == exp_bgrp_h[i]);
    }
    OK(uc_close(uc));

    for (i = 0; i < 4; i++) {
        n_s[i] = 0x12345678u + (uint32_t)i * 0x01020304u;
        m_s[i] = 0x96696996u ^ ((uint32_t)i * 0x11111111u);
        exp_bext_s[i] = (uint32_t)test_arm64_bitextract(n_s[i], m_s[i], 32);
        exp_bdep_s[i] = (uint32_t)test_arm64_bitdeposit(n_s[i], m_s[i], 32);
        exp_bgrp_s[i] = (uint32_t)test_arm64_bitgroup(n_s[i], m_s[i], 32);
    }

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_s,
                    sizeof(code_s) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_s, sizeof(n_s)));
    OK(uc_mem_write(uc, x5, m_s, sizeof(m_s)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_s) - 1, 0, 0));
    OK(uc_mem_read(uc, x6, got_s, sizeof(got_s)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(got_s[i] == exp_bext_s[i]);
    }
    OK(uc_mem_read(uc, x7, got_s, sizeof(got_s)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(got_s[i] == exp_bdep_s[i]);
    }
    OK(uc_mem_read(uc, x8, got_s, sizeof(got_s)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(got_s[i] == exp_bgrp_s[i]);
    }
    OK(uc_close(uc));

    n_d[0] = 0x0123456789abcdefull;
    n_d[1] = 0xfedcba9876543210ull;
    m_d[0] = 0x0f0f3333ccccf0f0ull;
    m_d[1] = 0x13579bdf2468ace0ull;
    for (i = 0; i < 2; i++) {
        exp_bext_d[i] = test_arm64_bitextract(n_d[i], m_d[i], 64);
        exp_bdep_d[i] = test_arm64_bitdeposit(n_d[i], m_d[i], 64);
        exp_bgrp_d[i] = test_arm64_bitgroup(n_d[i], m_d[i], 64);
    }

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_d,
                    sizeof(code_d) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_d, sizeof(n_d)));
    OK(uc_mem_write(uc, x5, m_d, sizeof(m_d)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_d) - 1, 0, 0));
    OK(uc_mem_read(uc, x6, got_d, sizeof(got_d)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_d[i] == exp_bext_d[i]);
    }
    OK(uc_mem_read(uc, x7, got_d, sizeof(got_d)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_d[i] == exp_bdep_d[i]);
    }
    OK(uc_mem_read(uc, x8, got_d, sizeof(got_d)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_d[i] == exp_bgrp_d[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_match_hist(void)
{
    uc_engine *uc;
    const char code_match_b[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x00\xa4" /* ld1b { z1.b },p0/z,[x4] */
        "\xa2\xa0\x00\xa4" /* ld1b { z2.b },p0/z,[x5] */
        "\xe4\xa0\x00\xa4" /* ld1b { z4.b },p0/z,[x7] */
        "\x21\x80\x22\x45" /* match p1.b,p0/z,z1.b,z2.b */
        "\xc4\xe4\x00\xe4" /* st1b { z4.b },p1,[x6] */
        "\x32\x80\x22\x45" /* nmatch p2.b,p0/z,z1.b,z2.b */
        "\x04\xe9\x00\xe4"; /* st1b { z4.b },p2,[x8] */
    const char code_match_h[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\xa0\xa4" /* ld1h { z1.h },p0/z,[x4] */
        "\xa2\xa0\xa0\xa4" /* ld1h { z2.h },p0/z,[x5] */
        "\xe4\xa0\xa0\xa4" /* ld1h { z4.h },p0/z,[x7] */
        "\x21\x80\x62\x45" /* match p1.h,p0/z,z1.h,z2.h */
        "\xc4\xe4\xa0\xe4" /* st1h { z4.h },p1,[x6] */
        "\x32\x80\x62\x45" /* nmatch p2.h,p0/z,z1.h,z2.h */
        "\x04\xe9\xa0\xe4"; /* st1h { z4.h },p2,[x8] */
    const char code_histcnt_s[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x40\xa5" /* ld1w { z1.s },p0/z,[x4] */
        "\xa2\xa0\x40\xa5" /* ld1w { z2.s },p0/z,[x5] */
        "\x20\xc0\xa2\x45" /* histcnt z0.s,p0/z,z1.s,z2.s */
        "\xc0\xe0\x40\xe5"; /* st1w { z0.s },p0,[x6] */
    const char code_histcnt_d[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\xe0\xa5" /* ld1d { z1.d },p0/z,[x4] */
        "\xa2\xa0\xe0\xa5" /* ld1d { z2.d },p0/z,[x5] */
        "\x20\xc0\xe2\x45" /* histcnt z0.d,p0/z,z1.d,z2.d */
        "\xc0\xe0\xe0\xe5"; /* st1d { z0.d },p0,[x6] */
    const char code_histseg[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x00\xa4" /* ld1b { z1.b },p0/z,[x4] */
        "\xa2\xa0\x00\xa4" /* ld1b { z2.b },p0/z,[x5] */
        "\x20\xa0\x22\x45" /* histseg z0.b,z1.b,z2.b */
        "\xc0\xe0\x00\xe4"; /* st1b { z0.b },p0,[x6] */
    uint8_t n_b[16] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
    };
    uint8_t m_b[16] = {
        3, 8, 13, 0x42, 1, 1, 0xaa, 0xbb,
        16, 7, 0x30, 0x31, 2, 2, 0xcc, 0xdd,
    };
    uint16_t n_h[8] = {
        0x1001, 0x1002, 0x2222, 0x3333,
        0x4444, 0x5555, 0x6666, 0x7777,
    };
    uint16_t m_h[8] = {
        0x3333, 0x1002, 0x7777, 0x9999,
        0x4444, 0xaaaa, 0xbbbb, 0x1001,
    };
    uint8_t fill_b[16], zero_b[16], got_b[16];
    uint8_t exp_match_b[16], exp_nmatch_b[16];
    uint16_t fill_h[8], zero_h[8], got_h[8];
    uint16_t exp_match_h[8], exp_nmatch_h[8];
    uint32_t n_s[4] = { 5, 7, 5, 9 };
    uint32_t m_s[4] = { 5, 5, 7, 5 };
    uint32_t exp_histcnt_s[4], got_s[4];
    uint64_t n_d[2] = { 0x11, 0x22 };
    uint64_t m_d[2] = { 0x22, 0x22 };
    uint64_t exp_histcnt_d[2], got_d[2];
    uint8_t n_seg[16] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 1, 2, 3, 4, 5, 6,
    };
    uint8_t m_seg[16] = {
        1, 1, 2, 3, 3, 3, 5, 8,
        8, 8, 8, 10, 0xff, 0, 4, 6,
    };
    uint8_t exp_histseg[16];
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40100;
    uint64_t x6 = 0x40200;
    uint64_t x7 = 0x40300;
    uint64_t x8 = 0x40400;
    int i, j;

    memset(fill_b, 0xff, sizeof(fill_b));
    memset(zero_b, 0, sizeof(zero_b));
    memset(fill_h, 0xff, sizeof(fill_h));
    memset(zero_h, 0, sizeof(zero_h));

    for (i = 0; i < 16; i++) {
        if (test_arm64_has_u8(m_b, 16, n_b[i])) {
            exp_match_b[i] = 0xff;
            exp_nmatch_b[i] = 0;
        } else {
            exp_match_b[i] = 0;
            exp_nmatch_b[i] = 0xff;
        }
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_match_b,
                    sizeof(code_match_b) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_b, sizeof(n_b)));
    OK(uc_mem_write(uc, x5, m_b, sizeof(m_b)));
    OK(uc_mem_write(uc, x6, zero_b, sizeof(zero_b)));
    OK(uc_mem_write(uc, x7, fill_b, sizeof(fill_b)));
    OK(uc_mem_write(uc, x8, zero_b, sizeof(zero_b)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_match_b) - 1,
                    0, 0));
    OK(uc_mem_read(uc, x6, got_b, sizeof(got_b)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got_b[i] == exp_match_b[i]);
    }
    OK(uc_mem_read(uc, x8, got_b, sizeof(got_b)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got_b[i] == exp_nmatch_b[i]);
    }
    OK(uc_close(uc));

    for (i = 0; i < 8; i++) {
        if (test_arm64_has_u16(m_h, 8, n_h[i])) {
            exp_match_h[i] = 0xffff;
            exp_nmatch_h[i] = 0;
        } else {
            exp_match_h[i] = 0;
            exp_nmatch_h[i] = 0xffff;
        }
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_match_h,
                    sizeof(code_match_h) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_h, sizeof(n_h)));
    OK(uc_mem_write(uc, x5, m_h, sizeof(m_h)));
    OK(uc_mem_write(uc, x6, zero_h, sizeof(zero_h)));
    OK(uc_mem_write(uc, x7, fill_h, sizeof(fill_h)));
    OK(uc_mem_write(uc, x8, zero_h, sizeof(zero_h)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_match_h) - 1,
                    0, 0));
    OK(uc_mem_read(uc, x6, got_h, sizeof(got_h)));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(got_h[i] == exp_match_h[i]);
    }
    OK(uc_mem_read(uc, x8, got_h, sizeof(got_h)));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(got_h[i] == exp_nmatch_h[i]);
    }
    OK(uc_close(uc));

    for (i = 0; i < 4; i++) {
        exp_histcnt_s[i] = 0;
        for (j = 0; j <= i; j++) {
            if (n_s[i] == m_s[j]) {
                exp_histcnt_s[i]++;
            }
        }
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_histcnt_s,
                    sizeof(code_histcnt_s) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_s, sizeof(n_s)));
    OK(uc_mem_write(uc, x5, m_s, sizeof(m_s)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_histcnt_s) - 1,
                    0, 0));
    OK(uc_mem_read(uc, x6, got_s, sizeof(got_s)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(got_s[i] == exp_histcnt_s[i]);
    }
    OK(uc_close(uc));

    for (i = 0; i < 2; i++) {
        exp_histcnt_d[i] = 0;
        for (j = 0; j <= i; j++) {
            if (n_d[i] == m_d[j]) {
                exp_histcnt_d[i]++;
            }
        }
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_histcnt_d,
                    sizeof(code_histcnt_d) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_d, sizeof(n_d)));
    OK(uc_mem_write(uc, x5, m_d, sizeof(m_d)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_histcnt_d) - 1,
                    0, 0));
    OK(uc_mem_read(uc, x6, got_d, sizeof(got_d)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(got_d[i] == exp_histcnt_d[i]);
    }
    OK(uc_close(uc));

    for (i = 0; i < 16; i++) {
        exp_histseg[i] = 0;
        for (j = 0; j < 16; j++) {
            if (n_seg[i] == m_seg[j]) {
                exp_histseg[i]++;
            }
        }
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_histseg,
                    sizeof(code_histseg) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n_seg, sizeof(n_seg)));
    OK(uc_mem_write(uc, x5, m_seg, sizeof(m_seg)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_histseg) - 1,
                    0, 0));
    OK(uc_mem_read(uc, x6, got_b, sizeof(got_b)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got_b[i] == exp_histseg[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_crypto_run(const char *code, size_t code_size,
                                       const uint8_t *input0,
                                       const uint8_t *input1,
                                       const uint8_t *expected)
{
    uc_engine *uc;
    uint8_t got[32];
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40100;
    uint64_t x6 = 0x40200;
    int i;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, code_size,
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, input0, 32));
    if (input1 != NULL) {
        OK(uc_mem_write(uc, x5, input1, 32));
    }
    test_arm64_mte_enable_sve_vq(uc, 1);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + code_size, 0, 0));
    OK(uc_mem_read(uc, x6, got, sizeof(got)));
    for (i = 0; i < 32; i++) {
        TEST_CHECK(got[i] == expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_crypto(void)
{
    const char code_aese[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x80\xa0\x00\xa4" /* ld1b { z0.b },p0/z,[x4] */
        "\xa2\xa0\x00\xa4" /* ld1b { z2.b },p0/z,[x5] */
        "\x40\xe0\x22\x45" /* aese z0.b,z2.b */
        "\xc0\xe0\x00\xe4"; /* st1b { z0.b },p0,[x6] */
    const char code_aesd[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x80\xa0\x00\xa4" /* ld1b { z0.b },p0/z,[x4] */
        "\xa2\xa0\x00\xa4" /* ld1b { z2.b },p0/z,[x5] */
        "\x40\xe4\x22\x45" /* aesd z0.b,z2.b */
        "\xc0\xe0\x00\xe4"; /* st1b { z0.b },p0,[x6] */
    const char code_aesmc[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x80\xa0\x00\xa4" /* ld1b { z0.b },p0/z,[x4] */
        "\x00\xe0\x20\x45" /* aesmc z0.b,z0.b */
        "\xc0\xe0\x00\xe4"; /* st1b { z0.b },p0,[x6] */
    const char code_aesimc[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x80\xa0\x00\xa4" /* ld1b { z0.b },p0/z,[x4] */
        "\x00\xe4\x20\x45" /* aesimc z0.b,z0.b */
        "\xc0\xe0\x00\xe4"; /* st1b { z0.b },p0,[x6] */
    const char code_sm4e[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x80\xa0\x00\xa4" /* ld1b { z0.b },p0/z,[x4] */
        "\xa2\xa0\x00\xa4" /* ld1b { z2.b },p0/z,[x5] */
        "\x40\xe0\x23\x45" /* sm4e z0.b,z2.b */
        "\xc0\xe0\x00\xe4"; /* st1b { z0.b },p0,[x6] */
    const char code_sm4ekey[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x00\xa4" /* ld1b { z1.b },p0/z,[x4] */
        "\xa2\xa0\x00\xa4" /* ld1b { z2.b },p0/z,[x5] */
        "\x20\xf0\x22\x45" /* sm4ekey z0.b,z1.b,z2.b */
        "\xc0\xe0\x00\xe4"; /* st1b { z0.b },p0,[x6] */
    const char code_rax1[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x00\xa4" /* ld1b { z1.b },p0/z,[x4] */
        "\xa2\xa0\x00\xa4" /* ld1b { z2.b },p0/z,[x5] */
        "\x20\xf4\x22\x45" /* rax1 z0.d,z1.d,z2.d */
        "\xc0\xe0\x00\xe4"; /* st1b { z0.b },p0,[x6] */
    const uint8_t state[32] = {
        0x10, 0x17, 0x1e, 0x25, 0x2c, 0x33, 0x3a, 0x41,
        0x48, 0x4f, 0x56, 0x5d, 0x64, 0x6b, 0x72, 0x79,
        0x80, 0x87, 0x8e, 0x95, 0x9c, 0xa3, 0xaa, 0xb1,
        0xb8, 0xbf, 0xc6, 0xcd, 0xd4, 0xdb, 0xe2, 0xe9,
    };
    const uint8_t key[32] = {
        0xa0, 0xab, 0xb6, 0x81, 0x8c, 0x97, 0xe2, 0xed,
        0xf8, 0xc3, 0xce, 0xd9, 0x24, 0x2f, 0x3a, 0x05,
        0x10, 0x1b, 0x66, 0x71, 0x7c, 0x47, 0x52, 0x5d,
        0xa8, 0xb3, 0xbe, 0x89, 0x94, 0x9f, 0xea, 0xf5,
    };
    const uint8_t state2[32] = {
        0x55, 0x62, 0x6f, 0x7c, 0x89, 0x96, 0xa3, 0xb0,
        0xbd, 0xca, 0xd7, 0xe4, 0xf1, 0xfe, 0x0b, 0x18,
        0x25, 0x32, 0x3f, 0x4c, 0x59, 0x66, 0x73, 0x80,
        0x8d, 0x9a, 0xa7, 0xb4, 0xc1, 0xce, 0xdb, 0xe8,
    };
    const uint8_t key2[32] = {
        0x33, 0x20, 0x15, 0x0a, 0x7f, 0x6c, 0x41, 0xb6,
        0xab, 0x98, 0x8d, 0xe2, 0xd7, 0xc4, 0x39, 0x2e,
        0x03, 0x70, 0x65, 0x5a, 0x4f, 0xbc, 0x91, 0x86,
        0xfb, 0xe8, 0xdd, 0x32, 0x27, 0x14, 0x09, 0x7e,
    };
    const uint8_t exp_aese[32] = {
        0xe7, 0x49, 0x46, 0x10, 0xe0, 0x64, 0x52, 0x49,
        0xe7, 0x1b, 0xc2, 0x91, 0x09, 0x65, 0x61, 0x5f,
        0x60, 0x69, 0xbc, 0x9c, 0xe1, 0xfe, 0x30, 0x69,
        0xca, 0x1b, 0x9b, 0xce, 0x09, 0xde, 0x41, 0x1b,
    };
    const uint8_t exp_aesd[32] = {
        0xfc, 0x86, 0xe2, 0xaa, 0x47, 0x78, 0xd4, 0x4f,
        0xfc, 0x1d, 0x6f, 0x01, 0x72, 0xf0, 0x2d, 0x1d,
        0x96, 0x86, 0xc1, 0x83, 0xa0, 0x1c, 0xbf, 0x86,
        0x7c, 0xae, 0xc8, 0xc4, 0x72, 0x81, 0xe1, 0xae,
    };
    const uint8_t exp_aesmc[32] = {
        0x22, 0x39, 0x54, 0x73, 0x76, 0x45, 0xa8, 0xff,
        0x4a, 0x71, 0x4c, 0x7b, 0x7e, 0x5d, 0x60, 0x47,
        0x92, 0x89, 0xa4, 0xa3, 0xc6, 0x95, 0xb8, 0xcf,
        0xba, 0x41, 0xdc, 0x2b, 0xce, 0xad, 0xf0, 0x97,
    };
    const uint8_t exp_aesimc[32] = {
        0xe1, 0x0a, 0x97, 0x40, 0x23, 0x9b, 0xfd, 0x21,
        0x52, 0x59, 0x54, 0x53, 0x06, 0x35, 0x18, 0x2f,
        0x4a, 0x21, 0x7c, 0x0b, 0x25, 0xe6, 0x5b, 0xbc,
        0x39, 0xf2, 0x5f, 0x98, 0x36, 0x45, 0x08, 0x7f,
    };
    const uint8_t exp_sm4e[32] = {
        0x26, 0x49, 0x13, 0xb2, 0x02, 0xa1, 0xba, 0x48,
        0xc7, 0x98, 0x0e, 0x8a, 0xaf, 0xb6, 0x37, 0x7e,
        0x32, 0xad, 0xb7, 0x55, 0x42, 0x0f, 0x26, 0x81,
        0x56, 0x58, 0x9a, 0x72, 0x09, 0x9d, 0x22, 0x60,
    };
    const uint8_t exp_sm4ekey[32] = {
        0xb2, 0xf4, 0xd1, 0xdc, 0x6c, 0x0b, 0x7f, 0xb4,
        0x92, 0xcb, 0xa2, 0x6b, 0x2c, 0x7b, 0x62, 0xcc,
        0x7d, 0x2c, 0xbf, 0x62, 0x3c, 0x1d, 0x8a, 0x50,
        0x3e, 0x61, 0xc0, 0x1a, 0x9a, 0x4d, 0x1e, 0x30,
    };
    const uint8_t exp_rax1[32] = {
        0x32, 0x22, 0x45, 0x68, 0x77, 0x4e, 0x21, 0xdc,
        0xeb, 0xfb, 0xcc, 0x21, 0x5e, 0x77, 0x78, 0x44,
        0x22, 0xd2, 0xf5, 0xf8, 0xc7, 0x1e, 0x50, 0x8d,
        0x7b, 0x4b, 0x1c, 0xd1, 0x8f, 0xe6, 0xc9, 0x14,
    };

    test_arm64_sve2_crypto_run(code_aese, sizeof(code_aese) - 1, state, key,
                               exp_aese);
    test_arm64_sve2_crypto_run(code_aesd, sizeof(code_aesd) - 1, state, key,
                               exp_aesd);
    test_arm64_sve2_crypto_run(code_aesmc, sizeof(code_aesmc) - 1, state, NULL,
                               exp_aesmc);
    test_arm64_sve2_crypto_run(code_aesimc, sizeof(code_aesimc) - 1, state,
                               NULL, exp_aesimc);
    test_arm64_sve2_crypto_run(code_sm4e, sizeof(code_sm4e) - 1, state, key,
                               exp_sm4e);
    test_arm64_sve2_crypto_run(code_sm4ekey, sizeof(code_sm4ekey) - 1, state2,
                               key2, exp_sm4ekey);
    test_arm64_sve2_crypto_run(code_rax1, sizeof(code_rax1) - 1, state2, key2,
                               exp_rax1);
}

static void test_arm64_sve2_ext(void)
{
    uc_engine *uc;
    const char code[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x00\xa4" /* ld1b { z1.b },p0/z,[x4] */
        "\xa2\xa0\x00\xa4" /* ld1b { z2.b },p0/z,[x5] */
        "\x23\x04\x61\x05" /* ext z3.b,{z1.b,z2.b},#9 */
        "\xc3\xe0\x00\xe4"; /* st1b { z3.b },p0,[x6] */
    uint8_t n[16], m[16], expected[16], got[16];
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40100;
    uint64_t x6 = 0x40200;
    int i;

    for (i = 0; i < 16; i++) {
        n[i] = (uint8_t)(0x10 + i);
        m[i] = (uint8_t)(0x80 + i);
    }
    for (i = 0; i < 7; i++) {
        expected[i] = n[i + 9];
    }
    for (i = 7; i < 16; i++) {
        expected[i] = m[i - 7];
    }

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, n, sizeof(n)));
    OK(uc_mem_write(uc, x5, m, sizeof(m)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, x6, got, sizeof(got)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got[i] == expected[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_splice(void)
{
    uc_engine *uc;
    const char code_b[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x00\xa4" /* ld1b { z1.b },p0/z,[x4] */
        "\xa2\xa0\x00\xa4" /* ld1b { z2.b },p0/z,[x5] */
        "\x80\xe0\x18\x25" /* ptrue p0.b,vl4 */
        "\x20\x80\x2d\x05" /* splice z0.b,p0,z1.b */
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\xc0\xe0\x00\xe4"; /* st1b { z0.b },p0,[x6] */
    const char code_s[] =
        "\xe0\xe3\x98\x25" /* ptrue p0.s */
        "\x81\xa0\x40\xa5" /* ld1w { z1.s },p0/z,[x4] */
        "\xa2\xa0\x40\xa5" /* ld1w { z2.s },p0/z,[x5] */
        "\x40\xe0\x98\x25" /* ptrue p0.s,vl2 */
        "\x20\x80\xad\x05" /* splice z0.s,p0,z1.s */
        "\xe0\xe3\x98\x25" /* ptrue p0.s */
        "\xc0\xe0\x40\xe5"; /* st1w { z0.s },p0,[x6] */
    uint8_t left_b[16], right_b[16], expected_b[16], got_b[16];
    uint32_t left_s[4], right_s[4], expected_s[4], got_s[4];
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40100;
    uint64_t x6 = 0x40200;
    int i;

    for (i = 0; i < 16; i++) {
        left_b[i] = (uint8_t)(0x10 + i);
        right_b[i] = (uint8_t)(0x80 + i);
        expected_b[i] = i < 4 ? left_b[i] : right_b[i - 4];
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_b,
                    sizeof(code_b) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, left_b, sizeof(left_b)));
    OK(uc_mem_write(uc, x5, right_b, sizeof(right_b)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_b) - 1, 0, 0));
    OK(uc_mem_read(uc, x6, got_b, sizeof(got_b)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got_b[i] == expected_b[i]);
    }
    OK(uc_close(uc));

    for (i = 0; i < 4; i++) {
        left_s[i] = 0x10101010u + (uint32_t)i;
        right_s[i] = 0x80808080u + (uint32_t)i;
        expected_s[i] = i < 2 ? left_s[i] : right_s[i - 2];
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_s,
                    sizeof(code_s) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, left_s, sizeof(left_s)));
    OK(uc_mem_write(uc, x5, right_s, sizeof(right_s)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_s) - 1, 0, 0));
    OK(uc_mem_read(uc, x6, got_s, sizeof(got_s)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(got_s[i] == expected_s[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_tbl_tbx(void)
{
    uc_engine *uc;
    const char code[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x00\xa4" /* ld1b { z1.b },p0/z,[x4] */
        "\xa2\xa0\x00\xa4" /* ld1b { z2.b },p0/z,[x5] */
        "\xc4\xa0\x00\xa4" /* ld1b { z4.b },p0/z,[x6] */
        "\x20\x28\x24\x05" /* tbl z0.b,{z1.b,z2.b},z4.b */
        "\x00\xe1\x00\xe4" /* st1b { z0.b },p0,[x8] */
        "\xe3\xa0\x00\xa4" /* ld1b { z3.b },p0/z,[x7] */
        "\x23\x2c\x24\x05" /* tbx z3.b,z1.b,z4.b */
        "\x23\xe1\x00\xe4"; /* st1b { z3.b },p0,[x9] */
    const char code_h[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\xa0\xa4" /* ld1h { z1.h },p0/z,[x4] */
        "\xa2\xa0\xa0\xa4" /* ld1h { z2.h },p0/z,[x5] */
        "\xc4\xa0\xa0\xa4" /* ld1h { z4.h },p0/z,[x6] */
        "\x20\x28\x64\x05" /* tbl z0.h,{z1.h,z2.h},z4.h */
        "\x00\xe1\xa0\xe4" /* st1h { z0.h },p0,[x8] */
        "\xe3\xa0\xa0\xa4" /* ld1h { z3.h },p0/z,[x7] */
        "\x23\x2c\x64\x05" /* tbx z3.h,z1.h,z4.h */
        "\x23\xe1\xa0\xe4"; /* st1h { z3.h },p0,[x9] */
    const char code_s[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x40\xa5" /* ld1w { z1.s },p0/z,[x4] */
        "\xa2\xa0\x40\xa5" /* ld1w { z2.s },p0/z,[x5] */
        "\xc4\xa0\x40\xa5" /* ld1w { z4.s },p0/z,[x6] */
        "\x20\x28\xa4\x05" /* tbl z0.s,{z1.s,z2.s},z4.s */
        "\x00\xe1\x40\xe5" /* st1w { z0.s },p0,[x8] */
        "\xe3\xa0\x40\xa5" /* ld1w { z3.s },p0/z,[x7] */
        "\x23\x2c\xa4\x05" /* tbx z3.s,z1.s,z4.s */
        "\x23\xe1\x40\xe5"; /* st1w { z3.s },p0,[x9] */
    const char code_d[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\xe0\xa5" /* ld1d { z1.d },p0/z,[x4] */
        "\xa2\xa0\xe0\xa5" /* ld1d { z2.d },p0/z,[x5] */
        "\xc4\xa0\xe0\xa5" /* ld1d { z4.d },p0/z,[x6] */
        "\x20\x28\xe4\x05" /* tbl z0.d,{z1.d,z2.d},z4.d */
        "\x00\xe1\xe0\xe5" /* st1d { z0.d },p0,[x8] */
        "\xe3\xa0\xe0\xa5" /* ld1d { z3.d },p0/z,[x7] */
        "\x23\x2c\xe4\x05" /* tbx z3.d,z1.d,z4.d */
        "\x23\xe1\xe0\xe5"; /* st1d { z3.d },p0,[x9] */
    uint8_t table0[16], table1[16], indexes[16], initial[16];
    uint8_t expected_tbl[16], expected_tbx[16], got[16];
    uint16_t table0_h[8], table1_h[8], indexes_h[8], initial_h[8];
    uint16_t expected_tbl_h[8], expected_tbx_h[8], got_h[8];
    uint32_t table0_s[4], table1_s[4], indexes_s[4], initial_s[4];
    uint32_t expected_tbl_s[4], expected_tbx_s[4], got_s[4];
    uint64_t table0_d[4], table1_d[4], indexes_d[4], initial_d[4];
    uint64_t expected_tbl_d[4], expected_tbx_d[4], got_d[4];
    uint64_t x4 = 0x40000;
    uint64_t x5 = 0x40100;
    uint64_t x6 = 0x40200;
    uint64_t x7 = 0x40300;
    uint64_t x8 = 0x40400;
    uint64_t x9 = 0x40500;
    int i;

    const uint8_t idx_values[16] = {
        0, 1, 15, 16, 17, 31, 32, 5,
        20, 14, 30, 40, 7, 18, 2, 29
    };
    const uint16_t idx_values_h[8] = { 0, 1, 7, 8, 9, 15, 16, 3 };
    const uint32_t idx_values_s[4] = { 0, 3, 4, 8 };
    const uint64_t idx_values_d[4] = { 0, 3, 4, 8 };

    for (i = 0; i < 16; i++) {
        table0[i] = (uint8_t)(0x10 + i);
        table1[i] = (uint8_t)(0x80 + i);
        indexes[i] = idx_values[i];
        initial[i] = (uint8_t)(0xd0 + i);
    }

    for (i = 0; i < 16; i++) {
        int index = idx_values[i];

        if (index < 16) {
            expected_tbl[i] = table0[index];
            expected_tbx[i] = table0[index];
        } else if (index < 32) {
            expected_tbl[i] = table1[index - 16];
            expected_tbx[i] = initial[i];
        } else {
            expected_tbl[i] = 0;
            expected_tbx[i] = initial[i];
        }
    }

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, table0, sizeof(table0)));
    OK(uc_mem_write(uc, x5, table1, sizeof(table1)));
    OK(uc_mem_write(uc, x6, indexes, sizeof(indexes)));
    OK(uc_mem_write(uc, x7, initial, sizeof(initial)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_reg_write(uc, UC_ARM64_REG_X9, &x9));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, x8, got, sizeof(got)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got[i] == expected_tbl[i]);
    }
    OK(uc_mem_read(uc, x9, got, sizeof(got)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(got[i] == expected_tbx[i]);
    }
    OK(uc_close(uc));

    for (i = 0; i < 8; i++) {
        table0_h[i] = (uint16_t)(0x1100 + i);
        table1_h[i] = (uint16_t)(0x8800 + i);
        indexes_h[i] = idx_values_h[i];
        initial_h[i] = (uint16_t)(0xd000 + i);
    }
    for (i = 0; i < 8; i++) {
        int index = idx_values_h[i];

        if (index < 8) {
            expected_tbl_h[i] = table0_h[index];
            expected_tbx_h[i] = table0_h[index];
        } else if (index < 16) {
            expected_tbl_h[i] = table1_h[index - 8];
            expected_tbx_h[i] = initial_h[i];
        } else {
            expected_tbl_h[i] = 0;
            expected_tbx_h[i] = initial_h[i];
        }
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_h,
                    sizeof(code_h) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, table0_h, sizeof(table0_h)));
    OK(uc_mem_write(uc, x5, table1_h, sizeof(table1_h)));
    OK(uc_mem_write(uc, x6, indexes_h, sizeof(indexes_h)));
    OK(uc_mem_write(uc, x7, initial_h, sizeof(initial_h)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_reg_write(uc, UC_ARM64_REG_X9, &x9));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_h) - 1, 0, 0));
    OK(uc_mem_read(uc, x8, got_h, sizeof(got_h)));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(got_h[i] == expected_tbl_h[i]);
    }
    OK(uc_mem_read(uc, x9, got_h, sizeof(got_h)));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(got_h[i] == expected_tbx_h[i]);
    }
    OK(uc_close(uc));

    for (i = 0; i < 4; i++) {
        table0_s[i] = 0x11000000u + (uint32_t)i;
        table1_s[i] = 0x88000000u + (uint32_t)i;
        indexes_s[i] = idx_values_s[i];
        initial_s[i] = 0xd0000000u + (uint32_t)i;
    }
    for (i = 0; i < 4; i++) {
        uint32_t index = idx_values_s[i];

        if (index < 4) {
            expected_tbl_s[i] = table0_s[index];
            expected_tbx_s[i] = table0_s[index];
        } else if (index < 8) {
            expected_tbl_s[i] = table1_s[index - 4];
            expected_tbx_s[i] = initial_s[i];
        } else {
            expected_tbl_s[i] = 0;
            expected_tbx_s[i] = initial_s[i];
        }
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_s,
                    sizeof(code_s) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, table0_s, sizeof(table0_s)));
    OK(uc_mem_write(uc, x5, table1_s, sizeof(table1_s)));
    OK(uc_mem_write(uc, x6, indexes_s, sizeof(indexes_s)));
    OK(uc_mem_write(uc, x7, initial_s, sizeof(initial_s)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_reg_write(uc, UC_ARM64_REG_X9, &x9));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_s) - 1, 0, 0));
    OK(uc_mem_read(uc, x8, got_s, sizeof(got_s)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(got_s[i] == expected_tbl_s[i]);
    }
    OK(uc_mem_read(uc, x9, got_s, sizeof(got_s)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(got_s[i] == expected_tbx_s[i]);
    }
    OK(uc_close(uc));

    for (i = 0; i < 4; i++) {
        table0_d[i] = 0x1100000000000000ull + (uint64_t)i;
        table1_d[i] = 0x8800000000000000ull + (uint64_t)i;
        indexes_d[i] = idx_values_d[i];
        initial_d[i] = 0xd000000000000000ull + (uint64_t)i;
    }
    for (i = 0; i < 4; i++) {
        uint64_t index = idx_values_d[i];

        if (index < 4) {
            expected_tbl_d[i] = table0_d[index];
            expected_tbx_d[i] = table0_d[index];
        } else if (index < 8) {
            expected_tbl_d[i] = table1_d[index - 4];
            expected_tbx_d[i] = initial_d[i];
        } else {
            expected_tbl_d[i] = 0;
            expected_tbx_d[i] = initial_d[i];
        }
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code_d,
                    sizeof(code_d) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, table0_d, sizeof(table0_d)));
    OK(uc_mem_write(uc, x5, table1_d, sizeof(table1_d)));
    OK(uc_mem_write(uc, x6, indexes_d, sizeof(indexes_d)));
    OK(uc_mem_write(uc, x7, initial_d, sizeof(initial_d)));
    test_arm64_mte_enable_sve_vq(uc, 1);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_reg_write(uc, UC_ARM64_REG_X9, &x9));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code_d) - 1, 0, 0));
    OK(uc_mem_read(uc, x8, got_d, sizeof(got_d)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(got_d[i] == expected_tbl_d[i]);
    }
    OK(uc_mem_read(uc, x9, got_d, sizeof(got_d)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(got_d[i] == expected_tbx_d[i]);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve2_ld1ro(void)
{
    uc_engine *uc;
    const char code[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\xc1\x20\x21\xa5" /* ld1row { z1.s },p0/z,[x6,#0x20] */
        "\xc2\x00\x27\xa5" /* ld1row { z2.s },p0/z,[x6,x7,lsl #2] */
        "\x01\xe1\x40\xe5" /* st1w { z1.s },p0,[x8] */
        "\x22\xe1\x40\xe5"; /* st1w { z2.s },p0,[x9] */
    const char invalid_vl_code[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\xc1\x20\x21\xa5"; /* ld1row { z1.s },p0/z,[x6,#0x20] */
    uint32_t data[16];
    uint32_t expected[2][16];
    uint32_t fill[16];
    uint32_t got[16];
    uint64_t x6 = 0x40000;
    uint64_t x7 = 8;
    uint64_t x8 = 0x40200;
    uint64_t x9 = 0x40300;
    const uint64_t zcr_len[2] = { 3, 2 };
    int i, j;

    for (i = 0; i < 16; i++) {
        data[i] = 0x1000 + i;
        fill[i] = 0x5a5a5a5a;
    }
    for (i = 0; i < 16; i++) {
        expected[0][i] = data[8 + (i & 7)];
        if (i < 8) {
            expected[1][i] = data[8 + i];
        } else if (i < 12) {
            expected[1][i] = 0;
        } else {
            expected[1][i] = fill[i];
        }
    }

    for (j = 0; j < 2; j++) {
        uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                        sizeof(code) - 1, UC_CPU_ARM64_MAX);
        OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
        OK(uc_mem_write(uc, 0x40000, data, sizeof(data)));
        OK(uc_mem_write(uc, x8, fill, sizeof(fill)));
        OK(uc_mem_write(uc, x9, fill, sizeof(fill)));
        test_arm64_mte_enable_sve_vq(uc, zcr_len[j]);
        OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
        OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
        OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
        OK(uc_reg_write(uc, UC_ARM64_REG_X9, &x9));

        OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
        OK(uc_mem_read(uc, x8, got, sizeof(got)));
        for (i = 0; i < 16; i++) {
            TEST_CHECK(got[i] == expected[j][i]);
        }
        OK(uc_mem_read(uc, x9, got, sizeof(got)));
        for (i = 0; i < 16; i++) {
            TEST_CHECK(got[i] == expected[j][i]);
        }

        OK(uc_close(uc));
    }

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, invalid_vl_code,
                    sizeof(invalid_vl_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, data, sizeof(data)));
    test_arm64_mte_enable_sve_vq(uc, 0);
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(invalid_vl_code) - 1,
                            0, 0) == UC_ERR_EXCEPTION);
    OK(uc_close(uc));

    test_arm64_i8mm_expect_exception(0xa52120c1, UC_CPU_ARM64_A72);
}

static void test_arm64_mte_sve_contiguous_access(void)
{
    uc_engine *uc;
    const char store_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x60\x38\x20\x05" /* mov z0.b,w3 */
        "\x80\xe0\x00\xe4"; /* st1b { z0.b },p0,[x4] */
    const char load_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x00\xa4" /* ld1b { z1.b },p0/z,[x4] */
        "\xc1\xe0\x00\xe4"; /* st1b { z1.b },p0,[x6] */
    const char ldff_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x61\x38\x20\x05" /* mov z1.b,w3 */
        "\x81\x60\x05\xa4" /* ldff1b { z1.b },p0/z,[x4,x5] */
        "\xc1\xe0\x00\xe4"; /* st1b { z1.b },p0,[x6] */
    const char ldnf_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\x10\xa4" /* ldnf1b { z1.b },p0/z,[x4] */
        "\xc1\xe0\x00\xe4"; /* st1b { z1.b },p0,[x6] */
    const char ldff_gather_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\xe2\xa0\x40\xa5" /* ld1w { z2.s },p0/z,[x7] */
        "\x61\x38\xa0\x05" /* mov z1.s,w3 */
        "\x81\x60\x02\x84" /* ldff1b { z1.s },p0/z,[x4,z2.s,uxtw] */
        "\xc1\xe0\x40\xe5"; /* st1w { z1.s },p0,[x6] */
    const char ld_gather_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\xe2\xa0\x40\xa5" /* ld1w { z2.s },p0/z,[x7] */
        "\x61\x38\xa0\x05" /* mov z1.s,w3 */
        "\x81\x40\x02\x84" /* ld1b { z1.s },p0/z,[x4,z2.s,uxtw] */
        "\xc1\xe0\x40\xe5"; /* st1w { z1.s },p0,[x6] */
    const char st_gather_code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\xc1\xa0\x40\xa5" /* ld1w { z1.s },p0/z,[x6] */
        "\xe2\xa0\x40\xa5" /* ld1w { z2.s },p0/z,[x7] */
        "\x81\x80\x42\xe4"; /* st1b { z1.s },p0,[x4,z2.s,uxtw] */
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0x0c00000000000000ull;
    uint64_t x3 = 0x5a;
    uint64_t x4 = 0x0c00000000040000ull;
    uint64_t x5 = 0;
    uint64_t x6 = 0x40100;
    uint64_t x7 = 0x40200;
    uint8_t mem[16];
    uint8_t expected[16];
    uint32_t offsets[4];
    uint32_t words[4];
    int i;

    memset(expected, 0x5a, sizeof(expected));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, store_code,
                    sizeof(store_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(store_code) - 1,
                    0, 0));
    OK(uc_mem_read(uc, 0x40000, mem, sizeof(mem)));
    TEST_CHECK(memcmp(mem, expected, sizeof(mem)) == 0);
    OK(uc_close(uc));

    memset(expected, 0xa5, sizeof(expected));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, store_code,
                    sizeof(store_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    x4 = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(store_code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40000, mem, sizeof(mem)));
    TEST_CHECK(memcmp(mem, expected, sizeof(mem)) == 0);
    OK(uc_close(uc));

    for (i = 0; i < (int)sizeof(expected); i++) {
        expected[i] = (uint8_t)(0x30 + i);
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, load_code,
                    sizeof(load_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    x4 = 0x0c00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(load_code) - 1,
                    0, 0));
    OK(uc_mem_read(uc, 0x40100, mem, sizeof(mem)));
    TEST_CHECK(memcmp(mem, expected, sizeof(mem)) == 0);
    OK(uc_close(uc));

    memset(mem, 0, sizeof(mem));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, load_code,
                    sizeof(load_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    OK(uc_mem_write(uc, 0x40100, mem, sizeof(mem)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    x4 = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(load_code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40100, mem, sizeof(mem)));
    for (i = 0; i < (int)sizeof(mem); i++) {
        TEST_CHECK(mem[i] == 0);
    }
    OK(uc_close(uc));

    memset(expected, 0xa5, sizeof(expected));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, ldff_code,
                    sizeof(ldff_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    OK(uc_mem_write(uc, 0x40100, expected, sizeof(expected)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    x3 = 0;
    x4 = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(ldff_code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40100, mem, sizeof(mem)));
    TEST_CHECK(memcmp(mem, expected, sizeof(mem)) == 0);
    OK(uc_close(uc));

    for (i = 0; i < (int)sizeof(expected); i++) {
        expected[i] = (uint8_t)(0x40 + i);
    }
    memset(mem, 0, sizeof(mem));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, ldff_code,
                    sizeof(ldff_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    OK(uc_mem_write(uc, 0x40100, mem, sizeof(mem)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    x4 = 0x0c00000000040008ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(ldff_code) - 1,
                    0, 0));
    OK(uc_mem_read(uc, 0x40100, mem, sizeof(mem)));
    TEST_CHECK(memcmp(mem, expected + 8, 8) == 0);
    for (i = 8; i < (int)sizeof(mem); i++) {
        TEST_CHECK(mem[i] == 0);
    }
    OK(uc_close(uc));

    memset(mem, 0xa5, sizeof(mem));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, ldnf_code,
                    sizeof(ldnf_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    OK(uc_mem_write(uc, 0x40100, mem, sizeof(mem)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    x4 = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(ldnf_code) - 1,
                    0, 0));
    OK(uc_mem_read(uc, 0x40100, mem, sizeof(mem)));
    for (i = 0; i < (int)sizeof(mem); i++) {
        TEST_CHECK(mem[i] == 0);
    }
    OK(uc_close(uc));

    for (i = 0; i < (int)sizeof(expected); i++) {
        expected[i] = (uint8_t)(0x60 + i);
    }
    for (i = 0; i < 4; i++) {
        offsets[i] = (uint32_t)i;
        words[i] = 0;
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, ld_gather_code,
                    sizeof(ld_gather_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    OK(uc_mem_write(uc, 0x40100, words, sizeof(words)));
    OK(uc_mem_write(uc, 0x40200, offsets, sizeof(offsets)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    x3 = 0;
    x4 = 0x0c00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_emu_start(uc, code_start,
                    code_start + sizeof(ld_gather_code) - 1, 0, 0));
    OK(uc_mem_read(uc, 0x40100, words, sizeof(words)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(words[i] == expected[i]);
    }
    OK(uc_close(uc));

    memset(expected, 0xa5, sizeof(expected));
    for (i = 0; i < 4; i++) {
        offsets[i] = (uint32_t)i;
        words[i] = 0xa5a5a5a5u;
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, ld_gather_code,
                    sizeof(ld_gather_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    OK(uc_mem_write(uc, 0x40100, words, sizeof(words)));
    OK(uc_mem_write(uc, 0x40200, offsets, sizeof(offsets)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    x4 = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(ld_gather_code) - 1,
                            0, 0) == UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40100, words, sizeof(words)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(words[i] == 0xa5a5a5a5u);
    }
    OK(uc_close(uc));

    memset(expected, 0xa5, sizeof(expected));
    for (i = 0; i < 4; i++) {
        offsets[i] = (uint32_t)i;
        words[i] = 0x70717273u + (uint32_t)i;
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, st_gather_code,
                    sizeof(st_gather_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    OK(uc_mem_write(uc, 0x40100, words, sizeof(words)));
    OK(uc_mem_write(uc, 0x40200, offsets, sizeof(offsets)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    x4 = 0x0c00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_emu_start(uc, code_start,
                    code_start + sizeof(st_gather_code) - 1, 0, 0));
    OK(uc_mem_read(uc, 0x40000, mem, sizeof(mem)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(mem[i] == (uint8_t)words[i]);
    }
    for (i = 4; i < (int)sizeof(mem); i++) {
        TEST_CHECK(mem[i] == 0xa5);
    }
    OK(uc_close(uc));

    memset(expected, 0xa5, sizeof(expected));
    offsets[0] = 0;
    offsets[1] = 1;
    offsets[2] = 16;
    offsets[3] = 17;
    for (i = 0; i < 4; i++) {
        words[i] = 0x80818283u + (uint32_t)i;
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, st_gather_code,
                    sizeof(st_gather_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    OK(uc_mem_write(uc, 0x40100, words, sizeof(words)));
    OK(uc_mem_write(uc, 0x40200, offsets, sizeof(offsets)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    x4 = 0x0c00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(st_gather_code) - 1,
                            0, 0) == UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40000, mem, sizeof(mem)));
    TEST_CHECK(memcmp(mem, expected, sizeof(mem)) == 0);
    OK(uc_close(uc));

    memset(expected, 0xa5, sizeof(expected));
    for (i = 0; i < 4; i++) {
        offsets[i] = (uint32_t)i;
        words[i] = 0xa5a5a5a5u;
    }
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, ldff_gather_code,
                    sizeof(ldff_gather_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    OK(uc_mem_write(uc, 0x40100, words, sizeof(words)));
    OK(uc_mem_write(uc, 0x40200, offsets, sizeof(offsets)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    x3 = 0;
    x4 = 0x0d00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(ldff_gather_code) - 1,
                            0, 0) == UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40100, words, sizeof(words)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(words[i] == 0xa5a5a5a5u);
    }
    OK(uc_close(uc));

    for (i = 0; i < (int)sizeof(expected); i++) {
        expected[i] = (uint8_t)(0x50 + i);
    }
    offsets[0] = 8;
    offsets[1] = 9;
    offsets[2] = 16;
    offsets[3] = 17;
    memset(words, 0, sizeof(words));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, ldff_gather_code,
                    sizeof(ldff_gather_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    OK(uc_mem_write(uc, 0x40100, words, sizeof(words)));
    OK(uc_mem_write(uc, 0x40200, offsets, sizeof(offsets)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    x4 = 0x0c00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_emu_start(uc, code_start,
                    code_start + sizeof(ldff_gather_code) - 1, 0, 0));
    OK(uc_mem_read(uc, 0x40100, words, sizeof(words)));
    TEST_CHECK(words[0] == expected[8]);
    TEST_CHECK(words[1] == expected[9]);
    TEST_CHECK(words[2] == 0);
    TEST_CHECK(words[3] == 0);
    OK(uc_close(uc));
}

static void test_arm64_mte_sve_gather_scatter_sizem1(void)
{
    uint8_t load_code[20];
    uint8_t store_code[20];
    uint8_t mem[32];
    uint8_t expected[32];
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    uint32_t offsets[4] = { 15, 0, 2, 4 };
    uint32_t words[4];
    uc_engine *uc;
    uint64_t x4 = 0x0c00000000040000ull;
    uint64_t x6 = 0x40100;
    uint64_t x7 = 0x40200;
    const uint64_t tag0 = 0x0c00000000000000ull;
    const uint64_t tag1 = 0x0d00000000000000ull;
    int i;

    test_arm64_emit32(load_code, 0, 0xd9200822);  /* stg x2,[x1] */
    test_arm64_emit32(load_code, 4, 0x2518e3e0);  /* ptrue p0.b */
    test_arm64_emit32(load_code, 8, 0xa540a0e2);  /* ld1w z2.s */
    test_arm64_emit32(load_code, 12, 0x84824081); /* ld1h z1.s */
    test_arm64_emit32(load_code, 16, 0xe540e0c1); /* st1w z1.s */

    test_arm64_emit32(store_code, 0, 0xd9200822);  /* stg x2,[x1] */
    test_arm64_emit32(store_code, 4, 0x2518e3e0);  /* ptrue p0.b */
    test_arm64_emit32(store_code, 8, 0xa540a0c1);  /* ld1w z1.s */
    test_arm64_emit32(store_code, 12, 0xa540a0e2); /* ld1w z2.s */
    test_arm64_emit32(store_code, 16, 0xe4c28081); /* st1h z1.s */

    for (i = 0; i < (int)sizeof(mem); i++) {
        mem[i] = (uint8_t)(0x10 + i);
    }
    memset(words, 0, sizeof(words));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)load_code,
                    sizeof(load_code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, mem, sizeof(mem)));
    OK(uc_mem_write(uc, 0x40100, words, sizeof(words)));
    OK(uc_mem_write(uc, 0x40200, offsets, sizeof(offsets)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    test_arm64_mte_store_tag_at(uc, 0x40000, tag0);
    test_arm64_mte_store_tag_at(uc, 0x40010, tag0);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_emu_start(uc, code_start + 4, code_start + sizeof(load_code),
                    0, 0));
    OK(uc_mem_read(uc, 0x40100, words, sizeof(words)));
    TEST_CHECK(words[0] == 0x0000201f);
    TEST_CHECK(words[1] == 0x00001110);
    TEST_CHECK(words[2] == 0x00001312);
    TEST_CHECK(words[3] == 0x00001514);
    OK(uc_close(uc));

    memset(words, 0xa5, sizeof(words));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)load_code,
                    sizeof(load_code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, mem, sizeof(mem)));
    OK(uc_mem_write(uc, 0x40100, words, sizeof(words)));
    OK(uc_mem_write(uc, 0x40200, offsets, sizeof(offsets)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    test_arm64_mte_store_tag_at(uc, 0x40000, tag0);
    test_arm64_mte_store_tag_at(uc, 0x40010, tag1);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    TEST_CHECK(uc_emu_start(uc, code_start + 4,
                            code_start + sizeof(load_code), 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40100, words, sizeof(words)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(words[i] == 0xa5a5a5a5u);
    }
    OK(uc_close(uc));

    memset(mem, 0xa5, sizeof(mem));
    memcpy(expected, mem, sizeof(expected));
    words[0] = 0x11112233;
    words[1] = 0x22224455;
    words[2] = 0x33336677;
    words[3] = 0x44448899;
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)store_code,
                    sizeof(store_code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, mem, sizeof(mem)));
    OK(uc_mem_write(uc, 0x40100, words, sizeof(words)));
    OK(uc_mem_write(uc, 0x40200, offsets, sizeof(offsets)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    test_arm64_mte_store_tag_at(uc, 0x40000, tag0);
    test_arm64_mte_store_tag_at(uc, 0x40010, tag0);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_emu_start(uc, code_start + 4, code_start + sizeof(store_code),
                    0, 0));
    OK(uc_mem_read(uc, 0x40000, mem, sizeof(mem)));
    TEST_CHECK(mem[15] == 0x33);
    TEST_CHECK(mem[16] == 0x22);
    TEST_CHECK(mem[0] == 0x55);
    TEST_CHECK(mem[1] == 0x44);
    TEST_CHECK(mem[2] == 0x77);
    TEST_CHECK(mem[3] == 0x66);
    TEST_CHECK(mem[4] == 0x99);
    TEST_CHECK(mem[5] == 0x88);
    OK(uc_close(uc));

    memset(mem, 0xa5, sizeof(mem));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)store_code,
                    sizeof(store_code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, mem, sizeof(mem)));
    OK(uc_mem_write(uc, 0x40100, words, sizeof(words)));
    OK(uc_mem_write(uc, 0x40200, offsets, sizeof(offsets)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    test_arm64_mte_store_tag_at(uc, 0x40000, tag0);
    test_arm64_mte_store_tag_at(uc, 0x40010, tag1);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    TEST_CHECK(uc_emu_start(uc, code_start + 4,
                            code_start + sizeof(store_code), 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40000, mem, sizeof(mem)));
    TEST_CHECK(memcmp(mem, expected, sizeof(mem)) == 0);
    OK(uc_close(uc));

    memset(words, 0xa5, sizeof(words));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)load_code,
                    sizeof(load_code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, expected, sizeof(expected)));
    OK(uc_mem_write(uc, 0x40100, words, sizeof(words)));
    OK(uc_mem_write(uc, 0x40200, offsets, sizeof(offsets)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    test_arm64_mte_enable_sve(uc);
    test_arm64_mte_store_tag_at(uc, 0x40000, tag0);
    test_arm64_mte_store_tag_at(uc, 0x40010, tag1);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    TEST_CHECK(uc_emu_start(uc, code_start + 4,
                            code_start + sizeof(load_code), 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40100, words, sizeof(words)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(words[i] == 0xa5a5a5a5u);
    }
    OK(uc_close(uc));

    memset(mem, 0xa5, sizeof(mem));
    words[0] = 0x11112233;
    words[1] = 0x22224455;
    words[2] = 0x33336677;
    words[3] = 0x44448899;
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)store_code,
                    sizeof(store_code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, mem, sizeof(mem)));
    OK(uc_mem_write(uc, 0x40100, words, sizeof(words)));
    OK(uc_mem_write(uc, 0x40200, offsets, sizeof(offsets)));
    test_arm64_mte_enable_checks(uc, 3ULL << 40);
    test_arm64_mte_enable_sve(uc);
    test_arm64_mte_store_tag_at(uc, 0x40000, tag0);
    test_arm64_mte_store_tag_at(uc, 0x40010, tag1);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_emu_start(uc, code_start + 4, code_start + sizeof(store_code),
                    0, 0));
    OK(uc_mem_read(uc, 0x40000, mem, sizeof(mem)));
    TEST_CHECK(mem[15] == 0x33);
    TEST_CHECK(mem[16] == 0x22);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 1);
    OK(uc_close(uc));
}

static void test_arm64_mte_sve_whole_register_access(void)
{
    uint8_t load_code[16];
    uint8_t store_code[20];
    uint8_t mem[32];
    uint8_t out[16];
    uint8_t expected[32];
    uc_engine *uc;
    uint64_t x4 = 0x0c00000000040008ull;
    uint64_t x6 = 0x40100;
    const uint64_t tag0 = 0x0c00000000000000ull;
    const uint64_t tag1 = 0x0d00000000000000ull;
    int i;

    test_arm64_emit32(load_code, 0, 0xd9200822);  /* stg x2,[x1] */
    test_arm64_emit32(load_code, 4, 0x2518e3e0);  /* ptrue p0.b */
    test_arm64_emit32(load_code, 8, 0x85804081);  /* ldr z1,[x4] */
    test_arm64_emit32(load_code, 12, 0xe400e0c1); /* st1b z1.b */

    test_arm64_emit32(store_code, 0, 0xd9200822);  /* stg x2,[x1] */
    test_arm64_emit32(store_code, 4, 0x2518e3e0);  /* ptrue p0.b */
    test_arm64_emit32(store_code, 8, 0xa400a0c1);  /* ld1b z1.b */
    test_arm64_emit32(store_code, 12, 0xe5804081); /* str z1,[x4] */
    test_arm64_emit32(store_code, 16, 0xd503201f); /* nop */

    for (i = 0; i < (int)sizeof(mem); i++) {
        mem[i] = (uint8_t)(0x30 + i);
    }
    memset(out, 0, sizeof(out));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)load_code,
                    sizeof(load_code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, mem, sizeof(mem)));
    OK(uc_mem_write(uc, 0x40100, out, sizeof(out)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    test_arm64_mte_store_tag_at(uc, 0x40000, tag0);
    test_arm64_mte_store_tag_at(uc, 0x40010, tag0);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start + 4, code_start + sizeof(load_code),
                    0, 0));
    OK(uc_mem_read(uc, 0x40100, out, sizeof(out)));
    TEST_CHECK(memcmp(out, mem + 8, sizeof(out)) == 0);
    OK(uc_close(uc));

    memset(out, 0xa5, sizeof(out));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)load_code,
                    sizeof(load_code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, mem, sizeof(mem)));
    OK(uc_mem_write(uc, 0x40100, out, sizeof(out)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    test_arm64_mte_store_tag_at(uc, 0x40000, tag0);
    test_arm64_mte_store_tag_at(uc, 0x40010, tag1);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    TEST_CHECK(uc_emu_start(uc, code_start + 4,
                            code_start + sizeof(load_code), 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40100, out, sizeof(out)));
    for (i = 0; i < (int)sizeof(out); i++) {
        TEST_CHECK(out[i] == 0xa5);
    }
    OK(uc_close(uc));

    for (i = 0; i < (int)sizeof(out); i++) {
        out[i] = (uint8_t)(0x70 + i);
    }
    memset(mem, 0xa5, sizeof(mem));
    memcpy(expected, mem, sizeof(expected));
    memcpy(expected + 8, out, sizeof(out));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)store_code,
                    sizeof(store_code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, mem, sizeof(mem)));
    OK(uc_mem_write(uc, 0x40100, out, sizeof(out)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    test_arm64_mte_store_tag_at(uc, 0x40000, tag0);
    test_arm64_mte_store_tag_at(uc, 0x40010, tag0);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_emu_start(uc, code_start + 4, code_start + sizeof(store_code),
                    0, 0));
    OK(uc_mem_read(uc, 0x40000, mem, sizeof(mem)));
    TEST_CHECK(memcmp(mem, expected, sizeof(mem)) == 0);
    OK(uc_close(uc));

    memset(mem, 0xa5, sizeof(mem));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)store_code,
                    sizeof(store_code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, mem, sizeof(mem)));
    OK(uc_mem_write(uc, 0x40100, out, sizeof(out)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_mte_enable_sve(uc);
    test_arm64_mte_store_tag_at(uc, 0x40000, tag0);
    test_arm64_mte_store_tag_at(uc, 0x40010, tag1);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    TEST_CHECK(uc_emu_start(uc, code_start + 4,
                            code_start + sizeof(store_code), 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40000, mem, sizeof(mem)));
    for (i = 0; i < (int)sizeof(mem); i++) {
        TEST_CHECK(mem[i] == 0xa5);
    }
    OK(uc_close(uc));
}

static void test_arm64_sve_contiguous_store_fault_no_partial(void)
{
    uint8_t code[12];
    uint8_t before[8];
    uint8_t after[8];
    uc_engine *uc;
    uint64_t x3 = 0x5a;
    uint64_t x4 = 0x40ff8;
    uc_err err;

    test_arm64_emit32(code, 0, 0x2518e3e0); /* ptrue p0.b */
    test_arm64_emit32(code, 4, 0x05203860); /* mov z0.b,w3 */
    test_arm64_emit32(code, 8, 0xe400e080); /* st1b { z0.b },p0,[x4] */

    memset(before, 0xa5, sizeof(before));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, before, sizeof(before)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));

    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    TEST_CHECK_(err == UC_ERR_WRITE_UNMAPPED, "err=%u", err);
    OK(uc_mem_read(uc, x4, after, sizeof(after)));
    TEST_CHECK(memcmp(after, before, sizeof(after)) == 0);
    OK(uc_close(uc));
}

static void test_arm64_sve_scatter_store_fault_no_partial(void)
{
    const char code[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\xc1\xa0\x40\xa5" /* ld1w { z1.s },p0/z,[x6] */
        "\xe2\xa0\x40\xa5" /* ld1w { z2.s },p0/z,[x7] */
        "\x81\x80\x42\xe4"; /* st1b { z1.s },p0,[x4,z2.s,uxtw] */
    uint8_t before[16];
    uint8_t after[16];
    uint32_t words[4] = {
        0x1111115a, 0x2222226b, 0x3333337c, 0x4444448d,
    };
    uint32_t offsets[4] = { 0, 0x1000, 1, 2 };
    uc_engine *uc;
    uint64_t x4 = 0x40000;
    uint64_t x6 = 0x40200;
    uint64_t x7 = 0x40300;
    uc_err err;

    memset(before, 0xa5, sizeof(before));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, before, sizeof(before)));
    OK(uc_mem_write(uc, x6, words, sizeof(words)));
    OK(uc_mem_write(uc, x7, offsets, sizeof(offsets)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));

    err = uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0);
    TEST_CHECK_(err == UC_ERR_WRITE_UNMAPPED, "err=%u", err);
    OK(uc_mem_read(uc, 0x40000, after, sizeof(after)));
    TEST_CHECK(memcmp(after, before, sizeof(after)) == 0);
    OK(uc_close(uc));
}

static void test_arm64_sve_ldff1_split_first_element(void)
{
    const char code[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\x60\xa5\xa4" /* ldff1h { z1.h },p0/z,[x4,x5] */
        "\xc1\xe0\xa0\xe4"; /* st1h { z1.h },p0,[x6] */
    uint8_t data[4] = { 0x34, 0x12, 0x78, 0x56 };
    uint16_t expected[8];
    uint16_t out[8];
    uc_engine *uc;
    uint64_t x4 = 0x40fff;
    uint64_t x5 = 0;
    uint64_t x6 = 0x42000;
    uc_err err;

    memset(expected, 0, sizeof(expected));
    expected[0] = 0x1234;
    memset(out, 0xa5, sizeof(out));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x3000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, data, sizeof(data)));
    OK(uc_mem_write(uc, x6, out, sizeof(out)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));

    err = uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0);
    TEST_CHECK_(err == UC_ERR_OK, "err=%u", err);
    OK(uc_mem_read(uc, x6, out, sizeof(out)));
    TEST_CHECK(memcmp(out, expected, sizeof(out)) == 0);
    OK(uc_close(uc));
}

static void test_arm64_sve_ldnf1_split_first_element(void)
{
    const char code[] =
        "\xe0\xe3\x18\x25" /* ptrue p0.b */
        "\x81\xa0\xb0\xa4" /* ldnf1h { z1.h },p0/z,[x4] */
        "\xc1\xe0\xa0\xe4"; /* st1h { z1.h },p0,[x6] */
    uint8_t data[4] = { 0x34, 0x12, 0x78, 0x56 };
    uint16_t expected[8];
    uint16_t out[8];
    uc_engine *uc;
    uint64_t x4 = 0x40fff;
    uint64_t x6 = 0x42000;
    uc_err err;

    memset(expected, 0, sizeof(expected));
    expected[0] = 0x1234;
    memset(out, 0xa5, sizeof(out));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x3000, UC_PROT_ALL));
    OK(uc_mem_write(uc, x4, data, sizeof(data)));
    OK(uc_mem_write(uc, x6, out, sizeof(out)));
    test_arm64_mte_enable_sve(uc);
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));

    err = uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0);
    TEST_CHECK_(err == UC_ERR_OK, "err=%u", err);
    OK(uc_mem_read(uc, x6, out, sizeof(out)));
    TEST_CHECK(memcmp(out, expected, sizeof(out)) == 0);
    OK(uc_close(uc));
}

static void test_arm64_mte_tag_split_lifecycle(void)
{
    uc_engine *uc;
    const char code[] =
        "\x22\x08\x20\xd9" /* stg x2,[x1] */
        "\x23\x00\x60\xd9"; /* ldg x3,[x1] */
    uint8_t prealloc[0x3000];

    memset(prealloc, 0, sizeof(prealloc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    test_arm64_mte_enable_checks(uc, 0);

    OK(uc_mem_map(uc, 0x40000, 0x3000, UC_PROT_ALL));
    test_arm64_mte_store_tag_at(uc, 0x40000, 0x0c00000000000000ull);
    test_arm64_mte_store_tag_at(uc, 0x41000, 0x0d00000000000000ull);
    test_arm64_mte_store_tag_at(uc, 0x42000, 0x0e00000000000000ull);
    OK(uc_mem_protect(uc, 0x41000, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    TEST_CHECK(test_arm64_mte_load_tag_at(uc, 0x40000, 0x5000) ==
               0x0c00000000005000ull);
    TEST_CHECK(test_arm64_mte_load_tag_at(uc, 0x41000, 0x6000) ==
               0x0d00000000006000ull);
    TEST_CHECK(test_arm64_mte_load_tag_at(uc, 0x42000, 0x7000) ==
               0x0e00000000007000ull);

    OK(uc_mem_map(uc, 0x50000, 0x3000, UC_PROT_ALL));
    test_arm64_mte_store_tag_at(uc, 0x50000, 0x0100000000000000ull);
    test_arm64_mte_store_tag_at(uc, 0x51000, 0x0200000000000000ull);
    test_arm64_mte_store_tag_at(uc, 0x52000, 0x0300000000000000ull);
    OK(uc_mem_unmap(uc, 0x51000, 0x1000));
    TEST_CHECK(test_arm64_mte_load_tag_at(uc, 0x50000, 0x8000) ==
               0x0100000000008000ull);
    TEST_CHECK(test_arm64_mte_load_tag_at(uc, 0x52000, 0x9000) ==
               0x0300000000009000ull);
    OK(uc_mem_map(uc, 0x51000, 0x1000, UC_PROT_ALL));
    TEST_CHECK(test_arm64_mte_load_tag_at(uc, 0x51000, 0xa000) == 0xa000);

    OK(uc_mem_map_ptr(uc, 0x60000, 0x3000, UC_PROT_ALL, prealloc));
    test_arm64_mte_store_tag_at(uc, 0x60000, 0x0400000000000000ull);
    test_arm64_mte_store_tag_at(uc, 0x61000, 0x0500000000000000ull);
    test_arm64_mte_store_tag_at(uc, 0x62000, 0x0600000000000000ull);
    OK(uc_mem_protect(uc, 0x61000, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    TEST_CHECK(test_arm64_mte_load_tag_at(uc, 0x60000, 0xb000) ==
               0x040000000000b000ull);
    TEST_CHECK(test_arm64_mte_load_tag_at(uc, 0x61000, 0xc000) ==
               0x050000000000c000ull);
    TEST_CHECK(test_arm64_mte_load_tag_at(uc, 0x62000, 0xd000) ==
               0x060000000000d000ull);

    OK(uc_close(uc));
}

static void test_arm64_mte_stgp(void)
{
    uc_engine *uc;
    const char code[] =
        "\x24\x14\x00\x69" /* stgp x4,x5,[x1] */
        "\x23\x00\x60\xd9" /* ldg  x3,[x1] */
        "\x46\x1c\x81\x69" /* stgp x6,x7,[x2,#0x20]! */
        "\x48\xa5\x80\x68" /* stgp x8,x9,[x10],#0x10 */
        "\x4b\x00\x60\xd9" /* ldg  x11,[x2] */
        "\xac\x01\x60\xd9"; /* ldg  x12,[x13] */
    const char invalid_code[] =
        "\x24\x14\x00\x68"; /* stgp x4,x5,[x1], invalid index */
    uint64_t x1 = 0x0a00000000040000ull;
    uint64_t x2 = 0x0b00000000040020ull;
    uint64_t x3 = 0x5000;
    uint64_t x4 = 0x1122334455667788ull;
    uint64_t x5 = 0x8877665544332211ull;
    uint64_t x6 = 0x0102030405060708ull;
    uint64_t x7 = 0x8090a0b0c0d0e0f0ull;
    uint64_t x8 = 0xfedcba9876543210ull;
    uint64_t x9 = 0x0011223344556677ull;
    uint64_t x10 = 0x0c00000000040080ull;
    uint64_t x11 = 0x6000;
    uint64_t x12 = 0x7000;
    uint64_t x13 = 0x0c00000000040080ull;
    uint64_t mem;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    test_arm64_mte_enable_checks(uc, 0);

    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_reg_write(uc, UC_ARM64_REG_X9, &x9));
    OK(uc_reg_write(uc, UC_ARM64_REG_X10, &x10));
    OK(uc_reg_write(uc, UC_ARM64_REG_X11, &x11));
    OK(uc_reg_write(uc, UC_ARM64_REG_X12, &x12));
    OK(uc_reg_write(uc, UC_ARM64_REG_X13, &x13));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_read(uc, UC_ARM64_REG_X10, &x10));
    OK(uc_reg_read(uc, UC_ARM64_REG_X11, &x11));
    OK(uc_reg_read(uc, UC_ARM64_REG_X12, &x12));
    TEST_CHECK(x2 == 0x0b00000000040040ull);
    TEST_CHECK(x3 == 0x0a00000000005000ull);
    TEST_CHECK(x10 == 0x0c00000000040090ull);
    TEST_CHECK(x11 == 0x0b00000000006000ull);
    TEST_CHECK(x12 == 0x0c00000000007000ull);

    OK(uc_mem_read(uc, 0x40000, &mem, sizeof(mem)));
    TEST_CHECK(mem == 0x1122334455667788ull);
    OK(uc_mem_read(uc, 0x40008, &mem, sizeof(mem)));
    TEST_CHECK(mem == 0x8877665544332211ull);
    OK(uc_mem_read(uc, 0x40040, &mem, sizeof(mem)));
    TEST_CHECK(mem == 0x0102030405060708ull);
    OK(uc_mem_read(uc, 0x40048, &mem, sizeof(mem)));
    TEST_CHECK(mem == 0x8090a0b0c0d0e0f0ull);
    OK(uc_mem_read(uc, 0x40080, &mem, sizeof(mem)));
    TEST_CHECK(mem == 0xfedcba9876543210ull);
    OK(uc_mem_read(uc, 0x40088, &mem, sizeof(mem)));
    TEST_CHECK(mem == 0x0011223344556677ull);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, invalid_code,
                    sizeof(invalid_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    test_arm64_mte_enable_checks(uc, 0);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(invalid_code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_close(uc));
}

static void test_arm64_mte_dc_zva_checked(void)
{
    uc_engine *uc;
    const char zva_code[] =
        "\x61\x74\x0b\xd5" /* dc     gva,x1 */
        "\x21\x74\x0b\xd5" /* dc     zva,x1 */
        "\x23\x00\x60\xd9"; /* ldg    x3,[x1] */
    const char mismatch_code[] =
        "\x61\x74\x0b\xd5" /* dc     gva,x1 */
        "\x24\x74\x0b\xd5"; /* dc     zva,x4 */
    const uint32_t TCO[5] = { 3, 3, 4, 2, 7 };
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    const uint64_t pstate_tco = 1ULL << 25;
    uint8_t fill[0x40];
    uint8_t zeroed[0x40];
    uint8_t expected_zero[0x40] = { 0 };
    uint64_t x1 = 0x0c00000000040000ull;
    uint64_t x3 = 0x5000;
    uint64_t x4 = 0x0d00000000040000ull;

    memset(fill, 0xaa, sizeof(fill));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, zva_code,
                    sizeof(zva_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, fill, sizeof(fill)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(zva_code) - 1,
                    0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_mem_read(uc, 0x40000, zeroed, sizeof(zeroed)));
    TEST_CHECK(x3 == 0x0c00000000005000ull);
    TEST_CHECK(memcmp(zeroed, expected_zero, sizeof(zeroed)) == 0);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, mismatch_code,
                    sizeof(mismatch_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, fill, sizeof(fill)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(mismatch_code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_mem_read(uc, 0x40000, zeroed, sizeof(zeroed)));
    TEST_CHECK(memcmp(zeroed, fill, sizeof(zeroed)) == 0);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, mismatch_code,
                    sizeof(mismatch_code) - 1, UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, fill, sizeof(fill)));
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    test_arm64_pauth_cp_reg_write(uc, TCO, pstate_tco);
    x1 = 0x0c00000000040000ull;
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_emu_start(uc, code_start,
                    code_start + sizeof(mismatch_code) - 1, 0, 0));
    OK(uc_mem_read(uc, 0x40000, zeroed, sizeof(zeroed)));
    TEST_CHECK(memcmp(zeroed, expected_zero, sizeof(zeroed)) == 0);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0);
    OK(uc_close(uc));
}

static void test_arm64_mte_dc_zva_original_fault_addr(void)
{
    uc_engine *uc;
    const char code[] = "\x21\x74\x0b\xd5"; /* dc zva,x1 */
    uint64_t x1 = 0x0c00000000040020ull;
    uint64_t invalid_addr = 0;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    test_arm64_mte_enable_checks(uc, 1ULL << 40);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                            0, 0) == UC_ERR_WRITE_UNMAPPED);
    OK(uc_ctl_get_invalid_addr(uc, &invalid_addr));
    TEST_CHECK_(invalid_addr == 0x40020, "invalid_addr=0x%llx",
                invalid_addr);
    OK(uc_close(uc));
}

static void test_arm64_mte_dc_gva_gzva(void)
{
    uc_engine *uc;
    const char code[] =
        "\x61\x74\x0b\xd5" /* dc   gva,x1 */
        "\x23\x00\x60\xd9" /* ldg  x3,[x1] */
        "\x84\x74\x0b\xd5" /* dc   gzva,x4 */
        "\x85\x00\x60\xd9"; /* ldg  x5,[x4] */
    uint8_t fill[0x40];
    uint8_t data[0x40];
    uint8_t expected_zero[0x40] = { 0 };
    uint64_t x1 = 0x0e00000000040000ull;
    uint64_t x3 = 0x5000;
    uint64_t x4 = 0x0f00000000040100ull;
    uint64_t x5 = 0x6000;

    memset(fill, 0xaa, sizeof(fill));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000, fill, sizeof(fill)));
    OK(uc_mem_write(uc, 0x40100, fill, sizeof(fill)));
    test_arm64_mte_enable_checks(uc, 0);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_read(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_mem_read(uc, 0x40000, data, sizeof(data)));
    TEST_CHECK(x3 == 0x0e00000000005000ull);
    TEST_CHECK(memcmp(data, fill, sizeof(data)) == 0);
    OK(uc_mem_read(uc, 0x40100, data, sizeof(data)));
    TEST_CHECK(x5 == 0x0f00000000006000ull);
    TEST_CHECK(memcmp(data, expected_zero, sizeof(data)) == 0);

    OK(uc_close(uc));
}

static void test_arm64_mte_dc_gva_probe(void)
{
    uc_engine *uc;
    const char code[] = "\x61\x74\x0b\xd5"; /* dc gva,x1 */
    uint64_t x1 = 0x40000;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                            0, 0) == UC_ERR_WRITE_UNMAPPED);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_mem_map(uc, 0x40000, 0x1000, UC_PROT_READ));
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                            0, 0) == UC_ERR_WRITE_PROT);
    OK(uc_close(uc));
}

static void test_arm64_mte_cache_ops(void)
{
    uc_engine *uc;
    const char code[] =
        "\x61\x76\x08\xd5" /* dc igvac,x1 */
        "\x82\x76\x08\xd5" /* dc igsw,x2 */
        "\x63\x7a\x0b\xd5"; /* dc cgvac,x3 */
    const char old_cpu_code[] = "\x63\x7a\x0b\xd5"; /* dc cgvac,x3 */
    uint64_t x1 = 0x40000;
    uint64_t x2 = 0;
    uint64_t x3 = 0x40020;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_MAX);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, old_cpu_code,
                    sizeof(old_cpu_code) - 1, UC_CPU_ARM64_A72);
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(old_cpu_code) - 1,
                            0, 0) == UC_ERR_EXCEPTION);
    OK(uc_close(uc));
}

static void test_arm64_generic_timer_state_one(const uint32_t cval_reg[5],
                                               const uint32_t ctl_reg[5])
{
    uc_engine *uc;
    uint8_t code[36];
    uint64_t x1 = UINT64_MAX;
    uint64_t x2 = 0;
    uint64_t x3 = 7;
    uint64_t x4 = 0;
    uint64_t x5 = 0;
    uint64_t x6 = 1;
    uint64_t x7 = 0;
    uint64_t x8 = 0;
    uint64_t x9 = 0;

    memset(code, 0, sizeof(code));
    test_arm64_emit32(code, 0, test_arm64_msr_sysreg(1, cval_reg));
    test_arm64_emit32(code, 4, test_arm64_mrs_sysreg(2, cval_reg));
    test_arm64_emit32(code, 8, test_arm64_msr_sysreg(3, ctl_reg));
    test_arm64_emit32(code, 12, test_arm64_mrs_sysreg(4, ctl_reg));
    test_arm64_emit32(code, 16, test_arm64_msr_sysreg(5, cval_reg));
    test_arm64_emit32(code, 20, test_arm64_msr_sysreg(6, ctl_reg));
    test_arm64_emit32(code, 24, test_arm64_mrs_sysreg(7, ctl_reg));
    test_arm64_emit32(code, 28, test_arm64_msr_sysreg(8, ctl_reg));
    test_arm64_emit32(code, 32, test_arm64_mrs_sysreg(9, ctl_reg));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_write(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_write(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_write(uc, UC_ARM64_REG_X8, &x8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X2, &x2));
    OK(uc_reg_read(uc, UC_ARM64_REG_X4, &x4));
    OK(uc_reg_read(uc, UC_ARM64_REG_X7, &x7));
    OK(uc_reg_read(uc, UC_ARM64_REG_X9, &x9));
    TEST_CHECK(x2 == UINT64_MAX);
    TEST_CHECK(x4 == 3);
    TEST_CHECK(x7 == 5);
    TEST_CHECK(x9 == 0);
    OK(uc_close(uc));
}

static void test_arm64_generic_timer_state(void)
{
    const uint32_t CNTP_CTL_EL0[5] = { 3, 3, 14, 2, 1 };
    const uint32_t CNTP_CVAL_EL0[5] = { 3, 3, 14, 2, 2 };
    const uint32_t CNTV_CTL_EL0[5] = { 3, 3, 14, 3, 1 };
    const uint32_t CNTV_CVAL_EL0[5] = { 3, 3, 14, 3, 2 };

    test_arm64_generic_timer_state_one(CNTP_CVAL_EL0, CNTP_CTL_EL0);
    test_arm64_generic_timer_state_one(CNTV_CVAL_EL0, CNTV_CTL_EL0);
}

static void test_arm64_pmu_counter_delta(void)
{
    uc_engine *uc;
    uint8_t code[28];
    const uint32_t PMCR_EL0[5] = { 3, 3, 9, 12, 0 };
    const uint32_t PMCNTENSET_EL0[5] = { 3, 3, 9, 12, 1 };
    const uint32_t PMCCNTR_EL0[5] = { 3, 3, 9, 13, 0 };
    const uint32_t PMEVTYPER0_EL0[5] = { 3, 3, 14, 12, 0 };
    const uint32_t PMEVCNTR0_EL0[5] = { 3, 3, 14, 8, 0 };
    uint64_t pmcr = 0x41;
    uint64_t pmccntr = 0x1234567800000000ULL;
    uint64_t pmevtyper = 0x11;
    uint64_t pmevcntr = 0x40000000;
    uint64_t pmcnten = (1ULL << 31) | 1;
    uint64_t x5 = 0;
    uint64_t x6 = 0;

    memset(code, 0, sizeof(code));
    test_arm64_emit32(code, 0, test_arm64_msr_sysreg(1, PMCR_EL0));
    test_arm64_emit32(code, 4, test_arm64_msr_sysreg(2, PMCCNTR_EL0));
    test_arm64_emit32(code, 8, test_arm64_msr_sysreg(3, PMEVTYPER0_EL0));
    test_arm64_emit32(code, 12, test_arm64_msr_sysreg(4, PMEVCNTR0_EL0));
    test_arm64_emit32(code, 16, test_arm64_msr_sysreg(7, PMCNTENSET_EL0));
    test_arm64_emit32(code, 20, test_arm64_mrs_sysreg(5, PMCCNTR_EL0));
    test_arm64_emit32(code, 24, test_arm64_mrs_sysreg(6, PMEVCNTR0_EL0));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &pmcr));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &pmccntr));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &pmevtyper));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &pmevcntr));
    OK(uc_reg_write(uc, UC_ARM64_REG_X7, &pmcnten));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X5, &x5));
    OK(uc_reg_read(uc, UC_ARM64_REG_X6, &x6));
    TEST_CHECK(x5 >= pmccntr);
    TEST_CHECK((uint32_t)x6 >= (uint32_t)pmevcntr);
    OK(uc_close(uc));
}

static void test_arm64_pmu_pmuv3p5_event_counter_one(int cpu_model,
                                                     uint64_t expected,
                                                     bool check_lp)
{
    uc_engine *uc;
    uint8_t code[16];
    const uint32_t PMCR_EL0[5] = { 3, 3, 9, 12, 0 };
    const uint32_t PMEVCNTR0_EL0[5] = { 3, 3, 14, 8, 0 };
    uint64_t pmcr = 0x80;
    uint64_t pmevcntr = 0x1234567887654321ULL;
    uint64_t x3 = 0;
    uint64_t x4 = 0;

    memset(code, 0, sizeof(code));
    test_arm64_emit32(code, 0, test_arm64_msr_sysreg(1, PMCR_EL0));
    test_arm64_emit32(code, 4, test_arm64_mrs_sysreg(4, PMCR_EL0));
    test_arm64_emit32(code, 8, test_arm64_msr_sysreg(2, PMEVCNTR0_EL0));
    test_arm64_emit32(code, 12, test_arm64_mrs_sysreg(3, PMEVCNTR0_EL0));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), cpu_model);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &pmcr));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &pmevcntr));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X3, &x3));
    OK(uc_reg_read(uc, UC_ARM64_REG_X4, &x4));
    TEST_CHECK(x3 == expected);
    if (check_lp) {
        TEST_CHECK((x4 & 0x80) == 0x80);
    }
    OK(uc_close(uc));
}

static void test_arm64_pmu_pmuv3p5_event_counter(void)
{
    uc_engine *uc;
    const char code[] = "\x1f\x20\x03\xd5";
    const uint32_t ID_AA64DFR0_EL1[5] = { 3, 0, 0, 5, 0 };
    uint64_t dfr0;

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code,
                    sizeof(code) - 1, UC_CPU_ARM64_MAX);
    dfr0 = test_arm64_pauth_cp_reg_read(uc, ID_AA64DFR0_EL1);
    TEST_CHECK(((dfr0 >> 8) & 0xf) == 6);
    OK(uc_close(uc));

    test_arm64_pmu_pmuv3p5_event_counter_one(
        UC_CPU_ARM64_MAX, 0x1234567887654321ULL, true);
    test_arm64_pmu_pmuv3p5_event_counter_one(
        UC_CPU_ARM64_A72, 0x87654321, false);
}

static void test_arm64_pmu_el2_hlp_long_counter_one(uint64_t mdcr_el2,
                                                    uint64_t expected_pmovsr)
{
    uc_engine *uc;
    uint8_t code[28];
    const uint32_t SCR_EL3[5] = { 3, 6, 1, 1, 0 };
    const uint32_t MDCR_EL2[5] = { 3, 4, 1, 1, 1 };
    const uint32_t PMCR_EL0[5] = { 3, 3, 9, 12, 0 };
    const uint32_t PMCNTENSET_EL0[5] = { 3, 3, 9, 12, 1 };
    const uint32_t PMOVSCLR_EL0[5] = { 3, 3, 9, 12, 3 };
    const uint32_t PMSWINC_EL0[5] = { 3, 3, 9, 12, 4 };
    const uint32_t PMEVTYPER1_EL0[5] = { 3, 3, 14, 12, 1 };
    const uint32_t PMEVCNTR1_EL0[5] = { 3, 3, 14, 8, 1 };
    uint64_t pmcr = 1;
    uint64_t pmevtyper = 0;
    uint64_t pmevcntr = UINT32_MAX;
    uint64_t pmcnten = 1ULL << 1;
    uint64_t x6 = 0;
    uint64_t x7 = 0;

    memset(code, 0, sizeof(code));
    test_arm64_emit32(code, 0, test_arm64_msr_sysreg(1, PMCR_EL0));
    test_arm64_emit32(code, 4, test_arm64_msr_sysreg(2, PMEVTYPER1_EL0));
    test_arm64_emit32(code, 8, test_arm64_msr_sysreg(3, PMEVCNTR1_EL0));
    test_arm64_emit32(code, 12, test_arm64_msr_sysreg(4, PMCNTENSET_EL0));
    test_arm64_emit32(code, 16, test_arm64_msr_sysreg(4, PMSWINC_EL0));
    test_arm64_emit32(code, 20, test_arm64_mrs_sysreg(6, PMOVSCLR_EL0));
    test_arm64_emit32(code, 24, test_arm64_mrs_sysreg(7, PMEVCNTR1_EL0));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SCR_EL3, 1);
    test_arm64_pauth_cp_reg_write(uc, MDCR_EL2, mdcr_el2);
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &pmcr));
    OK(uc_reg_write(uc, UC_ARM64_REG_X2, &pmevtyper));
    OK(uc_reg_write(uc, UC_ARM64_REG_X3, &pmevcntr));
    OK(uc_reg_write(uc, UC_ARM64_REG_X4, &pmcnten));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X6, &x6));
    OK(uc_reg_read(uc, UC_ARM64_REG_X7, &x7));
    TEST_CHECK((x6 & (1ULL << 1)) == expected_pmovsr);
    TEST_CHECK(x7 == 0x100000000ULL);
    OK(uc_close(uc));
}

static void test_arm64_pmu_el2_hlp_long_counter(void)
{
    const uint64_t mdcr_hlp_hpmn1 = (1ULL << 26) | (1ULL << 7) | 1;

    test_arm64_pmu_el2_hlp_long_counter_one(4, 1ULL << 1);
    test_arm64_pmu_el2_hlp_long_counter_one(mdcr_hlp_hpmn1, 0);
}

static uc_err test_arm64_pmu_el0_pmevcntr_run(uint64_t pmuserenr,
                                              bool is_write,
                                              uint64_t *x2)
{
    uc_engine *uc;
    uint8_t code[4];
    const uint32_t PMUSERENR_EL0[5] = { 3, 3, 9, 14, 0 };
    const uint32_t PMEVCNTR0_EL0[5] = { 3, 3, 14, 8, 0 };
    uint32_t pstate = 0;
    uint64_t pmevcntr = 0x12345678;
    uint64_t x1 = 0x87654321;
    uc_err err;

    memset(code, 0, sizeof(code));
    test_arm64_emit32(code, 0,
                      is_write ? test_arm64_msr_sysreg(1, PMEVCNTR0_EL0) :
                                 test_arm64_mrs_sysreg(2, PMEVCNTR0_EL0));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, PMUSERENR_EL0, pmuserenr);
    test_arm64_pauth_cp_reg_write(uc, PMEVCNTR0_EL0, pmevcntr);
    OK(uc_reg_write(uc, UC_ARM64_REG_PSTATE, &pstate));
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));

    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    if (x2) {
        OK(uc_reg_read(uc, UC_ARM64_REG_X2, x2));
    }

    OK(uc_close(uc));
    return err;
}

static void test_arm64_pmu_el0_direct_counter_access(void)
{
    uint64_t x2 = 0;

    TEST_CHECK(test_arm64_pmu_el0_pmevcntr_run(0, false, &x2) ==
               UC_ERR_EXCEPTION);
    TEST_CHECK(test_arm64_pmu_el0_pmevcntr_run(1ULL << 3, false, &x2) ==
               UC_ERR_OK);
    TEST_CHECK(x2 == 0x12345678);
    TEST_CHECK(test_arm64_pmu_el0_pmevcntr_run(1ULL << 3, true, NULL) ==
               UC_ERR_EXCEPTION);
}

static uc_err test_arm64_pmu_mdcr_tpm_run(uint64_t scr_el3)
{
    uc_engine *uc;
    uint8_t code[4];
    const uint32_t SCR_EL3[5] = { 3, 6, 1, 1, 0 };
    const uint32_t MDCR_EL2[5] = { 3, 4, 1, 1, 1 };
    const uint32_t PMCR_EL0[5] = { 3, 3, 9, 12, 0 };
    uint64_t mdcr_tpm = 1ULL << 6;
    uc_err err;

    memset(code, 0, sizeof(code));
    test_arm64_emit32(code, 0, test_arm64_mrs_sysreg(0, PMCR_EL0));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SCR_EL3, scr_el3);
    test_arm64_pauth_cp_reg_write(uc, MDCR_EL2, mdcr_tpm);

    err = uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0);
    OK(uc_close(uc));
    return err;
}

static void test_arm64_pmu_effective_mdcr_el2(void)
{
    TEST_CHECK(test_arm64_pmu_mdcr_tpm_run(0) == UC_ERR_OK);
    TEST_CHECK(test_arm64_pmu_mdcr_tpm_run(1) == UC_ERR_EXCEPTION);
}

static void test_arm64_pmu_pmcr_n_from_mdcr_el2(void)
{
    uc_engine *uc;
    uint8_t code[4];
    const uint32_t SCR_EL3[5] = { 3, 6, 1, 1, 0 };
    const uint32_t MDCR_EL2[5] = { 3, 4, 1, 1, 1 };
    const uint32_t PMCR_EL0[5] = { 3, 3, 9, 12, 0 };
    uint32_t pstate_el1h = 5;
    uint64_t mdcr_hpmn1 = 1;
    uint64_t x0 = 0;

    memset(code, 0, sizeof(code));
    test_arm64_emit32(code, 0, test_arm64_mrs_sysreg(0, PMCR_EL0));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, MDCR_EL2, mdcr_hpmn1);
    OK(uc_reg_write(uc, UC_ARM64_REG_PSTATE, &pstate_el1h));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &x0));
    TEST_CHECK(((x0 >> 11) & 0x1f) == 4);
    OK(uc_close(uc));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);
    test_arm64_pauth_cp_reg_write(uc, SCR_EL3, 1);
    test_arm64_pauth_cp_reg_write(uc, MDCR_EL2, mdcr_hpmn1);
    OK(uc_reg_write(uc, UC_ARM64_REG_PSTATE, &pstate_el1h));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X0, &x0));
    TEST_CHECK(((x0 >> 11) & 0x1f) == 1);
    OK(uc_close(uc));
}

static void test_arm64_vhe_el12_aliases(void)
{
    uc_engine *uc;
    uint8_t code[8];
    uint8_t old_code[4];
    uint32_t pstate = 9;
    uint64_t x1 = 0x333;
    uint64_t x2 = 0;
    const uint32_t ID_AA64PFR0_EL1[5] = { 3, 0, 0, 4, 0 };
    const uint32_t SCR_EL3[5] = { 3, 6, 1, 1, 0 };
    const uint32_t HCR_EL2[5] = { 3, 4, 1, 1, 0 };
    const uint32_t ZCR_EL1[5] = { 3, 0, 1, 2, 0 };
    const uint32_t ZCR_EL2[5] = { 3, 4, 1, 2, 0 };
    const uint32_t ZCR_EL12[5] = { 3, 5, 1, 2, 0 };
    const uint32_t SMCR_EL1[5] = { 3, 0, 1, 2, 6 };
    const uint32_t SMCR_EL2[5] = { 3, 4, 1, 2, 6 };
    const uint32_t SMCR_EL12[5] = { 3, 5, 1, 2, 6 };
    const uint32_t TFSR_EL1[5] = { 3, 0, 5, 6, 0 };
    const uint32_t TFSR_EL2[5] = { 3, 4, 5, 6, 0 };
    const uint32_t TFSR_EL12[5] = { 3, 5, 5, 6, 0 };
    const uint32_t SCXTNUM_EL1[5] = { 3, 0, 13, 0, 7 };
    const uint32_t SCXTNUM_EL2[5] = { 3, 4, 13, 0, 7 };
    const uint32_t SCXTNUM_EL12[5] = { 3, 5, 13, 0, 7 };
    const uint64_t scr = (1ULL << 0) | (1ULL << 8) | (1ULL << 10) |
                         (1ULL << 25) | (1ULL << 26);
    const uint64_t hcr = (1ULL << 31) | (1ULL << 34);

    memset(code, 0, sizeof(code));
    test_arm64_emit32(code, 0, test_arm64_msr_sysreg(1, TFSR_EL1));
    test_arm64_emit32(code, 4, test_arm64_mrs_sysreg(2, TFSR_EL1));

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)code,
                    sizeof(code), UC_CPU_ARM64_MAX);

    TEST_CHECK(((test_arm64_pauth_cp_reg_read(uc, ID_AA64PFR0_EL1) >> 56) &
                0xf) == 2);

    test_arm64_pauth_cp_reg_write(uc, ZCR_EL1, 0);
    test_arm64_pauth_cp_reg_write(uc, ZCR_EL2, 1);
    test_arm64_pauth_cp_reg_write(uc, ZCR_EL12, 2);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, ZCR_EL1) == 2);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, ZCR_EL2) == 1);

    test_arm64_pauth_cp_reg_write(uc, SMCR_EL1, 0);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL2, 1);
    test_arm64_pauth_cp_reg_write(uc, SMCR_EL12, 2);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, SMCR_EL1) == 2);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, SMCR_EL2) == 1);

    test_arm64_pauth_cp_reg_write(uc, SCXTNUM_EL1, 0x101);
    test_arm64_pauth_cp_reg_write(uc, SCXTNUM_EL2, 0x202);
    test_arm64_pauth_cp_reg_write(uc, SCXTNUM_EL12, 0x303);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, SCXTNUM_EL1) == 0x303);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, SCXTNUM_EL2) == 0x202);

    test_arm64_pauth_cp_reg_write(uc, TFSR_EL1, 0x111);
    test_arm64_pauth_cp_reg_write(uc, TFSR_EL2, 0x222);
    test_arm64_pauth_cp_reg_write(uc, TFSR_EL12, 0x444);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0x444);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL2) == 0x222);

    test_arm64_pauth_cp_reg_write(uc, TFSR_EL1, 0x111);
    test_arm64_pauth_cp_reg_write(uc, TFSR_EL2, 0x222);
    test_arm64_pauth_cp_reg_write(uc, SCR_EL3, scr);
    test_arm64_pauth_cp_reg_write(uc, HCR_EL2, hcr);
    OK(uc_reg_write(uc, UC_ARM64_REG_PSTATE, &pstate));
    OK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_ARM64_REG_X2, &x2));
    TEST_CHECK(x2 == x1);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL1) == 0x111);
    TEST_CHECK(test_arm64_pauth_cp_reg_read(uc, TFSR_EL2) == x1);
    OK(uc_close(uc));

    test_arm64_emit32(old_code, 0, test_arm64_mrs_sysreg(0, TFSR_EL12));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)old_code,
                    sizeof(old_code), UC_CPU_ARM64_A72);
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(old_code),
                            0, 0) == UC_ERR_EXCEPTION);
    OK(uc_close(uc));

    test_arm64_emit32(old_code, 0, test_arm64_mrs_sysreg(0, SCXTNUM_EL12));
    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, (const char *)old_code,
                    sizeof(old_code), UC_CPU_ARM64_A72);
    TEST_CHECK(uc_emu_start(uc, code_start, code_start + sizeof(old_code),
                            0, 0) == UC_ERR_EXCEPTION);
    OK(uc_close(uc));
}

static void test_arm64_mte_requires_max(void)
{
    uc_engine *uc;
    const char code[] = "\x20\x0c\x82\x91"; /* addg x0,x1,#0x20,#3 */

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM64_A72);
    TEST_CHECK(uc_emu_start(uc, code_start,
                            code_start + sizeof(code) - 1, 0, 0) ==
               UC_ERR_EXCEPTION);
    OK(uc_close(uc));
}

TEST_LIST = {{"test_arm64_until", test_arm64_until},
             {"test_arm64_code_patching", test_arm64_code_patching},
             {"test_arm64_code_patching_count", test_arm64_code_patching_count},
             {"test_arm64_v8_cas", test_arm64_v8_cas},
             {"test_arm64_lse_rcpc_unaligned",
              test_arm64_lse_rcpc_unaligned},
             {"test_arm64_lse_signed_minmax_byte",
              test_arm64_lse_signed_minmax_byte},
             {"test_arm64_lse_rcpc_id_registers",
              test_arm64_lse_rcpc_id_registers},
             {"test_arm64_lse_rcpc_a72_rejects",
              test_arm64_lse_rcpc_a72_rejects},
             {"test_arm64_dgh_hint", test_arm64_dgh_hint},
             {"test_arm64_read_sctlr", test_arm64_read_sctlr},
             {"test_arm64_hook_insn_mrs", test_arm64_hook_insn_mrs},
             {"test_arm64_hook_insn_wfi", test_arm64_hook_insn_wfi},
             {"test_arm64_correct_address_in_small_jump_hook",
              test_arm64_correct_address_in_small_jump_hook},
             {"test_arm64_correct_address_in_long_jump_hook",
              test_arm64_correct_address_in_long_jump_hook},
             {"test_arm64_block_sync_pc", test_arm64_block_sync_pc},
             {"test_arm64_block_invalid_mem_read_write_sync",
              test_arm64_block_invalid_mem_read_write_sync},
             {"test_arm64_mmu", test_arm64_mmu},
             {"test_arm64_pc_wrap", test_arm64_pc_wrap},
             {"test_arm64_mem_prot_regress", test_arm64_mem_prot_regress},
             {"test_arm64_mem_hook_read_write", test_arm64_mem_hook_read_write},
             {"test_arm64_pc_guarantee", test_arm64_pc_guarantee},
             {"test_arm64_sve_id_registers", test_arm64_sve_id_registers},
             {"test_arm64_sme_foundation", test_arm64_sme_foundation},
             {"test_arm64_sme_svlength", test_arm64_sme_svlength},
             {"test_arm64_sme_nonstreaming_sve_ffr",
              test_arm64_sme_nonstreaming_sve_ffr},
             {"test_arm64_sme_nonstreaming_sve_misc",
              test_arm64_sme_nonstreaming_sve_misc},
             {"test_arm64_sme_zero_mova", test_arm64_sme_zero_mova},
             {"test_arm64_sme_context_save_restore",
              test_arm64_sme_context_save_restore},
             {"test_arm64_sme_mova_q_horizontal",
              test_arm64_sme_mova_q_horizontal},
             {"test_arm64_sme_adda", test_arm64_sme_adda},
             {"test_arm64_sme_ldstr", test_arm64_sme_ldstr},
             {"test_arm64_sme_ldst1", test_arm64_sme_ldst1},
             {"test_arm64_sme_ldst1_fault_no_partial",
              test_arm64_sme_ldst1_fault_no_partial},
             {"test_arm64_sme_psel", test_arm64_sme_psel},
             {"test_arm64_sme_ldst1_mte", test_arm64_sme_ldst1_mte},
             {"test_arm64_sme_imopa", test_arm64_sme_imopa},
             {"test_arm64_sme_fpout", test_arm64_sme_fpout},
             {"test_arm64_i8mm_advsimd", test_arm64_i8mm_advsimd},
             {"test_arm64_bf16_advsimd", test_arm64_bf16_advsimd},
             {"test_arm64_pauth_vanilla", test_arm64_pauth_vanilla},
             {"test_arm64_pauth_ctl", test_arm64_pauth_ctl},
             {"test_arm64_mte_register_only", test_arm64_mte_register_only},
             {"test_arm64_mte_ata_tag_generation",
              test_arm64_mte_ata_tag_generation},
             {"test_arm64_mte_tag_load_store",
              test_arm64_mte_tag_load_store},
             {"test_arm64_mte_tag_snapshot", test_arm64_mte_tag_snapshot},
             {"test_arm64_mte_tag_multiple", test_arm64_mte_tag_multiple},
             {"test_arm64_mte_checked_scalar_access",
              test_arm64_mte_checked_scalar_access},
             {"test_arm64_mte_tco_msr_imm",
              test_arm64_mte_tco_msr_imm},
             {"test_arm64_mte_simd_fp_single_access",
              test_arm64_mte_simd_fp_single_access},
             {"test_arm64_mte_advsimd_struct_range",
              test_arm64_mte_advsimd_struct_range},
             {"test_arm64_mte_lse_atomic_asym_sync_no_side_effect",
              test_arm64_mte_lse_atomic_asym_sync_no_side_effect},
             {"test_arm64_mte_ldapr_sync_tag_check",
              test_arm64_mte_ldapr_sync_tag_check},
             {"test_arm64_mte_lse_cas_asym_async_side_effect",
              test_arm64_mte_lse_cas_asym_async_side_effect},
             {"test_arm64_mte_exclusive_asym_access",
              test_arm64_mte_exclusive_asym_access},
             {"test_arm64_mte_sp_addressing_tagchecked",
             test_arm64_mte_sp_addressing_tagchecked},
             {"test_arm64_mte_sp_writeback_tagchecked",
              test_arm64_mte_sp_writeback_tagchecked},
             {"test_arm64_mte_pair_sp_tagchecked",
              test_arm64_mte_pair_sp_tagchecked},
             {"test_arm64_mte_pac_load_sp_tagchecked",
              test_arm64_mte_pac_load_sp_tagchecked},
             {"test_arm64_mte_tcma0_tag_zero_unchecked",
              test_arm64_mte_tcma0_tag_zero_unchecked},
             {"test_arm64_mte_ldapur_stlur_unchecked",
              test_arm64_mte_ldapur_stlur_unchecked},
             {"test_arm64_mte_ldapur_stlur_variants_unchecked",
              test_arm64_mte_ldapur_stlur_variants_unchecked},
             {"test_arm64_mte_unpriv_sp_no_tag_check",
              test_arm64_mte_unpriv_sp_no_tag_check},
             {"test_arm64_mte_unpriv_async_tag_check",
              test_arm64_mte_unpriv_async_tag_check},
             {"test_arm64_mte_page_attrs", test_arm64_mte_page_attrs},
             {"test_arm64_bti_guarded_page", test_arm64_bti_guarded_page},
             {"test_arm64_mte_hcr_dct", test_arm64_mte_hcr_dct},
             {"test_arm64_mte_cross_page_fault_priority",
              test_arm64_mte_cross_page_fault_priority},
             {"test_arm64_mte_ata_disabled_tag_op_probe",
              test_arm64_mte_ata_disabled_tag_op_probe},
             {"test_arm64_sve2_non_temporal_gather_scatter",
              test_arm64_sve2_non_temporal_gather_scatter},
             {"test_arm64_sve2_bitwise_ternary",
              test_arm64_sve2_bitwise_ternary},
             {"test_arm64_sve2_xar", test_arm64_sve2_xar},
             {"test_arm64_sve2_pmull", test_arm64_sve2_pmull},
             {"test_arm64_sve2_mul_base", test_arm64_sve2_mul_base},
             {"test_arm64_sve2_mul_indexed", test_arm64_sve2_mul_indexed},
             {"test_arm64_sve2_widen_indexed",
             test_arm64_sve2_widen_indexed},
             {"test_arm64_sve2_widen_accumulate",
             test_arm64_sve2_widen_accumulate},
             {"test_arm64_sve2_abs_accumulate",
             test_arm64_sve2_abs_accumulate},
             {"test_arm64_sve2_cadd_sqcadd",
              test_arm64_sve2_cadd_sqcadd},
             {"test_arm64_sve2_sqrdmla", test_arm64_sve2_sqrdmla},
             {"test_arm64_sve2_complex_dot",
             test_arm64_sve2_complex_dot},
             {"test_arm64_sve_i8mm", test_arm64_sve_i8mm},
             {"test_arm64_sve_bf16", test_arm64_sve_bf16},
             {"test_arm64_sve_f32mm_f64mm", test_arm64_sve_f32mm_f64mm},
             {"test_arm64_sve2_fp_convert", test_arm64_sve2_fp_convert},
             {"test_arm64_sve2_fp_pairwise_flogb",
              test_arm64_sve2_fp_pairwise_flogb},
             {"test_arm64_sve2_fmlal", test_arm64_sve2_fmlal},
             {"test_arm64_sve2_widen_add_shift",
              test_arm64_sve2_widen_add_shift},
             {"test_arm64_sve2_addhn", test_arm64_sve2_addhn},
             {"test_arm64_sve2_xtn", test_arm64_sve2_xtn},
             {"test_arm64_sve2_shift_narrow",
             test_arm64_sve2_shift_narrow},
             {"test_arm64_sve2_shift_accumulate",
              test_arm64_sve2_shift_accumulate},
             {"test_arm64_sve2_shift_insert",
              test_arm64_sve2_shift_insert},
             {"test_arm64_sve2_sat_unary", test_arm64_sve2_sat_unary},
             {"test_arm64_sve2_adalp", test_arm64_sve2_adalp},
             {"test_arm64_sve2_halving_add_sub",
              test_arm64_sve2_halving_add_sub},
             {"test_arm64_sve2_pairwise_pred",
              test_arm64_sve2_pairwise_pred},
             {"test_arm64_sve2_saturating_add_sub",
             test_arm64_sve2_saturating_add_sub},
             {"test_arm64_sve2_int_estimate",
              test_arm64_sve2_int_estimate},
             {"test_arm64_sve2_variable_shift",
              test_arm64_sve2_variable_shift},
             {"test_arm64_sve2_eor_adcl", test_arm64_sve2_eor_adcl},
             {"test_arm64_sve2_bitperm", test_arm64_sve2_bitperm},
             {"test_arm64_sve2_match_hist", test_arm64_sve2_match_hist},
             {"test_arm64_sve2_crypto", test_arm64_sve2_crypto},
             {"test_arm64_sve2_ext", test_arm64_sve2_ext},
             {"test_arm64_sve2_splice", test_arm64_sve2_splice},
             {"test_arm64_sve2_tbl_tbx", test_arm64_sve2_tbl_tbx},
             {"test_arm64_sve2_ld1ro", test_arm64_sve2_ld1ro},
             {"test_arm64_mte_sve_contiguous_access",
              test_arm64_mte_sve_contiguous_access},
             {"test_arm64_mte_sve_gather_scatter_sizem1",
              test_arm64_mte_sve_gather_scatter_sizem1},
             {"test_arm64_mte_sve_whole_register_access",
              test_arm64_mte_sve_whole_register_access},
             {"test_arm64_sve_contiguous_store_fault_no_partial",
              test_arm64_sve_contiguous_store_fault_no_partial},
             {"test_arm64_sve_scatter_store_fault_no_partial",
              test_arm64_sve_scatter_store_fault_no_partial},
             {"test_arm64_sve_ldff1_split_first_element",
              test_arm64_sve_ldff1_split_first_element},
             {"test_arm64_sve_ldnf1_split_first_element",
              test_arm64_sve_ldnf1_split_first_element},
             {"test_arm64_mte_tag_split_lifecycle",
              test_arm64_mte_tag_split_lifecycle},
             {"test_arm64_mte_stgp", test_arm64_mte_stgp},
             {"test_arm64_mte_dc_zva_checked",
              test_arm64_mte_dc_zva_checked},
             {"test_arm64_mte_dc_zva_original_fault_addr",
              test_arm64_mte_dc_zva_original_fault_addr},
             {"test_arm64_mte_dc_gva_gzva", test_arm64_mte_dc_gva_gzva},
             {"test_arm64_mte_dc_gva_probe", test_arm64_mte_dc_gva_probe},
             {"test_arm64_mte_cache_ops", test_arm64_mte_cache_ops},
             {"test_arm64_generic_timer_state", test_arm64_generic_timer_state},
             {"test_arm64_pmu_counter_delta", test_arm64_pmu_counter_delta},
             {"test_arm64_pmu_pmuv3p5_event_counter",
              test_arm64_pmu_pmuv3p5_event_counter},
             {"test_arm64_pmu_el2_hlp_long_counter",
             test_arm64_pmu_el2_hlp_long_counter},
             {"test_arm64_pmu_el0_direct_counter_access",
              test_arm64_pmu_el0_direct_counter_access},
             {"test_arm64_pmu_effective_mdcr_el2",
              test_arm64_pmu_effective_mdcr_el2},
             {"test_arm64_pmu_pmcr_n_from_mdcr_el2",
              test_arm64_pmu_pmcr_n_from_mdcr_el2},
             {"test_arm64_vhe_el12_aliases", test_arm64_vhe_el12_aliases},
             {"test_arm64_mte_requires_max", test_arm64_mte_requires_max},
             {NULL, NULL}};
