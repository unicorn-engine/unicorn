#include "acutest.h"
#include "unicorn/unicorn.h"
#include "unicorn_test.h"
#include <stdbool.h>
#include <stdio.h>

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

static void test_arm64_v8_pac(void)
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

static uint32_t test_arm64_mrs_hook_cb(uc_engine *uc, uc_arm64_reg reg,
                                       const uc_arm64_cp_reg *cp_reg)
{
    uint64_t r_x2 = 0x114514;

    OK(uc_reg_write(uc, reg, &r_x2));

    // Skip
    return 1;
}

static void test_arm64_mrs_hook(void)
{
    uc_engine *uc;
    uc_hook hk;
    uint64_t r_x2;
    // mrs        x2, tpidrro_el0
    char code[] = "\x62\xd0\x3b\xd5";

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM,
                    code, sizeof(code) - 1, UC_CPU_ARM64_A72);

    OK(uc_hook_add(uc, &hk, UC_HOOK_INSN, (void *)test_arm64_mrs_hook_cb, NULL,
                   1, 0, UC_ARM64_INS_MRS));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM64_REG_X2, &r_x2));

    TEST_CHECK(r_x2 == 0x114514);

    OK(uc_hook_del(uc, hk));

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

TEST_LIST = {{"test_arm64_until", test_arm64_until},
             {"test_arm64_code_patching", test_arm64_code_patching},
             {"test_arm64_code_patching_count", test_arm64_code_patching_count},
             {"test_arm64_v8_pac", test_arm64_v8_pac},
             {"test_arm64_read_sctlr", test_arm64_read_sctlr},
             {"test_arm64_mrs_hook", test_arm64_mrs_hook},
             {"test_arm64_correct_address_in_small_jump_hook",
              test_arm64_correct_address_in_small_jump_hook},
             {"test_arm64_correct_address_in_long_jump_hook",
              test_arm64_correct_address_in_long_jump_hook},
             {"test_arm64_block_sync_pc", test_arm64_block_sync_pc},
             {"test_arm64_block_invalid_mem_read_write_sync",
              test_arm64_block_invalid_mem_read_write_sync},
             {NULL, NULL}};
