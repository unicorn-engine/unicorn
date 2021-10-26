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

static void test_arm64_until()
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

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) - 1);

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

TEST_LIST = {{"test_arm64_until", test_arm64_until}, {NULL, NULL}};
