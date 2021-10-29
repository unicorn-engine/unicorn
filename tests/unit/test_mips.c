#include "unicorn_test.h"

const uint64_t code_start = 0x10000000;
const uint64_t code_len = 0x4000;

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static void test_mips_el_ori()
{
    uc_engine *uc;
    char code[] = "\x56\x34\x21\x34"; // ori $at, $at, 0x3456;
    int r_r1 = 0x6789;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_32 | UC_MODE_LITTLE_ENDIAN, code,
                    sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_1, &r_r1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_1, &r_r1));

    TEST_CHECK(r_r1 == 0x77df);

    OK(uc_close(uc));
}

static void test_mips_eb_ori()
{
    uc_engine *uc;
    char code[] = "\x34\x21\x34\x56"; // ori $at, $at, 0x3456;
    int r_r1 = 0x6789;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_32 | UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_1, &r_r1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_1, &r_r1));

    TEST_CHECK(r_r1 == 0x77df);

    OK(uc_close(uc));
}

static void test_mips_stop_at_branch()
{
    uc_engine *uc;
    char code[] =
        "\x02\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"; // j 0x8; nop;
    int r_pc = 0x0;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_32 | UC_MODE_LITTLE_ENDIAN, code,
                    sizeof(code) - 1);

    // Execute one instruction with branch delay slot.
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 1));

    OK(uc_reg_read(uc, UC_MIPS_REG_PC, &r_pc));

    // Even if we just execute one instruction, the instruction in the
    // delay slot would also be executed.
    TEST_CHECK(r_pc == code_start + 0x8);

    OK(uc_close(uc));
}

static void test_mips_stop_at_delay_slot()
{
    uc_engine *uc;
    char code[] =
        "\x02\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"; // j 0x8; nop;
    int r_pc = 0x0;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_32 | UC_MODE_LITTLE_ENDIAN, code,
                    sizeof(code) - 1);

    // Stop at the delay slot by design.
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_PC, &r_pc));

    // The branch instruction isn't committed and the PC is not updated.
    // Users is responsible to restart emulation at the branch instruction.
    TEST_CHECK(r_pc == code_start);

    OK(uc_close(uc));
}

static void test_mips_lwx_exception_issue_1314()
{
    uc_engine *uc;
    char code[] = "\x0a\xc8\x79\x7e"; // lwx $t9, $t9($s3)
    int reg;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_32 | UC_MODE_LITTLE_ENDIAN, code,
                    sizeof(code) - 1);
    OK(uc_mem_map(uc, 0x10000, 0x4000, UC_PROT_ALL));

    // Enable DSP
    // https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/MD00090-2B-MIPS32PRA-AFP-06.02.pdf
    OK(uc_reg_read(uc, UC_MIPS_REG_CP0_STATUS, &reg));
    reg |= (1 << 24);
    OK(uc_reg_write(uc, UC_MIPS_REG_CP0_STATUS, &reg));

    reg = 0;
    OK(uc_reg_write(uc, UC_MIPS_REG_1, &reg));
    OK(uc_reg_write(uc, UC_MIPS_REG_T9, &reg));
    reg = 0xdeadbeef;
    OK(uc_mem_write(uc, 0x10000, &reg, 4));
    reg = 0x10000;
    OK(uc_reg_write(uc, UC_MIPS_REG_S3, &reg));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_T9, &reg));

    TEST_CHECK(reg == 0xdeadbeef);

    OK(uc_close(uc));
}

TEST_LIST = {
    {"test_mips_stop_at_branch", test_mips_stop_at_branch},
    {"test_mips_stop_at_delay_slot", test_mips_stop_at_delay_slot},
    {"test_mips_el_ori", test_mips_el_ori},
    {"test_mips_eb_ori", test_mips_eb_ori},
    {"test_mips_lwx_exception_issue_1314", test_mips_lwx_exception_issue_1314},
    {NULL, NULL}};