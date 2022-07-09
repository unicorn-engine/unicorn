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

static void test_riscv32_nop(void)
{
    uc_engine *uc;
    char code[] = "\x13\x00\x00\x00"; // nop
    uint32_t r_t0 = 0x1234;
    uint32_t r_t1 = 0x5678;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code,
                    sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &r_t1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &r_t1));
    TEST_CHECK(r_t0 == 0x1234);
    TEST_CHECK(r_t1 == 0x5678);

    OK(uc_close(uc));
}

static void test_riscv64_nop(void)
{
    uc_engine *uc;
    char code[] = "\x13\x00\x00\x00"; // nop
    uint64_t r_t0 = 0x1234;
    uint64_t r_t1 = 0x5678;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &r_t1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &r_t1));
    TEST_CHECK(r_t0 == 0x1234);
    TEST_CHECK(r_t1 == 0x5678);

    OK(uc_close(uc));
}

static void test_riscv32_until_pc_update(void)
{
    uc_engine *uc;
    char code[] = "\x93\x02\x10\x00\x13\x03\x00\x02\x13\x01\x81\x00";

    /*
    addi t0, zero, 1
    addi t1, zero, 0x20
    addi sp, sp, 8
    */

    uint32_t r_t0 = 0x1234;
    uint32_t r_t1 = 0x7890;
    uint32_t r_pc = 0x0000;
    uint32_t r_sp = 0x1234;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code,
                    sizeof(code) - 1);

    // initialize machine registers
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &r_t1));
    OK(uc_reg_write(uc, UC_RISCV_REG_SP, &r_sp));

    // emulate the three instructions
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &r_t1));
    OK(uc_reg_read(uc, UC_RISCV_REG_SP, &r_sp));
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &r_pc));

    TEST_CHECK(r_t0 == 0x1);
    TEST_CHECK(r_t1 == 0x20);
    TEST_CHECK(r_sp == 0x123c);

    TEST_CHECK(r_pc == (code_start + sizeof(code) - 1));

    OK(uc_close(uc));
}

static void test_riscv64_until_pc_update(void)
{
    uc_engine *uc;
    char code[] = "\x93\x02\x10\x00\x13\x03\x00\x02\x13\x01\x81\x00";

    /*
    addi t0, zero, 1
    addi t1, zero, 0x20
    addi sp, sp, 8
    */

    uint64_t r_t0 = 0x1234;
    uint64_t r_t1 = 0x7890;
    uint64_t r_pc = 0x0000;
    uint64_t r_sp = 0x1234;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);

    // initialize machine registers
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &r_t1));
    OK(uc_reg_write(uc, UC_RISCV_REG_SP, &r_sp));

    // emulate the three instructions
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &r_t1));
    OK(uc_reg_read(uc, UC_RISCV_REG_SP, &r_sp));
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &r_pc));

    TEST_CHECK(r_t0 == 0x1);
    TEST_CHECK(r_t1 == 0x20);
    TEST_CHECK(r_sp == 0x123c);
    TEST_CHECK(r_pc == (code_start + sizeof(code) - 1));

    OK(uc_close(uc));
}

static void test_riscv32_3steps_pc_update(void)
{
    uc_engine *uc;
    char code[] = "\x93\x02\x10\x00\x13\x03\x00\x02\x13\x01\x81\x00";

    /*
    addi t0, zero, 1
    addi t1, zero, 0x20
    addi sp, sp, 8
    */

    uint32_t r_t0 = 0x1234;
    uint32_t r_t1 = 0x7890;
    uint32_t r_pc = 0x0000;
    uint32_t r_sp = 0x1234;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code,
                    sizeof(code) - 1);

    // initialize machine registers
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &r_t1));
    OK(uc_reg_write(uc, UC_RISCV_REG_SP, &r_sp));

    // emulate the three instructions
    OK(uc_emu_start(uc, code_start, -1, 0, 3));

    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &r_t1));
    OK(uc_reg_read(uc, UC_RISCV_REG_SP, &r_sp));
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &r_pc));

    TEST_CHECK(r_t0 == 0x1);
    TEST_CHECK(r_t1 == 0x20);
    TEST_CHECK(r_sp == 0x123c);

    TEST_CHECK(r_pc == (code_start + sizeof(code) - 1));

    OK(uc_close(uc));
}

static void test_riscv64_3steps_pc_update(void)
{
    uc_engine *uc;
    char code[] = "\x93\x02\x10\x00\x13\x03\x00\x02\x13\x01\x81\x00";

    /*
    addi t0, zero, 1
    addi t1, zero, 0x20
    addi sp, sp, 8
    */

    uint64_t r_t0 = 0x1234;
    uint64_t r_t1 = 0x7890;
    uint64_t r_pc = 0x0000;
    uint64_t r_sp = 0x1234;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);

    // initialize machine registers
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &r_t1));
    OK(uc_reg_write(uc, UC_RISCV_REG_SP, &r_sp));

    // emulate the three instructions
    OK(uc_emu_start(uc, code_start, -1, 0, 3));

    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &r_t1));
    OK(uc_reg_read(uc, UC_RISCV_REG_SP, &r_sp));
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &r_pc));

    TEST_CHECK(r_t0 == 0x1);
    TEST_CHECK(r_t1 == 0x20);
    TEST_CHECK(r_sp == 0x123c);
    TEST_CHECK(r_pc == (code_start + sizeof(code) - 1));

    OK(uc_close(uc));
}

static void test_riscv32_fp_move(void)
{
    uc_engine *uc;
    char code[] = "\xd3\x81\x10\x22"; // fmv.d f3, f1

    uint32_t r_f1 = 0x1234;
    uint32_t r_f3 = 0x5678;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code,
                    sizeof(code) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_RISCV_REG_F1, &r_f1);
    uc_reg_write(uc, UC_RISCV_REG_F3, &r_f3);

    // emulate the instruction
    OK(uc_emu_start(uc, code_start, -1, 0, 1));

    OK(uc_reg_read(uc, UC_RISCV_REG_F1, &r_f1));
    OK(uc_reg_read(uc, UC_RISCV_REG_F3, &r_f3));

    TEST_CHECK(r_f1 == 0x1234);
    TEST_CHECK(r_f3 == 0x1234);

    uc_close(uc);
}

static void test_riscv64_fp_move(void)
{
    uc_engine *uc;
    char code[] = "\xd3\x81\x10\x22"; // fmv.d f3, f1

    uint64_t r_f1 = 0x12341234;
    uint64_t r_f3 = 0x56785678;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);

    // initialize machine registers
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &r_f1));
    OK(uc_reg_write(uc, UC_RISCV_REG_F3, &r_f3));

    // emulate the instruction
    OK(uc_emu_start(uc, code_start, -1, 0, 1));

    OK(uc_reg_read(uc, UC_RISCV_REG_F1, &r_f1));
    OK(uc_reg_read(uc, UC_RISCV_REG_F3, &r_f3));

    TEST_CHECK(r_f1 == 0x12341234);
    TEST_CHECK(r_f3 == 0x12341234);

    uc_close(uc);
}

static void test_riscv64_fp_move_from_int(void)
{
    uc_engine *uc;
    // https://riscv.org/wp-content/uploads/2017/05/riscv-spec-v2.2.pdf
    // https://five-embeddev.com/quickref/csrs.html
    // We have to enable mstatus.fs
    char code[] = "\xf3\x90\x01\x30\x53\x00\x0b\xf2"; // csrrw x2, mstatus, x3;
                                                      // fmvd.d.x ft0, s6

    uint64_t r_ft0 = 0x12341234;
    uint64_t r_s6 = 0x56785678;
    uint64_t r_x3 = 0x6000;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);

    // initialize machine registers
    OK(uc_reg_write(uc, UC_RISCV_REG_FT0, &r_ft0));
    OK(uc_reg_write(uc, UC_RISCV_REG_S6, &r_s6));

    // mstatus.fs
    OK(uc_reg_write(uc, UC_RISCV_REG_X3, &r_x3));

    // emulate the instruction
    OK(uc_emu_start(uc, code_start, -1, 0, 2));

    OK(uc_reg_read(uc, UC_RISCV_REG_FT0, &r_ft0));
    OK(uc_reg_read(uc, UC_RISCV_REG_S6, &r_s6));

    TEST_CHECK(r_ft0 == 0x56785678);
    TEST_CHECK(r_s6 == 0x56785678);

    uc_close(uc);
}

static void test_riscv64_fp_move_from_int_reg_write(void)
{
    uc_engine *uc;
    char code[] = "\x53\x00\x0b\xf2"; // fmvd.d.x ft0, s6

    uint64_t r_ft0 = 0x12341234;
    uint64_t r_s6 = 0x56785678;
    uint64_t r_mstatus = 0x6000;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);

    // initialize machine registers
    OK(uc_reg_write(uc, UC_RISCV_REG_FT0, &r_ft0));
    OK(uc_reg_write(uc, UC_RISCV_REG_S6, &r_s6));

    // mstatus.fs
    OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &r_mstatus));

    // emulate the instruction
    OK(uc_emu_start(uc, code_start, -1, 0, 1));

    OK(uc_reg_read(uc, UC_RISCV_REG_FT0, &r_ft0));
    OK(uc_reg_read(uc, UC_RISCV_REG_S6, &r_s6));

    TEST_CHECK(r_ft0 == 0x56785678);
    TEST_CHECK(r_s6 == 0x56785678);

    OK(uc_close(uc));
}

static void test_riscv64_fp_move_to_int(void)
{
    uc_engine *uc;
    // https://riscv.org/wp-content/uploads/2017/05/riscv-spec-v2.2.pdf
    // https://five-embeddev.com/quickref/csrs.html
    // We have to enable mstatus.fs
    char code[] = "\xf3\x90\x01\x30\x53\x0b\x00\xe2"; // csrrw x2, mstatus, x3;
                                                      // fmv.x.d s6, ft0

    uint64_t r_ft0 = 0x12341234;
    uint64_t r_s6 = 0x56785678;
    uint64_t r_x3 = 0x6000;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);

    // initialize machine registers
    OK(uc_reg_write(uc, UC_RISCV_REG_FT0, &r_ft0));
    OK(uc_reg_write(uc, UC_RISCV_REG_S6, &r_s6));

    // mstatus.fs
    OK(uc_reg_write(uc, UC_RISCV_REG_X3, &r_x3));

    // emulate the instruction
    OK(uc_emu_start(uc, code_start, -1, 0, 2));

    OK(uc_reg_read(uc, UC_RISCV_REG_FT0, &r_ft0));
    OK(uc_reg_read(uc, UC_RISCV_REG_S6, &r_s6));

    TEST_CHECK(r_ft0 == 0x12341234);
    TEST_CHECK(r_s6 == 0x12341234);

    uc_close(uc);
}

static void test_riscv64_code_patching(void)
{
    uc_engine *uc;
    char code[] = "\x93\x82\x12\x00"; // addi t0, t0, 0x1
    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    // Zero out t0 and t1
    uint64_t r_t0 = 0x0;
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &r_t0));
    // emulate the instruction
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    // check value
    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &r_t0));
    TEST_CHECK(r_t0 == 0x1);
    // patch instruction
    char patch_code[] = "\x93\x82\xf2\x7f"; // addi t0, t0, 0x7FF
    OK(uc_mem_write(uc, code_start, patch_code, sizeof(patch_code) - 1));
    // zero out t0
    r_t0 = 0x0;
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(patch_code) - 1, 0, 0));
    // check value
    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &r_t0));
    TEST_CHECK(r_t0 != 0x1);
    TEST_CHECK(r_t0 == 0x7ff);

    OK(uc_close(uc));
}

// Need to flush the cache before running the emulation after patching
static void test_riscv64_code_patching_count(void)
{
    uc_engine *uc;
    char code[] = "\x93\x82\x12\x00"; // addi t0, t0, 0x1
    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    // Zero out t0 and t1
    uint64_t r_t0 = 0x0;
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &r_t0));
    // emulate the instruction
    OK(uc_emu_start(uc, code_start, -1, 0, 1));
    // check value
    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &r_t0));
    TEST_CHECK(r_t0 == 0x1);
    // patch instruction
    char patch_code[] = "\x93\x82\xf2\x7f"; // addi t0, t0, 0x7FF
    OK(uc_mem_write(uc, code_start, patch_code, sizeof(patch_code) - 1));
    OK(uc_ctl_remove_cache(uc, code_start,
                           code_start + sizeof(patch_code) - 1));
    // zero out t0
    r_t0 = 0x0;
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_emu_start(uc, code_start, -1, 0, 1));
    // check value
    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &r_t0));
    TEST_CHECK(r_t0 != 0x1);
    TEST_CHECK(r_t0 == 0x7ff);

    OK(uc_close(uc));
}

static void test_riscv64_ecall_cb(uc_engine *uc, uint32_t intno, void *data)
{
    uc_emu_stop(uc);
    return;
}

static void test_riscv64_ecall(void)
{
    uc_engine *uc;
    char code[] = "\x73\x00\x00\x00"; // ecall
    uint64_t r_pc;
    uc_hook h;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);

    OK(uc_hook_add(uc, &h, UC_HOOK_INTR, test_riscv64_ecall_cb, NULL, 1, 0));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &r_pc));

    TEST_CHECK(r_pc == code_start + 4);

    OK(uc_close(uc));
}

static uint64_t test_riscv32_mmio_map_read_cb(uc_engine *uc, uint64_t offset,
                                              unsigned size, void *data)
{
    int r_a4;
    OK(uc_reg_read(uc, UC_RISCV_REG_A4, &r_a4));
    TEST_CHECK(r_a4 == 0x40021 << 12);
    TEST_CHECK(offset == 0x21018);
    return 0;
}

static void test_riscv32_mmio_map(void)
{
    uc_engine *uc;
    // 37 17 02 40   lui          a4, 0x40021
    // 1c 4f         c.lw         a5, 0x18(a4)
    //
    char code[] = "\x37\x17\x02\x40\x1c\x4f";

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code,
                    sizeof(code) - 1);

    OK(uc_mmio_map(uc, 0x40000000, 0x40000, test_riscv32_mmio_map_read_cb, NULL,
                   NULL, NULL));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static void test_riscv32_map(void)
{
    uc_engine *uc;
    // 37 17 02 40   lui          a4, 0x40021
    // 1c 4f         c.lw         a5, 0x18(a4)
    //
    char code[] = "\x37\x17\x02\x40\x1c\x4f";
    uint64_t val = 0xdeadbeef;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code,
                    sizeof(code) - 1);

    OK(uc_mem_map(uc, 0x40000000, 0x40000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x40000000 + 0x21018, &val, 8));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_A5, &val));

    TEST_CHECK(val == 0xdeadbeef);
    OK(uc_close(uc));
}

static uint64_t test_riscv64_mmio_map_read_cb(uc_engine *uc, uint64_t offset,
                                              unsigned size, void *data)
{
    uint64_t r_a4;
    OK(uc_reg_read(uc, UC_RISCV_REG_A4, &r_a4));
    TEST_CHECK(r_a4 == 0x40021 << 12);
    TEST_CHECK(offset == 0x21018);
    return 0;
}

static void test_riscv64_mmio_map(void)
{
    uc_engine *uc;
    // 37 17 02 40   lui          a4, 0x40021
    // 1c 4f         c.lw         a5, 0x18(a4)
    //
    char code[] = "\x37\x17\x02\x40\x1c\x4f";

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);

    OK(uc_mmio_map(uc, 0x40000000, 0x40000, test_riscv64_mmio_map_read_cb, NULL,
                   NULL, NULL));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static bool test_riscv_correct_address_in_small_jump_hook_callback(
    uc_engine *uc, int type, uint64_t address, int size, int64_t value,
    void *user_data)
{
    // Check registers
    uint64_t r_x5 = 0x0;
    uint64_t r_pc = 0x0;
    OK(uc_reg_read(uc, UC_RISCV_REG_X5, &r_x5));
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &r_pc));
    TEST_CHECK(r_x5 == 0x7F00);
    TEST_CHECK(r_pc == 0x7F00);

    // Check address
    // printf("%lx\n", address);
    TEST_CHECK(address == 0x7F00);

    return false;
}

static void test_riscv_correct_address_in_small_jump_hook(void)
{
    uc_engine *uc;
    // li 0x7F00, x5  >  lui t0, 8; addiw t0, t0, -256;
    // jr x5
    char code[] = "\xb7\x82\x00\x00\x9b\x82\x02\xf0\x67\x80\x02\x00";

    uint64_t r_x5 = 0x0;
    uint64_t r_pc = 0x0;
    uc_hook hook;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_UNMAPPED,
                   test_riscv_correct_address_in_small_jump_hook_callback, NULL,
                   1, 0));

    uc_assert_err(
        UC_ERR_FETCH_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_X5, &r_x5));
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &r_pc));
    TEST_CHECK(r_x5 == 0x7F00);
    TEST_CHECK(r_pc == 0x7F00);

    OK(uc_close(uc));
}

static bool test_riscv_correct_address_in_long_jump_hook_callback(
    uc_engine *uc, int type, uint64_t address, int size, int64_t value,
    void *user_data)
{
    // Check registers
    uint64_t r_x5 = 0x0;
    uint64_t r_pc = 0x0;
    OK(uc_reg_read(uc, UC_RISCV_REG_X5, &r_x5));
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &r_pc));
    TEST_CHECK(r_x5 == 0x7FFFFFFFFFFFFF00);
    TEST_CHECK(r_pc == 0x7FFFFFFFFFFFFF00);

    // Check address
    // printf("%lx\n", address);
    TEST_CHECK(address == 0x7FFFFFFFFFFFFF00);

    return false;
}

static void test_riscv_correct_address_in_long_jump_hook(void)
{
    uc_engine *uc;
    // li 0x7FFFFFFFFFFFFF00, x5  >  addi t0, zero, -1; slli t0, t0, 63; addi
    // t0, t0, -256; jr x5
    char code[] =
        "\x93\x02\xf0\xff\x93\x92\xf2\x03\x93\x82\x02\xf0\x67\x80\x02\x00";

    uint64_t r_x5 = 0x0;
    uint64_t r_pc = 0x0;
    uc_hook hook;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_UNMAPPED,
                   test_riscv_correct_address_in_long_jump_hook_callback, NULL,
                   1, 0));

    uc_assert_err(
        UC_ERR_FETCH_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_X5, &r_x5));
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &r_pc));
    TEST_CHECK(r_x5 == 0x7FFFFFFFFFFFFF00);
    TEST_CHECK(r_pc == 0x7FFFFFFFFFFFFF00);

    OK(uc_close(uc));
}

TEST_LIST = {
    {"test_riscv32_nop", test_riscv32_nop},
    {"test_riscv64_nop", test_riscv64_nop},
    {"test_riscv32_3steps_pc_update", test_riscv32_3steps_pc_update},
    {"test_riscv64_3steps_pc_update", test_riscv64_3steps_pc_update},
    {"test_riscv32_until_pc_update", test_riscv32_until_pc_update},
    {"test_riscv64_until_pc_update", test_riscv64_until_pc_update},
    {"test_riscv32_fp_move", test_riscv32_fp_move},
    {"test_riscv64_fp_move", test_riscv64_fp_move},
    {"test_riscv64_fp_move_from_int", test_riscv64_fp_move_from_int},
    {"test_riscv64_fp_move_from_int_reg_write",
     test_riscv64_fp_move_from_int_reg_write},
    {"test_riscv64_fp_move_to_int", test_riscv64_fp_move_to_int},
    {"test_riscv64_ecall", test_riscv64_ecall},
    {"test_riscv32_mmio_map", test_riscv32_mmio_map},
    {"test_riscv64_mmio_map", test_riscv64_mmio_map},
    {"test_riscv32_map", test_riscv32_map},
    {"test_riscv64_code_patching", test_riscv64_code_patching},
    {"test_riscv64_code_patching_count", test_riscv64_code_patching_count},
    {"test_riscv_correct_address_in_small_jump_hook",
     test_riscv_correct_address_in_small_jump_hook},
    {"test_riscv_correct_address_in_long_jump_hook",
     test_riscv_correct_address_in_long_jump_hook},
    {NULL, NULL}};
