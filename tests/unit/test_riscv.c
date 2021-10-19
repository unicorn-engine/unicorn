#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

static void uc_common_setup(uc_engine** uc, uc_arch arch, uc_mode mode, const char* code, uint64_t size) {
    OK(uc_open(arch, mode, uc));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static void test_riscv32_nop() {
    uc_engine* uc;
    char code[] = "\x13\x00\x00\x00"; // nop
    uint32_t r_t0 = 0x1234;
    uint32_t r_t1 = 0x5678;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &r_t1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &r_t1));
    TEST_CHECK(r_t0 == 0x1234);
    TEST_CHECK(r_t1 == 0x5678);

    OK(uc_close(uc));
}

static void test_riscv64_nop() {
    uc_engine* uc;
    char code[] = "\x13\x00\x00\x00"; // nop
    uint64_t r_t0 = 0x1234;
    uint64_t r_t1 = 0x5678;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &r_t1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &r_t0));
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &r_t1));
    TEST_CHECK(r_t0 == 0x1234);
    TEST_CHECK(r_t1 == 0x5678);

    OK(uc_close(uc));
}

static void test_riscv32_until_pc_update() {
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

  uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code, sizeof(code) - 1);

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

static void test_riscv64_until_pc_update() {
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

  uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code, sizeof(code) - 1);

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

static void test_riscv32_3steps_pc_update() {
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

  uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code, sizeof(code) - 1);

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

static void test_riscv64_3steps_pc_update() {
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

  uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code, sizeof(code) - 1);

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


TEST_LIST = {
    { "test_riscv32_nop", test_riscv32_nop },
    { "test_riscv64_nop", test_riscv64_nop },
    { "test_riscv32_3steps_pc_update", test_riscv32_3steps_pc_update },
    { "test_riscv64_3steps_pc_update", test_riscv64_3steps_pc_update },
    { "test_riscv32_until_pc_update", test_riscv32_until_pc_update },
    { "test_riscv64_until_pc_update", test_riscv64_until_pc_update },
    { NULL, NULL }
};
