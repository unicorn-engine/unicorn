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

static void test_arm_nop()
{
    uc_engine *uc;
    char code[] = "\x00\xf0\x20\xe3"; // nop
    int r_r0 = 0x1234;
    int r_r2 = 0x6789;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &r_r0));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r_r2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));
    OK(uc_reg_read(uc, UC_ARM_REG_R2, &r_r2));
    TEST_CHECK(r_r0 == 0x1234);
    TEST_CHECK(r_r2 == 0x6789);

    OK(uc_close(uc));
}

static void test_arm_thumb_sub()
{
    uc_engine *uc;
    char code[] = "\x83\xb0"; // sub    sp, #0xc
    int r_sp = 0x1234;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_SP, &r_sp));
    TEST_CHECK(r_sp == 0x1228);

    OK(uc_close(uc));
}

static void test_armeb_sub()
{
    uc_engine *uc;
    char code[] =
        "\xe3\xa0\x00\x37\xe0\x42\x10\x03"; // mov r0, #0x37; sub r1, r2, r3
    int r_r0 = 0x1234;
    int r_r2 = 0x6789;
    int r_r3 = 0x3333;
    int r_r1;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1);
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

static void test_arm_thumbeb_sub()
{
    uc_engine *uc;
    char code[] = "\xb0\x83"; // sub    sp, #0xc
    int r_sp = 0x1234;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1);
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

static void test_arm_thumb_ite()
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

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r_r2));
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &r_r3));

    OK(uc_mem_map(uc, r_sp, 0x1000, UC_PROT_ALL));
    r_r2 = 0x68;
    OK(uc_mem_write(uc, r_sp, &r_r2, 4));
    r_r2 = 0x4d;
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

static void test_arm_m_thumb_mrs()
{
    uc_engine *uc;
    char code[] =
        "\xef\xf3\x14\x80\xef\xf3\x00\x81"; // mrs r0, control; mrs r1, apsr
    uint32_t r_control = 0b10;
    uint32_t r_apsr = (0b10101 << 27);
    uint32_t r_r0, r_r1;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS, code,
                    sizeof(code) - 1);

    OK(uc_reg_write(uc, UC_ARM_REG_CONTROL, &r_control));
    OK(uc_reg_write(uc, UC_ARM_REG_APSR_NZCVQ, &r_apsr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r_r1));

    TEST_CHECK(r_r0 == 0b10);
    TEST_CHECK(r_r1 == (0b10101 << 27));

    OK(uc_close(uc));
}

static void test_arm_m_control()
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

static void test_arm_m_exc_return()
{
    uc_engine *uc;
    char code[] = "\x6f\xf0\x02\x00\x00\x47"; // mov r0, #0xFFFFFFFD; bx r0;
    int r_ipsr;
    int r_sp = 0x8000;
    uc_hook hook;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS, code,
                    sizeof(code) - 1);
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

TEST_LIST = {{"test_arm_nop", test_arm_nop},
             {"test_arm_thumb_sub", test_arm_thumb_sub},
             {"test_armeb_sub", test_armeb_sub},
             {"test_arm_thumbeb_sub", test_arm_thumbeb_sub},
             {"test_arm_thumb_ite", test_arm_thumb_ite},
             {"test_arm_m_thumb_mrs", test_arm_m_thumb_mrs},
             {"test_arm_m_control", test_arm_m_control},
             {"test_arm_m_exc_return", test_arm_m_exc_return},
             {NULL, NULL}};