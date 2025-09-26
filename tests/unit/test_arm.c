#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size, uc_cpu_arm cpu)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_ctl_set_cpu_model(*uc, cpu));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

typedef struct _WFI_HOOK_INSN_RESULT {
    bool called;
} WFI_HOOK_INSN_RESULT;

static void test_arm_nop(void)
{
    uc_engine *uc;
    char code[] = "\x00\xf0\x20\xe3"; // nop
    int r_r0 = 0x1234;
    int r_r2 = 0x6789;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &r_r0));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r_r2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));
    OK(uc_reg_read(uc, UC_ARM_REG_R2, &r_r2));
    TEST_CHECK(r_r0 == 0x1234);
    TEST_CHECK(r_r2 == 0x6789);

    OK(uc_close(uc));
}

static void test_arm_thumb_sub(void)
{
    uc_engine *uc;
    char code[] = "\x83\xb0"; // sub    sp, #0xc
    int r_sp = 0x1234;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_SP, &r_sp));
    TEST_CHECK(r_sp == 0x1228);

    OK(uc_close(uc));
}

static void test_armeb_sub(void)
{
    uc_engine *uc;
    char code[] =
        "\xe3\xa0\x00\x37\xe0\x42\x10\x03"; // mov r0, #0x37; sub r1, r2, r3
    int r_r0 = 0x1234;
    int r_r2 = 0x6789;
    int r_r3 = 0x3333;
    int r_r1;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1, UC_CPU_ARM_1176);
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

static void test_armeb_be8_sub(void)
{
    uc_engine *uc;
    char code[] =
        "\x37\x00\xa0\xe3\x03\x10\x42\xe0"; // mov r0, #0x37; sub r1, r2, r3
    int r_r0 = 0x1234;
    int r_r2 = 0x6789;
    int r_r3 = 0x3333;
    int r_r1;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_ARMBE8, code,
                    sizeof(code) - 1, UC_CPU_ARM_CORTEX_A15);
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

static void test_arm_thumbeb_sub(void)
{
    uc_engine *uc;
    char code[] = "\xb0\x83"; // sub    sp, #0xc
    int r_sp = 0x1234;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1, UC_CPU_ARM_1176);
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

static void test_arm_thumb_ite(void)
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

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r_r2));
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &r_r3));

    OK(uc_mem_map(uc, r_sp, 0x1000, UC_PROT_ALL));
    r_r2 = LEINT32(0x68);
    OK(uc_mem_write(uc, r_sp, &r_r2, 4));
    r_r2 = LEINT32(0x4d);
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

static void test_arm_m_thumb_mrs(void)
{
    uc_engine *uc;
    char code[] =
        "\xef\xf3\x14\x80\xef\xf3\x00\x81"; // mrs r0, control; mrs r1, apsr
    uint32_t r_control = 0b10;
    uint32_t r_apsr = (0b10101 << 27);
    uint32_t r_r0, r_r1;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS, code,
                    sizeof(code) - 1, UC_CPU_ARM_CORTEX_A15);

    OK(uc_reg_write(uc, UC_ARM_REG_CONTROL, &r_control));
    OK(uc_reg_write(uc, UC_ARM_REG_APSR_NZCVQ, &r_apsr));
    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r_r1));

    TEST_CHECK(r_r0 == 0b10);
    TEST_CHECK(r_r1 == (0b10101 << 27));

    OK(uc_close(uc));
}

static void test_arm_m_control(void)
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

static void test_arm_m_exc_return(void)
{
    uc_engine *uc;
    char code[] = "\x6f\xf0\x02\x00\x00\x47"; // mov r0, #0xFFFFFFFD; bx r0;
    int r_ipsr;
    int r_sp = 0x8000;
    uc_hook hook;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS, code,
                    sizeof(code) - 1, UC_CPU_ARM_CORTEX_A15);
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

// For details, see https://github.com/unicorn-engine/unicorn/issues/1494.
static void test_arm_und32_to_svc32(void)
{
    uc_engine *uc;
    // # MVN r0, #0
    // # MOVS pc, lr
    // # MVN r0, #0
    // # MVN r0, #0
    char code[] =
        "\x00\x00\xe0\xe3\x0e\xf0\xb0\xe1\x00\x00\xe0\xe3\x00\x00\xe0\xe3";
    int r_cpsr, r_sp, r_spsr, r_lr;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_A9));

    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    // https://www.keil.com/pack/doc/CMSIS/Core_A/html/group__CMSIS__CPSR__M.html
    r_cpsr = 0x40000093; // SVC32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_sp = 0x12345678;
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));

    r_cpsr = 0x4000009b; // UND32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_spsr = 0x40000093; // Save previous CPSR
    OK(uc_reg_write(uc, UC_ARM_REG_SPSR, &r_spsr));
    r_sp = 0xDEAD0000;
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));
    r_lr = code_start + 8;
    OK(uc_reg_write(uc, UC_ARM_REG_LR, &r_lr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 3));

    OK(uc_reg_read(uc, UC_ARM_REG_SP, &r_sp));

    TEST_CHECK(r_sp == 0x12345678);

    OK(uc_close(uc));
}

static void test_arm_usr32_to_svc32(void)
{
    uc_engine *uc;
    int r_cpsr, r_sp, r_spsr, r_lr;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_A9));

    // https://www.keil.com/pack/doc/CMSIS/Core_A/html/group__CMSIS__CPSR__M.html
    r_cpsr = 0x40000093; // SVC32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_sp = 0x12345678;
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));
    r_lr = 0x00102220;
    OK(uc_reg_write(uc, UC_ARM_REG_LR, &r_lr));

    r_cpsr = 0x4000009b; // UND32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_spsr = 0x40000093; // Save previous CPSR
    OK(uc_reg_write(uc, UC_ARM_REG_SPSR, &r_spsr));
    r_sp = 0xDEAD0000;
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));
    r_lr = 0x00509998;
    OK(uc_reg_write(uc, UC_ARM_REG_LR, &r_lr));

    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &r_cpsr));
    TEST_CHECK((r_cpsr & ((1 << 4) - 1)) == 0xb); // We are in UND32

    r_cpsr = 0x40000090; // USR32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_sp = 0x0010000;
    OK(uc_reg_write(uc, UC_ARM_REG_R13, &r_sp));
    r_lr = 0x0001234;
    OK(uc_reg_write(uc, UC_ARM_REG_LR, &r_lr));

    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &r_cpsr));
    TEST_CHECK((r_cpsr & ((1 << 4) - 1)) == 0); // We are in USR32

    r_cpsr = 0x40000093; // SVC32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));

    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &r_cpsr));
    OK(uc_reg_read(uc, UC_ARM_REG_SP, &r_sp));
    TEST_CHECK((r_cpsr & ((1 << 4) - 1)) == 3); // We are in SVC32
    TEST_CHECK(r_sp == 0x12345678);

    OK(uc_close(uc));
}

static void test_arm_v8(void)
{
    char code[] = "\xd0\xe8\xff\x17"; // LDAEXD.W R1, [R0]
    uc_engine *uc;
    uint32_t r_r1 = LEINT32(0xdeadbeef);
    uint32_t r_r0;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_M33);

    r_r0 = 0x8000;
    OK(uc_mem_map(uc, r_r0, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, r_r0, (void *)&r_r1, 4));
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &r_r0));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r_r1));

    TEST_CHECK(r_r1 == 0xdeadbeef);

    OK(uc_close(uc));
}

static void test_arm_thumb_smlabb(void)
{
    char code[] = "\x13\xfb\x01\x23";
    uint32_t r_r1, r_r2, r_r3;
    uc_engine *uc;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_M7);

    r_r3 = 5;
    r_r1 = 7;
    r_r2 = 9;
    OK(uc_reg_write(uc, UC_ARM_REG_R3, &r_r3));
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r_r1));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r_r2));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R3, &r_r3));

    TEST_CHECK(r_r3 == 5 * 7 + 9);

    OK(uc_close(uc));
}

static void test_arm_not_allow_privilege_escalation(void)
{
    uc_engine *uc;
    int r_cpsr, r_sp, r_spsr, r_lr;
    // E3C6601F : BIC     r6, r6, #&1F
    // E3866013 : ORR     r6, r6, #&13
    // E121F006 : MSR     cpsr_c, r6 ; switch to SVC32 (should be ineffective
    // from USR32)
    // E1A00000 : MOV     r0,r0 EF000011 : SWI     OS_Exit
    char code[] = "\x1f\x60\xc6\xe3\x13\x60\x86\xe3\x06\xf0\x21\xe1\x00\x00\xa0"
                  "\xe1\x11\x00\x00\xef";

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);

    // https://www.keil.com/pack/doc/CMSIS/Core_A/html/group__CMSIS__CPSR.html
    r_cpsr = 0x40000013; // SVC32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_spsr = 0x40000013;
    OK(uc_reg_write(uc, UC_ARM_REG_SPSR, &r_spsr));
    r_sp = 0x12345678;
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));
    r_lr = 0x00102220;
    OK(uc_reg_write(uc, UC_ARM_REG_LR, &r_lr));

    r_cpsr = 0x40000010; // USR32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_sp = 0x0010000;
    OK(uc_reg_write(uc, UC_ARM_REG_SP, &r_sp));
    r_lr = 0x0001234;
    OK(uc_reg_write(uc, UC_ARM_REG_LR, &r_lr));

    uc_assert_err(
        UC_ERR_EXCEPTION,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_SP, &r_sp));
    OK(uc_reg_read(uc, UC_ARM_REG_LR, &r_lr));
    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &r_cpsr));

    TEST_CHECK((r_cpsr & ((1 << 4) - 1)) == 0); // Stay in USR32
    TEST_CHECK(r_lr == 0x1234);
    TEST_CHECK(r_sp == 0x10000);

    OK(uc_close(uc));
}

static void test_arm_mrc(void)
{
    uc_engine *uc;
    // mrc p15, #0, r1, c13, c0, #3
    char code[] = "\x1d\xee\x70\x1f";

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_MAX);

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static void test_arm_hflags_rebuilt(void)
{
    // MRS     r6, apsr
    // BIC     r6, r6, #&1F
    // ORR     r6, r6, #&10
    // MSR     cpsr_c, r6
    // SWI     OS_EnterOS
    // MSR     cpsr_c, r6
    char code[] = "\x00\x60\x0f\xe1\x1f\x60\xc6\xe3\x10\x60\x86\xe3\x06\xf0\x21"
                  "\xe1\x16\x00\x02\xef\x06\xf0\x21\xe1";
    uc_engine *uc;
    uint32_t r_cpsr, r_spsr, r_r13, r_r14, r_pc;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A9);

    r_cpsr = 0x40000013; // SVC32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_spsr = 0x40000013;
    OK(uc_reg_write(uc, UC_ARM_REG_SPSR, &r_spsr));
    r_r13 = 0x12345678; // SP
    OK(uc_reg_write(uc, UC_ARM_REG_R13, &r_r13));
    r_r14 = 0x00102220; // LR
    OK(uc_reg_write(uc, UC_ARM_REG_R14, &r_r14));

    r_cpsr = 0x40000010; // USR32
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_r13 = 0x0010000; // SP
    OK(uc_reg_write(uc, UC_ARM_REG_R13, &r_r13));
    r_r14 = 0x0001234; // LR
    OK(uc_reg_write(uc, UC_ARM_REG_R14, &r_r14));

    uc_assert_err(
        UC_ERR_EXCEPTION,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    r_cpsr = 0x60000013;
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_cpsr = 0x60000010;
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_cpsr = 0x60000013;
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));

    OK(uc_reg_read(uc, UC_ARM_REG_PC, &r_pc));

    OK(uc_emu_start(uc, r_pc, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &r_cpsr));
    OK(uc_reg_read(uc, UC_ARM_REG_R13, &r_r13));
    OK(uc_reg_read(uc, UC_ARM_REG_R14, &r_r14));

    TEST_CHECK(r_cpsr == 0x60000010);
    TEST_CHECK(r_r13 == 0x00010000);
    TEST_CHECK(r_r14 == 0x00001234);

    OK(uc_close(uc));
}

static bool test_arm_mem_access_abort_hook_mem(uc_engine *uc, uc_mem_type type,
                                               uint64_t addr, int size,
                                               int64_t val, void *data)
{
    OK(uc_reg_read(uc, UC_ARM_REG_PC, data));
    return false;
}

static bool test_arm_mem_access_abort_hook_insn_invalid(uc_engine *uc,
                                                        void *data)
{
    OK(uc_reg_read(uc, UC_ARM_REG_PC, data));
    return false;
}

static void test_arm_mem_access_abort(void)
{
    // LDR     r0, [r0]
    // Undefined instruction
    char code[] = "\x00\x00\x90\xe5\x00\xa0\xf0\xf7";
    uc_engine *uc;
    uint32_t r_pc, r_r0, r_pc_in_hook;
    uc_hook hk, hkk;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A9);

    r_r0 = 0x990000;
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &r_r0));

    OK(uc_hook_add(uc, &hk, UC_HOOK_MEM_UNMAPPED,
                   test_arm_mem_access_abort_hook_mem, (void *)&r_pc_in_hook, 1,
                   0));
    OK(uc_hook_add(uc, &hkk, UC_HOOK_INSN_INVALID,
                   test_arm_mem_access_abort_hook_insn_invalid,
                   (void *)&r_pc_in_hook, 1, 0));

    uc_assert_err(UC_ERR_READ_UNMAPPED,
                  uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_PC, &r_pc));

    TEST_CHECK(r_pc == r_pc_in_hook);

    uc_assert_err(UC_ERR_INSN_INVALID,
                  uc_emu_start(uc, code_start + 4, code_start + 8, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_PC, &r_pc));

    TEST_CHECK(r_pc == r_pc_in_hook);

    uc_assert_err(UC_ERR_FETCH_UNMAPPED,
                  uc_emu_start(uc, 0x900000, 0x900000 + 8, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_PC, &r_pc));

    TEST_CHECK(r_pc == r_pc_in_hook);

    OK(uc_close(uc));
}

static void test_arm_read_sctlr(void)
{
    uc_engine *uc;
    uc_arm_cp_reg reg;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc));

    // SCTLR. See arm reference.
    reg.cp = 15;
    reg.is64 = 0;
    reg.sec = 0;
    reg.crn = 1;
    reg.crm = 0;
    reg.opc1 = 0;
    reg.opc2 = 0;

    OK(uc_reg_read(uc, UC_ARM_REG_CP_REG, &reg));

    TEST_CHECK((uint32_t)((reg.val >> 31) & 1) == 0);

    OK(uc_close(uc));
}

static void test_arm_be_cpsr_sctlr(void)
{
    uc_engine *uc;
    uc_arm_cp_reg reg;
    uint32_t cpsr;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_set_cpu_model(
        uc, UC_CPU_ARM_1176)); // big endian code, big endian data

    // SCTLR. See arm reference.
    reg.cp = 15;
    reg.is64 = 0;
    reg.sec = 0;
    reg.crn = 1;
    reg.crm = 0;
    reg.opc1 = 0;
    reg.opc2 = 0;

    OK(uc_reg_read(uc, UC_ARM_REG_CP_REG, &reg));
    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr));

    TEST_CHECK((reg.val & (1 << 7)) != 0);
    TEST_CHECK((cpsr & (1 << 9)) != 0);

    OK(uc_close(uc));

    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARMBE8, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_A15));

    // SCTLR. See arm reference.
    reg.cp = 15;
    reg.is64 = 0;
    reg.sec = 0;
    reg.crn = 1;
    reg.crm = 0;
    reg.opc1 = 0;
    reg.opc2 = 0;

    OK(uc_reg_read(uc, UC_ARM_REG_CP_REG, &reg));
    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr));

    // SCTLR.B == 0
    TEST_CHECK((reg.val & (1 << 7)) == 0);
    TEST_CHECK((cpsr & (1 << 9)) != 0);

    OK(uc_close(uc));
}

static void test_arm_switch_endian(void)
{
    uc_engine *uc;
    char code[] = "\x00\x00\x91\xe5"; // ldr r0, [r1]
    uint32_t r_r1 = (uint32_t)code_start;
    uint32_t r_r0, r_cpsr;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);
    OK(uc_reg_write(uc, UC_ARM_REG_R1, &r_r1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));

    // Little endian
    TEST_CHECK(r_r0 == 0xe5910000);

    OK(uc_reg_read(uc, UC_ARM_REG_CPSR, &r_cpsr));
    r_cpsr |= (1 << 9);
    OK(uc_reg_write(uc, UC_ARM_REG_CPSR, &r_cpsr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));

    // Big endian
    TEST_CHECK(r_r0 == 0x000091e5);

    OK(uc_close(uc));
}

static void test_armeb_ldrb(void)
{
    uc_engine *uc;
    const char test_code[] = "\xe5\xd2\x10\x00"; // ldrb r1, [r2]
    uint64_t data_address = 0x800000;
    int r1 = 0x1234;
    int r2 = data_address;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_BIG_ENDIAN,
                    test_code, sizeof(test_code) - 1, UC_CPU_ARM_1176);

    OK(uc_mem_map(uc, data_address, 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, data_address, "\x66\x67\x68\x69", 4));
    OK(uc_reg_write(uc, UC_ARM_REG_R2, &r2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(test_code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R1, &r1));

    TEST_CHECK(r1 == 0x66);

    OK(uc_close(uc));
}

static void test_arm_context_save(void)
{
    uc_engine *uc;
    uc_engine *uc2;
    char code[] = "\x83\xb0"; // sub    sp, #0xc
    uc_context *ctx;
    uint32_t pc;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_R5);

    OK(uc_context_alloc(uc, &ctx));
    OK(uc_context_save(uc, ctx));
    OK(uc_context_reg_read(ctx, UC_ARM_REG_PC, (void *)&pc));
    OK(uc_context_reg_write(ctx, UC_ARM_REG_PC, (void *)&pc));
    OK(uc_context_restore(uc, ctx));

    uc_common_setup(&uc2, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A7); // Note the different CPU model

    OK(uc_context_restore(uc2, ctx));

    OK(uc_context_free(ctx));
    OK(uc_close(uc));
    OK(uc_close(uc2));
}

static void test_arm_thumb2(void)
{
    uc_engine *uc;
    // MOVS  R0, #0x24
    // AND.W R0, R0, #4
    char code[] = "\x24\x20\x00\xF0\x04\x00";
    uint32_t r_r0;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1, UC_CPU_ARM_CORTEX_R5);

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));

    TEST_CHECK(r_r0 == 0x4);

    OK(uc_close(uc));
}

static void test_armeb_be32_thumb2(void)
{
    uc_engine *uc;
    // MOVS  R0, #0x24
    // AND.W R0, R0, #4
    char code[] = "\x20\x24\xF0\x00\x00\x04";
    uint32_t r_r0;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1, UC_CPU_ARM_CORTEX_R5);

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_ARM_REG_R0, &r_r0));

    TEST_CHECK(r_r0 == 0x4);

    OK(uc_close(uc));
}

static bool test_arm_mem_read_write_cb(uc_engine *uc, int type,
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
static void test_arm_mem_hook_read_write(void)
{
    uc_engine *uc;
    // ldr r1, [sp]
    // str r1, [sp, #4]
    // ldr r2, [sp, #4]
    // str r2, [sp]
    const char code[] =
        "\x00\x10\x9d\xe5\x04\x10\x8d\xe5\x04\x20\x9d\xe5\x00\x20\x8d\xe5";
    uint32_t r_sp;
    r_sp = 0x9000;
    uc_hook hk;
    uint64_t counter[2] = {0, 0};

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);

    uc_reg_write(uc, UC_ARM_REG_SP, &r_sp);
    uc_mem_map(uc, 0x8000, 1024 * 16, UC_PROT_ALL);

    OK(uc_hook_add(uc, &hk, UC_HOOK_MEM_READ, test_arm_mem_read_write_cb,
                   counter, 1, 0));
    OK(uc_hook_add(uc, &hk, UC_HOOK_MEM_WRITE, test_arm_mem_read_write_cb,
                   counter, 1, 0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    TEST_CHECK(counter[0] == 2 && counter[1] == 2);
    OK(uc_close(uc));
}

typedef struct {
    uint64_t v0;
    uint64_t v1;
    uint64_t size;
    uint64_t pc;
} _last_cmp_info;

static void _uc_hook_sub_cmp(uc_engine *uc, uint64_t address, uint64_t arg1,
                             uint64_t arg2, uint32_t size,
                             _last_cmp_info *user_data)
{
    user_data->pc = address;
    user_data->size = size;
    user_data->v0 = arg1;
    user_data->v1 = arg2;
}

static void test_arm_tcg_opcode_cmp(void)
{
    uc_engine *uc;
    const char code[] = "\x04\x00\x9f\xe5" // ldr   r0, [pc, #4]
                        "\x04\x10\x9f\xe5" // ldr   r1, [pc, #4]
                        "\x01\x00\x50\xe1" // cmp   r0, r1
                        "\x05\x00\x00\x00" // (5)
                        "\x03\x00\x00\x00" // (3)
        ;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);

    uc_hook hook;
    _last_cmp_info cmp_info = {0};

    OK(uc_hook_add(uc, &hook, UC_HOOK_TCG_OPCODE, (void *)_uc_hook_sub_cmp,
                   (void *)&cmp_info, 1, 0, UC_TCG_OP_SUB, UC_TCG_OP_FLAG_CMP));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 3));
    TEST_CHECK(cmp_info.v0 == 5 && cmp_info.v1 == 3);
    TEST_CHECK(cmp_info.pc == 0x1008);
    TEST_CHECK(cmp_info.size == 32);
    OK(uc_close(uc));
}

static void test_arm_thumb_tcg_opcode_cmn(void)
{
    uc_engine *uc;
    const char code[] = "\x01\x48"         // ldr  r0, [pc, #4]
                        "\x02\x49"         // ldr  r1, [pc, #8]
                        "\x00\xbf"         // nop
                        "\xc8\x42"         // cmn  r0, r1
                        "\x05\x00\x00\x00" // (5)
                        "\x03\x00\x00\x00" // (3)
        ;

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);

    uc_hook hook;
    _last_cmp_info cmp_info = {0};

    OK(uc_hook_add(uc, &hook, UC_HOOK_TCG_OPCODE, (void *)_uc_hook_sub_cmp,
                   (void *)&cmp_info, 1, 0, UC_TCG_OP_SUB, UC_TCG_OP_FLAG_CMP));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 4));
    TEST_CHECK(cmp_info.v0 == 5 && cmp_info.v1 == 3);
    TEST_CHECK(cmp_info.pc == 0x1006);
    TEST_CHECK(cmp_info.size == 32);
    OK(uc_close(uc));
}

static void test_arm_cp15_c1_c0_2(void)
{
    uc_engine *uc;
    uint32_t val = 0x12345678;
    uint32_t read_val;

    // Initialize emulator in ARM mode
    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_A15));

    // Write to CP15 C1_C0_2
    OK(uc_reg_write(uc, UC_ARM_REG_C1_C0_2, &val));

    // Read from CP15 C1_C0_2
    OK(uc_reg_read(uc, UC_ARM_REG_C1_C0_2, &read_val));

    TEST_CHECK(read_val == val);

    OK(uc_close(uc));
}

static bool test_arm_v7_lpae_hook_tlb(uc_engine *uc, uint64_t addr,
                                      uc_mem_type type, uc_tlb_entry *result,
                                      void *user_data)
{
    result->paddr = addr + 0x100000000;
    result->perms = UC_PROT_ALL;
    return 1;
}

static void test_arm_v7_lpae_hook_read(uc_engine *uc, uc_mem_type type,
                                       uint64_t address, int size,
                                       uint64_t value, void *user_data)
{
    TEST_CHECK(address == 0x100001000);
}

static void test_arm_v7_lpae(void)
{
    uc_engine *uc;
    uc_hook hook_read, hook_tlb;
    uint32_t reg;
    char code[] = "\x00\x10\x90\xe5"; // ldr r1, [r0]
    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_A7));

    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_hook_add(uc, &hook_tlb, UC_HOOK_TLB_FILL, test_arm_v7_lpae_hook_tlb,
                   NULL, 1, 0));
    OK(uc_hook_add(uc, &hook_read, UC_HOOK_MEM_READ, test_arm_v7_lpae_hook_read,
                   NULL, 1, 0));

    reg = 0x1000;
    OK(uc_reg_write(uc, UC_ARM_REG_R0, &reg));
    OK(uc_mem_map(uc, 0x100001000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x100001000, code, sizeof(code)));
    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_ARM_REG_R1, &reg));
    TEST_CHECK(reg == 0xe5901000);

    OK(uc_close(uc));
}

static void test_arm_svc_interrupt(uc_engine *uc, int intno, void *user_data)
{
    uint32_t esr;
    OK(uc_reg_read(uc, UC_ARM_REG_ESR, &esr));
    switch (intno) {
    // SVC
    case 2:
        TEST_CHECK((esr & 0xff) == 0x42);
        break;
    // HVC
    case 3:
        TEST_CHECK((esr & 0xff) == 0x33);
        break;
    }
}

static void test_arm_svc_hvc_syndrome(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x42, 0x00, 0x00, 0xef, // svc #0x42
        0x73, 0x03, 0x40, 0xe1, // hvc #0x33
    };

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_ARM, (char *)code, sizeof(code),
                    UC_CPU_ARM_CORTEX_A15);

    uc_hook hook;
    OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_arm_svc_interrupt, NULL, 1,
                   0));

    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_close(uc));
}

static int test_arm_hook_insn_wfi_callback(uc_engine *uc, void *user_data)
{
    WFI_HOOK_INSN_RESULT *result = (WFI_HOOK_INSN_RESULT *)user_data;
    result->called = true;
    return 0;
}

static void test_arm_hook_insn_wfi(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\x30\xbf";
    WFI_HOOK_INSN_RESULT result = {false};

    uc_common_setup(&uc, UC_ARCH_ARM, UC_MODE_THUMB, code, sizeof(code) - 1,
                    UC_CPU_ARM_CORTEX_A15);
    OK(uc_hook_add(uc, &hook, UC_HOOK_INSN, test_arm_hook_insn_wfi_callback, &result, 1, 0,
                   UC_ARM_INS_WFI));

    OK(uc_emu_start(uc, code_start | 1, code_start + sizeof(code) - 1, 0, 0));
    TEST_CHECK(result.called == true);

    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
}

TEST_LIST = {{"test_arm_nop", test_arm_nop},
             {"test_arm_thumb_sub", test_arm_thumb_sub},
             {"test_armeb_sub", test_armeb_sub},
             {"test_armeb_be8_sub", test_armeb_be8_sub},
             {"test_arm_thumbeb_sub", test_arm_thumbeb_sub},
             {"test_arm_thumb_ite", test_arm_thumb_ite},
             {"test_arm_m_thumb_mrs", test_arm_m_thumb_mrs},
             {"test_arm_m_control", test_arm_m_control},
             {"test_arm_m_exc_return", test_arm_m_exc_return},
             {"test_arm_und32_to_svc32", test_arm_und32_to_svc32},
             {"test_arm_usr32_to_svc32", test_arm_usr32_to_svc32},
             {"test_arm_v8", test_arm_v8},
             {"test_arm_thumb_smlabb", test_arm_thumb_smlabb},
             {"test_arm_not_allow_privilege_escalation",
              test_arm_not_allow_privilege_escalation},
             {"test_arm_mrc", test_arm_mrc},
             {"test_arm_hflags_rebuilt", test_arm_hflags_rebuilt},
             {"test_arm_mem_access_abort", test_arm_mem_access_abort},
             {"test_arm_read_sctlr", test_arm_read_sctlr},
             {"test_arm_be_cpsr_sctlr", test_arm_be_cpsr_sctlr},
             {"test_arm_switch_endian", test_arm_switch_endian},
             {"test_armeb_ldrb", test_armeb_ldrb},
             {"test_arm_context_save", test_arm_context_save},
             {"test_arm_thumb2", test_arm_thumb2},
             {"test_armeb_be32_thumb2", test_armeb_be32_thumb2},
             {"test_arm_mem_hook_read_write", test_arm_mem_hook_read_write},
             {"test_arm_tcg_opcode_cmp", test_arm_tcg_opcode_cmp},
             {"test_arm_thumb_tcg_opcode_cmn", test_arm_thumb_tcg_opcode_cmn},
             {"test_arm_cp15_c1_c0_2", test_arm_cp15_c1_c0_2},
             {"test_arm_v7_lpae", test_arm_v7_lpae},
             {"test_arm_svc_hvc_syndrome", test_arm_svc_hvc_syndrome},
             {"test_arm_hook_insn_wfi", test_arm_hook_insn_wfi},
             {NULL, NULL}};
