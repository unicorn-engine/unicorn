#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size,
                            uc_cpu_m68k cpu_model)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_ctl_set_cpu_model(*uc, cpu_model));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static void test_move_to_sr(void)
{

    uc_engine *uc;
    char code[] = "\x46\xfc\x27\x00"; // move    #$2700,sr
    int r_sr;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1, UC_CPU_M68K_M68000);
    OK(uc_reg_read(uc, UC_M68K_REG_SR, &r_sr));

    r_sr = r_sr | 0x2000;

    OK(uc_reg_write(uc, UC_M68K_REG_SR, &r_sr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_M68K_REG_SR, &r_sr));

    TEST_CHECK(r_sr == 0x2700);

    OK(uc_close(uc));
}

static void test_sr_contains_flags(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x76, 0xed, // moveq #-19, %d3
    };

    uint32_t d3, sr;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, code, sizeof(code),
                    UC_CPU_M68K_M68000);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_M68K_REG_D3, &d3));
    OK(uc_reg_read(uc, UC_M68K_REG_SR, &sr));

    TEST_CHECK(d3 == 0xFFFFFFED);
    TEST_CHECK((sr & 0x8) /* N flag */ == 0x8);

    OK(uc_close(uc));
}

static void test_sr_read_preserves_flags(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x02, 0x80, 0x00, 0x00, 0x3f, 0xff, // andi.l #0x3fff, %d0
        0x66, 0x04,                         // bne.s  1f
        0x72, 0x01,                         // moveq  #1, %d1
        0x60, 0x02,                         // bra.s  2f
        0x72, 0x02,                         // 1: moveq #2, %d1
                                            // 2:
    };
    uint32_t sr = 0x2000;
    uint32_t d0 = 0x4000;
    uint32_t d1 = 0;
    uint32_t pc;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, code, sizeof(code),
                    UC_CPU_M68K_M68000);

    // Writing SR leaves the condition codes in an explicit (Z clear) state.
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_reg_write(uc, UC_M68K_REG_D0, &d0));
    OK(uc_reg_write(uc, UC_M68K_REG_D1, &d1));

    // Run only the andi.l, which sets Z lazily.
    OK(uc_emu_start(uc, code_start, code_start + 6, 0, 0));

    // Reading SR must report Z and must not change the guest state.
    OK(uc_reg_read(uc, UC_M68K_REG_SR, &sr));
    TEST_CHECK((sr & 0x4) /* Z flag */ == 0x4);

    OK(uc_reg_read(uc, UC_M68K_REG_PC, &pc));
    OK(uc_emu_start(uc, pc, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_M68K_REG_D1, &d1));
    TEST_CHECK(d1 == 1);

    OK(uc_close(uc));
}

static void test_branch_on_initial_flags(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x67, 0x02, // beq.s  1f
        0x72, 0x01, // moveq  #1, %d1
                    // 1:
    };
    uint32_t d1;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, code, sizeof(code),
                    UC_CPU_M68K_M68000);

    // The condition codes must be valid before any instruction sets them.
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_M68K_REG_D1, &d1));
    TEST_CHECK(d1 == 1);

    OK(uc_close(uc));
}

// move #0,ccr; moveq #2,d0; cmpi.l #2,d0 (Z set); seq d3
static const uint8_t compare_then_seq[] = {
    0x44, 0xfc, 0x00, 0x00,             // move   #0, %ccr
    0x70, 0x02,                         // moveq  #2, %d0
    0x0c, 0x80, 0x00, 0x00, 0x00, 0x02, // cmpi.l #2, %d0
    0x57, 0xc3,                         // seq    %d3
};
static const uint64_t compare_then_seq_hooked = 12; // offset of seq

static void hook_write_pc_once(uc_engine *uc, uint64_t address, uint32_t size,
                               void *user_data)
{
    int *done = user_data;
    uint32_t pc = (uint32_t)address;

    if (!*done) {
        *done = 1;
        OK(uc_reg_write(uc, UC_M68K_REG_PC, &pc));
    }
}

static void test_code_hook_pc_write_preserves_flags(void)
{
    uc_engine *uc;
    uc_hook hook;
    uint64_t at = code_start + compare_then_seq_hooked;
    uint32_t sr = 0x2700;
    uint32_t d3 = 0;
    int done = 0;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN,
                    (const char *)compare_then_seq, sizeof(compare_then_seq),
                    UC_CPU_M68K_M68020);
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_hook_add(uc, &hook, UC_HOOK_CODE, hook_write_pc_once, &done, at, at));

    // The hook writes PC in the middle of the block; the cmpi.l's Z must
    // survive into the block that resumes at seq.
    OK(uc_emu_start(uc, code_start, code_start + sizeof(compare_then_seq), 0,
                    0));

    OK(uc_reg_read(uc, UC_M68K_REG_D3, &d3));
    TEST_CHECK((d3 & 0xff) == 0xff);

    OK(uc_close(uc));
}

static void hook_read_sr(uc_engine *uc, uint64_t address, uint32_t size,
                         void *user_data)
{
    OK(uc_reg_read(uc, UC_M68K_REG_SR, user_data));
}

static void test_code_hook_sr_read_sees_flags(void)
{
    uc_engine *uc;
    uc_hook hook;
    uint64_t at = code_start + compare_then_seq_hooked;
    uint32_t sr = 0x2700;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN,
                    (const char *)compare_then_seq, sizeof(compare_then_seq),
                    UC_CPU_M68K_M68020);
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_hook_add(uc, &hook, UC_HOOK_CODE, hook_read_sr, &sr, at, at));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(compare_then_seq), 0,
                    0));

    TEST_CHECK(sr == 0x2704);

    OK(uc_close(uc));
}

static void hook_write_sr(uc_engine *uc, uint64_t address, uint32_t size,
                          void *user_data)
{
    OK(uc_reg_write(uc, UC_M68K_REG_SR, user_data));
}

static void test_code_hook_sr_write_sets_flags(void)
{
    uc_engine *uc;
    uc_hook hook;
    uint64_t at = code_start + compare_then_seq_hooked;
    uint32_t sr = 0x2700;
    uint32_t d3 = 0;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN,
                    (const char *)compare_then_seq, sizeof(compare_then_seq),
                    UC_CPU_M68K_M68020);
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    // The hook clears Z; seq, later in the same block, must see that.
    OK(uc_hook_add(uc, &hook, UC_HOOK_CODE, hook_write_sr, &sr, at, at));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(compare_then_seq), 0,
                    0));

    OK(uc_reg_read(uc, UC_M68K_REG_D3, &d3));
    TEST_CHECK((d3 & 0xff) == 0);

    OK(uc_close(uc));
}

static void test_code_hook_sr_write_survives_fault(void)
{
    uc_engine *uc;
    uc_hook hook;
    uint8_t code[] = {
        0x44, 0xfc, 0x00, 0x00,             // move   #0, %ccr
        0x70, 0x02,                         // moveq  #2, %d0
        0x0c, 0x80, 0x00, 0x00, 0x00, 0x02, // cmpi.l #2, %d0
        0x22, 0x39, 0x00, 0x10, 0x00, 0x00, // move.l (0x100000).l, %d1
    };
    uint64_t at = code_start + 12; // the move.l, which faults
    uint32_t sr = 0x2700;
    uint32_t hooked = 0x2701;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (const char *)code,
                    sizeof(code), UC_CPU_M68K_M68020);
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_hook_add(uc, &hook, UC_HOOK_CODE, hook_write_sr, &hooked, at, at));

    // The move.l does not complete, so the hook's write of SR must stand.
    uc_assert_err(
        UC_ERR_READ_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_M68K_REG_SR, &sr));
    TEST_CHECK(sr == 0x2701);

    OK(uc_close(uc));
}

TEST_LIST = {{"test_move_to_sr", test_move_to_sr},
             {"test_sr_contains_flags", test_sr_contains_flags},
             {"test_sr_read_preserves_flags", test_sr_read_preserves_flags},
             {"test_branch_on_initial_flags", test_branch_on_initial_flags},
             {"test_code_hook_pc_write_preserves_flags",
              test_code_hook_pc_write_preserves_flags},
             {"test_code_hook_sr_read_sees_flags",
              test_code_hook_sr_read_sees_flags},
             {"test_code_hook_sr_write_sets_flags",
              test_code_hook_sr_write_sets_flags},
             {"test_code_hook_sr_write_survives_fault",
              test_code_hook_sr_write_survives_fault},
             {NULL, NULL}};
