#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;
const uint64_t riscv_data_start = 0x8000;

#define RISCV_MSTATUS_VS_INITIAL 0x200
#define RISCV_MSTATUS_VS_DIRTY 0x600
#define RISCV_MSTATUS_FS_INITIAL 0x2000
#define RISCV32_MSTATUS_SD 0x80000000u
#define RISCV64_MSTATUS_SD 0x8000000000000000ull
#define RISCV64_VTYPE_VILL 0x8000000000000000ull
#define RISCV_CSR_FFLAGS 0x001
#define RISCV_CSR_VSTART 0x008
#define RISCV_CSR_VXSAT 0x009
#define RISCV_CSR_VXRM 0x00a
#define RISCV_CSR_VSATP 0x280
#define RISCV_CSR_STIMECMP 0x14d
#define RISCV_CSR_MSTATUS 0x300
#define RISCV_CSR_PMPCFG0 0x3a0
#define RISCV_CSR_PMPADDR0 0x3b0
#define RISCV_CSR_HSTATUS 0x600
#define RISCV_CSR_HGATP 0x680
#define RISCV_MSTATUS_MXR 0x00080000ull
#define RISCV_PMPCFG_R 0x01
#define RISCV_PMPCFG_X 0x04
#define RISCV_PMPCFG_A_NA4 0x10
#define RISCV_PMPCFG_A_NAPOT 0x18
#define RISCV_EXCP_INST_ACCESS_FAULT 0x1
#define RISCV_EXCP_ILLEGAL_INST 0x2
#define RISCV_EXCP_LOAD_ACCESS_FAULT 0x5
#define RISCV_EXCP_STORE_AMO_ACCESS_FAULT 0x7
#define RISCV_EXCP_S_ECALL 0x9
#define RISCV_EXCP_VS_ECALL 0xa
#define RISCV_EXCP_M_ECALL 0xb
#define RISCV_EXCP_INST_GUEST_PAGE_FAULT 0x14
#define RISCV_EXCP_LOAD_GUEST_ACCESS_FAULT 0x15
#define RISCV_EXCP_VIRT_INSTRUCTION_FAULT 0x16
#define RISCV_EXCP_STORE_GUEST_AMO_ACCESS_FAULT 0x17
#define RISCV_HSTATUS_VSBE 0x00000020ull
#define RISCV_HSTATUS_SPVP 0x00000100ull
#define RISCV_HSTATUS_HU 0x00000200ull
#define RISCV_HSTATUS_VTW 0x00200000ull
#define RISCV_HSTATUS_VSXL 0x300000000ull
#define RISCV_HSTATUS_VSXL_RV64 0x200000000ull
#define RISCV64_SATP_MODE_SV39 0x8000000000000000ull
#define RISCV_PTE_V 0x001ull
#define RISCV_PTE_R 0x002ull
#define RISCV_PTE_X 0x008ull
#define RISCV_PTE_A 0x040ull
#define RISCV_PTE_D 0x080ull

static uint32_t riscv_encode_addi(uint32_t rd, uint32_t rs1, int32_t imm)
{
    return (((uint32_t)imm & 0xfff) << 20) | ((rs1 & 0x1f) << 15) |
           ((rd & 0x1f) << 7) | 0x13;
}

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static void uc_common_setup_model(uc_engine **uc, uc_arch arch, uc_mode mode,
                                  const char *code, uint64_t size,
                                  int cpu_model)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_ctl_set_cpu_model(*uc, cpu_model));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static void test_riscv_block_count_cb(uc_engine *uc, uint64_t address,
                                      uint32_t size, void *user_data)
{
    uint32_t *count = (uint32_t *)user_data;

    (*count)++;
}

static void riscv32_enable_vector_state(uc_engine *uc)
{
    uint32_t mstatus = RISCV_MSTATUS_VS_INITIAL;

    OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &mstatus));
}

static void riscv32_enable_vector_fp_state(uc_engine *uc)
{
    uint32_t mstatus = RISCV_MSTATUS_VS_INITIAL |
                       RISCV_MSTATUS_FS_INITIAL;

    OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &mstatus));
}

static void riscv64_enable_vector_state(uc_engine *uc)
{
    uint64_t mstatus = RISCV_MSTATUS_VS_INITIAL;

    OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &mstatus));
}

static void riscv64_enable_vector_fp_state(uc_engine *uc)
{
    uint64_t mstatus = RISCV_MSTATUS_VS_INITIAL |
                       RISCV_MSTATUS_FS_INITIAL;

    OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &mstatus));
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

static void test_riscv32_zihintpause(void)
{
    uc_engine *uc;
    uc_hook hook;
    uint8_t code[] = {
        0x0f, 0x00, 0x00, 0x01, /* pause */
        0x93, 0x02, 0x10, 0x00, /* addi t0, zero, 1 */
    };
    uint32_t block_count = 0;
    uint32_t t0 = 0;
    uint32_t pc = 0;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, (char *)code,
                    sizeof(code));
    OK(uc_hook_add(uc, &hook, UC_HOOK_BLOCK, test_riscv_block_count_cb,
                   &block_count, 1, 0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &pc));

    TEST_CHECK(t0 == 1);
    TEST_CHECK(pc == (uint32_t)(code_start + sizeof(code)));
    TEST_CHECK(block_count == 2);

    OK(uc_close(uc));
}

static void test_riscv64_zihintpause(void)
{
    uc_engine *uc;
    uc_hook hook;
    uint8_t code[] = {
        0x0f, 0x00, 0x00, 0x01, /* pause */
        0x93, 0x02, 0x10, 0x00, /* addi t0, zero, 1 */
    };
    uint32_t block_count = 0;
    uint64_t t0 = 0;
    uint64_t pc = 0;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, (char *)code,
                    sizeof(code));
    OK(uc_hook_add(uc, &hook, UC_HOOK_BLOCK, test_riscv_block_count_cb,
                   &block_count, 1, 0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &pc));

    TEST_CHECK(t0 == 1);
    TEST_CHECK(pc == code_start + sizeof(code));
    TEST_CHECK(block_count == 2);

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

static void test_riscv64_until_at_page_end(void)
{
    uc_engine *uc;
    uint64_t address = 0x6d76d7473ffc;
    uint64_t page = address & ~0xfffULL;
    char code[] = "\x13\x81\x00\x7d";
    uint64_t r_x1 = 0x1234;
    uint64_t r_x2 = 0;
    uint64_t r_pc = 0;

    OK(uc_open(UC_ARCH_RISCV, UC_MODE_RISCV64, &uc));
    OK(uc_mem_map(uc, page, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, address, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_RISCV_REG_X1, &r_x1));

    OK(uc_emu_start(uc, address, address + sizeof(code) - 1, 0, 1));

    OK(uc_reg_read(uc, UC_RISCV_REG_X2, &r_x2));
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &r_pc));

    TEST_CHECK(r_x2 == 0x1a04);
    TEST_CHECK(r_pc == address + sizeof(code) - 1);

    OK(uc_close(uc));
}

static void test_riscv32_fp_move(void)
{
    uc_engine *uc;
    char code[] = "\xd3\x81\x10\x22"; // fmv.d f3, f1

    uint64_t r_f1 = 0x123456781a2b3c4dULL;
    uint64_t r_f3 = 0x56780246aaaabbbbULL;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code,
                    sizeof(code) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_RISCV_REG_F1, &r_f1);
    uc_reg_write(uc, UC_RISCV_REG_F3, &r_f3);

    // emulate the instruction
    OK(uc_emu_start(uc, code_start, -1, 0, 1));

    OK(uc_reg_read(uc, UC_RISCV_REG_F1, &r_f1));
    OK(uc_reg_read(uc, UC_RISCV_REG_F3, &r_f3));

    TEST_CHECK(r_f1 == 0x123456781a2b3c4dULL);
    TEST_CHECK(r_f3 == 0x123456781a2b3c4dULL);

    uc_close(uc);
}

static void test_riscv64_fp_move(void)
{
    uc_engine *uc;
    char code[] = "\xd3\x81\x10\x22"; // fmv.d f3, f1

    uint64_t r_f1 = 0x123456781a2b3c4dULL;
    uint64_t r_f3 = 0x56780246aaaabbbbULL;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);

    // initialize machine registers
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &r_f1));
    OK(uc_reg_write(uc, UC_RISCV_REG_F3, &r_f3));

    // emulate the instruction
    OK(uc_emu_start(uc, code_start, -1, 0, 1));

    OK(uc_reg_read(uc, UC_RISCV_REG_F1, &r_f1));
    OK(uc_reg_read(uc, UC_RISCV_REG_F3, &r_f3));

    TEST_CHECK(r_f1 == 0x123456781a2b3c4dULL);
    TEST_CHECK(r_f3 == 0x123456781a2b3c4dULL);

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

static void test_riscv64_fclass_s_nanboxing(void)
{
    uc_engine *uc;
    char code[] = "\xd3\x95\x07\xe0"; /* fclass.s a1, f15 */
    uint64_t f15 = 0xffffffff7f800000ULL;
    uint64_t a1 = 0;
    uint64_t mstatus = 0x6000;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &mstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_F15, &f15));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 1));
    OK(uc_reg_read(uc, UC_RISCV_REG_A1, &a1));
    TEST_CHECK(a1 == 0x80);

    f15 = 0x62bf9dd562bf9dd5ULL;
    a1 = 0;
    OK(uc_reg_write(uc, UC_RISCV_REG_F15, &f15));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 1));
    OK(uc_reg_read(uc, UC_RISCV_REG_A1, &a1));
    TEST_CHECK(a1 == 0x200);

    f15 = 0xbc26093bbc260929ULL;
    a1 = 0;
    OK(uc_reg_write(uc, UC_RISCV_REG_F15, &f15));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 1));
    OK(uc_reg_read(uc, UC_RISCV_REG_A1, &a1));
    TEST_CHECK(a1 == 0x200);

    OK(uc_close(uc));
}

static void test_riscv64_fclass_s_produced_nanbox(void)
{
    uc_engine *uc;
    char code[] = "\xd3\x07\x05\xd0\xd3\x95\x07\xe0";
    uint64_t a0 = 1;
    uint64_t a1 = 0;
    uint64_t f15 = 0;
    uint64_t mstatus = 0x6000;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &mstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 2));
    OK(uc_reg_read(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_read(uc, UC_RISCV_REG_F15, &f15));

    TEST_CHECK(a1 == 0x40);
    TEST_CHECK(f15 == 0xffffffff3f800000ULL);

    OK(uc_close(uc));
}

static void test_riscv64_fmv_w_x_nanbox(void)
{
    uc_engine *uc;
    char code[] = "\xd3\x07\x05\xf0\xd3\x95\x07\xe0";
    uint64_t a0 = 0x7f800000;
    uint64_t a1 = 0;
    uint64_t f15 = 0;
    uint64_t mstatus = 0x6000;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &mstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 2));
    OK(uc_reg_read(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_read(uc, UC_RISCV_REG_F15, &f15));

    TEST_CHECK(a1 == 0x80);
    TEST_CHECK(f15 == 0xffffffff7f800000ULL);

    OK(uc_close(uc));
}

static void test_riscv64_fmin_fmax_snan(void)
{
    static const struct {
        const char *name;
        const char code[4];
        uint64_t lhs;
        uint64_t rhs;
        uint64_t expected;
    } cases[] = {
        {"fmin.s", "\x53\x85\xc5\x28", 0xffffffff7fa00000ULL,
         0xffffffff3fc00000ULL, 0xffffffff3fc00000ULL},
        {"fmax.s", "\x53\x95\xc5\x28", 0xffffffff7fa00000ULL,
         0xffffffff3fc00000ULL, 0xffffffff3fc00000ULL},
        {"fmin.d", "\x53\x85\xc5\x2a", 0x7ff4000000000000ULL,
         0x3ff8000000000000ULL, 0x3ff8000000000000ULL},
        {"fmax.d", "\x53\x95\xc5\x2a", 0x7ff4000000000000ULL,
         0x3ff8000000000000ULL, 0x3ff8000000000000ULL},
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uc_engine *uc;
        uint64_t dst = 0;
        uint64_t fflags = 0;
        uint64_t lhs = cases[i].lhs;
        uint64_t mstatus = 0x6000;
        uint64_t rhs = cases[i].rhs;

        uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, cases[i].code,
                        sizeof(cases[i].code));
        OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &mstatus));
        OK(uc_reg_write(uc, UC_RISCV_REG_F11, &lhs));
        OK(uc_reg_write(uc, UC_RISCV_REG_F12, &rhs));

        OK(uc_emu_start(uc, code_start, code_start + sizeof(cases[i].code),
                        0, 1));
        OK(uc_reg_read(uc, UC_RISCV_REG_F10, &dst));
        OK(uc_reg_read(uc, UC_RISCV_REG_FFLAGS, &fflags));

        TEST_CHECK_(dst == cases[i].expected, "%s result", cases[i].name);
        TEST_CHECK_(fflags == 0x10, "%s invalid flag", cases[i].name);

        OK(uc_close(uc));
    }
}

static void test_riscv32_zfh_load_store_move(void)
{
    uc_engine *uc;
    char code[] =
        "\x87\x10\x05\x00" /* flh f1, 0(a0) */
        "\xd3\x82\x00\xe4" /* fmv.x.h t0, f1 */
        "\x53\x01\x03\xf4" /* fmv.h.x f2, t1 */
        "\x27\x11\x25\x00"; /* fsh f2, 2(a0) */
    uint32_t a0 = code_start + 0x1000;
    uint32_t t0 = 0;
    uint32_t t1 = 0x3e00;
    uint64_t f1 = 0;
    uint64_t f2 = 0;
    uint64_t mstatus = 0x6000;
    uint8_t input[4] = { 0x00, 0xbc, 0x00, 0x00 };
    uint8_t output[4] = { 0 };

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code,
                    sizeof(code) - 1);
    OK(uc_mem_write(uc, a0, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &mstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 4));

    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_read(uc, UC_RISCV_REG_F1, &f1));
    OK(uc_reg_read(uc, UC_RISCV_REG_F2, &f2));
    OK(uc_mem_read(uc, a0, output, sizeof(output)));

    TEST_CHECK(t0 == 0xffffbc00);
    TEST_CHECK(f1 == 0xffffffffffffbc00ULL);
    TEST_CHECK(f2 == 0xffffffffffff3e00ULL);
    TEST_CHECK(output[2] == 0x00);
    TEST_CHECK(output[3] == 0x3e);

    OK(uc_close(uc));
}

static void test_riscv64_zfh_load_store_move(void)
{
    uc_engine *uc;
    char code[] =
        "\x87\x10\x05\x00" /* flh f1, 0(a0) */
        "\xd3\x82\x00\xe4" /* fmv.x.h t0, f1 */
        "\x53\x01\x03\xf4" /* fmv.h.x f2, t1 */
        "\x27\x11\x25\x00"; /* fsh f2, 2(a0) */
    uint64_t a0 = code_start + 0x1000;
    uint64_t t0 = 0;
    uint64_t t1 = 0x3e00;
    uint64_t f1 = 0;
    uint64_t f2 = 0;
    uint64_t mstatus = 0x6000;
    uint8_t input[4] = { 0x00, 0xbc, 0x00, 0x00 };
    uint8_t output[4] = { 0 };

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    OK(uc_mem_write(uc, a0, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &mstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 4));

    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_read(uc, UC_RISCV_REG_F1, &f1));
    OK(uc_reg_read(uc, UC_RISCV_REG_F2, &f2));
    OK(uc_mem_read(uc, a0, output, sizeof(output)));

    TEST_CHECK(t0 == 0xffffffffffffbc00ULL);
    TEST_CHECK(f1 == 0xffffffffffffbc00ULL);
    TEST_CHECK(f2 == 0xffffffffffff3e00ULL);
    TEST_CHECK(output[2] == 0x00);
    TEST_CHECK(output[3] == 0x3e);

    OK(uc_close(uc));
}

static void test_riscv64_zfh_arith_compare_class(void)
{
    uc_engine *uc;
    char code[] =
        "\x53\x82\x20\x04" /* fadd.h f4, f1, f2 */
        "\xd3\x02\x32\x14" /* fmul.h f5, f4, f3 */
        "\x53\x83\x20\x2c" /* fmin.h f6, f1, f2 */
        "\x53\x85\x20\x24" /* fsgnj.h f10, f1, f2 */
        "\xd3\x95\x10\x24" /* fsgnjn.h f11, f1, f1 */
        "\x53\xa6\xb5\x24" /* fsgnjx.h f12, f11, f11 */
        "\xc3\x84\x20\x1c" /* fmadd.h f9, f1, f2, f3 */
        "\xd3\x92\x20\xa4" /* flt.h t0, f1, f2 */
        "\x53\xa3\x20\xa4" /* feq.h t1, f1, f2 */
        "\xd3\x93\x00\xe4"; /* fclass.h t2, f1 */
    uint64_t f1 = 0xffffffffffff3c00ULL;
    uint64_t f2 = 0xffffffffffff4000ULL;
    uint64_t f3 = 0xffffffffffff3800ULL;
    uint64_t f4 = 0;
    uint64_t f5 = 0;
    uint64_t f6 = 0;
    uint64_t f9 = 0;
    uint64_t f10 = 0;
    uint64_t f11 = 0;
    uint64_t f12 = 0;
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    uint64_t t2 = 0;
    uint64_t mstatus = 0x6000;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &mstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &f1));
    OK(uc_reg_write(uc, UC_RISCV_REG_F2, &f2));
    OK(uc_reg_write(uc, UC_RISCV_REG_F3, &f3));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 10));

    OK(uc_reg_read(uc, UC_RISCV_REG_F4, &f4));
    OK(uc_reg_read(uc, UC_RISCV_REG_F5, &f5));
    OK(uc_reg_read(uc, UC_RISCV_REG_F6, &f6));
    OK(uc_reg_read(uc, UC_RISCV_REG_F9, &f9));
    OK(uc_reg_read(uc, UC_RISCV_REG_F10, &f10));
    OK(uc_reg_read(uc, UC_RISCV_REG_F11, &f11));
    OK(uc_reg_read(uc, UC_RISCV_REG_F12, &f12));
    OK(uc_reg_read(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &t1));
    OK(uc_reg_read(uc, UC_RISCV_REG_T2, &t2));

    TEST_CHECK(f4 == 0xffffffffffff4200ULL);
    TEST_CHECK(f5 == 0xffffffffffff3e00ULL);
    TEST_CHECK(f6 == 0xffffffffffff3c00ULL);
    TEST_CHECK(f9 == 0xffffffffffff4100ULL);
    TEST_CHECK(f10 == 0xffffffffffff3c00ULL);
    TEST_CHECK(f11 == 0xffffffffffffbc00ULL);
    TEST_CHECK(f12 == 0xffffffffffff3c00ULL);
    TEST_CHECK(t0 == 1);
    TEST_CHECK(t1 == 0);
    TEST_CHECK(t2 == 0x40);

    OK(uc_close(uc));
}

static void test_riscv32_zfh_conversions(void)
{
    uc_engine *uc;
    char code[] =
        "\xd3\x81\x02\xd4" /* fcvt.h.w f3, t0 */
        "\x53\x83\x01\xc4" /* fcvt.w.h t1, f3 */
        "\x53\x82\x00\x44" /* fcvt.h.s f4, f1 */
        "\xd3\x02\x22\x40" /* fcvt.s.h f5, f4 */
        "\x53\x03\x11\x44" /* fcvt.h.d f6, f2 */
        "\xd3\x03\x23\x42"; /* fcvt.d.h f7, f6 */
    uint64_t f1 = 0xffffffff3fc00000ULL;
    uint64_t f2 = 0x4008000000000000ULL;
    uint64_t f3 = 0;
    uint64_t f4 = 0;
    uint64_t f5 = 0;
    uint64_t f6 = 0;
    uint64_t f7 = 0;
    uint32_t t0 = 2;
    uint32_t t1 = 0;
    uint64_t mstatus = 0x6000;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code,
                    sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &mstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &f1));
    OK(uc_reg_write(uc, UC_RISCV_REG_F2, &f2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 6));

    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &t1));
    OK(uc_reg_read(uc, UC_RISCV_REG_F3, &f3));
    OK(uc_reg_read(uc, UC_RISCV_REG_F4, &f4));
    OK(uc_reg_read(uc, UC_RISCV_REG_F5, &f5));
    OK(uc_reg_read(uc, UC_RISCV_REG_F6, &f6));
    OK(uc_reg_read(uc, UC_RISCV_REG_F7, &f7));

    TEST_CHECK(t1 == 2);
    TEST_CHECK(f3 == 0xffffffffffff4000ULL);
    TEST_CHECK(f4 == 0xffffffffffff3e00ULL);
    TEST_CHECK(f5 == 0xffffffff3fc00000ULL);
    TEST_CHECK(f6 == 0xffffffffffff4200ULL);
    TEST_CHECK(f7 == 0x4008000000000000ULL);

    OK(uc_close(uc));
}

static void test_riscv64_zfh_conversions(void)
{
    uc_engine *uc;
    char code[] =
        "\xd3\x81\x02\xd4" /* fcvt.h.w f3, t0 */
        "\x53\x83\x01\xc4" /* fcvt.w.h t1, f3 */
        "\x53\x82\x00\x44" /* fcvt.h.s f4, f1 */
        "\xd3\x02\x22\x40" /* fcvt.s.h f5, f4 */
        "\x53\x03\x11\x44" /* fcvt.h.d f6, f2 */
        "\xd3\x03\x23\x42" /* fcvt.d.h f7, f6 */
        "\xd3\x03\x23\xc4" /* fcvt.l.h t2, f6 */
        "\x53\x84\x23\xd4"; /* fcvt.h.l f8, t2 */
    uint64_t f1 = 0xffffffff3fc00000ULL;
    uint64_t f2 = 0x4008000000000000ULL;
    uint64_t f3 = 0;
    uint64_t f4 = 0;
    uint64_t f5 = 0;
    uint64_t f6 = 0;
    uint64_t f7 = 0;
    uint64_t f8 = 0;
    uint64_t t0 = 2;
    uint64_t t1 = 0;
    uint64_t t2 = 0;
    uint64_t mstatus = 0x6000;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &mstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &f1));
    OK(uc_reg_write(uc, UC_RISCV_REG_F2, &f2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 8));

    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &t1));
    OK(uc_reg_read(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_read(uc, UC_RISCV_REG_F3, &f3));
    OK(uc_reg_read(uc, UC_RISCV_REG_F4, &f4));
    OK(uc_reg_read(uc, UC_RISCV_REG_F5, &f5));
    OK(uc_reg_read(uc, UC_RISCV_REG_F6, &f6));
    OK(uc_reg_read(uc, UC_RISCV_REG_F7, &f7));
    OK(uc_reg_read(uc, UC_RISCV_REG_F8, &f8));

    TEST_CHECK(t1 == 2);
    TEST_CHECK(t2 == 3);
    TEST_CHECK(f3 == 0xffffffffffff4000ULL);
    TEST_CHECK(f4 == 0xffffffffffff3e00ULL);
    TEST_CHECK(f5 == 0xffffffff3fc00000ULL);
    TEST_CHECK(f6 == 0xffffffffffff4200ULL);
    TEST_CHECK(f7 == 0x4008000000000000ULL);
    TEST_CHECK(f8 == 0xffffffffffff4200ULL);

    OK(uc_close(uc));
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

static void test_riscv_mmu_prepare_tlb(uc_engine *uc, uint32_t data_address,
                                       uint32_t code_address)
{
    uint64_t tlbe;
    uint32_t sptbr = 0x2000;
    uint64_t tlbe_mem;

    OK(uc_mem_map(uc, sptbr, 0x3000, UC_PROT_ALL)); // tlb base

    tlbe = ((sptbr + 0x1000) >> 2) | 1;
    tlbe_mem = LEINT64(tlbe);
    OK(uc_mem_write(uc, sptbr, &tlbe_mem, sizeof(tlbe)));
    tlbe = ((sptbr + 0x2000) >> 2) | 1;
    tlbe_mem = LEINT64(tlbe);
    OK(uc_mem_write(uc, sptbr + 0x1000, &tlbe_mem, sizeof(tlbe)));

    tlbe = (code_address >> 2) | (7 << 1) | 1;
    tlbe_mem = LEINT64(tlbe);
    OK(uc_mem_write(uc, sptbr + 0x2000 + 0x15 * 8, &tlbe_mem, sizeof(tlbe)));

    tlbe = (data_address >> 2) | (7 << 1) | 1;
    tlbe_mem = LEINT64(tlbe);
    OK(uc_mem_write(uc, sptbr + 0x2000 + 0x16 * 8, &tlbe_mem, sizeof(tlbe)));
}

static void test_riscv_mmu_hook_code(uc_engine *uc, uint64_t address,
                                     uint32_t size, void *userdata)
{
    if (address == 0x15010) {
        OK(uc_emu_stop(uc));
    }
}

static void test_riscv_mmu(void)
{
    uc_engine *uc;
    uc_hook h;
    uint32_t code_address = 0x5000;
    uint32_t data_address = 0x6000;
    uint32_t data_value = 0x41414141;
    uint32_t data_result = 0;

    /*
    li        t3, (8 << 60) | 2
    csrw      sptbr, t3
    li        t0, (1 << 11) | (1 << 5)
    csrw      mstatus, t0
    la        t1, 0x15000
    csrw      mepc, t1
    mret
    */
    char code_m[] = "\x1b\x0e\xf0\xff"
                    "\x13\x1e\xfe\x03"
                    "\x13\x0e\x2e\x00"
                    "\x73\x10\x0e\x18"
                    "\xb7\x12\x00\x00"
                    "\x9b\x82\x02\x82"
                    "\x73\x90\x02\x30"
                    "\x37\x53\x01\x00"
                    "\x73\x10\x13\x34"
                    "\x73\x00\x20\x30";

    /*
    li t0, 0x41414141
    li t1, 0x16000
    sw t0, 0(t1)
    nop
    */
    char code_s[] = "\xb7\x42\x41\x41"
                    "\x9b\x82\x12\x14"
                    "\x37\x63\x01\x00"
                    "\x23\x20\x53\x00"
                    "\x13\x00\x00\x00";

    OK(uc_open(UC_ARCH_RISCV, UC_MODE_RISCV64, &uc));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_CPU));
    OK(uc_hook_add(uc, &h, UC_HOOK_CODE, test_riscv_mmu_hook_code, NULL, 1, 0));
    OK(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, code_address, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, data_address, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_address, &code_s, sizeof(code_s)));
    OK(uc_mem_write(uc, 0x1000, &code_m, sizeof(code_m)));

    test_riscv_mmu_prepare_tlb(uc, data_address, code_address);

    OK(uc_emu_start(uc, 0x1000, sizeof(code_m) - 1, 0, 0));
    OK(uc_mem_read(uc, data_address, &data_result, sizeof(data_result)));

    TEST_CHECK(data_value == data_result);
    OK(uc_close(uc));
}

static void test_riscv_priv(void)
{
    uc_engine *uc;
    uc_err err;
    uint32_t m_entry_address = 0x1000;
    uint32_t main_address = 0x3000;
    uint64_t priv_value = ~0;
    uint64_t pc = ~0;
    uint64_t reg_value;

    /*
    li        t0, 0
    csrw      mstatus, t0
    li        t1, 0x3000
    csrw      mepc, t1
    mret
    */
    char code_m_entry[] = "\x93\x02\x00\x00"
                          "\x73\x90\x02\x30"
                          "\x37\x33\x00\x00"
                          "\x73\x10\x13\x34"
                          "\x73\x00\x20\x30";

    /*
    csrw    sscratch, t0
    nop
    */
    char code_main[] = "\x73\x90\x02\x14"
                       "\x13\x00\x00\x00";
    int main_end_address = main_address + sizeof(code_main) - 1;

    OK(uc_open(UC_ARCH_RISCV, UC_MODE_RISCV64, &uc));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_CPU));
    OK(uc_mem_map(uc, m_entry_address, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, main_address, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, m_entry_address, &code_m_entry, sizeof(code_m_entry)));
    OK(uc_mem_write(uc, main_address, &code_main, sizeof(code_main)));

    // Before anything executes we should be in M-Mode
    OK(uc_reg_read(uc, UC_RISCV_REG_PRIV, &priv_value));
    TEST_ASSERT(priv_value == 3);

    // We'll put a sentinel value in sscratch so we can determine whether we've
    // successfully written to it below.
    reg_value = 0xffff;
    OK(uc_reg_write(uc, UC_RISCV_REG_SSCRATCH, &reg_value));

    // Run until we reach the "csrw" at the start of code_main, at which
    // point we should be in U-Mode due to the mret instruction.
    OK(uc_emu_start(uc, m_entry_address, main_address, 0, 10));

    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &pc));
    TEST_ASSERT(pc == main_address);
    OK(uc_reg_read(uc, UC_RISCV_REG_PRIV, &priv_value));
    TEST_ASSERT(priv_value == 0); // Now in U-Mode

    // U-Mode can't write to sscratch, so execution at this point should
    // cause an invalid instruction exception.
    err = uc_emu_start(uc, main_address, main_end_address, 0, 0);
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &pc));
    TEST_ASSERT(err == UC_ERR_EXCEPTION);

    // ...but if we force S-Mode then we should be able to set it successfully.
    priv_value = 1;
    OK(uc_reg_write(uc, UC_RISCV_REG_PRIV, &priv_value));
    OK(uc_emu_start(uc, main_address, main_end_address, 0, 0));
    OK(uc_reg_read(uc, UC_RISCV_REG_SSCRATCH, &reg_value));
    TEST_ASSERT(reg_value == 0);
}

static uint32_t riscv_encode_r(uint32_t funct7, uint32_t rs2, uint32_t rs1,
                               uint32_t funct3, uint32_t rd, uint32_t opcode)
{
    return ((funct7 & 0x7f) << 25) | ((rs2 & 0x1f) << 20) |
           ((rs1 & 0x1f) << 15) | ((funct3 & 0x7) << 12) |
           ((rd & 0x1f) << 7) | (opcode & 0x7f);
}

static uint32_t riscv_encode_i(uint32_t imm, uint32_t rs1, uint32_t funct3,
                               uint32_t rd, uint32_t opcode)
{
    return ((imm & 0xfff) << 20) | ((rs1 & 0x1f) << 15) |
           ((funct3 & 0x7) << 12) | ((rd & 0x1f) << 7) |
           (opcode & 0x7f);
}

static uint32_t riscv_encode_s(uint32_t imm, uint32_t rs2, uint32_t rs1,
                               uint32_t funct3, uint32_t opcode)
{
    return (((imm >> 5) & 0x7f) << 25) | ((rs2 & 0x1f) << 20) |
           ((rs1 & 0x1f) << 15) | ((funct3 & 0x7) << 12) |
           ((imm & 0x1f) << 7) | (opcode & 0x7f);
}

static uint32_t riscv_encode_csr(uint32_t csr, uint32_t rs1,
                                 uint32_t funct3, uint32_t rd)
{
    return riscv_encode_i(csr, rs1, funct3, rd, 0x73);
}

static uint32_t riscv_encode_k_aes(uint32_t funct5, uint32_t shamt,
                                   uint32_t rs2, uint32_t rs1, uint32_t rd)
{
    uint32_t funct7 = ((shamt >> 3) << 5) | (funct5 & 0x1f);

    return riscv_encode_r(funct7, rs2, rs1, 0, rd, 0x33);
}

static uint32_t riscv_encode_rvv_op(uint32_t funct6, uint32_t vm,
                                    uint32_t vs2, uint32_t rs1,
                                    uint32_t funct3, uint32_t vd)
{
    return ((funct6 & 0x3f) << 26) | ((vm & 1) << 25) |
           ((vs2 & 0x1f) << 20) | ((rs1 & 0x1f) << 15) |
           ((funct3 & 0x7) << 12) | ((vd & 0x1f) << 7) | 0x57;
}

static uint32_t riscv_encode_rvv_vsetvli(uint32_t rd, uint32_t rs1,
                                         uint32_t zimm)
{
    return ((zimm & 0x7ff) << 20) | ((rs1 & 0x1f) << 15) |
           (7 << 12) | ((rd & 0x1f) << 7) | 0x57;
}

static uint32_t riscv_encode_rvv_ldst(int is_store, uint32_t width,
                                      uint32_t vm, uint32_t rs1,
                                      uint32_t reg)
{
    return ((vm & 1) << 25) | ((rs1 & 0x1f) << 15) |
           ((width & 0x7) << 12) | ((reg & 0x1f) << 7) |
           (is_store ? 0x27 : 0x07);
}

static uint32_t riscv_encode_rvv_segment_ldst(int is_store, uint32_t width,
                                              uint32_t vm, uint32_t rs1,
                                              uint32_t reg, uint32_t nf)
{
    return riscv_encode_rvv_ldst(is_store, width, vm, rs1, reg) |
           (((nf - 1) & 0x7) << 29);
}

static uint32_t riscv_encode_rvv_stride_ldst(int is_store, uint32_t width,
                                             uint32_t vm, uint32_t rs1,
                                             uint32_t rs2, uint32_t reg,
                                             uint32_t nf)
{
    return (((nf - 1) & 0x7) << 29) | (2 << 26) | ((vm & 1) << 25) |
           ((rs2 & 0x1f) << 20) | ((rs1 & 0x1f) << 15) |
           ((width & 0x7) << 12) | ((reg & 0x1f) << 7) |
           (is_store ? 0x27 : 0x07);
}

static uint32_t riscv_encode_rvv_index_ldst(int is_store, uint32_t width,
                                            uint32_t mop, uint32_t vm,
                                            uint32_t rs1, uint32_t rs2,
                                            uint32_t reg, uint32_t nf)
{
    return (((nf - 1) & 0x7) << 29) | ((mop & 0x7) << 26) |
           ((vm & 1) << 25) | ((rs2 & 0x1f) << 20) |
           ((rs1 & 0x1f) << 15) | ((width & 0x7) << 12) |
           ((reg & 0x1f) << 7) | (is_store ? 0x27 : 0x07);
}

static uint32_t riscv_encode_rvv_ff_load(uint32_t width, uint32_t vm,
                                         uint32_t rs1, uint32_t reg,
                                         uint32_t nf)
{
    return (((nf - 1) & 0x7) << 29) | ((vm & 1) << 25) |
           (0x10 << 20) | ((rs1 & 0x1f) << 15) |
           ((width & 0x7) << 12) | ((reg & 0x1f) << 7) | 0x07;
}

static uint32_t riscv_rvv_whole_nf_code(uint32_t nf)
{
    switch (nf) {
    case 1:
        return 0;
    case 2:
        return 1;
    case 4:
        return 3;
    case 8:
        return 7;
    default:
        return 0;
    }
}

static uint32_t riscv_encode_rvv_whole_ldst(int is_store, uint32_t width,
                                            uint32_t rs1, uint32_t reg,
                                            uint32_t nf)
{
    return (riscv_rvv_whole_nf_code(nf) << 29) | (1 << 25) |
           (0x08 << 20) | ((rs1 & 0x1f) << 15) |
           ((width & 0x7) << 12) | ((reg & 0x1f) << 7) |
           (is_store ? 0x27 : 0x07);
}

static uint32_t riscv_encode_rvv_mask_ldst(int is_store, uint32_t rs1,
                                           uint32_t reg)
{
    return (1 << 25) | (0x0b << 20) | ((rs1 & 0x1f) << 15) |
           ((reg & 0x1f) << 7) | (is_store ? 0x27 : 0x07);
}

static uint32_t riscv_encode_rvv_vmvnr(uint32_t nf, uint32_t rs2,
                                       uint32_t rd)
{
    return (0x27 << 26) | (1 << 25) |
           ((rs2 & 0x1f) << 20) |
           (riscv_rvv_whole_nf_code(nf) << 15) | (3 << 12) |
           ((rd & 0x1f) << 7) | 0x57;
}

static uint32_t riscv_encode_rvh_load(uint32_t funct7, uint32_t selector,
                                      uint32_t rs1, uint32_t rd)
{
    return ((funct7 & 0x7f) << 25) | ((selector & 0x1f) << 20) |
           ((rs1 & 0x1f) << 15) | (4 << 12) | ((rd & 0x1f) << 7) |
           0x73;
}

static uint32_t riscv_encode_rvh_store(uint32_t funct7, uint32_t rs2,
                                       uint32_t rs1)
{
    return ((funct7 & 0x7f) << 25) | ((rs2 & 0x1f) << 20) |
           ((rs1 & 0x1f) << 15) | (4 << 12) | 0x73;
}

static void riscv_insn_to_code(uint8_t code[4], uint32_t insn)
{
    code[0] = insn;
    code[1] = insn >> 8;
    code[2] = insn >> 16;
    code[3] = insn >> 24;
}

static void test_riscv64_sstc_stimecmp(void)
{
    uc_engine *uc;
    uint32_t insns[] = {
        riscv_encode_csr(RISCV_CSR_STIMECMP, 5, 1, 0),
        riscv_encode_csr(RISCV_CSR_STIMECMP, 0, 2, 6),
    };
    uint8_t code[sizeof(insns)];
    uint64_t t0 = 0x1122334455667788ull;
    uint64_t t1 = 0;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup_model(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                          (const char *)code, sizeof(code),
                          UC_CPU_RISCV64_BASE64);
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &t1));
    TEST_CHECK(t1 == t0);
    OK(uc_close(uc));
}

static void run_riscv32_zbb_case(uint32_t insn, uint32_t rs1,
                                 uint32_t rs2, int rd, uint32_t expected)
{
    uc_engine *uc;
    uint8_t code[4];
    uint32_t actual = 0;

    riscv_insn_to_code(code, insn);
    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, (const char *)code,
                    sizeof(code));
    OK(uc_reg_write(uc, UC_RISCV_REG_X6, &rs1));
    OK(uc_reg_write(uc, UC_RISCV_REG_X7, &rs2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_X0 + rd, &actual));
    TEST_CHECK(actual == expected);
    OK(uc_close(uc));
}

static void run_riscv64_zbb_case(uint32_t insn, uint64_t rs1,
                                 uint64_t rs2, int rd, uint64_t expected)
{
    uc_engine *uc;
    uint8_t code[4];
    uint64_t actual = 0;

    riscv_insn_to_code(code, insn);
    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, (const char *)code,
                    sizeof(code));
    OK(uc_reg_write(uc, UC_RISCV_REG_X6, &rs1));
    OK(uc_reg_write(uc, UC_RISCV_REG_X7, &rs2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_X0 + rd, &actual));
    TEST_CHECK(actual == expected);
    OK(uc_close(uc));
}

static void run_riscv_insn_illegal(uc_mode mode, uint32_t insn)
{
    uc_engine *uc;
    uint8_t code[4];

    riscv_insn_to_code(code, insn);
    uc_common_setup(&uc, UC_ARCH_RISCV, mode, (const char *)code,
                    sizeof(code));
    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_close(uc));
}

static void run_riscv_model_insn_illegal(uc_mode mode, int cpu_model,
                                         uint32_t insn)
{
    uc_engine *uc;
    uint8_t code[4];

    riscv_insn_to_code(code, insn);
    uc_common_setup_model(&uc, UC_ARCH_RISCV, mode, (const char *)code,
                          sizeof(code), cpu_model);

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_close(uc));
}

static void run_riscv_non_fp_model_insn_illegal(uc_mode mode, int cpu_model,
                                                uint32_t insn)
{
    uc_engine *uc;
    uint8_t code[4];
    uint64_t a0 = code_start + 0x1000;
    uint64_t mstatus = RISCV_MSTATUS_FS_INITIAL;
    uint8_t data[8] = { 0 };

    riscv_insn_to_code(code, insn);
    uc_common_setup_model(&uc, UC_ARCH_RISCV, mode, (const char *)code,
                          sizeof(code), cpu_model);
    OK(uc_mem_write(uc, a0, data, sizeof(data)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_MSTATUS, &mstatus));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_close(uc));
}

static void run_riscv_rvv_non_vector_model_illegal(uc_mode mode,
                                                   int cpu_model)
{
    uc_engine *uc;
    uint8_t code[4];
    uint64_t t0 = 4;

    riscv_insn_to_code(code, riscv_encode_rvv_vsetvli(0, 5, 0xc0));
    uc_common_setup_model(&uc, UC_ARCH_RISCV, mode, (const char *)code,
                          sizeof(code), cpu_model);
    if (mode == UC_MODE_RISCV64) {
        riscv64_enable_vector_state(uc);
    } else {
        riscv32_enable_vector_state(uc);
    }
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_close(uc));
}

static void run_riscv_rvv_non_vector_model_data_illegal(uc_mode mode,
                                                        int cpu_model)
{
    uc_engine *uc;
    uint8_t code[4];
    uint64_t a0 = code_start + 0x1000;
    uint64_t vl = 4;
    uint64_t vtype = 0xc0;

    riscv_insn_to_code(code, riscv_encode_rvv_ldst(0, 0, 1, 10, 1));
    uc_common_setup_model(&uc, UC_ARCH_RISCV, mode, (const char *)code,
                          sizeof(code), cpu_model);
    if (mode == UC_MODE_RISCV64) {
        riscv64_enable_vector_state(uc);
    } else {
        riscv32_enable_vector_state(uc);
    }
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_VTYPE, &vtype));
    OK(uc_reg_write(uc, UC_RISCV_REG_VL, &vl));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_close(uc));
}

static void run_riscv64_rvv_illegal_vtype(uint32_t insn, uint32_t zimm)
{
    uc_engine *uc;
    uint8_t code[2 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, zimm),
        insn,
    };
    uint64_t t0 = 8;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_close(uc));
}

static void run_riscv64_rvv_illegal(uint32_t insn)
{
    run_riscv64_rvv_illegal_vtype(insn, 0xc0);
}

static void run_riscv64_rvv_illegal_vstart_vl0(uint32_t insn)
{
    uc_engine *uc;
    uint8_t code[3 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xc0),
        riscv_encode_csr(RISCV_CSR_VSTART, 6, 1, 0),
        insn,
    };
    uint64_t t0 = 0;
    uint64_t t1 = 1;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_close(uc));
}

static void run_riscv64_rvv_fp_illegal_vtype(uint32_t insn, uint32_t zimm)
{
    uc_engine *uc;
    uint8_t code[2 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, zimm),
        insn,
    };
    uint64_t t0 = 8;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_close(uc));
}

static void run_riscv_svinval_case(uc_mode mode)
{
    uc_engine *uc;
    uint8_t code[12];
    uint32_t insns[] = {
        0x16208073, /* sinval.vma x1, x2 */
        0x18000073, /* sfence.w.inval */
        0x18100073, /* sfence.inval.ir */
    };
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, mode, (const char *)code,
                    sizeof(code));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_close(uc));
}

static void test_riscv32_svinval(void)
{
    run_riscv_svinval_case(UC_MODE_RISCV32);
}

static void test_riscv64_svinval(void)
{
    run_riscv_svinval_case(UC_MODE_RISCV64);
}

static void test_riscv_svinval_hinval_requires_rvh(void)
{
    run_riscv_insn_illegal(UC_MODE_RISCV32, 0x26208073);
    run_riscv_insn_illegal(UC_MODE_RISCV32, 0x66208073);
    run_riscv_insn_illegal(UC_MODE_RISCV64, 0x26208073);
    run_riscv_insn_illegal(UC_MODE_RISCV64, 0x66208073);
}

static void test_riscv_svinval_requires_s(void)
{
    uint32_t insns[] = {
        0x16208073, /* sinval.vma x1, x2 */
        0x18000073, /* sfence.w.inval */
        0x18100073, /* sfence.inval.ir */
    };
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        run_riscv_model_insn_illegal(UC_MODE_RISCV32,
                                     UC_CPU_RISCV32_SIFIVE_E31, insns[i]);
        run_riscv_model_insn_illegal(UC_MODE_RISCV64,
                                     UC_CPU_RISCV64_SIFIVE_E51, insns[i]);
    }
}

static void test_riscv32_rvh_hlv_hsv(void)
{
    uc_engine *uc;
    uint32_t insns[] = {
        riscv_encode_rvh_load(0x30, 0, 6, 5),
        riscv_encode_rvh_load(0x30, 1, 6, 8),
        riscv_encode_rvh_load(0x32, 0, 7, 9),
        riscv_encode_rvh_load(0x32, 1, 7, 10),
        riscv_encode_rvh_load(0x34, 0, 11, 12),
        riscv_encode_rvh_store(0x31, 13, 14),
        riscv_encode_rvh_store(0x33, 15, 16),
        riscv_encode_rvh_store(0x35, 17, 18),
        riscv_encode_rvh_load(0x32, 3, 19, 20),
        riscv_encode_rvh_load(0x34, 3, 21, 22),
    };
    uint8_t code[sizeof(insns)];
    uint8_t data[0x40] = {
        [0x00] = 0x80,
        [0x04] = 0x80, [0x05] = 0xff,
        [0x08] = 0x78, [0x09] = 0x56, [0x0a] = 0x34, [0x0b] = 0x80,
        [0x20] = 0xcd, [0x21] = 0xab,
        [0x24] = 0xef, [0x25] = 0xcd, [0x26] = 0xab, [0x27] = 0x89,
    };
    uint8_t stored[12] = { 0 };
    uint32_t regs[23] = { 0 };
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup_model(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32,
                          (const char *)code, sizeof(code),
                          UC_CPU_RISCV32_BASE32);
    OK(uc_mem_map(uc, riscv_data_start, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, riscv_data_start, data, sizeof(data)));

    regs[6] = (uint32_t)riscv_data_start;
    regs[7] = (uint32_t)(riscv_data_start + 0x04);
    regs[11] = (uint32_t)(riscv_data_start + 0x08);
    regs[13] = 0xaabbccdd;
    regs[14] = (uint32_t)(riscv_data_start + 0x10);
    regs[15] = 0x11223344;
    regs[16] = (uint32_t)(riscv_data_start + 0x14);
    regs[17] = 0x55667788;
    regs[18] = (uint32_t)(riscv_data_start + 0x18);
    regs[19] = (uint32_t)(riscv_data_start + 0x20);
    regs[21] = (uint32_t)(riscv_data_start + 0x24);

    for (i = 0; i < sizeof(regs) / sizeof(regs[0]); i++) {
        if (regs[i] != 0) {
            OK(uc_reg_write(uc, UC_RISCV_REG_X0 + (int)i, &regs[i]));
        }
    }

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_X5, &regs[5]));
    OK(uc_reg_read(uc, UC_RISCV_REG_X8, &regs[8]));
    OK(uc_reg_read(uc, UC_RISCV_REG_X9, &regs[9]));
    OK(uc_reg_read(uc, UC_RISCV_REG_X10, &regs[10]));
    OK(uc_reg_read(uc, UC_RISCV_REG_X12, &regs[12]));
    OK(uc_reg_read(uc, UC_RISCV_REG_X20, &regs[20]));
    OK(uc_reg_read(uc, UC_RISCV_REG_X22, &regs[22]));
    OK(uc_mem_read(uc, riscv_data_start + 0x10, stored, sizeof(stored)));

    TEST_CHECK(regs[5] == 0xffffff80u);
    TEST_CHECK(regs[8] == 0x80);
    TEST_CHECK(regs[9] == 0xffffff80u);
    TEST_CHECK(regs[10] == 0xff80);
    TEST_CHECK(regs[12] == 0x80345678u);
    TEST_CHECK(regs[20] == 0xabcd);
    TEST_CHECK(regs[22] == 0x89abcdefu);
    TEST_CHECK(stored[0] == 0xdd);
    TEST_CHECK(stored[4] == 0x44);
    TEST_CHECK(stored[5] == 0x33);
    TEST_CHECK(stored[8] == 0x88);
    TEST_CHECK(stored[9] == 0x77);
    TEST_CHECK(stored[10] == 0x66);
    TEST_CHECK(stored[11] == 0x55);

    OK(uc_close(uc));
}

static void test_riscv64_rvh_hlv_hsv(void)
{
    uc_engine *uc;
    uint32_t insns[] = {
        riscv_encode_rvh_load(0x30, 0, 6, 5),
        riscv_encode_rvh_load(0x34, 1, 7, 8),
        riscv_encode_rvh_load(0x36, 0, 9, 10),
        riscv_encode_rvh_store(0x37, 11, 12),
        riscv_encode_rvh_load(0x34, 3, 13, 14),
    };
    uint8_t code[sizeof(insns)];
    uint8_t data[0x40] = {
        [0x00] = 0x80,
        [0x08] = 0xef, [0x09] = 0xcd, [0x0a] = 0xab, [0x0b] = 0x89,
        [0x10] = 0x08, [0x11] = 0x07, [0x12] = 0x06, [0x13] = 0x05,
        [0x14] = 0x04, [0x15] = 0x03, [0x16] = 0x02, [0x17] = 0x01,
        [0x28] = 0xef, [0x29] = 0xcd, [0x2a] = 0xab, [0x2b] = 0x89,
    };
    uint8_t stored[8] = { 0 };
    uint64_t regs[15] = { 0 };
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup_model(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                          (const char *)code, sizeof(code),
                          UC_CPU_RISCV64_BASE64);
    OK(uc_mem_map(uc, riscv_data_start, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, riscv_data_start, data, sizeof(data)));

    regs[6] = riscv_data_start;
    regs[7] = riscv_data_start + 0x08;
    regs[9] = riscv_data_start + 0x10;
    regs[11] = 0x8877665544332211ull;
    regs[12] = riscv_data_start + 0x20;
    regs[13] = riscv_data_start + 0x28;

    for (i = 0; i < sizeof(regs) / sizeof(regs[0]); i++) {
        if (regs[i] != 0) {
            OK(uc_reg_write(uc, UC_RISCV_REG_X0 + (int)i, &regs[i]));
        }
    }

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_X5, &regs[5]));
    OK(uc_reg_read(uc, UC_RISCV_REG_X8, &regs[8]));
    OK(uc_reg_read(uc, UC_RISCV_REG_X10, &regs[10]));
    OK(uc_reg_read(uc, UC_RISCV_REG_X14, &regs[14]));
    OK(uc_mem_read(uc, riscv_data_start + 0x20, stored, sizeof(stored)));

    TEST_CHECK(regs[5] == 0xffffffffffffff80ull);
    TEST_CHECK(regs[8] == 0x89abcdefull);
    TEST_CHECK(regs[10] == 0x0102030405060708ull);
    TEST_CHECK(regs[14] == 0x89abcdefull);
    TEST_CHECK(stored[0] == 0x11);
    TEST_CHECK(stored[1] == 0x22);
    TEST_CHECK(stored[2] == 0x33);
    TEST_CHECK(stored[3] == 0x44);
    TEST_CHECK(stored[4] == 0x55);
    TEST_CHECK(stored[5] == 0x66);
    TEST_CHECK(stored[6] == 0x77);
    TEST_CHECK(stored[7] == 0x88);

    OK(uc_close(uc));
}

static void test_riscv64_rvh_hlvx_vs_stage_xonly_mxr(void)
{
    uc_engine *uc;
    uint32_t insns[] = {
        riscv_encode_csr(RISCV_CSR_VSATP, 5, 1, 0),
        riscv_encode_csr(RISCV_CSR_HSTATUS, 6, 1, 0),
        riscv_encode_csr(RISCV_CSR_MSTATUS, 7, 1, 0),
        riscv_encode_rvh_load(0x34, 3, 13, 14),
    };
    uint8_t code[sizeof(insns)];
    uint8_t data[4] = { 0xef, 0xcd, 0xab, 0x89 };
    uint64_t pt_root = 0x20000;
    uint64_t pt_l1 = 0x21000;
    uint64_t pt_l0 = 0x22000;
    uint64_t va = riscv_data_start;
    uint64_t root_pte = LEINT64((pt_l1 >> 2) | RISCV_PTE_V);
    uint64_t l1_pte = LEINT64((pt_l0 >> 2) | RISCV_PTE_V);
    uint64_t leaf_pte = LEINT64((riscv_data_start >> 2) | RISCV_PTE_V |
                                RISCV_PTE_X | RISCV_PTE_A | RISCV_PTE_D);
    uint64_t vsatp = RISCV64_SATP_MODE_SV39 | (pt_root >> 12);
    uint64_t hstatus = RISCV_HSTATUS_SPVP;
    uint64_t mstatus = RISCV_MSTATUS_MXR;
    uint64_t value = 0;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup_model(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                          (const char *)code, sizeof(code),
                          UC_CPU_RISCV64_BASE64);
    OK(uc_mem_map(uc, riscv_data_start, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, pt_root, 0x3000, UC_PROT_ALL));
    OK(uc_mem_write(uc, riscv_data_start, data, sizeof(data)));
    OK(uc_mem_write(uc, pt_root, &root_pte, sizeof(root_pte)));
    OK(uc_mem_write(uc, pt_l1, &l1_pte, sizeof(l1_pte)));
    OK(uc_mem_write(uc, pt_l0 + 8 * 8, &leaf_pte, sizeof(leaf_pte)));
    OK(uc_reg_write(uc, UC_RISCV_REG_X5, &vsatp));
    OK(uc_reg_write(uc, UC_RISCV_REG_X6, &hstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_X7, &mstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_X13, &va));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_RISCV_REG_X14, &value));
    TEST_CHECK(value == 0x89abcdefull);

    OK(uc_close(uc));
}

static void test_riscv_rvh_requires_h(void)
{
    run_riscv_insn_illegal(UC_MODE_RISCV32,
                           riscv_encode_rvh_load(0x30, 0, 6, 5));
    run_riscv_insn_illegal(UC_MODE_RISCV64,
                           riscv_encode_rvh_load(0x30, 0, 6, 5));
}

static void test_riscv_rvh_requires_hlsx(void)
{
    uc_engine *uc;
    uint8_t code[4];
    uint64_t addr = riscv_data_start;
    uint64_t priv = 0;

    riscv_insn_to_code(code, riscv_encode_rvh_load(0x30, 0, 6, 5));
    uc_common_setup_model(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                          (const char *)code, sizeof(code),
                          UC_CPU_RISCV64_BASE64);
    OK(uc_mem_map(uc, riscv_data_start, 0x1000, UC_PROT_ALL));
    OK(uc_reg_write(uc, UC_RISCV_REG_X6, &addr));
    OK(uc_reg_write(uc, UC_RISCV_REG_PRIV, &priv));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_close(uc));
}

static void test_riscv_rvh_hstatus_layout(void)
{
    uc_engine *uc;
    uint32_t code = riscv_encode_addi(0, 0, 0);
    uint64_t hstatus = RISCV_HSTATUS_HU | RISCV_HSTATUS_SPVP |
                       RISCV_HSTATUS_VSBE;
    uint64_t actual = 0;

    uc_common_setup_model(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                          (const char *)&code, sizeof(code),
                          UC_CPU_RISCV64_BASE64);
    OK(uc_reg_write(uc, UC_RISCV_REG_HSTATUS, &hstatus));
    OK(uc_reg_read(uc, UC_RISCV_REG_HSTATUS, &actual));

    TEST_CHECK((actual & RISCV_HSTATUS_HU) != 0);
    TEST_CHECK((actual & RISCV_HSTATUS_SPVP) != 0);
    TEST_CHECK((actual & RISCV_HSTATUS_VSBE) == 0);
    TEST_CHECK((actual & RISCV_HSTATUS_VSXL) == RISCV_HSTATUS_VSXL_RV64);

    OK(uc_close(uc));
}

static void test_riscv_rvh_hedeleg_mask(void)
{
    uc_engine *uc;
    uint32_t code = riscv_encode_addi(0, 0, 0);
    uint64_t hedeleg = UINT64_MAX;
    uint64_t actual = 0;

    uc_common_setup_model(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                          (const char *)&code, sizeof(code),
                          UC_CPU_RISCV64_BASE64);
    OK(uc_reg_write(uc, UC_RISCV_REG_HEDELEG, &hedeleg));
    OK(uc_reg_read(uc, UC_RISCV_REG_HEDELEG, &actual));

    TEST_CHECK((actual & (1ull << RISCV_EXCP_ILLEGAL_INST)) != 0);
    TEST_CHECK((actual & (1ull << RISCV_EXCP_S_ECALL)) == 0);
    TEST_CHECK((actual & (1ull << RISCV_EXCP_VS_ECALL)) == 0);
    TEST_CHECK((actual & (1ull << RISCV_EXCP_M_ECALL)) == 0);
    TEST_CHECK((actual & (1ull << RISCV_EXCP_INST_GUEST_PAGE_FAULT)) == 0);
    TEST_CHECK((actual & (1ull << RISCV_EXCP_LOAD_GUEST_ACCESS_FAULT)) == 0);
    TEST_CHECK((actual & (1ull << RISCV_EXCP_VIRT_INSTRUCTION_FAULT)) == 0);
    TEST_CHECK((actual &
                (1ull << RISCV_EXCP_STORE_GUEST_AMO_ACCESS_FAULT)) == 0);

    OK(uc_close(uc));
}

static void test_riscv_rvh_hu_allows_u_mode(void)
{
    uc_engine *uc;
    uint8_t code[4];
    uint8_t data = 0x7f;
    uint64_t addr = riscv_data_start;
    uint64_t hstatus = RISCV_HSTATUS_HU;
    uint64_t priv = 0;
    uint64_t value = 0;

    riscv_insn_to_code(code, riscv_encode_rvh_load(0x30, 0, 6, 5));
    uc_common_setup_model(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                          (const char *)code, sizeof(code),
                          UC_CPU_RISCV64_BASE64);
    OK(uc_mem_map(uc, riscv_data_start, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, riscv_data_start, &data, sizeof(data)));
    OK(uc_reg_write(uc, UC_RISCV_REG_X6, &addr));
    OK(uc_reg_write(uc, UC_RISCV_REG_HSTATUS, &hstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_PRIV, &priv));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_RISCV_REG_X5, &value));
    TEST_CHECK(value == data);

    OK(uc_close(uc));
}

static void test_riscv_rvh_hu_tb_flags(void)
{
    uc_engine *uc;
    uint8_t code[4];
    uint8_t data = 0x7f;
    uint64_t addr = riscv_data_start;
    uint64_t hstatus = RISCV_HSTATUS_HU;
    uint64_t priv = 0;
    uint64_t value = 0;

    riscv_insn_to_code(code, riscv_encode_rvh_load(0x30, 0, 6, 5));
    uc_common_setup_model(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                          (const char *)code, sizeof(code),
                          UC_CPU_RISCV64_BASE64);
    OK(uc_mem_map(uc, riscv_data_start, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, riscv_data_start, &data, sizeof(data)));
    OK(uc_reg_write(uc, UC_RISCV_REG_X6, &addr));
    OK(uc_reg_write(uc, UC_RISCV_REG_HSTATUS, &hstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_PRIV, &priv));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    hstatus = 0;
    value = 0;
    priv = 3;
    OK(uc_reg_write(uc, UC_RISCV_REG_PRIV, &priv));
    OK(uc_reg_write(uc, UC_RISCV_REG_HSTATUS, &hstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_X5, &value));
    priv = 0;
    OK(uc_reg_write(uc, UC_RISCV_REG_PRIV, &priv));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));

    OK(uc_close(uc));
}

typedef struct {
    uint32_t count;
    uint32_t intno;
} RiscvIntrCapture;

static void test_riscv_intr_capture_cb(uc_engine *uc, uint32_t intno,
                                       void *data)
{
    RiscvIntrCapture *capture = (RiscvIntrCapture *)data;

    capture->count++;
    capture->intno = intno;
    uc_emu_stop(uc);
}

static uint64_t riscv_pmp_napot_addr(uint64_t base, uint64_t size)
{
    return (base >> 2) | (((size / 2) - 1) >> 2);
}

static void run_riscv64_pmp_na4_data_access(uint32_t access_insn,
                                            uint64_t access_addr,
                                            RiscvIntrCapture *capture,
                                            uint64_t *result)
{
    uc_engine *uc;
    uc_hook hook;
    uint32_t insns[] = {
        riscv_encode_csr(RISCV_CSR_PMPADDR0, 5, 1, 0),
        riscv_encode_csr(RISCV_CSR_PMPADDR0 + 1, 6, 1, 0),
        riscv_encode_csr(RISCV_CSR_PMPCFG0, 7, 1, 0),
        access_insn,
    };
    uint8_t code[sizeof(insns)];
    uint32_t data = 0x12345678;
    uint64_t code_pmpaddr = riscv_pmp_napot_addr(code_start, 0x1000);
    uint64_t data_pmpaddr = riscv_data_start >> 2;
    uint64_t pmpcfg = ((RISCV_PMPCFG_R | RISCV_PMPCFG_A_NA4) << 8) |
                      (RISCV_PMPCFG_X | RISCV_PMPCFG_A_NAPOT);
    uint64_t priv = 0;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup_model(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                          (const char *)code, sizeof(code),
                          UC_CPU_RISCV64_SIFIVE_U54);
    OK(uc_mem_map(uc, riscv_data_start, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, riscv_data_start, &data, sizeof(data)));
    OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_riscv_intr_capture_cb,
                   capture, 1, 0));
    OK(uc_reg_write(uc, UC_RISCV_REG_X5, &code_pmpaddr));
    OK(uc_reg_write(uc, UC_RISCV_REG_X6, &data_pmpaddr));
    OK(uc_reg_write(uc, UC_RISCV_REG_X7, &pmpcfg));
    OK(uc_reg_write(uc, UC_RISCV_REG_X8, &access_addr));

    OK(uc_emu_start(uc, code_start, code_start + 3 * 4, 0, 0));
    OK(uc_reg_write(uc, UC_RISCV_REG_PRIV, &priv));
    OK(uc_emu_start(uc, code_start + 3 * 4, code_start + sizeof(code), 0, 0));
    if (result != NULL) {
        OK(uc_reg_read(uc, UC_RISCV_REG_X9, result));
    }

    OK(uc_close(uc));
}

static void test_riscv64_pmp_na4_load(void)
{
    RiscvIntrCapture capture = { 0 };
    uint32_t load = riscv_encode_i(0, 8, 2, 9, 0x03);
    uint64_t value = 0;

    run_riscv64_pmp_na4_data_access(load, riscv_data_start, &capture,
                                    &value);
    TEST_CHECK(capture.count == 0);
    TEST_CHECK(value == 0x12345678);
}

static void test_riscv64_pmp_na4_rejects_outside(void)
{
    RiscvIntrCapture capture = { 0 };
    uint32_t load = riscv_encode_i(0, 8, 2, 9, 0x03);

    run_riscv64_pmp_na4_data_access(load, riscv_data_start + 4, &capture,
                                    NULL);
    TEST_CHECK(capture.count == 1);
    TEST_CHECK(capture.intno == RISCV_EXCP_LOAD_ACCESS_FAULT);
}

static void test_riscv64_pmp_na4_rejects_store(void)
{
    RiscvIntrCapture capture = { 0 };
    uint32_t store = riscv_encode_s(0, 9, 8, 2, 0x23);

    run_riscv64_pmp_na4_data_access(store, riscv_data_start, &capture, NULL);
    TEST_CHECK(capture.count == 1);
    TEST_CHECK(capture.intno == RISCV_EXCP_STORE_AMO_ACCESS_FAULT);
}

static void run_riscv64_rvh_virtual_instruction(uint32_t insn)
{
    uc_engine *uc;
    uc_hook hook;
    RiscvIntrCapture capture = { 0 };
    uint8_t code[4];
    uint64_t priv = 5;

    riscv_insn_to_code(code, insn);
    uc_common_setup_model(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                          (const char *)code, sizeof(code),
                          UC_CPU_RISCV64_BASE64);
    OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_riscv_intr_capture_cb,
                   &capture, 1, 0));
    OK(uc_reg_write(uc, UC_RISCV_REG_PRIV, &priv));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    TEST_CHECK(capture.count == 1);
    TEST_CHECK(capture.intno == RISCV_EXCP_VIRT_INSTRUCTION_FAULT);

    OK(uc_close(uc));
}

static void test_riscv_rvh_virtual_instruction_fault(void)
{
    run_riscv64_rvh_virtual_instruction(riscv_encode_rvh_load(0x30, 0, 6, 5));
    run_riscv64_rvh_virtual_instruction(0x22000073);
    run_riscv64_rvh_virtual_instruction(0x62000073);
}

static void test_riscv64_rvh_indirect_g_stage_fault(void)
{
    uc_engine *uc;
    uc_hook hook;
    RiscvIntrCapture capture = { 0 };
    uint32_t insns[] = {
        riscv_encode_csr(RISCV_CSR_VSATP, 5, 1, 0),
        riscv_encode_csr(RISCV_CSR_HGATP, 6, 1, 0),
        riscv_encode_csr(RISCV_CSR_HSTATUS, 7, 1, 0),
        riscv_encode_rvh_load(0x34, 0, 13, 14),
    };
    uint8_t code[sizeof(insns)];
    uint64_t vs_pt_root = 0x20000;
    uint64_t g_pt_root = 0x30000;
    uint64_t invalid_pte = 0;
    uint64_t va = riscv_data_start;
    uint64_t vsatp = RISCV64_SATP_MODE_SV39 | (vs_pt_root >> 12);
    uint64_t hgatp = RISCV64_SATP_MODE_SV39 | (g_pt_root >> 12);
    uint64_t hstatus = RISCV_HSTATUS_SPVP;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup_model(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                          (const char *)code, sizeof(code),
                          UC_CPU_RISCV64_BASE64);
    OK(uc_mem_map(uc, g_pt_root, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, g_pt_root, &invalid_pte, sizeof(invalid_pte)));
    OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_riscv_intr_capture_cb,
                   &capture, 1, 0));
    OK(uc_reg_write(uc, UC_RISCV_REG_X5, &vsatp));
    OK(uc_reg_write(uc, UC_RISCV_REG_X6, &hgatp));
    OK(uc_reg_write(uc, UC_RISCV_REG_X7, &hstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_X13, &va));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    TEST_CHECK(capture.count == 1);
    TEST_CHECK(capture.intno == RISCV_EXCP_LOAD_GUEST_ACCESS_FAULT);

    OK(uc_close(uc));
}

static void test_riscv_virtual_wfi_fault(void)
{
    uc_engine *uc;
    uc_hook hook;
    RiscvIntrCapture capture = { 0 };
    uint32_t insn = 0x10500073;
    uint8_t code[4];
    uint64_t priv = 5;
    uint64_t hstatus = RISCV_HSTATUS_VTW;

    riscv_insn_to_code(code, insn);
    uc_common_setup_model(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                          (const char *)code, sizeof(code),
                          UC_CPU_RISCV64_BASE64);
    OK(uc_hook_add(uc, &hook, UC_HOOK_INTR, test_riscv_intr_capture_cb,
                   &capture, 1, 0));
    OK(uc_reg_write(uc, UC_RISCV_REG_HSTATUS, &hstatus));
    OK(uc_reg_write(uc, UC_RISCV_REG_PRIV, &priv));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    TEST_CHECK(capture.count == 1);
    TEST_CHECK(capture.intno == RISCV_EXCP_VIRT_INSTRUCTION_FAULT);

    OK(uc_close(uc));
}

static void test_riscv_rvh_hfence(void)
{
    uc_engine *uc;
    uint32_t insns[] = {
        0x22000073,
        0x62000073,
    };
    uint8_t code[sizeof(insns)];
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup_model(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                          (const char *)code, sizeof(code),
                          UC_CPU_RISCV64_BASE64);
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_close(uc));
}

static void test_riscv_rvh_hfence_requires_h(void)
{
    uint32_t insns[] = {
        0x22000073,
        0x62000073,
    };
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        run_riscv_model_insn_illegal(UC_MODE_RISCV32,
                                     UC_CPU_RISCV32_SIFIVE_E31, insns[i]);
        run_riscv_model_insn_illegal(UC_MODE_RISCV64,
                                     UC_CPU_RISCV64_SIFIVE_E51, insns[i]);
    }
}

static void test_riscv64_rv128_opcodes_rejected(void)
{
    uint32_t lq = riscv_encode_i(0, 6, 2, 5, 0x0f);
    uint32_t sq = riscv_encode_s(0, 5, 6, 4, 0x23);
    uint32_t addd = riscv_encode_r(0, 7, 6, 0, 5, 0x7b);
    uint32_t muld = riscv_encode_r(1, 7, 6, 0, 5, 0x7b);

    run_riscv_insn_illegal(UC_MODE_RISCV64, lq);
    run_riscv_insn_illegal(UC_MODE_RISCV64, sq);
    run_riscv_insn_illegal(UC_MODE_RISCV64, addd);
    run_riscv_insn_illegal(UC_MODE_RISCV64, muld);
}

static void test_riscv32_xventanacondops(void)
{
    uint32_t vt_maskc = riscv_encode_r(0x00, 7, 6, 6, 5, 0x7b);
    uint32_t vt_maskcn = riscv_encode_r(0x00, 7, 6, 7, 5, 0x7b);

    run_riscv32_zbb_case(vt_maskc, 0xa5a55a5a, 1, 5, 0xa5a55a5a);
    run_riscv32_zbb_case(vt_maskc, 0xa5a55a5a, 0, 5, 0);
    run_riscv32_zbb_case(vt_maskcn, 0x55aa1234, 0, 5, 0x55aa1234);
    run_riscv32_zbb_case(vt_maskcn, 0x55aa1234, 1, 5, 0);
}

static void test_riscv64_xventanacondops(void)
{
    uint32_t vt_maskc = riscv_encode_r(0x00, 7, 6, 6, 5, 0x7b);
    uint32_t vt_maskcn = riscv_encode_r(0x00, 7, 6, 7, 5, 0x7b);

    run_riscv64_zbb_case(vt_maskc, 0xfedcba9876543210ull, 1, 5,
                         0xfedcba9876543210ull);
    run_riscv64_zbb_case(vt_maskc, 0xfedcba9876543210ull, 0, 5, 0);
    run_riscv64_zbb_case(vt_maskcn, 0x0123456789abcdefull, 0, 5,
                         0x0123456789abcdefull);
    run_riscv64_zbb_case(vt_maskcn, 0x0123456789abcdefull, 1, 5, 0);
}

static void run_riscv32_seed_case(void)
{
    uc_engine *uc;
    uint8_t code[4];
    uint32_t source = 0;
    uint32_t actual = 0;

    riscv_insn_to_code(code, riscv_encode_i(0x015, 6, 1, 5, 0x73));
    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, (const char *)code,
                    sizeof(code));
    OK(uc_reg_write(uc, UC_RISCV_REG_X6, &source));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_X5, &actual));
    TEST_CHECK((actual & 0xc0000000u) == 0x80000000u);
    OK(uc_close(uc));
}

static void run_riscv64_seed_case(void)
{
    uc_engine *uc;
    uint8_t code[4];
    uint64_t source = 0;
    uint64_t actual = 0;

    riscv_insn_to_code(code, riscv_encode_i(0x015, 6, 1, 5, 0x73));
    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, (const char *)code,
                    sizeof(code));
    OK(uc_reg_write(uc, UC_RISCV_REG_X6, &source));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_X5, &actual));
    TEST_CHECK((actual & 0xc0000000ull) == 0x80000000ull);
    TEST_CHECK((actual >> 32) == 0);
    OK(uc_close(uc));
}

static uint64_t riscv_ref_clmul(uint64_t rs1, uint64_t rs2, int bits)
{
    uint64_t mask = bits == 64 ? ~0ull : 0xffffffffull;
    uint64_t result = 0;
    int i;

    rs1 &= mask;
    rs2 &= mask;

    for (i = 0; i < bits; i++) {
        if ((rs2 >> i) & 1) {
            result ^= rs1 << i;
        }
    }

    return result & mask;
}

static uint64_t riscv_ref_clmulr(uint64_t rs1, uint64_t rs2, int bits)
{
    uint64_t mask = bits == 64 ? ~0ull : 0xffffffffull;
    uint64_t result = 0;
    int i;

    rs1 &= mask;
    rs2 &= mask;

    for (i = 0; i < bits; i++) {
        if ((rs2 >> i) & 1) {
            result ^= rs1 >> (bits - i - 1);
        }
    }

    return result & mask;
}

static uint64_t riscv_ref_brev8(uint64_t value, int bits)
{
    uint64_t result = 0;
    int byte;
    int bit;

    for (byte = 0; byte < bits; byte += 8) {
        uint64_t src = (value >> byte) & 0xff;
        uint64_t dst = 0;

        for (bit = 0; bit < 8; bit++) {
            dst |= ((src >> bit) & 1) << (7 - bit);
        }
        result |= dst << byte;
    }

    return bits == 64 ? result : result & 0xffffffffull;
}

static uint64_t riscv_ref_pack(uint64_t rs1, uint64_t rs2, int bits)
{
    int half = bits / 2;
    uint64_t half_mask = (1ull << half) - 1;

    return (rs1 & half_mask) | ((rs2 & half_mask) << half);
}

static uint64_t riscv_ref_packh(uint64_t rs1, uint64_t rs2)
{
    return (rs1 & 0xff) | ((rs2 & 0xff) << 8);
}

static uint64_t riscv_ref_packw(uint64_t rs1, uint64_t rs2)
{
    uint32_t word = (rs1 & 0xffff) | ((rs2 & 0xffff) << 16);

    return (uint64_t)(int64_t)(int32_t)word;
}

static uint32_t riscv_ref_shuf_stage(uint32_t src, uint32_t mask_l,
                                     uint32_t mask_r, int shift)
{
    uint32_t x = src & ~(mask_l | mask_r);

    x |= ((src << shift) & mask_l) | ((src >> shift) & mask_r);
    return x;
}

static uint32_t riscv_ref_unzip(uint32_t value)
{
    value = riscv_ref_shuf_stage(value, 0x44444444u, 0x22222222u, 1);
    value = riscv_ref_shuf_stage(value, 0x30303030u, 0x0c0c0c0cu, 2);
    value = riscv_ref_shuf_stage(value, 0x0f000f00u, 0x00f000f0u, 4);
    value = riscv_ref_shuf_stage(value, 0x00ff0000u, 0x0000ff00u, 8);
    return value;
}

static uint32_t riscv_ref_zip(uint32_t value)
{
    value = riscv_ref_shuf_stage(value, 0x00ff0000u, 0x0000ff00u, 8);
    value = riscv_ref_shuf_stage(value, 0x0f000f00u, 0x00f000f0u, 4);
    value = riscv_ref_shuf_stage(value, 0x30303030u, 0x0c0c0c0cu, 2);
    value = riscv_ref_shuf_stage(value, 0x44444444u, 0x22222222u, 1);
    return value;
}

static uint64_t riscv_ref_xperm(uint64_t rs1, uint64_t rs2, int bits,
                                int sz_log2)
{
    uint64_t result = 0;
    uint64_t sz = 1ull << sz_log2;
    uint64_t mask = (1ull << sz) - 1;
    uint64_t pos;
    int i;

    for (i = 0; i < bits; i += sz) {
        pos = ((rs2 >> i) & mask) << sz_log2;
        if (pos < (uint64_t)bits) {
            result |= ((rs1 >> pos) & mask) << i;
        }
    }

    return bits == 64 ? result : result & 0xffffffffull;
}

static uint32_t riscv_rotl32(uint32_t value, unsigned int shift)
{
    return (value << shift) | (value >> (32 - shift));
}

static uint32_t riscv_rotr32(uint32_t value, unsigned int shift)
{
    return (value >> shift) | (value << (32 - shift));
}

static uint64_t riscv_rotl64(uint64_t value, unsigned int shift)
{
    return (value << shift) | (value >> (64 - shift));
}

static uint64_t riscv_rotr64(uint64_t value, unsigned int shift)
{
    return (value >> shift) | (value << (64 - shift));
}

static uint64_t riscv_sext32(uint32_t value)
{
    return (uint64_t)(int64_t)(int32_t)value;
}

static uint32_t riscv_ref_sha256(uint32_t value, int op)
{
    switch (op) {
    case 0:
        return riscv_rotr32(value, 2) ^ riscv_rotr32(value, 13) ^
               riscv_rotr32(value, 22);
    case 1:
        return riscv_rotr32(value, 6) ^ riscv_rotr32(value, 11) ^
               riscv_rotr32(value, 25);
    case 2:
        return riscv_rotr32(value, 7) ^ riscv_rotr32(value, 18) ^
               (value >> 3);
    default:
        return riscv_rotr32(value, 17) ^ riscv_rotr32(value, 19) ^
               (value >> 10);
    }
}

static uint64_t riscv_ref_sha512_rv32(uint32_t rs1, uint32_t rs2, int op)
{
    uint64_t value = ((uint64_t)rs2 << 32) | rs1;
    uint64_t result;

    switch (op) {
    case 0:
        result = riscv_rotl64(value, 25) ^ riscv_rotl64(value, 30) ^
                 riscv_rotr64(value, 28);
        break;
    case 1:
        result = riscv_rotl64(value, 23) ^ riscv_rotr64(value, 14) ^
                 riscv_rotr64(value, 18);
        break;
    case 2:
        result = riscv_rotr64(value, 1) ^ riscv_rotr64(value, 7) ^
                 riscv_rotr64(value, 8);
        break;
    case 3:
        result = riscv_rotr64(value, 1) ^ ((uint32_t)value >> 7) ^
                 riscv_rotr64(value, 8);
        break;
    case 4:
        result = riscv_rotl64(value, 3) ^ riscv_rotr64(value, 6) ^
                 riscv_rotr64(value, 19);
        break;
    default:
        result = riscv_rotl64(value, 3) ^ ((uint32_t)value >> 6) ^
                 riscv_rotr64(value, 19);
        break;
    }

    return result & 0xffffffffull;
}

static uint64_t riscv_ref_sha512_rv64(uint64_t value, int op)
{
    switch (op) {
    case 0:
        return riscv_rotr64(value, 28) ^ riscv_rotr64(value, 34) ^
               riscv_rotr64(value, 39);
    case 1:
        return riscv_rotr64(value, 14) ^ riscv_rotr64(value, 18) ^
               riscv_rotr64(value, 41);
    case 2:
        return riscv_rotr64(value, 1) ^ riscv_rotr64(value, 8) ^
               (value >> 7);
    default:
        return riscv_rotr64(value, 19) ^ riscv_rotr64(value, 61) ^
               (value >> 6);
    }
}

static uint32_t riscv_ref_sm3(uint32_t value, int op)
{
    if (op == 0) {
        return value ^ riscv_rotl32(value, 9) ^ riscv_rotl32(value, 17);
    }

    return value ^ riscv_rotl32(value, 15) ^ riscv_rotl32(value, 23);
}

static void test_riscv32_zba(void)
{
    run_riscv32_zbb_case(riscv_encode_r(0x10, 7, 6, 2, 5, 0x33),
                         3, 5, 5, 11);
    run_riscv32_zbb_case(riscv_encode_r(0x10, 7, 6, 4, 5, 0x33),
                         3, 5, 5, 17);
    run_riscv32_zbb_case(riscv_encode_r(0x10, 7, 6, 6, 5, 0x33),
                         3, 5, 5, 29);
    run_riscv_insn_illegal(UC_MODE_RISCV32,
                           riscv_encode_r(0x04, 7, 6, 0, 5, 0x3b));
    run_riscv_insn_illegal(UC_MODE_RISCV32,
                           riscv_encode_i(0x081, 6, 1, 5, 0x1b));
}

static void test_riscv64_zba(void)
{
    run_riscv64_zbb_case(riscv_encode_r(0x10, 7, 6, 2, 5, 0x33),
                         3, 5, 5, 11);
    run_riscv64_zbb_case(riscv_encode_r(0x10, 7, 6, 4, 5, 0x33),
                         3, 5, 5, 17);
    run_riscv64_zbb_case(riscv_encode_r(0x10, 7, 6, 6, 5, 0x33),
                         3, 5, 5, 29);
    run_riscv64_zbb_case(riscv_encode_r(0x04, 7, 6, 0, 5, 0x3b),
                         0xffffffff00000002ull, 5, 5, 7);
    run_riscv64_zbb_case(riscv_encode_r(0x10, 7, 6, 2, 5, 0x3b),
                         0xffffffff00000002ull, 5, 5, 9);
    run_riscv64_zbb_case(riscv_encode_r(0x10, 7, 6, 4, 5, 0x3b),
                         0xffffffff00000002ull, 5, 5, 13);
    run_riscv64_zbb_case(riscv_encode_r(0x10, 7, 6, 6, 5, 0x3b),
                         0xffffffff00000002ull, 5, 5, 21);
    run_riscv64_zbb_case(riscv_encode_i(0x081, 6, 1, 5, 0x1b),
                         0xffffffff80000001ull, 0, 5, 0x100000002ull);
    run_riscv64_zbb_case(riscv_encode_i(0x09f, 6, 1, 5, 0x1b),
                         0xffffffff80000001ull, 0, 5,
                         0x4000000080000000ull);
    run_riscv64_zbb_case(riscv_encode_i(0x0a0, 6, 1, 5, 0x1b),
                         0xffffffff80000001ull, 0, 5,
                         0x8000000100000000ull);
    run_riscv64_zbb_case(riscv_encode_i(0x0bf, 6, 1, 5, 0x1b),
                         1, 0, 5, 0x8000000000000000ull);
    run_riscv_insn_illegal(UC_MODE_RISCV64,
                           riscv_encode_i(0x0c0, 6, 1, 5, 0x1b));
}

static void test_riscv32_zbc(void)
{
    uint32_t rs1 = 0x12345678u;
    uint32_t rs2 = 0x00f0f00fu;

    run_riscv32_zbb_case(riscv_encode_r(0x05, 7, 6, 1, 5, 0x33),
                         rs1, rs2, 5,
                         riscv_ref_clmul(rs1, rs2, 32));
    run_riscv32_zbb_case(riscv_encode_r(0x05, 7, 6, 2, 5, 0x33),
                         rs1, rs2, 5,
                         riscv_ref_clmulr(rs1, rs2, 32));
    run_riscv32_zbb_case(riscv_encode_r(0x05, 7, 6, 3, 5, 0x33),
                         rs1, rs2, 5,
                         riscv_ref_clmulr(rs1, rs2, 32) >> 1);
}

static void test_riscv64_zbc(void)
{
    uint64_t rs1 = 0x0123456789abcdefull;
    uint64_t rs2 = 0xf0f00f0f33333333ull;

    run_riscv64_zbb_case(riscv_encode_r(0x05, 7, 6, 1, 5, 0x33),
                         rs1, rs2, 5,
                         riscv_ref_clmul(rs1, rs2, 64));
    run_riscv64_zbb_case(riscv_encode_r(0x05, 7, 6, 2, 5, 0x33),
                         rs1, rs2, 5,
                         riscv_ref_clmulr(rs1, rs2, 64));
    run_riscv64_zbb_case(riscv_encode_r(0x05, 7, 6, 3, 5, 0x33),
                         rs1, rs2, 5,
                         riscv_ref_clmulr(rs1, rs2, 64) >> 1);
}

static void test_riscv32_zbkb(void)
{
    uint32_t rs1 = 0x12345678u;
    uint32_t rs2 = 0x89abcdefu;
    uint32_t value = 0x01234567u;

    run_riscv32_zbb_case(riscv_encode_i(0x687, 6, 5, 5, 0x13),
                         value, 0, 5, riscv_ref_brev8(value, 32));
    run_riscv32_zbb_case(riscv_encode_r(0x04, 7, 6, 4, 5, 0x33),
                         rs1, rs2, 5, riscv_ref_pack(rs1, rs2, 32));
    run_riscv32_zbb_case(riscv_encode_r(0x04, 7, 6, 7, 5, 0x33),
                         rs1, rs2, 5, riscv_ref_packh(rs1, rs2));
    run_riscv32_zbb_case(riscv_encode_i(0x08f, 6, 1, 5, 0x13),
                         value, 0, 5, riscv_ref_zip(value));
    run_riscv32_zbb_case(riscv_encode_i(0x08f, 6, 5, 5, 0x13),
                         value, 0, 5, riscv_ref_unzip(value));
}

static void test_riscv64_zbkb(void)
{
    uint64_t rs1 = 0x123456789abcdef0ull;
    uint64_t rs2 = 0x0fedcba987658321ull;
    uint64_t value = 0x0123456789abcdefull;

    run_riscv64_zbb_case(riscv_encode_i(0x687, 6, 5, 5, 0x13),
                         value, 0, 5, riscv_ref_brev8(value, 64));
    run_riscv64_zbb_case(riscv_encode_r(0x04, 7, 6, 4, 5, 0x33),
                         rs1, rs2, 5, riscv_ref_pack(rs1, rs2, 64));
    run_riscv64_zbb_case(riscv_encode_r(0x04, 7, 6, 7, 5, 0x33),
                         rs1, rs2, 5, riscv_ref_packh(rs1, rs2));
    run_riscv64_zbb_case(riscv_encode_r(0x04, 7, 6, 4, 5, 0x3b),
                         rs1, rs2, 5, riscv_ref_packw(rs1, rs2));
    run_riscv_insn_illegal(UC_MODE_RISCV64,
                           riscv_encode_i(0x08f, 6, 1, 5, 0x13));
    run_riscv_insn_illegal(UC_MODE_RISCV64,
                           riscv_encode_i(0x08f, 6, 5, 5, 0x13));
}

static void test_riscv32_zbkx(void)
{
    uint32_t rs1 = 0xfedcba98u;
    uint32_t rs2 = 0x01234567u;

    run_riscv32_zbb_case(riscv_encode_r(0x14, 7, 6, 2, 5, 0x33),
                         rs1, rs2, 5, riscv_ref_xperm(rs1, rs2, 32, 2));
    run_riscv32_zbb_case(riscv_encode_r(0x14, 7, 6, 4, 5, 0x33),
                         rs1, rs2, 5, riscv_ref_xperm(rs1, rs2, 32, 3));
}

static void test_riscv64_zbkx(void)
{
    uint64_t rs1 = 0xfedcba9876543210ull;
    uint64_t rs2 = 0x0123456789abcdefull;

    run_riscv64_zbb_case(riscv_encode_r(0x14, 7, 6, 2, 5, 0x33),
                         rs1, rs2, 5, riscv_ref_xperm(rs1, rs2, 64, 2));
    run_riscv64_zbb_case(riscv_encode_r(0x14, 7, 6, 4, 5, 0x33),
                         rs1, rs2, 5, riscv_ref_xperm(rs1, rs2, 64, 3));
}

static void test_riscv32_zknh_sha256(void)
{
    uint32_t value = 0x89abcdefu;

    run_riscv32_zbb_case(riscv_encode_i(0x100, 6, 1, 5, 0x13),
                         value, 0, 5, riscv_ref_sha256(value, 0));
    run_riscv32_zbb_case(riscv_encode_i(0x101, 6, 1, 5, 0x13),
                         value, 0, 5, riscv_ref_sha256(value, 1));
    run_riscv32_zbb_case(riscv_encode_i(0x102, 6, 1, 5, 0x13),
                         value, 0, 5, riscv_ref_sha256(value, 2));
    run_riscv32_zbb_case(riscv_encode_i(0x103, 6, 1, 5, 0x13),
                         value, 0, 5, riscv_ref_sha256(value, 3));
}

static void test_riscv64_zknh_sha256(void)
{
    uint32_t value = 0x89abcdefu;
    uint64_t reg_value = 0xffffffff89abcdefull;

    run_riscv64_zbb_case(riscv_encode_i(0x100, 6, 1, 5, 0x13),
                         reg_value, 0, 5,
                         riscv_sext32(riscv_ref_sha256(value, 0)));
    run_riscv64_zbb_case(riscv_encode_i(0x101, 6, 1, 5, 0x13),
                         reg_value, 0, 5,
                         riscv_sext32(riscv_ref_sha256(value, 1)));
    run_riscv64_zbb_case(riscv_encode_i(0x102, 6, 1, 5, 0x13),
                         reg_value, 0, 5,
                         riscv_sext32(riscv_ref_sha256(value, 2)));
    run_riscv64_zbb_case(riscv_encode_i(0x103, 6, 1, 5, 0x13),
                         reg_value, 0, 5,
                         riscv_sext32(riscv_ref_sha256(value, 3)));
}

static void test_riscv32_zknh_sha512(void)
{
    uint32_t rs1 = 0x89abcdefu;
    uint32_t rs2 = 0x01234567u;

    run_riscv32_zbb_case(riscv_encode_r(0x28, 7, 6, 0, 5, 0x33),
                         rs1, rs2, 5, riscv_ref_sha512_rv32(rs1, rs2, 0));
    run_riscv32_zbb_case(riscv_encode_r(0x29, 7, 6, 0, 5, 0x33),
                         rs1, rs2, 5, riscv_ref_sha512_rv32(rs1, rs2, 1));
    run_riscv32_zbb_case(riscv_encode_r(0x2a, 7, 6, 0, 5, 0x33),
                         rs1, rs2, 5, riscv_ref_sha512_rv32(rs1, rs2, 2));
    run_riscv32_zbb_case(riscv_encode_r(0x2e, 7, 6, 0, 5, 0x33),
                         rs1, rs2, 5, riscv_ref_sha512_rv32(rs1, rs2, 3));
    run_riscv32_zbb_case(riscv_encode_r(0x2b, 7, 6, 0, 5, 0x33),
                         rs1, rs2, 5, riscv_ref_sha512_rv32(rs1, rs2, 4));
    run_riscv32_zbb_case(riscv_encode_r(0x2f, 7, 6, 0, 5, 0x33),
                         rs1, rs2, 5, riscv_ref_sha512_rv32(rs1, rs2, 5));
}

static void test_riscv64_zknh_sha512(void)
{
    uint64_t value = 0x0123456789abcdefull;

    run_riscv64_zbb_case(riscv_encode_i(0x104, 6, 1, 5, 0x13),
                         value, 0, 5, riscv_ref_sha512_rv64(value, 0));
    run_riscv64_zbb_case(riscv_encode_i(0x105, 6, 1, 5, 0x13),
                         value, 0, 5, riscv_ref_sha512_rv64(value, 1));
    run_riscv64_zbb_case(riscv_encode_i(0x106, 6, 1, 5, 0x13),
                         value, 0, 5, riscv_ref_sha512_rv64(value, 2));
    run_riscv64_zbb_case(riscv_encode_i(0x107, 6, 1, 5, 0x13),
                         value, 0, 5, riscv_ref_sha512_rv64(value, 3));
}

static void test_riscv_zksh_sm3(void)
{
    uint32_t value = 0x89abcdefu;
    uint64_t reg_value = 0xffffffff89abcdefull;

    run_riscv32_zbb_case(riscv_encode_i(0x108, 6, 1, 5, 0x13),
                         value, 0, 5, riscv_ref_sm3(value, 0));
    run_riscv32_zbb_case(riscv_encode_i(0x109, 6, 1, 5, 0x13),
                         value, 0, 5, riscv_ref_sm3(value, 1));
    run_riscv64_zbb_case(riscv_encode_i(0x108, 6, 1, 5, 0x13),
                         reg_value, 0, 5,
                         riscv_sext32(riscv_ref_sm3(value, 0)));
    run_riscv64_zbb_case(riscv_encode_i(0x109, 6, 1, 5, 0x13),
                         reg_value, 0, 5,
                         riscv_sext32(riscv_ref_sm3(value, 1)));
}

static void test_riscv32_zkne_aes(void)
{
    uint32_t rs1 = 0x11223344u;
    uint32_t rs2 = 0x89abcdefu;

    run_riscv32_zbb_case(riscv_encode_k_aes(0x11, 0, 7, 6, 5),
                         rs1, rs2, 5, 0x1122339bu);
    run_riscv32_zbb_case(riscv_encode_k_aes(0x13, 16, 7, 6, 5),
                         rs1, rs2, 5, 0x73e69526u);
    run_riscv_insn_illegal(UC_MODE_RISCV64,
                           riscv_encode_k_aes(0x11, 0, 7, 6, 5));
}

static void test_riscv32_zknd_aes(void)
{
    uint32_t rs1 = 0x11223344u;
    uint32_t rs2 = 0x89abcdefu;

    run_riscv32_zbb_case(riscv_encode_k_aes(0x15, 8, 7, 6, 5),
                         rs1, rs2, 5, 0x1122b344u);
    run_riscv32_zbb_case(riscv_encode_k_aes(0x17, 24, 7, 6, 5),
                         rs1, rs2, 5, 0xdafef567u);
    run_riscv_insn_illegal(UC_MODE_RISCV32,
                           riscv_encode_r(0x19, 7, 6, 0, 5, 0x33));
}

static void test_riscv64_zkne_zknd_aes(void)
{
    uint64_t rs1 = 0x0011223344556677ull;
    uint64_t rs2 = 0x8899aabbccddeeffull;

    run_riscv64_zbb_case(riscv_encode_r(0x19, 7, 6, 0, 5, 0x33),
                         rs1, rs2, 5, 0x1bee28c3c4c193f5ull);
    run_riscv64_zbb_case(riscv_encode_r(0x1b, 7, 6, 0, 5, 0x33),
                         rs1, rs2, 5, 0xae01a110c5a8545aull);
    run_riscv64_zbb_case(riscv_encode_r(0x1d, 7, 6, 0, 5, 0x33),
                         rs1, rs2, 5, 0x27f9d36652c96202ull);
    run_riscv64_zbb_case(riscv_encode_r(0x1f, 7, 6, 0, 5, 0x33),
                         rs1, rs2, 5, 0x460a644350878da1ull);
    run_riscv64_zbb_case(riscv_encode_r(0x3f, 7, 6, 0, 5, 0x33),
                         rs1, rs2, 5, 0x44556677ccccccccull);
    run_riscv64_zbb_case(riscv_encode_i(0x310, 6, 1, 5, 0x13),
                         rs1, 0, 5, 0xc3638292c3638292ull);
    run_riscv64_zbb_case(riscv_encode_i(0x31a, 6, 1, 5, 0x13),
                         rs1, 0, 5, 0x638293c3638293c3ull);
    run_riscv64_zbb_case(riscv_encode_i(0x300, 6, 1, 5, 0x13),
                         rs1, 0, 5, 0xeebbcc99aaff88ddull);
    run_riscv_insn_illegal(UC_MODE_RISCV64,
                           riscv_encode_i(0x31b, 6, 1, 5, 0x13));
    run_riscv_insn_illegal(UC_MODE_RISCV32,
                           riscv_encode_i(0x300, 6, 1, 5, 0x13));
}

static void test_riscv_zksed_sm4(void)
{
    uint32_t rs1 = 0x11223344u;
    uint32_t rs2 = 0x89abcdefu;
    uint64_t rs1_64 = 0xffffffff11223344ull;
    uint64_t rs2_64 = 0xffffffff89abcdefull;

    run_riscv32_zbb_case(riscv_encode_k_aes(0x18, 0, 7, 6, 5),
                         rs1, rs2, 5, 0x0330b5d0u);
    run_riscv32_zbb_case(riscv_encode_k_aes(0x1a, 24, 7, 6, 5),
                         rs1, rs2, 5, 0xe6c2ad3fu);
    run_riscv64_zbb_case(riscv_encode_k_aes(0x18, 0, 7, 6, 5),
                         rs1_64, rs2_64, 5, 0x000000000330b5d0ull);
    run_riscv64_zbb_case(riscv_encode_k_aes(0x1a, 24, 7, 6, 5),
                         rs1_64, rs2_64, 5, 0xffffffffe6c2ad3full);
}

static void test_riscv_zkr_seed(void)
{
    run_riscv32_seed_case();
    run_riscv64_seed_case();
    run_riscv_insn_illegal(UC_MODE_RISCV32,
                           riscv_encode_i(0x015, 0, 2, 5, 0x73));
    run_riscv_insn_illegal(UC_MODE_RISCV64,
                           riscv_encode_i(0x015, 0, 2, 5, 0x73));
    run_riscv_insn_illegal(UC_MODE_RISCV64,
                           riscv_encode_i(0x015, 0, 7, 5, 0x73));
}

static void test_riscv32_zbb_unary(void)
{
    run_riscv32_zbb_case(riscv_encode_i(0x600, 6, 1, 5, 0x13),
                         0, 0, 5, 32);
    run_riscv32_zbb_case(riscv_encode_i(0x601, 6, 1, 5, 0x13),
                         0, 0, 5, 32);
    run_riscv32_zbb_case(riscv_encode_i(0x602, 6, 1, 5, 0x13),
                         0xffffffffu, 0, 5, 32);
    run_riscv32_zbb_case(riscv_encode_i(0x604, 6, 1, 5, 0x13),
                         0x80, 0, 5, 0xffffff80u);
    run_riscv32_zbb_case(riscv_encode_i(0x605, 6, 1, 5, 0x13),
                         0x8001, 0, 5, 0xffff8001u);
    run_riscv32_zbb_case(riscv_encode_r(0x04, 0, 6, 4, 5, 0x33),
                         0xffff8001u, 0, 5, 0x8001);
    run_riscv32_zbb_case(riscv_encode_i(0x287, 6, 5, 5, 0x13),
                         0x01008000, 0, 5, 0xff00ff00u);
    run_riscv32_zbb_case(riscv_encode_i(0x698, 6, 5, 5, 0x13),
                         0x11223344, 0, 5, 0x44332211);
}

static void test_riscv64_zbb_unary(void)
{
    run_riscv64_zbb_case(riscv_encode_i(0x600, 6, 1, 5, 0x13),
                         0, 0, 5, 64);
    run_riscv64_zbb_case(riscv_encode_i(0x601, 6, 1, 5, 0x13),
                         0, 0, 5, 64);
    run_riscv64_zbb_case(riscv_encode_i(0x602, 6, 1, 5, 0x13),
                         0xffffffffffffffffull, 0, 5, 64);
    run_riscv64_zbb_case(riscv_encode_i(0x604, 6, 1, 5, 0x13),
                         0x80, 0, 5, 0xffffffffffffff80ull);
    run_riscv64_zbb_case(riscv_encode_i(0x605, 6, 1, 5, 0x13),
                         0x8001, 0, 5, 0xffffffffffff8001ull);
    run_riscv64_zbb_case(riscv_encode_r(0x04, 0, 6, 4, 5, 0x3b),
                         0xffffffffffff8001ull, 0, 5, 0x8001);
    run_riscv64_zbb_case(riscv_encode_i(0x287, 6, 5, 5, 0x13),
                         0x0100800000000001ull, 0, 5,
                         0xff00ff00000000ffull);
    run_riscv64_zbb_case(riscv_encode_i(0x6b8, 6, 5, 5, 0x13),
                         0x1122334455667788ull, 0, 5,
                         0x8877665544332211ull);
}

static void test_riscv32_zbb_binary(void)
{
    run_riscv32_zbb_case(riscv_encode_r(0x20, 7, 6, 7, 5, 0x33),
                         0xff00ff00u, 0x0f0f0f0fu, 5, 0xf000f000u);
    run_riscv32_zbb_case(riscv_encode_r(0x20, 7, 6, 6, 5, 0x33),
                         0x0000ff00u, 0x00ff00ffu, 5, 0xff00ff00u);
    run_riscv32_zbb_case(riscv_encode_r(0x20, 7, 6, 4, 5, 0x33),
                         0xaaaaaaaau, 0xffff0000u, 5, 0xaaaa5555u);
    run_riscv32_zbb_case(riscv_encode_r(0x05, 7, 6, 4, 5, 0x33),
                         0x80000000u, 0x7fffffffu, 5, 0x80000000u);
    run_riscv32_zbb_case(riscv_encode_r(0x05, 7, 6, 6, 5, 0x33),
                         0x80000000u, 0x7fffffffu, 5, 0x7fffffffu);
    run_riscv32_zbb_case(riscv_encode_r(0x05, 7, 6, 5, 5, 0x33),
                         0x80000000u, 0x7fffffffu, 5, 0x7fffffffu);
    run_riscv32_zbb_case(riscv_encode_r(0x05, 7, 6, 7, 5, 0x33),
                         0x80000000u, 0x7fffffffu, 5, 0x80000000u);
}

static void test_riscv64_zbb_binary(void)
{
    run_riscv64_zbb_case(riscv_encode_r(0x20, 7, 6, 7, 5, 0x33),
                         0xff00ff00ff00ff00ull, 0x0f0f0f0f0f0f0f0full,
                         5, 0xf000f000f000f000ull);
    run_riscv64_zbb_case(riscv_encode_r(0x20, 7, 6, 6, 5, 0x33),
                         0x000000000000ff00ull, 0x00ff00ff00ff00ffull,
                         5, 0xff00ff00ff00ff00ull);
    run_riscv64_zbb_case(riscv_encode_r(0x20, 7, 6, 4, 5, 0x33),
                         0xaaaaaaaaaaaaaaaaull, 0xffff0000ffff0000ull,
                         5, 0xaaaa5555aaaa5555ull);
    run_riscv64_zbb_case(riscv_encode_r(0x05, 7, 6, 4, 5, 0x33),
                         0x8000000000000000ull, 0x7fffffffffffffffull,
                         5, 0x8000000000000000ull);
    run_riscv64_zbb_case(riscv_encode_r(0x05, 7, 6, 6, 5, 0x33),
                         0x8000000000000000ull, 0x7fffffffffffffffull,
                         5, 0x7fffffffffffffffull);
    run_riscv64_zbb_case(riscv_encode_r(0x05, 7, 6, 5, 5, 0x33),
                         0x8000000000000000ull, 0x7fffffffffffffffull,
                         5, 0x7fffffffffffffffull);
    run_riscv64_zbb_case(riscv_encode_r(0x05, 7, 6, 7, 5, 0x33),
                         0x8000000000000000ull, 0x7fffffffffffffffull,
                         5, 0x8000000000000000ull);
}

static void test_riscv32_zbb_rotate(void)
{
    run_riscv32_zbb_case(riscv_encode_r(0x30, 7, 6, 1, 5, 0x33),
                         1, 33, 5, 2);
    run_riscv32_zbb_case(riscv_encode_r(0x30, 7, 6, 5, 5, 0x33),
                         2, 33, 5, 1);
    run_riscv32_zbb_case(riscv_encode_i(0x61f, 6, 5, 5, 0x13),
                         1, 0, 5, 2);
    run_riscv_insn_illegal(UC_MODE_RISCV32,
                           riscv_encode_i(0x620, 6, 5, 5, 0x13));
}

static void test_riscv64_zbb_rotate(void)
{
    run_riscv64_zbb_case(riscv_encode_r(0x30, 7, 6, 1, 5, 0x33),
                         1, 65, 5, 2);
    run_riscv64_zbb_case(riscv_encode_r(0x30, 7, 6, 5, 5, 0x33),
                         2, 65, 5, 1);
    run_riscv64_zbb_case(riscv_encode_i(0x63f, 6, 5, 5, 0x13),
                         1, 0, 5, 2);
}

static void test_riscv64_zbb_word(void)
{
    run_riscv64_zbb_case(riscv_encode_i(0x600, 6, 1, 5, 0x1b),
                         0xffff000000008000ull, 0, 5, 16);
    run_riscv64_zbb_case(riscv_encode_i(0x601, 6, 1, 5, 0x1b),
                         0xffff000080000000ull, 0, 5, 31);
    run_riscv64_zbb_case(riscv_encode_i(0x602, 6, 1, 5, 0x1b),
                         0xffff0000f0f00000ull, 0, 5, 8);
    run_riscv64_zbb_case(riscv_encode_r(0x30, 7, 6, 1, 5, 0x3b),
                         0x80000001ull, 1, 5, 3);
    run_riscv64_zbb_case(riscv_encode_r(0x30, 7, 6, 5, 5, 0x3b),
                         1, 1, 5, 0xffffffff80000000ull);
    run_riscv64_zbb_case(riscv_encode_i(0x601, 6, 5, 5, 0x1b),
                         1, 0, 5, 0xffffffff80000000ull);
}

static void test_riscv_zbb_illegal_encodings(void)
{
    run_riscv_insn_illegal(UC_MODE_RISCV32,
                           riscv_encode_i(0x6b8, 6, 5, 5, 0x13));
    run_riscv_insn_illegal(UC_MODE_RISCV32,
                           riscv_encode_r(0x30, 7, 6, 5, 5, 0x3b));
    run_riscv_insn_illegal(UC_MODE_RISCV64,
                           riscv_encode_i(0x698, 6, 5, 5, 0x13));
}

static void run_riscv32_zbs_reg_case(const char *code, uint32_t rs1,
                                     uint32_t rs2, int rd, uint32_t expected)
{
    uc_engine *uc;
    uint32_t actual = 0;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code, 4);
    OK(uc_reg_write(uc, UC_RISCV_REG_X6, &rs1));
    OK(uc_reg_write(uc, UC_RISCV_REG_X7, &rs2));

    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_X0 + rd, &actual));
    TEST_CHECK(actual == expected);
    OK(uc_close(uc));
}

static void run_riscv64_zbs_reg_case(const char *code, uint64_t rs1,
                                     uint64_t rs2, int rd, uint64_t expected)
{
    uc_engine *uc;
    uint64_t actual = 0;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code, 4);
    OK(uc_reg_write(uc, UC_RISCV_REG_X6, &rs1));
    OK(uc_reg_write(uc, UC_RISCV_REG_X7, &rs2));

    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_X0 + rd, &actual));
    TEST_CHECK(actual == expected);
    OK(uc_close(uc));
}

static void run_riscv32_zbs_imm_case(const char *code, uint32_t rs1, int rd,
                                     uint32_t expected)
{
    uc_engine *uc;
    uint32_t actual = 0;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code, 4);
    OK(uc_reg_write(uc, UC_RISCV_REG_X6, &rs1));

    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_X0 + rd, &actual));
    TEST_CHECK(actual == expected);
    OK(uc_close(uc));
}

static void run_riscv64_zbs_imm_case(const char *code, uint64_t rs1, int rd,
                                     uint64_t expected)
{
    uc_engine *uc;
    uint64_t actual = 0;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code, 4);
    OK(uc_reg_write(uc, UC_RISCV_REG_X6, &rs1));

    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_X0 + rd, &actual));
    TEST_CHECK(actual == expected);
    OK(uc_close(uc));
}

static void test_riscv32_zbs_register(void)
{
    const char bset[] = "\xb3\x12\x73\x28";
    const char bclr[] = "\x33\x14\x73\x48";
    const char binv[] = "\xb3\x14\x73\x68";
    const char bext[] = "\x33\x55\x73\x48";

    run_riscv32_zbs_reg_case(bset, 0, 33, 5, 2);
    run_riscv32_zbs_reg_case(bclr, 0xffffffffu, 33, 8, 0xfffffffdu);
    run_riscv32_zbs_reg_case(binv, 0, 33, 9, 2);
    run_riscv32_zbs_reg_case(bext, 2, 33, 10, 1);
}

static void test_riscv64_zbs_register(void)
{
    const char bset[] = "\xb3\x12\x73\x28";
    const char bclr[] = "\x33\x14\x73\x48";
    const char binv[] = "\xb3\x14\x73\x68";
    const char bext[] = "\x33\x55\x73\x48";

    run_riscv64_zbs_reg_case(bset, 0, 65, 5, 2);
    run_riscv64_zbs_reg_case(bclr, 0xffffffffffffffffull, 65, 8,
                             0xfffffffffffffffdull);
    run_riscv64_zbs_reg_case(binv, 0, 65, 9, 2);
    run_riscv64_zbs_reg_case(bext, 2, 65, 10, 1);
}

static void test_riscv32_zbs_immediate(void)
{
    const char bseti[] = "\x93\x12\x13\x28";
    const char bclri[] = "\x13\x14\x33\x48";
    const char binvi[] = "\x93\x14\x43\x68";
    const char bexti[] = "\x13\x55\x53\x48";
    const char bseti_sh32[] = "\x93\x12\x03\x2a";
    uc_engine *uc;

    run_riscv32_zbs_imm_case(bseti, 0, 5, 2);
    run_riscv32_zbs_imm_case(bclri, 0xffffffffu, 8, 0xfffffff7u);
    run_riscv32_zbs_imm_case(binvi, 0, 9, 0x10);
    run_riscv32_zbs_imm_case(bexti, 0x20, 10, 1);

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, bseti_sh32, 4);
    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + 4, 0, 0));
    OK(uc_close(uc));
}

static void test_riscv64_zbs_immediate(void)
{
    const char bseti[] = "\x93\x12\x13\x28";
    const char bclri[] = "\x13\x14\x33\x48";
    const char binvi[] = "\x93\x14\x43\x68";
    const char bexti[] = "\x13\x55\x53\x48";
    const char bseti_sh63[] = "\x93\x12\xf3\x2b";

    run_riscv64_zbs_imm_case(bseti, 0, 5, 2);
    run_riscv64_zbs_imm_case(bclri, 0xffffffffffffffffull, 8,
                             0xfffffffffffffff7ull);
    run_riscv64_zbs_imm_case(binvi, 0, 9, 0x10);
    run_riscv64_zbs_imm_case(bexti, 0x20, 10, 1);
    run_riscv64_zbs_imm_case(bseti_sh63, 0, 5, 0x8000000000000000ull);
}

static void test_riscv32_rvv_vsetvli_csrs(void)
{
    uc_engine *uc;
    char code[] =
        "\x57\xf5\x05\x0c"
        "\x73\x26\x00\xc2"
        "\xf3\x26\x10\xc2"
        "\x73\x27\x20\xc2"
        "\xf3\x27\x00\x30";
    uint32_t a0 = 0;
    uint32_t a1 = 5;
    uint32_t a2 = 0;
    uint32_t a3 = 0;
    uint32_t a4 = 0;
    uint32_t a5 = 0;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code,
                    sizeof(code) - 1);
    riscv32_enable_vector_state(uc);
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_read(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_read(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_read(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_read(uc, UC_RISCV_REG_A5, &a5));

    TEST_CHECK(a0 == 5);
    TEST_CHECK(a2 == 5);
    TEST_CHECK(a3 == 0xc0);
    TEST_CHECK(a4 == 16);
    TEST_CHECK(a5 == (RISCV32_MSTATUS_SD | RISCV_MSTATUS_VS_DIRTY));

    OK(uc_close(uc));
}

static void test_riscv64_rvv_vsetvli_csrs(void)
{
    uc_engine *uc;
    char code[] =
        "\x57\xf5\x05\x0c"
        "\x73\x26\x00\xc2"
        "\xf3\x26\x10\xc2"
        "\x73\x27\x20\xc2"
        "\xf3\x27\x00\x30";
    uint64_t a0 = 0;
    uint64_t a1 = 5;
    uint64_t a2 = 0;
    uint64_t a3 = 0;
    uint64_t a4 = 0;
    uint64_t a5 = 0;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    riscv64_enable_vector_state(uc);
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_read(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_read(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_read(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_read(uc, UC_RISCV_REG_A5, &a5));

    TEST_CHECK(a0 == 5);
    TEST_CHECK(a2 == 5);
    TEST_CHECK(a3 == 0xc0);
    TEST_CHECK(a4 == 16);
    TEST_CHECK(a5 == (RISCV64_MSTATUS_SD | RISCV_MSTATUS_VS_DIRTY));

    OK(uc_close(uc));
}

static void test_riscv64_rvv_vsetvl_clamp(void)
{
    uc_engine *uc;
    char code[] =
        "\x93\x02\x00\x0c"
        "\x57\xf5\x55\x80"
        "\x73\x26\x00\xc2";
    uint64_t a0 = 0;
    uint64_t a1 = 32;
    uint64_t a2 = 0;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    riscv64_enable_vector_state(uc);
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_read(uc, UC_RISCV_REG_A2, &a2));

    TEST_CHECK(a0 == 16);
    TEST_CHECK(a2 == 16);

    OK(uc_close(uc));
}

static void test_riscv32_rvv_vsetivli(void)
{
    uc_engine *uc;
    char code[] =
        "\x57\xf5\x03\xcc"
        "\x73\x26\x00\xc2"
        "\xf3\x26\x10\xc2";
    uint32_t a0 = 0;
    uint32_t a2 = 0;
    uint32_t a3 = 0;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code,
                    sizeof(code) - 1);
    riscv32_enable_vector_state(uc);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_read(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_read(uc, UC_RISCV_REG_A3, &a3));

    TEST_CHECK(a0 == 7);
    TEST_CHECK(a2 == 7);
    TEST_CHECK(a3 == 0xc0);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_vle8_vadd_vv_vse8(void)
{
    uc_engine *uc;
    char code[] =
        "\x57\xf0\x05\x0c"
        "\x87\x00\x05\x02"
        "\x07\x81\x05\x02"
        "\xd7\x81\x20\x02"
        "\xa7\x01\x06\x02";
    uint8_t input_a[] = {
        0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff, 0x10,
        0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0xf0,
    };
    uint8_t input_b[] = {
        0x01, 0x02, 0x03, 0x01, 0x80, 0x03, 0x02, 0xf0,
        0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x20,
    };
    uint8_t expected[] = {
        0x01, 0x03, 0x05, 0x80, 0x00, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    };
    uint8_t output[sizeof(expected)] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    size_t i;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, input_a, sizeof(input_a)));
    OK(uc_mem_write(uc, a1, input_b, sizeof(input_b)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, a2, output, sizeof(output)));
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv32_rvv_vle8_vadd_vv_vse8(void)
{
    uc_engine *uc;
    char code[] =
        "\x57\xf0\x05\x0c"
        "\x87\x00\x05\x02"
        "\x07\x81\x05\x02"
        "\xd7\x81\x20\x02"
        "\xa7\x01\x06\x02";
    uint8_t input_a[] = {
        0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x10, 0xf0,
    };
    uint8_t input_b[] = {
        0x01, 0x02, 0x01, 0x80, 0x03, 0x02, 0xf0, 0x20,
    };
    uint8_t expected[] = {
        0x01, 0x03, 0x80, 0x00, 0x01, 0x01, 0x00, 0x10,
    };
    uint8_t output[sizeof(expected)] = { 0 };
    uint32_t a0 = code_start + 0x1000;
    uint32_t a1 = code_start + 0x1100;
    uint32_t a2 = code_start + 0x1200;
    size_t i;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code,
                    sizeof(code) - 1);
    riscv32_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, input_a, sizeof(input_a)));
    OK(uc_mem_write(uc, a1, input_b, sizeof(input_b)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, a2, output, sizeof(output)));
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_vmv_vi_vadd_vi_vse32(void)
{
    uc_engine *uc;
    char code[] =
        "\x57\xf0\x05\x0d"
        "\xd7\xb0\x0f\x5e"
        "\x57\xb1\x12\x02"
        "\x27\x61\x05\x02";
    uint32_t expected[] = { 4, 4, 4, 4 };
    uint32_t output[sizeof(expected) / sizeof(expected[0])] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = 4;
    size_t i;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    riscv64_enable_vector_state(uc);
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, a0, output, sizeof(output)));
    for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_tail_agnostic_vmv(void)
{
    uc_engine *uc;
    char code[] =
        "\x93\x05\x40\x00"
        "\x57\xf0\x05\x0c"
        "\xd7\xb0\x03\x5e"
        "\x93\x05\x80\x00"
        "\x57\xf0\x05\x0c"
        "\xa7\x00\x05\x02";
    uint8_t expected[] = {
        0x07, 0x07, 0x07, 0x07, 0xff, 0xff, 0xff, 0xff,
    };
    uint8_t output[sizeof(expected)] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    size_t i;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    riscv64_enable_vector_state(uc);
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, a0, output, sizeof(output)));
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv32_rvv_vle16_vsub_vse16(void)
{
    uc_engine *uc;
    char code[] =
        "\x57\xf0\x85\x0c"
        "\x87\x50\x05\x02"
        "\x07\xd1\x05\x02"
        "\xd7\x81\x20\x0a"
        "\xa7\x51\x06\x02";
    uint16_t input_a[] = {
        0x0001, 0x0002, 0x0100, 0xffff,
        0x8000, 0x0001, 0x1234, 0x0100,
    };
    uint16_t input_b[] = {
        0x0003, 0x0001, 0x0101, 0x0000,
        0x7fff, 0xffff, 0x2234, 0x00ff,
    };
    uint16_t expected[] = {
        0x0002, 0xffff, 0x0001, 0x0001,
        0xffff, 0xfffe, 0x1000, 0xffff,
    };
    uint16_t output[sizeof(expected) / sizeof(expected[0])] = { 0 };
    uint32_t a0 = code_start + 0x1000;
    uint32_t a1 = code_start + 0x1100;
    uint32_t a2 = code_start + 0x1200;
    size_t i;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code,
                    sizeof(code) - 1);
    riscv32_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, input_a, sizeof(input_a)));
    OK(uc_mem_write(uc, a1, input_b, sizeof(input_b)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, a2, output, sizeof(output)));
    for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_vle64_moves_logic_compare(void)
{
    uc_engine *uc;
    char code[] =
        "\x57\xf0\x85\x0d"
        "\x87\x70\x05\x02"
        "\x57\x81\x00\x5e"
        "\xd7\xc1\x06\x5e"
        "\x57\x80\x21\x66"
        "\x27\x80\x07\x02"
        "\x57\x82\x21\x2e"
        "\xd7\xb2\x47\x26"
        "\x57\x43\x57\x2a"
        "\x27\x73\x06\x02";
    uint64_t scalar = 0xff00ff00ff00fff0ull;
    uint64_t input[] = {
        0x000000000000000full,
        0xff00ff00ff00fff0ull,
    };
    uint64_t expected[] = {
        0x000000000000001full,
        0x0000000000000010ull,
    };
    uint64_t output[sizeof(expected) / sizeof(expected[0])] = { 0 };
    uint8_t expected_mask[] = { 0xfd, 0xff };
    uint8_t mask_output[sizeof(expected_mask)] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = 2;
    uint64_t a2 = code_start + 0x1100;
    uint64_t a3 = scalar;
    uint64_t a4 = 0x10;
    uint64_t a5 = code_start + 0x1200;
    size_t i;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, a2, output, sizeof(output)));
    for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }

    OK(uc_mem_read(uc, a5, mask_output, sizeof(mask_output)));
    for (i = 0; i < sizeof(expected_mask); i++) {
        TEST_CHECK(mask_output[i] == expected_mask[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_scalar_moves_compare(void)
{
    uc_engine *uc;
    char code[] =
        "\x57\xf0\x85\x0c"
        "\x87\x50\x05\x02"
        "\xd7\x26\x10\x42"
        "\x57\x61\x07\x42"
        "\x27\x51\x08\x02"
        "\x57\xc0\x17\x7e"
        "\x27\x00\x06\x02";
    uint16_t input[] = {
        0xff80, 0x0000, 0x0001, 0x0002,
        0xffff, 0x7fff, 0x8000, 0x0005,
    };
    uint16_t expected_move[] = {
        0x1234, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000,
    };
    uint16_t move_output[sizeof(expected_move) /
                         sizeof(expected_move[0])] = { 0 };
    uint8_t expected_mask[] = {
        0xac, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    uint8_t mask_output[sizeof(expected_mask)] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = 8;
    uint64_t a2 = code_start + 0x1100;
    uint64_t a3 = 0;
    uint64_t a4 = 0x1234;
    uint64_t a5 = 0;
    uint64_t a6 = code_start + 0x1200;
    size_t i;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_A3, &a3));
    TEST_CHECK(a3 == 0xffffffffffffff80ull);

    OK(uc_mem_read(uc, a6, move_output, sizeof(move_output)));
    for (i = 0; i < sizeof(expected_move) / sizeof(expected_move[0]); i++) {
        TEST_CHECK(move_output[i] == expected_move[i]);
    }

    OK(uc_mem_read(uc, a2, mask_output, sizeof(mask_output)));
    for (i = 0; i < sizeof(expected_mask); i++) {
        TEST_CHECK(mask_output[i] == expected_mask[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv32_rvv_minmax(void)
{
    uc_engine *uc;
    uint8_t code[11 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 14, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_op(0x04, 1, 1, 2, 0, 3),
        riscv_encode_rvv_op(0x07, 1, 1, 2, 0, 4),
        riscv_encode_rvv_op(0x05, 1, 1, 5, 4, 5),
        riscv_encode_rvv_op(0x06, 1, 1, 6, 4, 6),
        riscv_encode_rvv_ldst(1, 6, 1, 12, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 15, 5),
        riscv_encode_rvv_ldst(1, 6, 1, 16, 6),
    };
    uint32_t input_a[] = {
        0xffffffffu, 0x80000000u, 5, 0x7fffffffu,
    };
    uint32_t input_b[] = {
        1, 0xffffffffu, 6, 0x80000000u,
    };
    uint32_t expected_minu[] = {
        1, 0x80000000u, 5, 0x7fffffffu,
    };
    uint32_t expected_max[] = {
        1, 0xffffffffu, 6, 0x7fffffffu,
    };
    uint32_t expected_min_scalar[] = {
        0xfffffffeu, 0x80000000u, 0xfffffffeu, 0xfffffffeu,
    };
    uint32_t expected_maxu_scalar[] = {
        0xffffffffu, 0x80000001u, 0x80000001u, 0x80000001u,
    };
    uint32_t out_minu[4] = { 0 };
    uint32_t out_max[4] = { 0 };
    uint32_t out_min_scalar[4] = { 0 };
    uint32_t out_maxu_scalar[4] = { 0 };
    uint32_t a0 = code_start + 0x1000;
    uint32_t a1 = code_start + 0x1100;
    uint32_t a2 = code_start + 0x1200;
    uint32_t a3 = code_start + 0x1300;
    uint32_t a5 = code_start + 0x1400;
    uint32_t a6 = code_start + 0x1500;
    uint32_t a4 = 4;
    uint32_t t0 = 0xfffffffeu;
    uint32_t t1 = 0x80000001u;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, (const char *)code,
                    sizeof(code));
    riscv32_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, input_a, sizeof(input_a)));
    OK(uc_mem_write(uc, a1, input_b, sizeof(input_b)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_minu, sizeof(out_minu)));
    OK(uc_mem_read(uc, a3, out_max, sizeof(out_max)));
    OK(uc_mem_read(uc, a5, out_min_scalar, sizeof(out_min_scalar)));
    OK(uc_mem_read(uc, a6, out_maxu_scalar, sizeof(out_maxu_scalar)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_minu[i] == expected_minu[i]);
        TEST_CHECK(out_max[i] == expected_max[i]);
        TEST_CHECK(out_min_scalar[i] == expected_min_scalar[i]);
        TEST_CHECK(out_maxu_scalar[i] == expected_maxu_scalar[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_reverse_subtract(void)
{
    uc_engine *uc;
    uint8_t code[21 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xc0),
        riscv_encode_rvv_ldst(0, 0, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 0, 1, 29, 0),
        riscv_encode_rvv_op(0x03, 1, 1, 6, 4, 2),
        riscv_encode_rvv_ldst(1, 0, 1, 11, 2),
        riscv_encode_rvv_op(0x03, 1, 1, 0x1f, 3, 3),
        riscv_encode_rvv_ldst(1, 0, 1, 12, 3),
        riscv_encode_rvv_op(0x03, 0, 1, 6, 4, 4),
        riscv_encode_rvv_ldst(1, 0, 1, 30, 4),
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 13, 1),
        riscv_encode_rvv_op(0x03, 1, 1, 6, 4, 2),
        riscv_encode_rvv_ldst(1, 6, 1, 14, 2),
        riscv_encode_rvv_op(0x03, 1, 1, 0x10, 3, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 15, 3),
        riscv_encode_rvv_vsetvli(0, 7, 0xd8),
        riscv_encode_rvv_ldst(0, 7, 1, 16, 1),
        riscv_encode_rvv_op(0x03, 1, 1, 6, 4, 2),
        riscv_encode_rvv_ldst(1, 7, 1, 17, 2),
        riscv_encode_rvv_op(0x03, 1, 1, 0x1f, 3, 3),
        riscv_encode_rvv_ldst(1, 7, 1, 28, 3),
    };
    uint8_t e8_src[] = { 1u, 2u, 0u, 0xffu };
    uint8_t mask_src[] = { 0x05u, 0, 0, 0 };
    uint32_t e32_src[] = { 1u, 0x20u, 0xffffffffu, 0x80000000u };
    uint64_t e64_src[] = { 1ull, 0xffffffffffffffffull };
    uint8_t expected_e8_vx[] = { 0x0fu, 0x0eu, 0x10u, 0x11u };
    uint8_t expected_e8_vi[] = { 0xfeu, 0xfdu, 0xffu, 0u };
    uint8_t expected_e8_mask[] = { 0x0fu, 0xffu, 0x10u, 0xffu };
    uint32_t expected_e32_vx[] = {
        0x0fu, 0xfffffff0u, 0x11u, 0x80000010u,
    };
    uint32_t expected_e32_vi[] = {
        0xffffffefu, 0xffffffd0u, 0xfffffff1u, 0x7ffffff0u,
    };
    uint64_t expected_e64_vx[] = {
        0x10000000full, 0x100000011ull,
    };
    uint64_t expected_e64_vi[] = {
        0xfffffffffffffffeull, 0,
    };
    uint8_t out_e8_vx[4] = { 0 };
    uint8_t out_e8_vi[4] = { 0 };
    uint8_t out_e8_mask[4] = { 0 };
    uint32_t out_e32_vx[4] = { 0 };
    uint32_t out_e32_vi[4] = { 0 };
    uint64_t out_e64_vx[2] = { 0 };
    uint64_t out_e64_vi[2] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 4;
    uint64_t t1 = 0x100000010ull;
    uint64_t t2 = 2;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    uint64_t t5 = code_start + 0x1a00;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, e8_src, sizeof(e8_src)));
    OK(uc_mem_write(uc, a3, e32_src, sizeof(e32_src)));
    OK(uc_mem_write(uc, a6, e64_src, sizeof(e64_src)));
    OK(uc_mem_write(uc, t4, mask_src, sizeof(mask_src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T5, &t5));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, out_e8_vx, sizeof(out_e8_vx)));
    OK(uc_mem_read(uc, a2, out_e8_vi, sizeof(out_e8_vi)));
    OK(uc_mem_read(uc, t5, out_e8_mask, sizeof(out_e8_mask)));
    OK(uc_mem_read(uc, a4, out_e32_vx, sizeof(out_e32_vx)));
    OK(uc_mem_read(uc, a5, out_e32_vi, sizeof(out_e32_vi)));
    OK(uc_mem_read(uc, a7, out_e64_vx, sizeof(out_e64_vx)));
    OK(uc_mem_read(uc, t3, out_e64_vi, sizeof(out_e64_vi)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_e8_vx[i] == expected_e8_vx[i]);
        TEST_CHECK(out_e8_vi[i] == expected_e8_vi[i]);
        TEST_CHECK(out_e8_mask[i] == expected_e8_mask[i]);
        TEST_CHECK(out_e32_vx[i] == expected_e32_vx[i]);
        TEST_CHECK(out_e32_vi[i] == expected_e32_vi[i]);
    }
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_e64_vx[i] == expected_e64_vx[i]);
        TEST_CHECK(out_e64_vi[i] == expected_e64_vi[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv32_rvv_reverse_subtract(void)
{
    uc_engine *uc;
    uint8_t code[6 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_op(0x03, 1, 1, 6, 4, 2),
        riscv_encode_rvv_ldst(1, 6, 1, 11, 2),
        riscv_encode_rvv_op(0x03, 1, 1, 0x1f, 3, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 12, 3),
    };
    uint32_t src[] = { 1u, 0xffffffffu };
    uint32_t expected_vx[] = { 0x0fu, 0x11u };
    uint32_t expected_vi[] = { 0xfffffffeu, 0 };
    uint32_t out_vx[2] = { 0 };
    uint32_t out_vi[2] = { 0 };
    uint32_t a0 = code_start + 0x1000;
    uint32_t a1 = code_start + 0x1100;
    uint32_t a2 = code_start + 0x1200;
    uint32_t t0 = 2;
    uint32_t t1 = 0x10;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32,
                    (const char *)code, sizeof(code));
    riscv32_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, src, sizeof(src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, out_vx, sizeof(out_vx)));
    OK(uc_mem_read(uc, a2, out_vi, sizeof(out_vi)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_vx[i] == expected_vx[i]);
        TEST_CHECK(out_vi[i] == expected_vi[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_slide(void)
{
    uc_engine *uc;
    uint8_t code[22 * 4];
    uint32_t insns[22] = {
        riscv_encode_rvv_vsetvli(0, 6, 0xc0),
        riscv_encode_rvv_ldst(0, 0, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 0, 1, 11, 3),
        riscv_encode_rvv_op(0x0e, 1, 1, 2, 3, 3),
        riscv_encode_rvv_ldst(1, 0, 1, 12, 3),
        riscv_encode_rvv_ldst(0, 0, 1, 30, 0),
        riscv_encode_rvv_ldst(0, 0, 1, 11, 6),
        riscv_encode_rvv_op(0x0e, 0, 1, 28, 4, 6),
        riscv_encode_rvv_ldst(1, 0, 1, 29, 6),
        riscv_encode_rvv_ldst(0, 0, 1, 10, 5),
        riscv_encode_rvv_op(0x0f, 1, 5, 28, 4, 5),
        riscv_encode_rvv_ldst(1, 0, 1, 13, 5),
        riscv_encode_rvv_ldst(0, 0, 1, 10, 7),
        riscv_encode_rvv_op(0x0f, 1, 7, 2, 3, 7),
        riscv_encode_rvv_ldst(1, 0, 1, 14, 7),
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 15, 1),
        riscv_encode_rvv_op(0x0e, 1, 1, 7, 6, 2),
        riscv_encode_rvv_ldst(1, 6, 1, 16, 2),
    };
    uint32_t tail_insns[] = {
        riscv_encode_rvv_ldst(0, 6, 1, 15, 4),
        riscv_encode_rvv_op(0x0f, 1, 4, 7, 6, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 17, 4),
    };
    uint8_t src_e8[] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
    };
    uint8_t init_e8[] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    uint8_t mask_src[] = { 0x55, 0x55, 0, 0 };
    uint8_t expected_up_vi[] = {
        0xa0, 0xa1, 1, 2, 3, 4, 5, 6,
        7, 8, 9, 10, 11, 12, 13, 14,
    };
    uint8_t expected_up_vx_masked[] = {
        0xa0, 0xff, 2, 0xff, 4, 0xff, 6, 0xff,
        8, 0xff, 10, 0xff, 12, 0xff, 14, 0xff,
    };
    uint8_t expected_down_vx[] = {
        2, 3, 4, 5, 6, 7, 8, 9,
        10, 11, 12, 13, 14, 15, 16, 0,
    };
    uint8_t expected_down_vi[] = {
        3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 0, 0,
    };
    uint32_t src_e32[] = {
        0x11111111u, 0x22222222u, 0x33333333u, 0x44444444u,
    };
    uint32_t expected_slide1up[] = {
        0x9abcdef0u, 0x11111111u, 0x22222222u, 0x33333333u,
    };
    uint32_t expected_slide1down[] = {
        0x22222222u, 0x33333333u, 0x44444444u, 0x9abcdef0u,
    };
    uint8_t out_up_vi[16] = { 0 };
    uint8_t out_up_vx_masked[16] = { 0 };
    uint8_t out_down_vx[16] = { 0 };
    uint8_t out_down_vi[16] = { 0 };
    uint32_t out_slide1up[4] = { 0 };
    uint32_t out_slide1down[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 4;
    uint64_t t1 = 16;
    uint64_t t2 = 0x123456789abcdef0ull;
    uint64_t t3 = 1;
    uint64_t t4 = code_start + 0x1800;
    uint64_t t5 = code_start + 0x1900;
    size_t i;

    memcpy(&insns[19], tail_insns, sizeof(tail_insns));
    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, src_e8, sizeof(src_e8)));
    OK(uc_mem_write(uc, a1, init_e8, sizeof(init_e8)));
    OK(uc_mem_write(uc, a5, src_e32, sizeof(src_e32)));
    OK(uc_mem_write(uc, t5, mask_src, sizeof(mask_src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T5, &t5));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_up_vi, sizeof(out_up_vi)));
    OK(uc_mem_read(uc, t4, out_up_vx_masked, sizeof(out_up_vx_masked)));
    OK(uc_mem_read(uc, a3, out_down_vx, sizeof(out_down_vx)));
    OK(uc_mem_read(uc, a4, out_down_vi, sizeof(out_down_vi)));
    OK(uc_mem_read(uc, a6, out_slide1up, sizeof(out_slide1up)));
    OK(uc_mem_read(uc, a7, out_slide1down, sizeof(out_slide1down)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(out_up_vi[i] == expected_up_vi[i]);
        TEST_CHECK(out_up_vx_masked[i] == expected_up_vx_masked[i]);
        TEST_CHECK(out_down_vx[i] == expected_down_vx[i]);
        TEST_CHECK(out_down_vi[i] == expected_down_vi[i]);
    }
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_slide1up[i] == expected_slide1up[i]);
        TEST_CHECK(out_slide1down[i] == expected_slide1down[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv32_rvv_slide(void)
{
    uc_engine *uc;
    uint8_t code[8 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 14, 2),
        riscv_encode_rvv_op(0x0e, 1, 1, 1, 3, 2),
        riscv_encode_rvv_ldst(1, 6, 1, 11, 2),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 3),
        riscv_encode_rvv_op(0x0f, 1, 3, 6, 6, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
    };
    uint32_t src[] = { 0x11111111u, 0x22222222u };
    uint32_t init[] = { 0xaaaaaaaa, 0xbbbbbbbb };
    uint32_t expected_up[] = { 0xaaaaaaaa, 0x11111111u };
    uint32_t expected_down1[] = { 0x22222222u, 0x87654321u };
    uint32_t out_up[2] = { 0 };
    uint32_t out_down1[2] = { 0 };
    uint32_t a0 = code_start + 0x1000;
    uint32_t a1 = code_start + 0x1100;
    uint32_t a3 = code_start + 0x1300;
    uint32_t a4 = code_start + 0x1400;
    uint32_t t0 = 2;
    uint32_t t1 = 0x87654321u;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32,
                    (const char *)code, sizeof(code));
    riscv32_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, src, sizeof(src)));
    OK(uc_mem_write(uc, a4, init, sizeof(init)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, out_up, sizeof(out_up)));
    OK(uc_mem_read(uc, a3, out_down1, sizeof(out_down1)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_up[i] == expected_up[i]);
        TEST_CHECK(out_down1[i] == expected_down1[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_slide_illegal(void)
{
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_op(0x0e, 1, 2, 6, 4, 2));
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_op(0x0e, 1, 2, 2, 3, 2));
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_op(0x0e, 1, 2, 6, 6, 2));
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_op(0x0f, 0, 1, 6, 4, 0));
}

static void test_riscv64_rvv_gather_compress(void)
{
    uc_engine *uc;
    uint8_t code[20 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xc0),
        riscv_encode_rvv_ldst(0, 0, 1, 12, 2),
        riscv_encode_rvv_ldst(0, 0, 1, 11, 1),
        riscv_encode_rvv_op(0x0c, 1, 1, 2, 0, 3),
        riscv_encode_rvv_ldst(1, 0, 1, 13, 3),
        riscv_encode_rvv_op(0x0c, 1, 1, 7, 4, 4),
        riscv_encode_rvv_ldst(1, 0, 1, 14, 4),
        riscv_encode_rvv_op(0x0c, 1, 1, 0x1f, 3, 5),
        riscv_encode_rvv_ldst(1, 0, 1, 15, 5),
        riscv_encode_rvv_ldst(0, 0, 1, 10, 0),
        riscv_encode_rvv_op(0x0c, 0, 1, 2, 0, 6),
        riscv_encode_rvv_ldst(1, 0, 1, 30, 6),
        riscv_encode_rvv_ldst(0, 5, 1, 17, 10),
        riscv_encode_rvv_op(0x0e, 1, 1, 10, 0, 8),
        riscv_encode_rvv_ldst(1, 0, 1, 18, 8),
        riscv_encode_rvv_vsetvli(0, 7, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 24, 1),
        riscv_encode_rvv_mask_ldst(0, 25, 2),
        riscv_encode_rvv_op(0x17, 1, 1, 2, 2, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 26, 3),
    };
    uint8_t src_e8[] = {
        10, 20, 30, 40, 50, 60, 70, 80,
        90, 100, 110, 120, 130, 140, 150, 160,
    };
    uint8_t index_e8[] = {
        0, 3, 15, 16, 1, 2, 4, 5,
        6, 7, 8, 9, 10, 11, 12, 13,
    };
    uint8_t mask_src[] = { 0x0b, 0, 0, 0 };
    uint16_t index_e16[] = { 0, 3, 16, 1, 2, 15, 4, 5 };
    uint32_t compress_src[] = {
        0x11111111u, 0x22222222u, 0x33333333u, 0x44444444u,
    };
    uint32_t compress_mask[] = { 0x0du, 0, 0, 0 };
    uint8_t expected_vv[] = {
        10, 40, 160, 0, 20, 30, 50, 60,
        70, 80, 90, 100, 110, 120, 130, 140,
    };
    uint8_t expected_vx[] = {
        50, 50, 50, 50, 50, 50, 50, 50,
        50, 50, 50, 50, 50, 50, 50, 50,
    };
    uint8_t expected_vi[] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    uint8_t expected_masked[] = {
        10, 40, 0xff, 0, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    uint8_t expected_ei16[] = {
        10, 40, 0, 20, 30, 160, 50, 60,
    };
    uint32_t expected_compress[] = {
        0x11111111u, 0x33333333u, 0x44444444u, 0xffffffffu,
    };
    uint8_t out_vv[16] = { 0 };
    uint8_t out_vx[16] = { 0 };
    uint8_t out_vi[16] = { 0 };
    uint8_t out_masked[16] = { 0 };
    uint8_t out_ei16[8] = { 0 };
    uint32_t out_compress[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a7 = code_start + 0x1700;
    uint64_t s2 = code_start + 0x1800;
    uint64_t s8 = code_start + 0x1d00;
    uint64_t s9 = code_start + 0x1e00;
    uint64_t s10 = code_start + 0x1f00;
    uint64_t t0 = 16;
    uint64_t t2 = 4;
    uint64_t t5 = code_start + 0x2100;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask_src, sizeof(mask_src)));
    OK(uc_mem_write(uc, a1, src_e8, sizeof(src_e8)));
    OK(uc_mem_write(uc, a2, index_e8, sizeof(index_e8)));
    OK(uc_mem_write(uc, a7, index_e16, sizeof(index_e16)));
    OK(uc_mem_write(uc, s8, compress_src, sizeof(compress_src)));
    OK(uc_mem_write(uc, s9, compress_mask, sizeof(compress_mask)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_S2, &s2));
    OK(uc_reg_write(uc, UC_RISCV_REG_S8, &s8));
    OK(uc_reg_write(uc, UC_RISCV_REG_S9, &s9));
    OK(uc_reg_write(uc, UC_RISCV_REG_S10, &s10));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T5, &t5));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_vv, sizeof(out_vv)));
    OK(uc_mem_read(uc, a4, out_vx, sizeof(out_vx)));
    OK(uc_mem_read(uc, a5, out_vi, sizeof(out_vi)));
    OK(uc_mem_read(uc, t5, out_masked, sizeof(out_masked)));
    OK(uc_mem_read(uc, s2, out_ei16, sizeof(out_ei16)));
    OK(uc_mem_read(uc, s10, out_compress, sizeof(out_compress)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(out_vv[i] == expected_vv[i]);
        TEST_CHECK(out_vx[i] == expected_vx[i]);
        TEST_CHECK(out_vi[i] == expected_vi[i]);
        TEST_CHECK(out_masked[i] == expected_masked[i]);
    }
    for (i = 0; i < 8; i++) {
        TEST_CHECK(out_ei16[i] == expected_ei16[i]);
    }
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_compress[i] == expected_compress[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv32_rvv_gather_compress(void)
{
    uc_engine *uc;
    uint8_t code[10 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 2),
        riscv_encode_rvv_op(0x0c, 1, 1, 2, 0, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 14, 3),
        riscv_encode_rvv_vsetvli(0, 6, 0xc0),
        riscv_encode_rvv_ldst(0, 0, 1, 13, 4),
        riscv_encode_rvv_mask_ldst(0, 10, 5),
        riscv_encode_rvv_op(0x17, 1, 4, 5, 2, 6),
        riscv_encode_rvv_ldst(1, 0, 1, 7, 6),
    };
    uint32_t src[] = { 0x11111111u, 0x22222222u };
    uint32_t idx[] = { 1, 4 };
    uint32_t expected_gather[] = { 0x22222222u, 0 };
    uint8_t mask_src[] = { 0x0b, 0, 0, 0 };
    uint8_t compress_src[] = { 10, 20, 30, 40 };
    uint8_t expected_compress[] = { 10, 20, 40, 0xff };
    uint32_t out_gather[2] = { 0 };
    uint8_t out_compress[4] = { 0 };
    uint32_t a0 = code_start + 0x1000;
    uint32_t a1 = code_start + 0x1100;
    uint32_t a2 = code_start + 0x1200;
    uint32_t a3 = code_start + 0x1300;
    uint32_t a4 = code_start + 0x1400;
    uint32_t t0 = 2;
    uint32_t t1 = 4;
    uint32_t t2 = code_start + 0x1600;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32,
                    (const char *)code, sizeof(code));
    riscv32_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask_src, sizeof(mask_src)));
    OK(uc_mem_write(uc, a1, src, sizeof(src)));
    OK(uc_mem_write(uc, a2, idx, sizeof(idx)));
    OK(uc_mem_write(uc, a3, compress_src, sizeof(compress_src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a4, out_gather, sizeof(out_gather)));
    OK(uc_mem_read(uc, t2, out_compress, sizeof(out_compress)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_gather[i] == expected_gather[i]);
    }
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_compress[i] == expected_compress[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_whole_register_move(void)
{
    uc_engine *uc;
    uint8_t code[11 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xc0),
        riscv_encode_rvv_whole_ldst(0, 0, 10, 1, 1),
        riscv_encode_rvv_vmvnr(1, 1, 2),
        riscv_encode_rvv_ldst(1, 0, 1, 11, 2),
        riscv_encode_rvv_vmvnr(1, 1, 4),
        riscv_encode_rvv_vmvnr(2, 4, 6),
        riscv_encode_rvv_ldst(1, 0, 1, 12, 6),
        riscv_encode_rvv_ldst(1, 0, 1, 13, 7),
        riscv_encode_rvv_ldst(1, 0, 1, 14, 8),
        riscv_encode_rvv_vmvnr(4, 8, 12),
        riscv_encode_rvv_vmvnr(8, 16, 24),
    };
    uint8_t src[] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
    };
    uint8_t out_v2[16] = { 0 };
    uint8_t out_v6[16] = { 0 };
    uint8_t out_v7[16] = { 0 };
    uint8_t out_v8[16] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t t0 = 16;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, src, sizeof(src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, out_v2, sizeof(out_v2)));
    OK(uc_mem_read(uc, a2, out_v6, sizeof(out_v6)));
    OK(uc_mem_read(uc, a3, out_v7, sizeof(out_v7)));
    OK(uc_mem_read(uc, a4, out_v8, sizeof(out_v8)));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(out_v2[i] == src[i]);
        TEST_CHECK(out_v6[i] == src[i]);
        TEST_CHECK(out_v7[i] == 0);
        TEST_CHECK(out_v8[i] == 0);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_gather_compress_move_illegal(void)
{
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_op(0x0c, 1, 2, 3, 0, 2));
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_op(0x0c, 1, 3, 2, 0, 2));
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x0e, 1, 2, 1, 0, 2), 0xc8);
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_op(0x17, 1, 2, 0, 2, 2));
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_op(0x17, 0, 1, 0, 2, 0));
    run_riscv64_rvv_illegal_vstart_vl0(
        riscv_encode_rvv_op(0x17, 1, 1, 2, 2, 3));
    run_riscv64_rvv_illegal(riscv_encode_rvv_vmvnr(2, 2, 3));
}

static void test_riscv64_rvv_vmerge(void)
{
    uc_engine *uc;
    uint8_t code[11 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_rvv_ldst(0, 0, 1, 10, 0),
        riscv_encode_rvv_op(0x18, 1, 0, 1, 3, 0),
        riscv_encode_rvv_ldst(0, 0, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 0, 1, 12, 2),
        riscv_encode_rvv_op(0x17, 0, 1, 2, 0, 3),
        riscv_encode_rvv_ldst(1, 0, 1, 13, 3),
        riscv_encode_rvv_op(0x17, 0, 1, 0x1d, 3, 4),
        riscv_encode_rvv_ldst(1, 0, 1, 14, 4),
        riscv_encode_rvv_op(0x17, 0, 1, 5, 4, 5),
        riscv_encode_rvv_ldst(1, 0, 1, 15, 5),
    };
    uint8_t mask_src[] = { 1, 0, 1, 0, 0, 1, 0, 1 };
    uint8_t low[] = { 10, 20, 30, 40, 50, 60, 70, 80 };
    uint8_t high[] = { 101, 102, 103, 104, 105, 106, 107, 108 };
    uint8_t expected_vvm[] = { 101, 20, 103, 40, 50, 106, 70, 108 };
    uint8_t expected_vim[] = { 0xfd, 20, 0xfd, 40, 50, 0xfd, 70, 0xfd };
    uint8_t expected_vxm[] = { 0xaa, 20, 0xaa, 40, 50, 0xaa, 70, 0xaa };
    uint8_t out_vvm[8] = { 0 };
    uint8_t out_vim[8] = { 0 };
    uint8_t out_vxm[8] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = 8;
    uint64_t t0 = 0xaa;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, (const char *)code,
                    sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask_src, sizeof(mask_src)));
    OK(uc_mem_write(uc, a1, low, sizeof(low)));
    OK(uc_mem_write(uc, a2, high, sizeof(high)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_vvm, sizeof(out_vvm)));
    OK(uc_mem_read(uc, a4, out_vim, sizeof(out_vim)));
    OK(uc_mem_read(uc, a5, out_vxm, sizeof(out_vxm)));
    for (i = 0; i < sizeof(expected_vvm); i++) {
        TEST_CHECK(out_vvm[i] == expected_vvm[i]);
        TEST_CHECK(out_vim[i] == expected_vim[i]);
        TEST_CHECK(out_vxm[i] == expected_vxm[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_shift_vv(void)
{
    uc_engine *uc;
    uint8_t code[9 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xd8),
        riscv_encode_rvv_ldst(0, 7, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 7, 1, 11, 2),
        riscv_encode_rvv_op(0x25, 1, 1, 2, 0, 3),
        riscv_encode_rvv_op(0x28, 1, 1, 2, 0, 4),
        riscv_encode_rvv_op(0x29, 1, 1, 2, 0, 5),
        riscv_encode_rvv_ldst(1, 7, 1, 12, 3),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 4),
    };
    uint32_t store_sra = riscv_encode_rvv_ldst(1, 7, 1, 14, 5);
    uint64_t input[] = {
        0x8000000000000001ull, 0xf000000000000000ull,
    };
    uint64_t shifts[] = { 4, 68 };
    uint64_t expected_sll[] = { 0x0000000000000010ull, 0 };
    uint64_t expected_srl[] = {
        0x0800000000000000ull, 0x0f00000000000000ull,
    };
    uint64_t expected_sra[] = {
        0xf800000000000000ull, 0xff00000000000000ull,
    };
    uint64_t out_sll[2] = { 0 };
    uint64_t out_srl[2] = { 0 };
    uint64_t out_sra[2] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a6 = 2;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }
    riscv_insn_to_code(&code[8 * 4], store_sra);

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, (const char *)code,
                    sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, input, sizeof(input)));
    OK(uc_mem_write(uc, a1, shifts, sizeof(shifts)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_sll, sizeof(out_sll)));
    OK(uc_mem_read(uc, a3, out_srl, sizeof(out_srl)));
    OK(uc_mem_read(uc, a4, out_sra, sizeof(out_sra)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_sll[i] == expected_sll[i]);
        TEST_CHECK(out_srl[i] == expected_srl[i]);
        TEST_CHECK(out_sra[i] == expected_sra[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv32_rvv_shift_vx_vi(void)
{
    uc_engine *uc;
    uint8_t code[8 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 14, 0xc0),
        riscv_encode_rvv_ldst(0, 0, 1, 10, 1),
        riscv_encode_rvv_op(0x25, 1, 1, 5, 4, 2),
        riscv_encode_rvv_op(0x28, 1, 1, 15, 3, 3),
        riscv_encode_rvv_op(0x29, 1, 1, 2, 3, 4),
        riscv_encode_rvv_ldst(1, 0, 1, 11, 2),
        riscv_encode_rvv_ldst(1, 0, 1, 12, 3),
    };
    uint32_t store_sra = riscv_encode_rvv_ldst(1, 0, 1, 13, 4);
    uint8_t input[] = { 0x01, 0x7f, 0x80, 0xff, 0x10, 0x40, 0xc0, 0x81 };
    uint8_t expected_sll[] = {
        0x02, 0xfe, 0x00, 0xfe, 0x20, 0x80, 0x80, 0x02,
    };
    uint8_t expected_srl[] = {
        0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01,
    };
    uint8_t expected_sra[] = {
        0x00, 0x1f, 0xe0, 0xff, 0x04, 0x10, 0xf0, 0xe0,
    };
    uint8_t out_sll[8] = { 0 };
    uint8_t out_srl[8] = { 0 };
    uint8_t out_sra[8] = { 0 };
    uint32_t a0 = code_start + 0x1000;
    uint32_t a1 = code_start + 0x1100;
    uint32_t a2 = code_start + 0x1200;
    uint32_t a3 = code_start + 0x1300;
    uint32_t a4 = 8;
    uint32_t t0 = 9;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }
    riscv_insn_to_code(&code[7 * 4], store_sra);

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, (const char *)code,
                    sizeof(code));
    riscv32_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, out_sll, sizeof(out_sll)));
    OK(uc_mem_read(uc, a2, out_srl, sizeof(out_srl)));
    OK(uc_mem_read(uc, a3, out_sra, sizeof(out_sra)));
    for (i = 0; i < sizeof(expected_sll); i++) {
        TEST_CHECK(out_sll[i] == expected_sll[i]);
        TEST_CHECK(out_srl[i] == expected_srl[i]);
        TEST_CHECK(out_sra[i] == expected_sra[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv32_rvv_mask_load_store(void)
{
    uc_engine *uc;
    uint8_t code[3 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 12, 0xc0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_mask_ldst(1, 11, 0),
    };
    uint8_t mask_input[] = { 0xad, 0x02 };
    uint8_t mask_output[] = { 0, 0 };
    uint32_t a0 = code_start + 0x1000;
    uint32_t a1 = code_start + 0x1100;
    uint32_t a2 = 10;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, (const char *)code,
                    sizeof(code));
    riscv32_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask_input, sizeof(mask_input)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, mask_output, sizeof(mask_output)));
    for (i = 0; i < sizeof(mask_input); i++) {
        TEST_CHECK(mask_output[i] == mask_input[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_masked_unit_stride(void)
{
    uc_engine *uc;
    uint8_t code[5 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 0, 0, 11, 1),
        riscv_encode_rvv_ldst(1, 0, 1, 12, 1),
        riscv_encode_rvv_ldst(1, 0, 0, 13, 1),
    };
    uint8_t mask_input[] = { 0xad };
    uint8_t input[] = { 10, 20, 30, 40, 50, 60, 70, 80 };
    uint8_t expected_loaded[] = { 10, 0xff, 30, 40, 0xff, 60, 0xff, 80 };
    uint8_t expected_masked[] = { 10, 0xee, 30, 40, 0xee, 60, 0xee, 80 };
    uint8_t out_loaded[8] = { 0 };
    uint8_t out_masked[8] = {
        0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a6 = 8;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, (const char *)code,
                    sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask_input, sizeof(mask_input)));
    OK(uc_mem_write(uc, a1, input, sizeof(input)));
    OK(uc_mem_write(uc, a3, out_masked, sizeof(out_masked)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_loaded, sizeof(out_loaded)));
    OK(uc_mem_read(uc, a3, out_masked, sizeof(out_masked)));
    for (i = 0; i < sizeof(expected_loaded); i++) {
        TEST_CHECK(out_loaded[i] == expected_loaded[i]);
        TEST_CHECK(out_masked[i] == expected_masked[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_unit_stride_fault_vstart(void)
{
    uc_engine *uc;
    uint8_t code[3 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_rvv_ldst(0, 0, 1, 10, 1),
        riscv_encode_rvv_ldst(1, 0, 1, 11, 1),
    };
    uint8_t first_source[] = { 0x11, 0x22 };
    uint8_t overwritten_source[] = { 0xaa, 0xbb };
    uint8_t second_source[] = { 0x33, 0x44 };
    uint8_t expected[] = { 0x11, 0x22, 0x33, 0x44 };
    uint8_t output[4] = { 0 };
    uint64_t a0 = code_start + code_len - sizeof(first_source);
    uint64_t a1 = code_start + 0x2000;
    uint64_t a6 = 4;
    uint64_t pc;
    uint64_t vstart;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, first_source, sizeof(first_source)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    uc_assert_err(UC_ERR_READ_UNMAPPED,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &pc));
    OK(uc_reg_read(uc, UC_RISCV_REG_VSTART, &vstart));
    TEST_CHECK(pc == code_start + 4);
    TEST_CHECK(vstart == 2);

    OK(uc_mem_write(uc, a0, overwritten_source,
                    sizeof(overwritten_source)));
    OK(uc_mem_map(uc, code_start + code_len, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start + code_len, second_source,
                    sizeof(second_source)));

    OK(uc_emu_start(uc, pc, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, a1, output, sizeof(output)));
    OK(uc_reg_read(uc, UC_RISCV_REG_VSTART, &vstart));
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }
    TEST_CHECK(vstart == 0);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_strided_fault_vstart(void)
{
    uc_engine *uc;
    uint8_t code[3 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_rvv_stride_ldst(0, 0, 1, 10, 5, 1, 1),
        riscv_encode_rvv_ldst(1, 0, 1, 11, 1),
    };
    uint8_t first_source[] = { 0x11, 0x22 };
    uint8_t overwritten_source[] = { 0xaa, 0xbb };
    uint8_t second_source[] = { 0x33, 0x44 };
    uint8_t expected[] = { 0x11, 0x22, 0x33, 0x44 };
    uint8_t output[4] = { 0 };
    uint64_t a0 = code_start + code_len - 4;
    uint64_t a1 = code_start + 0x2000;
    uint64_t a6 = 4;
    uint64_t t0 = 2;
    uint64_t pc;
    uint64_t vstart;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, &first_source[0], sizeof(first_source[0])));
    OK(uc_mem_write(uc, a0 + 2, &first_source[1], sizeof(first_source[1])));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    uc_assert_err(UC_ERR_READ_UNMAPPED,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &pc));
    OK(uc_reg_read(uc, UC_RISCV_REG_VSTART, &vstart));
    TEST_CHECK(pc == code_start + 4);
    TEST_CHECK(vstart == 2);

    OK(uc_mem_write(uc, a0, &overwritten_source[0],
                    sizeof(overwritten_source[0])));
    OK(uc_mem_write(uc, a0 + 2, &overwritten_source[1],
                    sizeof(overwritten_source[1])));
    OK(uc_mem_map(uc, code_start + code_len, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start + code_len, &second_source[0],
                    sizeof(second_source[0])));
    OK(uc_mem_write(uc, code_start + code_len + 2, &second_source[1],
                    sizeof(second_source[1])));

    OK(uc_emu_start(uc, pc, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, a1, output, sizeof(output)));
    OK(uc_reg_read(uc, UC_RISCV_REG_VSTART, &vstart));
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }
    TEST_CHECK(vstart == 0);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_indexed_fault_vstart(void)
{
    uc_engine *uc;
    uint8_t code[4 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_rvv_ldst(0, 0, 1, 12, 1),
        riscv_encode_rvv_index_ldst(0, 0, 1, 1, 10, 1, 2, 1),
        riscv_encode_rvv_ldst(1, 0, 1, 11, 2),
    };
    uint8_t indexes[] = { 0, 2, 4, 6 };
    uint8_t first_source[] = { 0x11, 0x22 };
    uint8_t overwritten_source[] = { 0xaa, 0xbb };
    uint8_t second_source[] = { 0x33, 0x44 };
    uint8_t expected[] = { 0x11, 0x22, 0x33, 0x44 };
    uint8_t output[4] = { 0 };
    uint64_t a0 = code_start + code_len - 4;
    uint64_t a1 = code_start + 0x2000;
    uint64_t a2 = code_start + 0x2100;
    uint64_t a6 = 4;
    uint64_t pc;
    uint64_t vstart;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, &first_source[0], sizeof(first_source[0])));
    OK(uc_mem_write(uc, a0 + 2, &first_source[1], sizeof(first_source[1])));
    OK(uc_mem_write(uc, a2, indexes, sizeof(indexes)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    uc_assert_err(UC_ERR_READ_UNMAPPED,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_reg_read(uc, UC_RISCV_REG_PC, &pc));
    OK(uc_reg_read(uc, UC_RISCV_REG_VSTART, &vstart));
    TEST_CHECK(pc == code_start + 8);
    TEST_CHECK(vstart == 2);

    OK(uc_mem_write(uc, a0, &overwritten_source[0],
                    sizeof(overwritten_source[0])));
    OK(uc_mem_write(uc, a0 + 2, &overwritten_source[1],
                    sizeof(overwritten_source[1])));
    OK(uc_mem_map(uc, code_start + code_len, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start + code_len, &second_source[0],
                    sizeof(second_source[0])));
    OK(uc_mem_write(uc, code_start + code_len + 2, &second_source[1],
                    sizeof(second_source[1])));

    OK(uc_emu_start(uc, pc, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, a1, output, sizeof(output)));
    OK(uc_reg_read(uc, UC_RISCV_REG_VSTART, &vstart));
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }
    TEST_CHECK(vstart == 0);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_unit_stride_segment_memory(void)
{
    uc_engine *uc;
    uint8_t code[7 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_rvv_segment_ldst(0, 5, 1, 10, 2, 2),
        riscv_encode_rvv_ldst(1, 5, 1, 11, 2),
        riscv_encode_rvv_ldst(1, 5, 1, 12, 3),
        riscv_encode_rvv_ldst(0, 5, 1, 13, 4),
        riscv_encode_rvv_ldst(0, 5, 1, 14, 5),
        riscv_encode_rvv_segment_ldst(1, 5, 1, 15, 4, 2),
    };
    uint16_t segment_input[] = {
        0x101, 0x201, 0x102, 0x202, 0x103, 0x203,
    };
    uint16_t store_field0[] = {
        0x111, 0x222, 0x333,
    };
    uint16_t store_field1[] = {
        0xaaa, 0xbbb, 0xccc,
    };
    uint16_t expected_field0[] = {
        0x101, 0x102, 0x103,
    };
    uint16_t expected_field1[] = {
        0x201, 0x202, 0x203,
    };
    uint16_t expected_segment_output[] = {
        0x111, 0xaaa, 0x222, 0xbbb, 0x333, 0xccc,
    };
    uint16_t out_field0[3] = { 0 };
    uint16_t out_field1[3] = { 0 };
    uint16_t segment_output[6] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = 3;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, segment_input, sizeof(segment_input)));
    OK(uc_mem_write(uc, a3, store_field0, sizeof(store_field0)));
    OK(uc_mem_write(uc, a4, store_field1, sizeof(store_field1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, out_field0, sizeof(out_field0)));
    OK(uc_mem_read(uc, a2, out_field1, sizeof(out_field1)));
    OK(uc_mem_read(uc, a5, segment_output, sizeof(segment_output)));
    for (i = 0; i < sizeof(expected_field0) / sizeof(expected_field0[0]);
         i++) {
        TEST_CHECK(out_field0[i] == expected_field0[i]);
        TEST_CHECK(out_field1[i] == expected_field1[i]);
    }
    for (i = 0;
         i < sizeof(expected_segment_output) /
             sizeof(expected_segment_output[0]);
         i++) {
        TEST_CHECK(segment_output[i] == expected_segment_output[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_masked_unit_stride_segment(void)
{
    uc_engine *uc;
    uint8_t code[8 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 17, 0xc0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_segment_ldst(0, 0, 0, 11, 2, 2),
        riscv_encode_rvv_ldst(1, 0, 1, 12, 2),
        riscv_encode_rvv_ldst(1, 0, 1, 13, 3),
        riscv_encode_rvv_ldst(0, 0, 1, 14, 4),
        riscv_encode_rvv_ldst(0, 0, 1, 15, 5),
        riscv_encode_rvv_segment_ldst(1, 0, 0, 16, 4, 2),
    };
    uint8_t mask_input[] = { 0xad };
    uint8_t segment_input[] = {
        10, 20, 11, 21, 12, 22, 13, 23,
        14, 24, 15, 25, 16, 26, 17, 27,
    };
    uint8_t store_field0[] = {
        1, 2, 3, 4, 5, 6, 7, 8,
    };
    uint8_t store_field1[] = {
        11, 12, 13, 14, 15, 16, 17, 18,
    };
    uint8_t expected_field0[] = {
        10, 0xff, 12, 13, 0xff, 15, 0xff, 17,
    };
    uint8_t expected_field1[] = {
        20, 0xff, 22, 23, 0xff, 25, 0xff, 27,
    };
    uint8_t segment_output[16] = {
        0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
        0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    };
    uint8_t expected_segment_output[] = {
        1, 11, 0xee, 0xee, 3, 13, 4, 14,
        0xee, 0xee, 6, 16, 0xee, 0xee, 8, 18,
    };
    uint8_t out_field0[8] = { 0 };
    uint8_t out_field1[8] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = 8;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask_input, sizeof(mask_input)));
    OK(uc_mem_write(uc, a1, segment_input, sizeof(segment_input)));
    OK(uc_mem_write(uc, a4, store_field0, sizeof(store_field0)));
    OK(uc_mem_write(uc, a5, store_field1, sizeof(store_field1)));
    OK(uc_mem_write(uc, a6, segment_output, sizeof(segment_output)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_field0, sizeof(out_field0)));
    OK(uc_mem_read(uc, a3, out_field1, sizeof(out_field1)));
    OK(uc_mem_read(uc, a6, segment_output, sizeof(segment_output)));
    for (i = 0; i < sizeof(expected_field0); i++) {
        TEST_CHECK(out_field0[i] == expected_field0[i]);
        TEST_CHECK(out_field1[i] == expected_field1[i]);
    }
    for (i = 0; i < sizeof(expected_segment_output); i++) {
        TEST_CHECK(segment_output[i] == expected_segment_output[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_unit_stride_segment_illegal(void)
{
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_segment_ldst(0, 0, 0, 10, 0, 2));
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_segment_ldst(0, 0, 1, 10, 31, 2));
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_segment_ldst(0, 7, 1, 10, 0, 2), 0xc0);
}

static void test_riscv64_rvv_strided_load_store(void)
{
    uc_engine *uc;
    uint8_t code[5 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_rvv_stride_ldst(0, 5, 1, 10, 5, 1, 1),
        riscv_encode_rvv_ldst(1, 5, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 5, 1, 12, 2),
        riscv_encode_rvv_stride_ldst(1, 5, 1, 13, 6, 2, 1),
    };
    uint16_t gather_input[] = {
        0x1010, 0xeeee, 0x2020, 0xeeee,
        0x3030, 0xeeee, 0x4040, 0xeeee,
    };
    uint16_t store_input[] = {
        0x5151, 0x6262, 0x7373, 0x8484,
    };
    uint16_t expected_gather[] = {
        0x1010, 0x2020, 0x3030, 0x4040,
    };
    uint16_t scatter[8] = {
        0xeeee, 0xeeee, 0xeeee, 0xeeee,
        0xeeee, 0xeeee, 0xeeee, 0xeeee,
    };
    uint16_t expected_scatter[] = {
        0x5151, 0xeeee, 0x6262, 0xeeee,
        0x7373, 0xeeee, 0x8484, 0xeeee,
    };
    uint16_t out_gather[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a6 = 4;
    uint64_t t0 = 4;
    uint64_t t1 = 4;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, gather_input, sizeof(gather_input)));
    OK(uc_mem_write(uc, a2, store_input, sizeof(store_input)));
    OK(uc_mem_write(uc, a3, scatter, sizeof(scatter)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, out_gather, sizeof(out_gather)));
    OK(uc_mem_read(uc, a3, scatter, sizeof(scatter)));
    for (i = 0; i < sizeof(expected_gather) / sizeof(expected_gather[0]);
         i++) {
        TEST_CHECK(out_gather[i] == expected_gather[i]);
    }
    for (i = 0; i < sizeof(expected_scatter) / sizeof(expected_scatter[0]);
         i++) {
        TEST_CHECK(scatter[i] == expected_scatter[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_negative_stride_load(void)
{
    uc_engine *uc;
    uint8_t code[3 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_rvv_stride_ldst(0, 5, 1, 10, 5, 1, 1),
        riscv_encode_rvv_ldst(1, 5, 1, 11, 1),
    };
    uint16_t input[] = {
        0x1111, 0x2222, 0x3333, 0x4444,
    };
    uint16_t expected[] = {
        0x4444, 0x3333, 0x2222, 0x1111,
    };
    uint16_t output[4] = { 0 };
    uint64_t data = code_start + 0x1000;
    uint64_t a0 = data + 3 * sizeof(input[0]);
    uint64_t a1 = code_start + 0x1100;
    uint64_t a6 = 4;
    uint64_t t0 = (uint64_t)-2;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, data, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, output, sizeof(output)));
    for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_masked_strided_memory(void)
{
    uc_engine *uc;
    uint8_t code[6 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_stride_ldst(0, 0, 0, 11, 5, 1, 1),
        riscv_encode_rvv_ldst(1, 0, 1, 12, 1),
        riscv_encode_rvv_ldst(0, 0, 1, 13, 2),
        riscv_encode_rvv_stride_ldst(1, 0, 0, 14, 5, 2, 1),
    };
    uint8_t mask_input[] = { 0xad };
    uint8_t gather_input[] = {
        10, 11, 20, 21, 30, 31, 40, 41,
        50, 51, 60, 61, 70, 71, 80, 81,
    };
    uint8_t store_input[] = {
        1, 2, 3, 4, 5, 6, 7, 8,
    };
    uint8_t expected_loaded[] = {
        10, 0xff, 30, 40, 0xff, 60, 0xff, 80,
    };
    uint8_t scatter[16] = {
        0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
        0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    };
    uint8_t expected_scatter[] = {
        1, 0xee, 0xee, 0xee, 3, 0xee, 4, 0xee,
        0xee, 0xee, 6, 0xee, 0xee, 0xee, 8, 0xee,
    };
    uint8_t out_loaded[8] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a6 = 8;
    uint64_t t0 = 2;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask_input, sizeof(mask_input)));
    OK(uc_mem_write(uc, a1, gather_input, sizeof(gather_input)));
    OK(uc_mem_write(uc, a3, store_input, sizeof(store_input)));
    OK(uc_mem_write(uc, a4, scatter, sizeof(scatter)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_loaded, sizeof(out_loaded)));
    OK(uc_mem_read(uc, a4, scatter, sizeof(scatter)));
    for (i = 0; i < sizeof(expected_loaded); i++) {
        TEST_CHECK(out_loaded[i] == expected_loaded[i]);
    }
    for (i = 0; i < sizeof(expected_scatter); i++) {
        TEST_CHECK(scatter[i] == expected_scatter[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_strided_segment_memory(void)
{
    uc_engine *uc;
    uint8_t code[7 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_rvv_stride_ldst(0, 5, 1, 10, 5, 2, 2),
        riscv_encode_rvv_ldst(1, 5, 1, 11, 2),
        riscv_encode_rvv_ldst(1, 5, 1, 12, 3),
        riscv_encode_rvv_ldst(0, 5, 1, 13, 4),
        riscv_encode_rvv_ldst(0, 5, 1, 14, 5),
        riscv_encode_rvv_stride_ldst(1, 5, 1, 15, 5, 4, 2),
    };
    uint16_t segment_input[12] = {
        0x101, 0x201, 0xeeee, 0xeeee,
        0x102, 0x202, 0xeeee, 0xeeee,
        0x103, 0x203, 0xeeee, 0xeeee,
    };
    uint16_t store_field0[] = {
        0x111, 0x222, 0x333,
    };
    uint16_t store_field1[] = {
        0xaaa, 0xbbb, 0xccc,
    };
    uint16_t expected_field0[] = {
        0x101, 0x102, 0x103,
    };
    uint16_t expected_field1[] = {
        0x201, 0x202, 0x203,
    };
    uint16_t segment_output[12] = {
        0xeeee, 0xeeee, 0xeeee, 0xeeee,
        0xeeee, 0xeeee, 0xeeee, 0xeeee,
        0xeeee, 0xeeee, 0xeeee, 0xeeee,
    };
    uint16_t expected_segment_output[] = {
        0x111, 0xaaa, 0xeeee, 0xeeee,
        0x222, 0xbbb, 0xeeee, 0xeeee,
        0x333, 0xccc, 0xeeee, 0xeeee,
    };
    uint16_t out_field0[3] = { 0 };
    uint16_t out_field1[3] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = 3;
    uint64_t t0 = 8;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, segment_input, sizeof(segment_input)));
    OK(uc_mem_write(uc, a3, store_field0, sizeof(store_field0)));
    OK(uc_mem_write(uc, a4, store_field1, sizeof(store_field1)));
    OK(uc_mem_write(uc, a5, segment_output, sizeof(segment_output)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, out_field0, sizeof(out_field0)));
    OK(uc_mem_read(uc, a2, out_field1, sizeof(out_field1)));
    OK(uc_mem_read(uc, a5, segment_output, sizeof(segment_output)));
    for (i = 0; i < sizeof(expected_field0) / sizeof(expected_field0[0]);
         i++) {
        TEST_CHECK(out_field0[i] == expected_field0[i]);
        TEST_CHECK(out_field1[i] == expected_field1[i]);
    }
    for (i = 0;
         i < sizeof(expected_segment_output) /
             sizeof(expected_segment_output[0]);
         i++) {
        TEST_CHECK(segment_output[i] == expected_segment_output[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_strided_memory_illegal(void)
{
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_stride_ldst(0, 0, 0, 10, 5, 0, 1));
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_stride_ldst(0, 0, 1, 10, 5, 1, 1), 0xc1);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_stride_ldst(0, 7, 1, 10, 5, 0, 2), 0xc0);
}

static void test_riscv64_rvv_indexed_load_store(void)
{
    uc_engine *uc;
    uint8_t code[10 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_rvv_ldst(0, 0, 1, 10, 1),
        riscv_encode_rvv_index_ldst(0, 0, 1, 1, 11, 1, 2, 1),
        riscv_encode_rvv_ldst(1, 5, 1, 12, 2),
        riscv_encode_rvv_index_ldst(0, 0, 3, 1, 11, 1, 3, 1),
        riscv_encode_rvv_ldst(1, 5, 1, 13, 3),
        riscv_encode_rvv_ldst(0, 5, 1, 14, 4),
        riscv_encode_rvv_index_ldst(1, 0, 1, 1, 15, 1, 4, 1),
        riscv_encode_rvv_ldst(0, 5, 1, 17, 5),
        riscv_encode_rvv_index_ldst(1, 0, 3, 1, 6, 1, 5, 1),
    };
    uint8_t offsets[] = { 0, 4, 8, 12 };
    uint16_t gather_input[] = {
        0x1010, 0xeeee, 0x2020, 0xeeee,
        0x3030, 0xeeee, 0x4040, 0xeeee,
    };
    uint16_t store_input[] = {
        0x5151, 0x6262, 0x7373, 0x8484,
    };
    uint16_t ordered_store_input[] = {
        0x9191, 0xa2a2, 0xb3b3, 0xc4c4,
    };
    uint16_t expected_gather[] = {
        0x1010, 0x2020, 0x3030, 0x4040,
    };
    uint16_t expected_scatter[] = {
        0x5151, 0xeeee, 0x6262, 0xeeee,
        0x7373, 0xeeee, 0x8484, 0xeeee,
    };
    uint16_t expected_ordered_scatter[] = {
        0x9191, 0xeeee, 0xa2a2, 0xeeee,
        0xb3b3, 0xeeee, 0xc4c4, 0xeeee,
    };
    uint16_t out_unordered[4] = { 0 };
    uint16_t out_ordered[4] = { 0 };
    uint16_t scatter[8] = {
        0xeeee, 0xeeee, 0xeeee, 0xeeee,
        0xeeee, 0xeeee, 0xeeee, 0xeeee,
    };
    uint16_t ordered_scatter[8] = {
        0xeeee, 0xeeee, 0xeeee, 0xeeee,
        0xeeee, 0xeeee, 0xeeee, 0xeeee,
    };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = 4;
    uint64_t a7 = code_start + 0x1600;
    uint64_t t1 = code_start + 0x1700;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, offsets, sizeof(offsets)));
    OK(uc_mem_write(uc, a1, gather_input, sizeof(gather_input)));
    OK(uc_mem_write(uc, a4, store_input, sizeof(store_input)));
    OK(uc_mem_write(uc, a5, scatter, sizeof(scatter)));
    OK(uc_mem_write(uc, a7, ordered_store_input,
                    sizeof(ordered_store_input)));
    OK(uc_mem_write(uc, t1, ordered_scatter, sizeof(ordered_scatter)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_unordered, sizeof(out_unordered)));
    OK(uc_mem_read(uc, a3, out_ordered, sizeof(out_ordered)));
    OK(uc_mem_read(uc, a5, scatter, sizeof(scatter)));
    OK(uc_mem_read(uc, t1, ordered_scatter, sizeof(ordered_scatter)));
    for (i = 0; i < sizeof(expected_gather) / sizeof(expected_gather[0]);
         i++) {
        TEST_CHECK(out_unordered[i] == expected_gather[i]);
        TEST_CHECK(out_ordered[i] == expected_gather[i]);
    }
    for (i = 0; i < sizeof(expected_scatter) / sizeof(expected_scatter[0]);
         i++) {
        TEST_CHECK(scatter[i] == expected_scatter[i]);
        TEST_CHECK(ordered_scatter[i] == expected_ordered_scatter[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_indexed_mixed_widths(void)
{
    uc_engine *uc;
    uint8_t code[12 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_rvv_ldst(0, 5, 1, 10, 2),
        riscv_encode_rvv_index_ldst(0, 5, 1, 1, 11, 2, 4, 1),
        riscv_encode_rvv_ldst(1, 0, 1, 12, 4),
        riscv_encode_rvv_vsetvli(0, 16, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 13, 1),
        riscv_encode_rvv_index_ldst(0, 6, 1, 1, 14, 1, 2, 1),
        riscv_encode_rvv_ldst(1, 6, 1, 15, 2),
        riscv_encode_rvv_vsetvli(0, 16, 0xd8),
        riscv_encode_rvv_ldst(0, 7, 1, 17, 1),
        riscv_encode_rvv_index_ldst(0, 7, 1, 1, 5, 1, 2, 1),
        riscv_encode_rvv_ldst(1, 7, 1, 6, 2),
    };
    uint16_t offsets16[] = { 0, 2, 4, 6 };
    uint32_t offsets32[] = { 0, 8, 16, 24 };
    uint64_t offsets64[] = { 0, 16, 32, 48 };
    uint8_t data8[] = {
        10, 0xee, 20, 0xee, 30, 0xee, 40, 0xee,
    };
    uint32_t data32[] = {
        0x10101010, 0xeeeeeeee, 0x20202020, 0xeeeeeeee,
        0x30303030, 0xeeeeeeee, 0x40404040, 0xeeeeeeee,
    };
    uint64_t data64[] = {
        0x1111111111111111ull, 0xeeeeeeeeeeeeeeeeull,
        0x2222222222222222ull, 0xeeeeeeeeeeeeeeeeull,
        0x3333333333333333ull, 0xeeeeeeeeeeeeeeeeull,
        0x4444444444444444ull, 0xeeeeeeeeeeeeeeeeull,
    };
    uint8_t expected8[] = { 10, 20, 30, 40 };
    uint32_t expected32[] = {
        0x10101010, 0x20202020, 0x30303030, 0x40404040,
    };
    uint64_t expected64[] = {
        0x1111111111111111ull, 0x2222222222222222ull,
    };
    uint8_t out8[4] = { 0 };
    uint32_t out32[4] = { 0 };
    uint64_t out64[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = 4;
    uint64_t a7 = code_start + 0x1600;
    uint64_t t0 = code_start + 0x1700;
    uint64_t t1 = code_start + 0x1800;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, offsets16, sizeof(offsets16)));
    OK(uc_mem_write(uc, a1, data8, sizeof(data8)));
    OK(uc_mem_write(uc, a3, offsets32, sizeof(offsets32)));
    OK(uc_mem_write(uc, a4, data32, sizeof(data32)));
    OK(uc_mem_write(uc, a7, offsets64, sizeof(offsets64)));
    OK(uc_mem_write(uc, t0, data64, sizeof(data64)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out8, sizeof(out8)));
    OK(uc_mem_read(uc, a5, out32, sizeof(out32)));
    OK(uc_mem_read(uc, t1, out64, sizeof(out64)));
    for (i = 0; i < sizeof(expected8); i++) {
        TEST_CHECK(out8[i] == expected8[i]);
    }
    for (i = 0; i < sizeof(expected32) / sizeof(expected32[0]); i++) {
        TEST_CHECK(out32[i] == expected32[i]);
    }
    for (i = 0; i < sizeof(expected64) / sizeof(expected64[0]); i++) {
        TEST_CHECK(out64[i] == expected64[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_masked_indexed_memory(void)
{
    uc_engine *uc;
    uint8_t code[7 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 0, 1, 11, 1),
        riscv_encode_rvv_index_ldst(0, 0, 1, 0, 12, 1, 2, 1),
        riscv_encode_rvv_ldst(1, 0, 1, 13, 2),
        riscv_encode_rvv_ldst(0, 0, 1, 14, 3),
        riscv_encode_rvv_index_ldst(1, 0, 1, 0, 15, 1, 3, 1),
    };
    uint8_t mask_input[] = { 0xad };
    uint8_t offsets[] = { 0, 2, 4, 6, 8, 10, 12, 14 };
    uint8_t gather_input[] = {
        10, 0xee, 20, 0xee, 30, 0xee, 40, 0xee,
        50, 0xee, 60, 0xee, 70, 0xee, 80, 0xee,
    };
    uint8_t expected_loaded[] = {
        10, 0xff, 30, 40, 0xff, 60, 0xff, 80,
    };
    uint8_t store_input[] = {
        1, 2, 3, 4, 5, 6, 7, 8,
    };
    uint8_t scatter[16] = {
        0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
        0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    };
    uint8_t expected_scatter[] = {
        1, 0xee, 0xee, 0xee, 3, 0xee, 4, 0xee,
        0xee, 0xee, 6, 0xee, 0xee, 0xee, 8, 0xee,
    };
    uint8_t out_loaded[8] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = 8;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask_input, sizeof(mask_input)));
    OK(uc_mem_write(uc, a1, offsets, sizeof(offsets)));
    OK(uc_mem_write(uc, a2, gather_input, sizeof(gather_input)));
    OK(uc_mem_write(uc, a4, store_input, sizeof(store_input)));
    OK(uc_mem_write(uc, a5, scatter, sizeof(scatter)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_loaded, sizeof(out_loaded)));
    OK(uc_mem_read(uc, a5, scatter, sizeof(scatter)));
    for (i = 0; i < sizeof(expected_loaded); i++) {
        TEST_CHECK(out_loaded[i] == expected_loaded[i]);
    }
    for (i = 0; i < sizeof(expected_scatter); i++) {
        TEST_CHECK(scatter[i] == expected_scatter[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_indexed_segment_memory(void)
{
    uc_engine *uc;
    uint8_t code[8 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_rvv_ldst(0, 0, 1, 10, 1),
        riscv_encode_rvv_index_ldst(0, 0, 1, 1, 11, 1, 2, 2),
        riscv_encode_rvv_ldst(1, 5, 1, 12, 2),
        riscv_encode_rvv_ldst(1, 5, 1, 13, 3),
        riscv_encode_rvv_ldst(0, 5, 1, 14, 4),
        riscv_encode_rvv_ldst(0, 5, 1, 15, 5),
        riscv_encode_rvv_index_ldst(1, 0, 1, 1, 17, 1, 4, 2),
    };
    uint8_t offsets[] = { 0, 8, 16 };
    uint16_t segment_input[12] = {
        0x101, 0x201, 0xeeee, 0xeeee,
        0x102, 0x202, 0xeeee, 0xeeee,
        0x103, 0x203, 0xeeee, 0xeeee,
    };
    uint16_t store_fields[] = {
        0x111, 0x222, 0x333, 0xaaa, 0xbbb, 0xccc,
    };
    uint16_t expected_field0[] = {
        0x101, 0x102, 0x103,
    };
    uint16_t expected_field1[] = {
        0x201, 0x202, 0x203,
    };
    uint16_t segment_output[12] = {
        0xeeee, 0xeeee, 0xeeee, 0xeeee,
        0xeeee, 0xeeee, 0xeeee, 0xeeee,
        0xeeee, 0xeeee, 0xeeee, 0xeeee,
    };
    uint16_t expected_segment_output[] = {
        0x111, 0xaaa, 0xeeee, 0xeeee,
        0x222, 0xbbb, 0xeeee, 0xeeee,
        0x333, 0xccc, 0xeeee, 0xeeee,
    };
    uint16_t out_field0[3] = { 0 };
    uint16_t out_field1[3] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = a4 + 3 * sizeof(store_fields[0]);
    uint64_t a6 = 3;
    uint64_t a7 = code_start + 0x1500;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, offsets, sizeof(offsets)));
    OK(uc_mem_write(uc, a1, segment_input, sizeof(segment_input)));
    OK(uc_mem_write(uc, a4, store_fields, sizeof(store_fields)));
    OK(uc_mem_write(uc, a7, segment_output, sizeof(segment_output)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_field0, sizeof(out_field0)));
    OK(uc_mem_read(uc, a3, out_field1, sizeof(out_field1)));
    OK(uc_mem_read(uc, a7, segment_output, sizeof(segment_output)));
    for (i = 0; i < sizeof(expected_field0) / sizeof(expected_field0[0]);
         i++) {
        TEST_CHECK(out_field0[i] == expected_field0[i]);
        TEST_CHECK(out_field1[i] == expected_field1[i]);
    }
    for (i = 0;
         i < sizeof(expected_segment_output) /
             sizeof(expected_segment_output[0]);
         i++) {
        TEST_CHECK(segment_output[i] == expected_segment_output[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_indexed_memory_illegal(void)
{
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_index_ldst(0, 0, 1, 0, 10, 5, 0, 1));
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_index_ldst(0, 7, 1, 1, 10, 1, 8, 1), 0xc0);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_index_ldst(0, 0, 1, 1, 10, 1, 1, 1), 0xc8);
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_index_ldst(0, 0, 1, 1, 10, 1, 31, 2));
}

static void test_riscv64_rvv_fault_only_first_segment(void)
{
    uc_engine *uc;
    uint8_t code[4 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_rvv_ff_load(5, 1, 10, 2, 2),
        riscv_encode_rvv_ldst(1, 5, 1, 11, 2),
        riscv_encode_rvv_ldst(1, 5, 1, 12, 3),
    };
    uint16_t segment_input[] = {
        0x101, 0x201, 0x102, 0x202, 0x103, 0x203,
    };
    uint16_t expected_field0[] = {
        0x101, 0x102, 0x103,
    };
    uint16_t expected_field1[] = {
        0x201, 0x202, 0x203,
    };
    uint16_t out_field0[3] = { 0 };
    uint16_t out_field1[3] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a6 = 3;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, segment_input, sizeof(segment_input)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, out_field0, sizeof(out_field0)));
    OK(uc_mem_read(uc, a2, out_field1, sizeof(out_field1)));
    for (i = 0; i < sizeof(expected_field0) / sizeof(expected_field0[0]);
         i++) {
        TEST_CHECK(out_field0[i] == expected_field0[i]);
        TEST_CHECK(out_field1[i] == expected_field1[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_masked_fault_only_first(void)
{
    uc_engine *uc;
    uint8_t code[4 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ff_load(0, 0, 11, 1, 1),
        riscv_encode_rvv_ldst(1, 0, 1, 12, 1),
    };
    uint8_t mask_input[] = { 0xad };
    uint8_t input[] = {
        10, 20, 30, 40, 50, 60, 70, 80,
    };
    uint8_t expected[] = {
        10, 0xff, 30, 40, 0xff, 60, 0xff, 80,
    };
    uint8_t output[8] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a6 = 8;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask_input, sizeof(mask_input)));
    OK(uc_mem_write(uc, a1, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, output, sizeof(output)));
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_fault_only_first_partial_fault(void)
{
    uc_engine *uc;
    uint8_t code[3 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_rvv_ff_load(5, 1, 10, 1, 1),
        riscv_encode_rvv_ldst(1, 5, 1, 11, 1),
    };
    uint16_t input[] = {
        0x1111, 0x2222,
    };
    uint16_t output[4] = {
        0xeeee, 0xeeee, 0xeeee, 0xeeee,
    };
    uint16_t expected[] = {
        0x1111, 0x2222, 0xeeee, 0xeeee,
    };
    uint64_t a0 = code_start + code_len - sizeof(input);
    uint64_t a1 = code_start + 0x1000;
    uint64_t a6 = 4;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, input, sizeof(input)));
    OK(uc_mem_write(uc, a1, output, sizeof(output)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, output, sizeof(output)));
    for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_fault_only_first_first_fault(void)
{
    uc_engine *uc;
    uint8_t code[2 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_rvv_ff_load(5, 1, 10, 1, 1),
    };
    uint64_t a0 = code_start + code_len;
    uint64_t a6 = 4;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    uc_assert_err(UC_ERR_READ_UNMAPPED,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_close(uc));
}

static void test_riscv64_rvv_fault_only_first_illegal(void)
{
    run_riscv64_rvv_illegal(riscv_encode_rvv_ff_load(0, 0, 10, 0, 1));
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_ff_load(7, 1, 10, 0, 2), 0xc0);
}

static void test_riscv64_rvv_whole_register_single(void)
{
    uc_engine *uc;
    uint8_t code[8 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_whole_ldst(0, 0, 10, 1, 1),
        riscv_encode_rvv_whole_ldst(1, 0, 11, 1, 1),
        riscv_encode_rvv_whole_ldst(0, 5, 12, 2, 1),
        riscv_encode_rvv_whole_ldst(1, 0, 13, 2, 1),
        riscv_encode_rvv_whole_ldst(0, 6, 14, 3, 1),
        riscv_encode_rvv_whole_ldst(1, 0, 15, 3, 1),
        riscv_encode_rvv_whole_ldst(0, 7, 16, 4, 1),
        riscv_encode_rvv_whole_ldst(1, 0, 17, 4, 1),
    };
    uint8_t input8[16];
    uint8_t input16[16];
    uint8_t input32[16];
    uint8_t input64[16];
    uint8_t output8[16] = { 0 };
    uint8_t output16[16] = { 0 };
    uint8_t output32[16] = { 0 };
    uint8_t output64[16] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    size_t i;

    for (i = 0; i < sizeof(input8); i++) {
        input8[i] = (uint8_t)(0x10 + i);
        input16[i] = (uint8_t)(0x30 + i);
        input32[i] = (uint8_t)(0x50 + i);
        input64[i] = (uint8_t)(0x70 + i);
    }
    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, input8, sizeof(input8)));
    OK(uc_mem_write(uc, a2, input16, sizeof(input16)));
    OK(uc_mem_write(uc, a4, input32, sizeof(input32)));
    OK(uc_mem_write(uc, a6, input64, sizeof(input64)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, output8, sizeof(output8)));
    OK(uc_mem_read(uc, a3, output16, sizeof(output16)));
    OK(uc_mem_read(uc, a5, output32, sizeof(output32)));
    OK(uc_mem_read(uc, a7, output64, sizeof(output64)));
    for (i = 0; i < sizeof(input8); i++) {
        TEST_CHECK(output8[i] == input8[i]);
        TEST_CHECK(output16[i] == input16[i]);
        TEST_CHECK(output32[i] == input32[i]);
        TEST_CHECK(output64[i] == input64[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_whole_register_groups(void)
{
    uc_engine *uc;
    uint8_t code[6 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_whole_ldst(0, 0, 10, 2, 2),
        riscv_encode_rvv_whole_ldst(1, 0, 11, 2, 2),
        riscv_encode_rvv_whole_ldst(0, 5, 12, 4, 4),
        riscv_encode_rvv_whole_ldst(1, 0, 13, 4, 4),
        riscv_encode_rvv_whole_ldst(0, 6, 14, 8, 8),
        riscv_encode_rvv_whole_ldst(1, 0, 15, 8, 8),
    };
    uint8_t input2[32];
    uint8_t input4[64];
    uint8_t input8[128];
    uint8_t output2[32] = { 0 };
    uint8_t output4[64] = { 0 };
    uint8_t output8[128] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1200;
    uint64_t a2 = code_start + 0x1400;
    uint64_t a3 = code_start + 0x1800;
    uint64_t a4 = code_start + 0x1c00;
    uint64_t a5 = code_start + 0x2400;
    size_t i;

    for (i = 0; i < sizeof(input8); i++) {
        if (i < sizeof(input2)) {
            input2[i] = (uint8_t)(0x20 + i);
        }
        if (i < sizeof(input4)) {
            input4[i] = (uint8_t)(0x60 + i);
        }
        input8[i] = (uint8_t)(0xa0 + i);
    }
    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, input2, sizeof(input2)));
    OK(uc_mem_write(uc, a2, input4, sizeof(input4)));
    OK(uc_mem_write(uc, a4, input8, sizeof(input8)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, output2, sizeof(output2)));
    OK(uc_mem_read(uc, a3, output4, sizeof(output4)));
    OK(uc_mem_read(uc, a5, output8, sizeof(output8)));
    for (i = 0; i < sizeof(input8); i++) {
        if (i < sizeof(input2)) {
            TEST_CHECK(output2[i] == input2[i]);
        }
        if (i < sizeof(input4)) {
            TEST_CHECK(output4[i] == input4[i]);
        }
        TEST_CHECK(output8[i] == input8[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_whole_register_ignores_vl_vill(void)
{
    uc_engine *uc;
    uint8_t code[6 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_rvv_whole_ldst(0, 0, 10, 1, 1),
        riscv_encode_rvv_whole_ldst(1, 0, 11, 1, 1),
        riscv_encode_rvv_vsetvli(0, 17, 0x400),
        riscv_encode_rvv_whole_ldst(0, 0, 12, 2, 1),
        riscv_encode_rvv_whole_ldst(1, 0, 13, 2, 1),
    };
    uint8_t input_vl0[16];
    uint8_t input_vill[16];
    uint8_t output_vl0[16] = { 0 };
    uint8_t output_vill[16] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a6 = 0;
    uint64_t a7 = 5;
    size_t i;

    for (i = 0; i < sizeof(input_vl0); i++) {
        input_vl0[i] = (uint8_t)(0x40 + i);
        input_vill[i] = (uint8_t)(0x80 + i);
    }
    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, input_vl0, sizeof(input_vl0)));
    OK(uc_mem_write(uc, a2, input_vill, sizeof(input_vill)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, output_vl0, sizeof(output_vl0)));
    OK(uc_mem_read(uc, a3, output_vill, sizeof(output_vill)));
    for (i = 0; i < sizeof(input_vl0); i++) {
        TEST_CHECK(output_vl0[i] == input_vl0[i]);
        TEST_CHECK(output_vill[i] == input_vill[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_whole_register_vstart(void)
{
    uc_engine *uc;
    uint8_t code[5 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_whole_ldst(0, 0, 10, 1, 1),
        riscv_encode_csr(RISCV_CSR_VSTART, 5, 1, 0),
        riscv_encode_rvv_whole_ldst(0, 0, 11, 1, 1),
        riscv_encode_rvv_whole_ldst(1, 0, 12, 1, 1),
        riscv_encode_csr(RISCV_CSR_VSTART, 0, 2, 6),
    };
    uint8_t seed[16];
    uint8_t source[16];
    uint8_t expected[16];
    uint8_t output[16] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t t0 = 8;
    uint64_t t1 = 0xffff;
    size_t i;

    for (i = 0; i < sizeof(seed); i++) {
        seed[i] = (uint8_t)(0x10 + i);
        source[i] = (uint8_t)(0x80 + i);
        expected[i] = i < 8 ? seed[i] : source[i];
    }
    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, seed, sizeof(seed)));
    OK(uc_mem_write(uc, a1, source, sizeof(source)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, output, sizeof(output)));
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &t1));
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }
    TEST_CHECK(t1 == 0);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_whole_register_illegal(void)
{
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_whole_ldst(0, 0, 10, 1, 2));
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_whole_ldst(0, 5, 10, 2, 4));
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_whole_ldst(1, 0, 10, 4, 8));
}

static void test_riscv32_rvv_whole_register_smoke(void)
{
    uc_engine *uc;
    uint8_t code[2 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_whole_ldst(0, 0, 10, 1, 1),
        riscv_encode_rvv_whole_ldst(1, 0, 11, 1, 1),
    };
    uint8_t input[16];
    uint8_t output[16] = { 0 };
    uint32_t a0 = code_start + 0x1000;
    uint32_t a1 = code_start + 0x1100;
    size_t i;

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(0x30 + i);
    }
    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32,
                    (const char *)code, sizeof(code));
    riscv32_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, output, sizeof(output)));
    for (i = 0; i < sizeof(input); i++) {
        TEST_CHECK(output[i] == input[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_float32_arith(void)
{
    uc_engine *uc;
    uint8_t code[19 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_op(0x00, 1, 1, 2, 1, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x02, 1, 1, 2, 1, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 4),
        riscv_encode_rvv_op(0x24, 1, 1, 2, 1, 5),
        riscv_encode_rvv_ldst(1, 6, 1, 14, 5),
        riscv_encode_rvv_op(0x20, 1, 1, 2, 1, 6),
        riscv_encode_rvv_ldst(1, 6, 1, 15, 6),
        riscv_encode_rvv_op(0x00, 1, 1, 1, 5, 7),
        riscv_encode_rvv_ldst(1, 6, 1, 16, 7),
        riscv_encode_rvv_op(0x02, 1, 1, 1, 5, 8),
        riscv_encode_rvv_ldst(1, 6, 1, 17, 8),
        riscv_encode_rvv_op(0x24, 1, 1, 1, 5, 9),
        riscv_encode_rvv_ldst(1, 6, 1, 28, 9),
        riscv_encode_rvv_op(0x20, 1, 1, 1, 5, 10),
        riscv_encode_rvv_ldst(1, 6, 1, 29, 10),
    };
    uint32_t src2[] = {
        0x41000000u, 0x40800000u, 0xc0c00000u, 0x41100000u,
    };
    uint32_t src1[] = {
        0x40000000u, 0xc0000000u, 0x40400000u, 0x00000000u,
    };
    uint32_t expected_add_vv[] = {
        0x41200000u, 0x40000000u, 0xc0400000u, 0x41100000u,
    };
    uint32_t expected_sub_vv[] = {
        0x40c00000u, 0x40c00000u, 0xc1100000u, 0x41100000u,
    };
    uint32_t expected_mul_vv[] = {
        0x41800000u, 0xc1000000u, 0xc1900000u, 0x00000000u,
    };
    uint32_t expected_div_vv[] = {
        0x40800000u, 0xc0000000u, 0xc0000000u, 0x7f800000u,
    };
    uint32_t expected_add_vf[] = {
        0x41200000u, 0x40c00000u, 0xc0800000u, 0x41300000u,
    };
    uint32_t expected_sub_vf[] = {
        0x40c00000u, 0x40000000u, 0xc1000000u, 0x40e00000u,
    };
    uint32_t expected_mul_vf[] = {
        0x41800000u, 0x41000000u, 0xc1400000u, 0x41900000u,
    };
    uint32_t expected_div_vf[] = {
        0x40800000u, 0x40000000u, 0xc0400000u, 0x40900000u,
    };
    uint32_t out_add_vv[4] = { 0 };
    uint32_t out_sub_vv[4] = { 0 };
    uint32_t out_mul_vv[4] = { 0 };
    uint32_t out_div_vv[4] = { 0 };
    uint32_t out_add_vf[4] = { 0 };
    uint32_t out_sub_vf[4] = { 0 };
    uint32_t out_mul_vf[4] = { 0 };
    uint32_t out_div_vf[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 4;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    uint64_t f1 = 0xffffffff40000000ull;
    uint64_t fflags = 0;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a1, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &f1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_add_vv, sizeof(out_add_vv)));
    OK(uc_mem_read(uc, a3, out_sub_vv, sizeof(out_sub_vv)));
    OK(uc_mem_read(uc, a4, out_mul_vv, sizeof(out_mul_vv)));
    OK(uc_mem_read(uc, a5, out_div_vv, sizeof(out_div_vv)));
    OK(uc_mem_read(uc, a6, out_add_vf, sizeof(out_add_vf)));
    OK(uc_mem_read(uc, a7, out_sub_vf, sizeof(out_sub_vf)));
    OK(uc_mem_read(uc, t3, out_mul_vf, sizeof(out_mul_vf)));
    OK(uc_mem_read(uc, t4, out_div_vf, sizeof(out_div_vf)));
    OK(uc_reg_read(uc, UC_RISCV_REG_FFLAGS, &fflags));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_add_vv[i] == expected_add_vv[i]);
        TEST_CHECK(out_sub_vv[i] == expected_sub_vv[i]);
        TEST_CHECK(out_mul_vv[i] == expected_mul_vv[i]);
        TEST_CHECK(out_div_vv[i] == expected_div_vv[i]);
        TEST_CHECK(out_add_vf[i] == expected_add_vf[i]);
        TEST_CHECK(out_sub_vf[i] == expected_sub_vf[i]);
        TEST_CHECK(out_mul_vf[i] == expected_mul_vf[i]);
        TEST_CHECK(out_div_vf[i] == expected_div_vf[i]);
    }
    TEST_CHECK(fflags == 0x08);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_float32_minmax_sign(void)
{
    enum {
        FP32_RSUB_VF,
        FP32_RDIV_VF,
        FP32_MIN_VV,
        FP32_MIN_VF,
        FP32_MAX_VV,
        FP32_MAX_VF,
        FP32_SGNJ_VV,
        FP32_SGNJ_VF,
        FP32_SGNJN_VV,
        FP32_SGNJN_VF,
        FP32_SGNJX_VV,
        FP32_SGNJX_VF,
        FP32_OPS,
    };
    uc_engine *uc;
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_op(0x27, 1, 1, 1, 5, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_op(0x21, 1, 1, 1, 5, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 4),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_op(0x04, 1, 1, 2, 1, 5),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 5),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_op(0x04, 1, 1, 1, 5, 6),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 6),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_op(0x06, 1, 1, 2, 1, 7),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 7),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_op(0x06, 1, 1, 1, 5, 8),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 8),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_op(0x08, 1, 1, 2, 1, 9),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 9),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_op(0x08, 1, 1, 1, 5, 10),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 10),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_op(0x09, 1, 1, 2, 1, 11),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 11),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_op(0x09, 1, 1, 1, 5, 12),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 12),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_op(0x0a, 1, 1, 2, 1, 13),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 13),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_op(0x0a, 1, 1, 1, 5, 14),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 14),
        riscv_encode_csr(RISCV_CSR_FFLAGS, 0, 2, 6),
    };
    uint8_t code[sizeof(insns)];
    uint32_t src2[] = {
        0x40800000u, 0xbf800000u, 0x7f800001u, 0x41000000u,
    };
    uint32_t src1[] = {
        0x3f800000u, 0xc0400000u, 0x40a00000u, 0xc0c00000u,
    };
    uint32_t expected[FP32_OPS][4] = {
        { 0xc0c00000u, 0xbf800000u, 0x7fc00000u, 0xc1200000u },
        { 0xbf000000u, 0x40000000u, 0x7fc00000u, 0xbe800000u },
        { 0x3f800000u, 0xc0400000u, 0x40a00000u, 0xc0c00000u },
        { 0xc0000000u, 0xc0000000u, 0xc0000000u, 0xc0000000u },
        { 0x40800000u, 0xbf800000u, 0x40a00000u, 0x41000000u },
        { 0x40800000u, 0xbf800000u, 0xc0000000u, 0x41000000u },
        { 0x40800000u, 0xbf800000u, 0x7f800001u, 0xc1000000u },
        { 0xc0800000u, 0xbf800000u, 0xff800001u, 0xc1000000u },
        { 0xc0800000u, 0x3f800000u, 0xff800001u, 0x41000000u },
        { 0x40800000u, 0x3f800000u, 0x7f800001u, 0x41000000u },
        { 0x40800000u, 0x3f800000u, 0x7f800001u, 0xc1000000u },
        { 0xc0800000u, 0x3f800000u, 0xff800001u, 0xc1000000u },
    };
    const char *names[FP32_OPS] = {
        "vfrsub.vf", "vfrdiv.vf", "vfmin.vv", "vfmin.vf",
        "vfmax.vv", "vfmax.vf", "vfsgnj.vv", "vfsgnj.vf",
        "vfsgnjn.vv", "vfsgnjn.vf", "vfsgnjx.vv", "vfsgnjx.vf",
    };
    uint32_t output[FP32_OPS][4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a3 = code_start + 0x1300;
    uint64_t t0 = 4;
    uint64_t f1 = 0xffffffffc0000000ull;
    uint64_t t1;
    size_t i;
    size_t j;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a1, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &f1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, code_start + 0x1300, output, sizeof(output)));
    for (i = 0; i < FP32_OPS; i++) {
        for (j = 0; j < 4; j++) {
            TEST_CHECK_(output[i][j] == expected[i][j],
                        "%s lane %u: got 0x%08x expected 0x%08x",
                        names[i], (unsigned)j, output[i][j],
                        expected[i][j]);
        }
    }
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &t1));
    TEST_CHECK(t1 == 0x10);

    OK(uc_close(uc));
}

static void test_riscv32_rvv_float32_minmax_sign_smoke(void)
{
    uc_engine *uc;
    uint8_t code[7 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_op(0x06, 1, 1, 2, 1, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x08, 1, 1, 1, 5, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 4),
    };
    uint32_t src2[] = { 0x3f800000u, 0xc0000000u };
    uint32_t src1[] = { 0x40000000u, 0xc0400000u };
    uint32_t expected_max[] = { 0x40000000u, 0xc0000000u };
    uint32_t expected_sgnj[] = { 0xbf800000u, 0xc0000000u };
    uint32_t out_max[2] = { 0 };
    uint32_t out_sgnj[2] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t t0 = 2;
    uint64_t f1 = 0xffffffffbf800000ull;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32,
                    (const char *)code, sizeof(code));
    riscv32_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a1, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &f1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_max, sizeof(out_max)));
    OK(uc_mem_read(uc, a3, out_sgnj, sizeof(out_sgnj)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_max[i] == expected_max[i]);
        TEST_CHECK(out_sgnj[i] == expected_sgnj[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_float32_compare(void)
{
    uc_engine *uc;
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 2),
        riscv_encode_rvv_op(0x18, 1, 1, 2, 1, 3),
        riscv_encode_rvv_mask_ldst(1, 13, 3),
        riscv_encode_addi(13, 13, 1),
        riscv_encode_rvv_op(0x1b, 1, 1, 2, 1, 4),
        riscv_encode_rvv_mask_ldst(1, 13, 4),
        riscv_encode_addi(13, 13, 1),
        riscv_encode_rvv_op(0x1c, 1, 1, 1, 5, 5),
        riscv_encode_rvv_mask_ldst(1, 13, 5),
        riscv_encode_addi(13, 13, 1),
        riscv_encode_rvv_op(0x1f, 1, 1, 1, 5, 6),
        riscv_encode_rvv_mask_ldst(1, 13, 6),
        riscv_encode_addi(13, 13, 1),
        riscv_encode_rvv_op(0x19, 1, 1, 1, 5, 7),
        riscv_encode_rvv_mask_ldst(1, 13, 7),
        riscv_encode_addi(13, 13, 1),
        riscv_encode_rvv_op(0x1b, 0, 1, 1, 5, 8),
        riscv_encode_rvv_mask_ldst(1, 13, 8),
        riscv_encode_csr(RISCV_CSR_FFLAGS, 0, 2, 6),
    };
    uint8_t code[sizeof(insns)];
    uint8_t mask[] = { 0x05 };
    uint32_t src2[] = {
        0x3f800000u, 0x40000000u, 0x7f800001u, 0xbf800000u,
    };
    uint32_t src1[] = {
        0x3f800000u, 0x40400000u, 0x40800000u, 0xc0000000u,
    };
    uint8_t expected[] = { 0xf1, 0xf2, 0xfd, 0xf2, 0xfb, 0xfb };
    uint8_t output[sizeof(expected)] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t t0 = 4;
    uint64_t t1;
    uint64_t f1 = 0xffffffff40000000ull;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a2, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &f1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, code_start + 0x1300, output, sizeof(output)));
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK_(output[i] == expected[i],
                    "compare mask %u: got 0x%02x expected 0x%02x",
                    (unsigned)i, output[i], expected[i]);
    }
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &t1));
    TEST_CHECK(t1 == 0x10);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_float32_class_merge(void)
{
    uc_engine *uc;
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 1),
        riscv_encode_rvv_op(0x13, 1, 1, 16, 1, 2),
        riscv_encode_rvv_ldst(1, 6, 1, 12, 2),
        riscv_encode_rvv_ldst(0, 6, 1, 13, 3),
        riscv_encode_rvv_op(0x17, 0, 3, 1, 5, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 14, 4),
    };
    uint8_t code[sizeof(insns)];
    uint8_t mask[] = { 0x05 };
    uint32_t class_src[] = {
        0xff800000u, 0x80000000u, 0x00000001u, 0x7f800001u,
    };
    uint32_t merge_src[] = {
        0x3f800000u, 0xbf800000u, 0x40400000u, 0xc0400000u,
    };
    uint32_t expected_class[] = { 0x001u, 0x008u, 0x020u, 0x100u };
    uint32_t expected_merge[] = {
        0x40000000u, 0xbf800000u, 0x40000000u, 0xc0400000u,
    };
    uint32_t out_class[4] = { 0 };
    uint32_t out_merge[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t t0 = 4;
    uint64_t f1 = 0xffffffff40000000ull;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, class_src, sizeof(class_src)));
    OK(uc_mem_write(uc, a3, merge_src, sizeof(merge_src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &f1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_class, sizeof(out_class)));
    OK(uc_mem_read(uc, a4, out_merge, sizeof(out_merge)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_class[i] == expected_class[i]);
        TEST_CHECK(out_merge[i] == expected_merge[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_float32_moves(void)
{
    uc_engine *uc;
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_op(0x17, 1, 0, 1, 5, 1),
        riscv_encode_rvv_ldst(1, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_op(0x10, 1, 0, 2, 5, 2),
        riscv_encode_rvv_ldst(1, 6, 1, 12, 2),
        riscv_encode_rvv_op(0x10, 1, 2, 0, 1, 3),
    };
    uint8_t code[sizeof(insns)];
    uint32_t move_src[] = {
        0x3f800000u, 0xbf800000u, 0x40400000u, 0xc0400000u,
    };
    uint32_t expected_broadcast[] = {
        0x7fc00000u, 0x7fc00000u, 0x7fc00000u, 0x7fc00000u,
    };
    uint32_t expected_scalar_insert[] = {
        0x40000000u, 0xbf800000u, 0x40400000u, 0xc0400000u,
    };
    uint32_t out_broadcast[4] = { 0 };
    uint32_t out_scalar_insert[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t t0 = 4;
    uint64_t f1 = 0x0000000040000000ull;
    uint64_t f2 = 0xffffffff40000000ull;
    uint64_t f3 = 0;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a1, move_src, sizeof(move_src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &f1));
    OK(uc_reg_write(uc, UC_RISCV_REG_F2, &f2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a0, out_broadcast, sizeof(out_broadcast)));
    OK(uc_mem_read(uc, a2, out_scalar_insert, sizeof(out_scalar_insert)));
    OK(uc_reg_read(uc, UC_RISCV_REG_F3, &f3));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_broadcast[i] == expected_broadcast[i]);
        TEST_CHECK(out_scalar_insert[i] == expected_scalar_insert[i]);
    }
    TEST_CHECK(f3 == 0xffffffff40000000ull);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_float64_arith(void)
{
    uc_engine *uc;
    uint8_t code[19 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd8),
        riscv_encode_rvv_ldst(0, 7, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 7, 1, 11, 2),
        riscv_encode_rvv_op(0x00, 1, 1, 2, 1, 3),
        riscv_encode_rvv_ldst(1, 7, 1, 12, 3),
        riscv_encode_rvv_op(0x02, 1, 1, 2, 1, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 4),
        riscv_encode_rvv_op(0x24, 1, 1, 2, 1, 5),
        riscv_encode_rvv_ldst(1, 7, 1, 14, 5),
        riscv_encode_rvv_op(0x20, 1, 1, 2, 1, 6),
        riscv_encode_rvv_ldst(1, 7, 1, 15, 6),
        riscv_encode_rvv_op(0x00, 1, 1, 1, 5, 7),
        riscv_encode_rvv_ldst(1, 7, 1, 16, 7),
        riscv_encode_rvv_op(0x02, 1, 1, 1, 5, 8),
        riscv_encode_rvv_ldst(1, 7, 1, 17, 8),
        riscv_encode_rvv_op(0x24, 1, 1, 1, 5, 9),
        riscv_encode_rvv_ldst(1, 7, 1, 28, 9),
        riscv_encode_rvv_op(0x20, 1, 1, 1, 5, 10),
        riscv_encode_rvv_ldst(1, 7, 1, 29, 10),
    };
    uint64_t src2[] = {
        0x4020000000000000ull, 0xc018000000000000ull,
    };
    uint64_t src1[] = {
        0x4000000000000000ull, 0xc008000000000000ull,
    };
    uint64_t expected_add_vv[] = {
        0x4024000000000000ull, 0xc022000000000000ull,
    };
    uint64_t expected_sub_vv[] = {
        0x4018000000000000ull, 0xc008000000000000ull,
    };
    uint64_t expected_mul_vv[] = {
        0x4030000000000000ull, 0x4032000000000000ull,
    };
    uint64_t expected_div_vv[] = {
        0x4010000000000000ull, 0x4000000000000000ull,
    };
    uint64_t expected_add_vf[] = {
        0x4024000000000000ull, 0xc010000000000000ull,
    };
    uint64_t expected_sub_vf[] = {
        0x4018000000000000ull, 0xc020000000000000ull,
    };
    uint64_t expected_mul_vf[] = {
        0x4030000000000000ull, 0xc028000000000000ull,
    };
    uint64_t expected_div_vf[] = {
        0x4010000000000000ull, 0xc008000000000000ull,
    };
    uint64_t out_add_vv[2] = { 0 };
    uint64_t out_sub_vv[2] = { 0 };
    uint64_t out_mul_vv[2] = { 0 };
    uint64_t out_div_vv[2] = { 0 };
    uint64_t out_add_vf[2] = { 0 };
    uint64_t out_sub_vf[2] = { 0 };
    uint64_t out_mul_vf[2] = { 0 };
    uint64_t out_div_vf[2] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 2;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    uint64_t f1 = 0x4000000000000000ull;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a1, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &f1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_add_vv, sizeof(out_add_vv)));
    OK(uc_mem_read(uc, a3, out_sub_vv, sizeof(out_sub_vv)));
    OK(uc_mem_read(uc, a4, out_mul_vv, sizeof(out_mul_vv)));
    OK(uc_mem_read(uc, a5, out_div_vv, sizeof(out_div_vv)));
    OK(uc_mem_read(uc, a6, out_add_vf, sizeof(out_add_vf)));
    OK(uc_mem_read(uc, a7, out_sub_vf, sizeof(out_sub_vf)));
    OK(uc_mem_read(uc, t3, out_mul_vf, sizeof(out_mul_vf)));
    OK(uc_mem_read(uc, t4, out_div_vf, sizeof(out_div_vf)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_add_vv[i] == expected_add_vv[i]);
        TEST_CHECK(out_sub_vv[i] == expected_sub_vv[i]);
        TEST_CHECK(out_mul_vv[i] == expected_mul_vv[i]);
        TEST_CHECK(out_div_vv[i] == expected_div_vv[i]);
        TEST_CHECK(out_add_vf[i] == expected_add_vf[i]);
        TEST_CHECK(out_sub_vf[i] == expected_sub_vf[i]);
        TEST_CHECK(out_mul_vf[i] == expected_mul_vf[i]);
        TEST_CHECK(out_div_vf[i] == expected_div_vf[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_float32_mask_nanbox(void)
{
    uc_engine *uc;
    uint8_t code[5 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 1),
        riscv_encode_rvv_op(0x00, 0, 1, 1, 5, 2),
        riscv_encode_rvv_ldst(1, 6, 1, 12, 2),
    };
    uint8_t mask[] = { 0x05 };
    uint32_t src[] = {
        0x3f800000u, 0x40000000u, 0x40400000u, 0x40800000u,
    };
    uint32_t expected[] = {
        0x7fc00000u, 0xffffffffu, 0x7fc00000u, 0x00000000u,
    };
    uint32_t output[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t t0 = 3;
    uint64_t f1 = 0x0000000040000000ull;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, src, sizeof(src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &f1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, output, sizeof(output)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK_(output[i] == expected[i],
                    "lane %u: got 0x%08x expected 0x%08x",
                    (unsigned)i, output[i], expected[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_float32_sqrt(void)
{
    uc_engine *uc;
    uint8_t code[5 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_op(0x13, 1, 1, 0, 1, 2),
        riscv_encode_rvv_ldst(1, 6, 1, 11, 2),
        riscv_encode_csr(RISCV_CSR_FFLAGS, 0, 2, 6),
    };
    uint32_t src[] = {
        0x40800000u, 0x41100000u, 0xbf800000u, 0x3e800000u,
    };
    uint32_t expected[] = {
        0x40000000u, 0x40400000u, 0x7fc00000u, 0x3f000000u,
    };
    uint32_t output[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t t0 = 4;
    uint64_t t1;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, src, sizeof(src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, output, sizeof(output)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK_(output[i] == expected[i],
                    "sqrt lane %u: got 0x%08x expected 0x%08x",
                    (unsigned)i, output[i], expected[i]);
    }
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &t1));
    TEST_CHECK(t1 == 0x10);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_float32_estimate(void)
{
    uc_engine *uc;
    uint8_t code[8 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 3),
        riscv_encode_rvv_op(0x13, 1, 1, 4, 1, 2),
        riscv_encode_rvv_ldst(1, 6, 1, 12, 2),
        riscv_encode_rvv_op(0x13, 1, 3, 5, 1, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 4),
        riscv_encode_csr(RISCV_CSR_FFLAGS, 0, 2, 6),
    };
    uint32_t frsqrt_src[] = {
        0x40800000u, 0x3e800000u, 0x00000000u, 0xbf800000u,
    };
    uint32_t frec_src[] = {
        0x40800000u, 0xc0000000u, 0x00000000u, 0x7f800001u,
    };
    uint32_t expected_frsqrt[] = {
        0x3eff0000u, 0x3fff0000u, 0x7f800000u, 0x7fc00000u,
    };
    uint32_t expected_frec[] = {
        0x3e7f0000u, 0xbeff0000u, 0x7f800000u, 0x7fc00000u,
    };
    uint32_t out_frsqrt[4] = { 0 };
    uint32_t out_frec[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t t0 = 4;
    uint64_t t1;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, frsqrt_src, sizeof(frsqrt_src)));
    OK(uc_mem_write(uc, a1, frec_src, sizeof(frec_src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_frsqrt, sizeof(out_frsqrt)));
    OK(uc_mem_read(uc, a3, out_frec, sizeof(out_frec)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK_(out_frsqrt[i] == expected_frsqrt[i],
                    "frsqrt7 lane %u: got 0x%08x expected 0x%08x",
                    (unsigned)i, out_frsqrt[i], expected_frsqrt[i]);
        TEST_CHECK_(out_frec[i] == expected_frec[i],
                    "frec7 lane %u: got 0x%08x expected 0x%08x",
                    (unsigned)i, out_frec[i], expected_frec[i]);
    }
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &t1));
    TEST_CHECK(t1 == 0x18);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_float32_convert(void)
{
    uc_engine *uc;
    uint8_t code[18 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_ldst(0, 6, 1, 13, 4),
        riscv_encode_rvv_op(0x12, 1, 1, 0, 1, 5),
        riscv_encode_rvv_ldst(1, 6, 1, 14, 5),
        riscv_encode_rvv_op(0x12, 1, 2, 1, 1, 6),
        riscv_encode_rvv_ldst(1, 6, 1, 15, 6),
        riscv_encode_rvv_op(0x12, 1, 1, 6, 1, 7),
        riscv_encode_rvv_ldst(1, 6, 1, 16, 7),
        riscv_encode_rvv_op(0x12, 1, 2, 7, 1, 8),
        riscv_encode_rvv_ldst(1, 6, 1, 17, 8),
        riscv_encode_rvv_op(0x12, 1, 3, 2, 1, 9),
        riscv_encode_rvv_ldst(1, 6, 1, 28, 9),
        riscv_encode_rvv_op(0x12, 1, 4, 3, 1, 10),
        riscv_encode_rvv_ldst(1, 6, 1, 29, 10),
        riscv_encode_csr(RISCV_CSR_FFLAGS, 0, 2, 6),
    };
    uint32_t fp_unsigned[] = {
        0x3fc00000u, 0x40200000u, 0x40400000u, 0x40800000u,
    };
    uint32_t fp_signed[] = {
        0x3fc00000u, 0xc0200000u, 0x40400000u, 0xc0800000u,
    };
    uint32_t int_unsigned[] = { 1u, 2u, 0x01000003u, 16u };
    uint32_t int_signed[] = { 1u, 0xffffffffu, 0x01000003u, 16u };
    uint32_t expected_xu[] = { 2u, 2u, 3u, 4u };
    uint32_t expected_x[] = { 2u, 0xfffffffeu, 3u, 0xfffffffcu };
    uint32_t expected_rtz_xu[] = { 1u, 2u, 3u, 4u };
    uint32_t expected_rtz_x[] = { 1u, 0xfffffffeu, 3u, 0xfffffffcu };
    uint32_t expected_f_xu[] = {
        0x3f800000u, 0x40000000u, 0x4b800002u, 0x41800000u,
    };
    uint32_t expected_f_x[] = {
        0x3f800000u, 0xbf800000u, 0x4b800002u, 0x41800000u,
    };
    uint32_t out_xu[4] = { 0 };
    uint32_t out_x[4] = { 0 };
    uint32_t out_rtz_xu[4] = { 0 };
    uint32_t out_rtz_x[4] = { 0 };
    uint32_t out_f_xu[4] = { 0 };
    uint32_t out_f_x[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 4;
    uint64_t t1;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, fp_unsigned, sizeof(fp_unsigned)));
    OK(uc_mem_write(uc, a1, fp_signed, sizeof(fp_signed)));
    OK(uc_mem_write(uc, a2, int_unsigned, sizeof(int_unsigned)));
    OK(uc_mem_write(uc, a3, int_signed, sizeof(int_signed)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a4, out_xu, sizeof(out_xu)));
    OK(uc_mem_read(uc, a5, out_x, sizeof(out_x)));
    OK(uc_mem_read(uc, a6, out_rtz_xu, sizeof(out_rtz_xu)));
    OK(uc_mem_read(uc, a7, out_rtz_x, sizeof(out_rtz_x)));
    OK(uc_mem_read(uc, t3, out_f_xu, sizeof(out_f_xu)));
    OK(uc_mem_read(uc, t4, out_f_x, sizeof(out_f_x)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_xu[i] == expected_xu[i]);
        TEST_CHECK(out_x[i] == expected_x[i]);
        TEST_CHECK(out_rtz_xu[i] == expected_rtz_xu[i]);
        TEST_CHECK(out_rtz_x[i] == expected_rtz_x[i]);
        TEST_CHECK(out_f_xu[i] == expected_f_xu[i]);
        TEST_CHECK(out_f_x[i] == expected_f_x[i]);
    }
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &t1));
    TEST_CHECK(t1 == 0x01);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_widening_float_convert(void)
{
    uc_engine *uc;
    uint8_t code[27 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x12, 1, 1, 8, 1, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 4),
        riscv_encode_rvv_op(0x12, 1, 1, 9, 1, 6),
        riscv_encode_rvv_ldst(1, 7, 1, 14, 6),
        riscv_encode_rvv_op(0x12, 1, 1, 14, 1, 8),
        riscv_encode_rvv_ldst(1, 7, 1, 15, 8),
        riscv_encode_rvv_op(0x12, 1, 1, 15, 1, 10),
        riscv_encode_rvv_ldst(1, 7, 1, 16, 10),
        riscv_encode_rvv_op(0x12, 1, 2, 10, 1, 12),
        riscv_encode_rvv_ldst(1, 7, 1, 17, 12),
        riscv_encode_rvv_op(0x12, 1, 3, 11, 1, 14),
        riscv_encode_rvv_ldst(1, 7, 1, 28, 14),
        riscv_encode_rvv_op(0x12, 1, 1, 12, 1, 16),
        riscv_encode_rvv_ldst(1, 7, 1, 29, 16),
        riscv_encode_rvv_vsetvli(0, 5, 0xc0),
        riscv_encode_rvv_ldst(0, 0, 1, 8, 1),
        riscv_encode_rvv_ldst(0, 0, 1, 9, 2),
        riscv_encode_rvv_op(0x12, 1, 1, 10, 1, 4),
        riscv_encode_rvv_op(0x12, 1, 2, 11, 1, 6),
        riscv_encode_rvv_vsetvli(0, 5, 0xc8),
        riscv_encode_rvv_ldst(1, 5, 1, 30, 4),
        riscv_encode_rvv_ldst(1, 5, 1, 31, 6),
        riscv_encode_csr(RISCV_CSR_FFLAGS, 0, 2, 6),
    };
    uint32_t fp_src[] = { 0x3fc00000u, 0x40200000u };
    uint32_t uint_src[] = { 1u, 0x80000000u };
    uint32_t int_src[] = { 1u, 0xfffffffeu };
    uint8_t u8_src[] = { 1u, 2u };
    uint8_t s8_src[] = { 1u, 0xfeu };
    uint64_t expected_xu[] = { 2ull, 2ull };
    uint64_t expected_x[] = { 2ull, 2ull };
    uint64_t expected_rtz_xu[] = { 1ull, 2ull };
    uint64_t expected_rtz_x[] = { 1ull, 2ull };
    uint64_t expected_f_xu[] = {
        0x3ff0000000000000ull, 0x41e0000000000000ull,
    };
    uint64_t expected_f_x[] = {
        0x3ff0000000000000ull, 0xc000000000000000ull,
    };
    uint64_t expected_f_f[] = {
        0x3ff8000000000000ull, 0x4004000000000000ull,
    };
    uint16_t expected_f_xu_b[] = { 0x3c00u, 0x4000u };
    uint16_t expected_f_x_b[] = { 0x3c00u, 0xc000u };
    uint64_t out_xu[2] = { 0 };
    uint64_t out_x[2] = { 0 };
    uint64_t out_rtz_xu[2] = { 0 };
    uint64_t out_rtz_x[2] = { 0 };
    uint64_t out_f_xu[2] = { 0 };
    uint64_t out_f_x[2] = { 0 };
    uint64_t out_f_f[2] = { 0 };
    uint16_t out_f_xu_b[2] = { 0 };
    uint16_t out_f_x_b[2] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 2;
    uint64_t t1;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    uint64_t t5 = code_start + 0x1a00;
    uint64_t t6 = code_start + 0x1b00;
    uint64_t s0 = code_start + 0x1c00;
    uint64_t s1 = code_start + 0x1d00;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, fp_src, sizeof(fp_src)));
    OK(uc_mem_write(uc, a1, uint_src, sizeof(uint_src)));
    OK(uc_mem_write(uc, a2, int_src, sizeof(int_src)));
    OK(uc_mem_write(uc, s0, u8_src, sizeof(u8_src)));
    OK(uc_mem_write(uc, s1, s8_src, sizeof(s8_src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T5, &t5));
    OK(uc_reg_write(uc, UC_RISCV_REG_T6, &t6));
    OK(uc_reg_write(uc, UC_RISCV_REG_S0, &s0));
    OK(uc_reg_write(uc, UC_RISCV_REG_S1, &s1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_xu, sizeof(out_xu)));
    OK(uc_mem_read(uc, a4, out_x, sizeof(out_x)));
    OK(uc_mem_read(uc, a5, out_rtz_xu, sizeof(out_rtz_xu)));
    OK(uc_mem_read(uc, a6, out_rtz_x, sizeof(out_rtz_x)));
    OK(uc_mem_read(uc, a7, out_f_xu, sizeof(out_f_xu)));
    OK(uc_mem_read(uc, t3, out_f_x, sizeof(out_f_x)));
    OK(uc_mem_read(uc, t4, out_f_f, sizeof(out_f_f)));
    OK(uc_mem_read(uc, t5, out_f_xu_b, sizeof(out_f_xu_b)));
    OK(uc_mem_read(uc, t6, out_f_x_b, sizeof(out_f_x_b)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_xu[i] == expected_xu[i]);
        TEST_CHECK(out_x[i] == expected_x[i]);
        TEST_CHECK(out_rtz_xu[i] == expected_rtz_xu[i]);
        TEST_CHECK(out_rtz_x[i] == expected_rtz_x[i]);
        TEST_CHECK(out_f_xu[i] == expected_f_xu[i]);
        TEST_CHECK(out_f_x[i] == expected_f_x[i]);
        TEST_CHECK(out_f_f[i] == expected_f_f[i]);
        TEST_CHECK_(out_f_xu_b[i] == expected_f_xu_b[i],
                    "vfwcvt.f.xu.b lane %u: got 0x%04x expected 0x%04x",
                    (unsigned)i, out_f_xu_b[i], expected_f_xu_b[i]);
        TEST_CHECK_(out_f_x_b[i] == expected_f_x_b[i],
                    "vfwcvt.f.x.b lane %u: got 0x%04x expected 0x%04x",
                    (unsigned)i, out_f_x_b[i], expected_f_x_b[i]);
    }
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &t1));
    TEST_CHECK(t1 == 0x01);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_narrowing_float_convert(void)
{
    uc_engine *uc;
    uint8_t code[20 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 7, 1, 10, 2),
        riscv_encode_rvv_ldst(0, 7, 1, 11, 4),
        riscv_encode_rvv_ldst(0, 7, 1, 12, 6),
        riscv_encode_rvv_ldst(0, 7, 1, 13, 8),
        riscv_encode_rvv_op(0x12, 1, 2, 16, 1, 10),
        riscv_encode_rvv_ldst(1, 6, 1, 14, 10),
        riscv_encode_rvv_op(0x12, 1, 2, 17, 1, 11),
        riscv_encode_rvv_ldst(1, 6, 1, 15, 11),
        riscv_encode_rvv_op(0x12, 1, 2, 22, 1, 12),
        riscv_encode_rvv_ldst(1, 6, 1, 16, 12),
        riscv_encode_rvv_op(0x12, 1, 4, 18, 1, 13),
        riscv_encode_rvv_ldst(1, 6, 1, 17, 13),
        riscv_encode_rvv_op(0x12, 1, 6, 19, 1, 14),
        riscv_encode_rvv_ldst(1, 6, 1, 28, 14),
        riscv_encode_rvv_op(0x12, 1, 8, 20, 1, 15),
        riscv_encode_rvv_ldst(1, 6, 1, 29, 15),
        riscv_encode_rvv_op(0x12, 1, 8, 21, 1, 16),
        riscv_encode_rvv_ldst(1, 6, 1, 30, 16),
        riscv_encode_csr(RISCV_CSR_FFLAGS, 0, 2, 6),
    };
    uint64_t fp_src[] = {
        0x3ff8000000000000ull, 0x4004000000000000ull,
    };
    uint64_t uint_src[] = { 1ull, 0x01000001ull };
    uint64_t int_src[] = { 0xfffffffffffffffeull, 0xffffffff80000000ull };
    uint64_t rod_src[] = {
        0x3ff0000010000000ull, 0x3ff8000000000000ull,
    };
    uint32_t expected_xu[] = { 2u, 2u };
    uint32_t expected_x[] = { 2u, 2u };
    uint32_t expected_rtz_xu[] = { 1u, 2u };
    uint32_t expected_f_xu[] = { 0x3f800000u, 0x4b800000u };
    uint32_t expected_f_x[] = { 0xc0000000u, 0xcf000000u };
    uint32_t expected_f_f[] = { 0x3f800000u, 0x3fc00000u };
    uint32_t expected_rod_f_f[] = { 0x3f800001u, 0x3fc00000u };
    uint32_t out_xu[2] = { 0 };
    uint32_t out_x[2] = { 0 };
    uint32_t out_rtz_xu[2] = { 0 };
    uint32_t out_f_xu[2] = { 0 };
    uint32_t out_f_x[2] = { 0 };
    uint32_t out_f_f[2] = { 0 };
    uint32_t out_rod_f_f[2] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 2;
    uint64_t t1;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    uint64_t t5 = code_start + 0x1a00;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, fp_src, sizeof(fp_src)));
    OK(uc_mem_write(uc, a1, uint_src, sizeof(uint_src)));
    OK(uc_mem_write(uc, a2, int_src, sizeof(int_src)));
    OK(uc_mem_write(uc, a3, rod_src, sizeof(rod_src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T5, &t5));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a4, out_xu, sizeof(out_xu)));
    OK(uc_mem_read(uc, a5, out_x, sizeof(out_x)));
    OK(uc_mem_read(uc, a6, out_rtz_xu, sizeof(out_rtz_xu)));
    OK(uc_mem_read(uc, a7, out_f_xu, sizeof(out_f_xu)));
    OK(uc_mem_read(uc, t3, out_f_x, sizeof(out_f_x)));
    OK(uc_mem_read(uc, t4, out_f_f, sizeof(out_f_f)));
    OK(uc_mem_read(uc, t5, out_rod_f_f, sizeof(out_rod_f_f)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_xu[i] == expected_xu[i]);
        TEST_CHECK(out_x[i] == expected_x[i]);
        TEST_CHECK(out_rtz_xu[i] == expected_rtz_xu[i]);
        TEST_CHECK(out_f_xu[i] == expected_f_xu[i]);
        TEST_CHECK(out_f_x[i] == expected_f_x[i]);
        TEST_CHECK(out_f_f[i] == expected_f_f[i]);
        TEST_CHECK(out_rod_f_f[i] == expected_rod_f_f[i]);
    }
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &t1));
    TEST_CHECK(t1 == 0x01);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_float32_slide(void)
{
    uc_engine *uc;
    uint8_t code[7 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 1),
        riscv_encode_rvv_op(0x0e, 0, 1, 1, 5, 5),
        riscv_encode_rvv_ldst(1, 6, 1, 12, 5),
        riscv_encode_rvv_op(0x0f, 1, 1, 2, 5, 1),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 1),
    };
    uint8_t mask[] = { 0x05 };
    uint32_t src[] = {
        0x40000000u, 0x40400000u, 0x40800000u, 0x40a00000u,
    };
    uint32_t expected_up[] = {
        0x3f800000u, 0xffffffffu, 0x40400000u, 0xffffffffu,
    };
    uint32_t expected_down[] = {
        0x40400000u, 0x40800000u, 0x40a00000u, 0x40c00000u,
    };
    uint32_t out_up[4] = { 0 };
    uint32_t out_down[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t t0 = 4;
    uint64_t f1 = 0xffffffff3f800000ull;
    uint64_t f2 = 0xffffffff40c00000ull;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, src, sizeof(src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &f1));
    OK(uc_reg_write(uc, UC_RISCV_REG_F2, &f2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_up, sizeof(out_up)));
    OK(uc_mem_read(uc, a3, out_down, sizeof(out_down)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK_(out_up[i] == expected_up[i],
                    "up lane %u: got 0x%08x expected 0x%08x",
                    (unsigned)i, out_up[i], expected_up[i]);
        TEST_CHECK_(out_down[i] == expected_down[i],
                    "down lane %u: got 0x%08x expected 0x%08x",
                    (unsigned)i, out_down[i], expected_down[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_float32_fma(void)
{
    enum {
        FMA_VFMACC_VV,
        FMA_VFNMACC_VV,
        FMA_VFMSAC_VV,
        FMA_VFNMSAC_VV,
        FMA_VFMADD_VV,
        FMA_VFNMADD_VV,
        FMA_VFMSUB_VV,
        FMA_VFNMSUB_VV,
        FMA_VFMACC_VF,
        FMA_VFNMACC_VF,
        FMA_VFMSAC_VF,
        FMA_VFNMSAC_VF,
        FMA_VFMADD_VF,
        FMA_VFNMADD_VF,
        FMA_VFMSUB_VF,
        FMA_VFNMSUB_VF,
        FMA_OPS,
    };
    uc_engine *uc;
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x2c, 1, 1, 2, 1, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x2d, 1, 1, 2, 1, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x2e, 1, 1, 2, 1, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x2f, 1, 1, 2, 1, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x28, 1, 1, 2, 1, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x29, 1, 1, 2, 1, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x2a, 1, 1, 2, 1, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x2b, 1, 1, 2, 1, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x2c, 1, 1, 5, 5, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x2d, 1, 1, 5, 5, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x2e, 1, 1, 5, 5, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x2f, 1, 1, 5, 5, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x28, 1, 1, 5, 5, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x29, 1, 1, 5, 5, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x2a, 1, 1, 5, 5, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_addi(13, 13, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x2b, 1, 1, 5, 5, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
    };
    uint8_t code[sizeof(insns)];
    uint32_t src2[] = { 0x40000000u, 0xc0400000u };
    uint32_t src1[] = { 0x40a00000u, 0x40e00000u };
    uint32_t acc[] = { 0x41300000u, 0xc1500000u };
    uint32_t expected[FMA_OPS][2] = {
        { 0x41a80000u, 0xc2080000u },
        { 0xc1a80000u, 0x42080000u },
        { 0xbf800000u, 0xc1000000u },
        { 0x3f800000u, 0x41000000u },
        { 0x42640000u, 0xc2bc0000u },
        { 0xc2640000u, 0x42bc0000u },
        { 0x42540000u, 0xc2b00000u },
        { 0xc2540000u, 0x42b00000u },
        { 0x41980000u, 0xc1c80000u },
        { 0xc1980000u, 0x41c80000u },
        { 0xc0400000u, 0x3f800000u },
        { 0x40400000u, 0xbf800000u },
        { 0x42380000u, 0xc25c0000u },
        { 0xc2380000u, 0x425c0000u },
        { 0x42280000u, 0xc2440000u },
        { 0xc2280000u, 0x42440000u },
    };
    uint32_t output[FMA_OPS][2] = { { 0 } };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t t0 = 2;
    uint64_t f5 = 0xffffffff40800000ull;
    size_t i;
    size_t lane;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a1, src1, sizeof(src1)));
    OK(uc_mem_write(uc, a2, acc, sizeof(acc)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_F5, &f5));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, output, sizeof(output)));
    for (i = 0; i < FMA_OPS; i++) {
        for (lane = 0; lane < 2; lane++) {
            TEST_CHECK_(output[i][lane] == expected[i][lane],
                        "op %u lane %u: got 0x%08x expected 0x%08x",
                        (unsigned)i, (unsigned)lane, output[i][lane],
                        expected[i][lane]);
        }
    }

    OK(uc_close(uc));
}

static void test_riscv32_rvv_float32_smoke(void)
{
    uc_engine *uc;
    uint8_t code[5 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_op(0x00, 1, 1, 2, 1, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 12, 3),
    };
    uint32_t src2[] = { 0x3f800000u, 0x40000000u };
    uint32_t src1[] = { 0x40400000u, 0x40800000u };
    uint32_t expected[] = { 0x40800000u, 0x40c00000u };
    uint32_t output[2] = { 0 };
    uint32_t a0 = code_start + 0x1000;
    uint32_t a1 = code_start + 0x1100;
    uint32_t a2 = code_start + 0x1200;
    uint32_t t0 = 2;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32,
                    (const char *)code, sizeof(code));
    riscv32_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a1, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, output, sizeof(output)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(output[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_widening_float_fma(void)
{
    enum {
        FWMA_VFWMACC_VV,
        FWMA_VFWNMACC_VV,
        FWMA_VFWMSAC_VV,
        FWMA_VFWNMSAC_VV,
        FWMA_VFWMACC_VF,
        FWMA_VFWNMACC_VF,
        FWMA_VFWMSAC_VF,
        FWMA_VFWNMSAC_VF,
        FWMA_OPS,
    };
    uc_engine *uc;
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_ldst(0, 7, 1, 12, 4),
        riscv_encode_rvv_op(0x3c, 1, 1, 2, 1, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 4),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_ldst(0, 7, 1, 12, 4),
        riscv_encode_rvv_op(0x3d, 1, 1, 2, 1, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 4),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_ldst(0, 7, 1, 12, 4),
        riscv_encode_rvv_op(0x3e, 1, 1, 2, 1, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 4),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_ldst(0, 7, 1, 12, 4),
        riscv_encode_rvv_op(0x3f, 1, 1, 2, 1, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 4),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_ldst(0, 7, 1, 12, 4),
        riscv_encode_rvv_op(0x3c, 1, 1, 5, 5, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 4),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_ldst(0, 7, 1, 12, 4),
        riscv_encode_rvv_op(0x3d, 1, 1, 5, 5, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 4),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_ldst(0, 7, 1, 12, 4),
        riscv_encode_rvv_op(0x3e, 1, 1, 5, 5, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 4),
        riscv_encode_addi(13, 13, 16),
        riscv_encode_rvv_ldst(0, 7, 1, 12, 4),
        riscv_encode_rvv_op(0x3f, 1, 1, 5, 5, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 4),
    };
    uint8_t code[sizeof(insns)];
    uint32_t src2[] = { 0x40000000u, 0xc0400000u };
    uint32_t src1[] = { 0x40a00000u, 0x40e00000u };
    uint64_t acc[] = {
        0x4026000000000000ull, 0xc02a000000000000ull,
    };
    uint64_t expected[FWMA_OPS][2] = {
        { 0x4035000000000000ull, 0xc041000000000000ull },
        { 0xc035000000000000ull, 0x4041000000000000ull },
        { 0xbff0000000000000ull, 0xc020000000000000ull },
        { 0x3ff0000000000000ull, 0x4020000000000000ull },
        { 0x4033000000000000ull, 0xc039000000000000ull },
        { 0xc033000000000000ull, 0x4039000000000000ull },
        { 0xc008000000000000ull, 0x3ff0000000000000ull },
        { 0x4008000000000000ull, 0xbff0000000000000ull },
    };
    uint64_t output[FWMA_OPS][2] = { { 0 } };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t t0 = 2;
    uint64_t f5 = 0xffffffff40800000ull;
    size_t i;
    size_t lane;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a1, src1, sizeof(src1)));
    OK(uc_mem_write(uc, a2, acc, sizeof(acc)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_F5, &f5));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, output, sizeof(output)));
    for (i = 0; i < FWMA_OPS; i++) {
        for (lane = 0; lane < 2; lane++) {
            TEST_CHECK_(output[i][lane] == expected[i][lane],
                        "op %u lane %u: got 0x%016llx expected 0x%016llx",
                        (unsigned)i, (unsigned)lane,
                        (unsigned long long)output[i][lane],
                        (unsigned long long)expected[i][lane]);
        }
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_widening_float_arith(void)
{
    uc_engine *uc;
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_ldst(0, 7, 1, 12, 4),
        riscv_encode_rvv_op(0x30, 1, 1, 2, 1, 6),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 6),
        riscv_encode_rvv_op(0x32, 1, 1, 2, 1, 8),
        riscv_encode_rvv_ldst(1, 7, 1, 14, 8),
        riscv_encode_rvv_op(0x38, 1, 1, 2, 1, 10),
        riscv_encode_rvv_ldst(1, 7, 1, 15, 10),
        riscv_encode_rvv_op(0x30, 1, 1, 1, 5, 12),
        riscv_encode_rvv_ldst(1, 7, 1, 16, 12),
        riscv_encode_rvv_op(0x32, 1, 1, 1, 5, 14),
        riscv_encode_rvv_ldst(1, 7, 1, 17, 14),
        riscv_encode_rvv_op(0x38, 1, 1, 1, 5, 16),
        riscv_encode_rvv_ldst(1, 7, 1, 28, 16),
        riscv_encode_rvv_op(0x34, 1, 4, 2, 1, 18),
        riscv_encode_rvv_ldst(1, 7, 1, 29, 18),
        riscv_encode_rvv_op(0x36, 1, 4, 2, 1, 20),
        riscv_encode_rvv_ldst(1, 7, 1, 30, 20),
        riscv_encode_rvv_op(0x34, 1, 4, 1, 5, 22),
        riscv_encode_rvv_ldst(1, 7, 1, 31, 22),
        riscv_encode_rvv_op(0x36, 1, 4, 1, 5, 24),
        riscv_encode_rvv_ldst(1, 7, 1, 8, 24),
    };
    uint8_t code[sizeof(insns)];
    uint32_t src2[] = { 0x3f800000u, 0xc0000000u };
    uint32_t src1[] = { 0x40400000u, 0x40800000u };
    uint64_t wide_src[] = {
        0x4024000000000000ull, 0xc024000000000000ull,
    };
    uint64_t expected_add_vv[] = {
        0x4010000000000000ull, 0x4000000000000000ull,
    };
    uint64_t expected_sub_vv[] = {
        0xc000000000000000ull, 0xc018000000000000ull,
    };
    uint64_t expected_mul_vv[] = {
        0x4008000000000000ull, 0xc020000000000000ull,
    };
    uint64_t expected_add_vf[] = {
        0x4008000000000000ull, 0x0000000000000000ull,
    };
    uint64_t expected_sub_vf[] = {
        0xbff0000000000000ull, 0xc010000000000000ull,
    };
    uint64_t expected_mul_vf[] = {
        0x4000000000000000ull, 0xc010000000000000ull,
    };
    uint64_t expected_add_wv[] = {
        0x402a000000000000ull, 0xc018000000000000ull,
    };
    uint64_t expected_sub_wv[] = {
        0x401c000000000000ull, 0xc02c000000000000ull,
    };
    uint64_t expected_add_wf[] = {
        0x4028000000000000ull, 0xc020000000000000ull,
    };
    uint64_t expected_sub_wf[] = {
        0x4020000000000000ull, 0xc028000000000000ull,
    };
    uint64_t out_add_vv[2] = { 0 };
    uint64_t out_sub_vv[2] = { 0 };
    uint64_t out_mul_vv[2] = { 0 };
    uint64_t out_add_vf[2] = { 0 };
    uint64_t out_sub_vf[2] = { 0 };
    uint64_t out_mul_vf[2] = { 0 };
    uint64_t out_add_wv[2] = { 0 };
    uint64_t out_sub_wv[2] = { 0 };
    uint64_t out_add_wf[2] = { 0 };
    uint64_t out_sub_wf[2] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 2;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    uint64_t t5 = code_start + 0x1a00;
    uint64_t t6 = code_start + 0x1b00;
    uint64_t s0 = code_start + 0x1c00;
    uint64_t f1 = 0xffffffff40000000ull;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a1, src1, sizeof(src1)));
    OK(uc_mem_write(uc, a2, wide_src, sizeof(wide_src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T5, &t5));
    OK(uc_reg_write(uc, UC_RISCV_REG_T6, &t6));
    OK(uc_reg_write(uc, UC_RISCV_REG_S0, &s0));
    OK(uc_reg_write(uc, UC_RISCV_REG_F1, &f1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_add_vv, sizeof(out_add_vv)));
    OK(uc_mem_read(uc, a4, out_sub_vv, sizeof(out_sub_vv)));
    OK(uc_mem_read(uc, a5, out_mul_vv, sizeof(out_mul_vv)));
    OK(uc_mem_read(uc, a6, out_add_vf, sizeof(out_add_vf)));
    OK(uc_mem_read(uc, a7, out_sub_vf, sizeof(out_sub_vf)));
    OK(uc_mem_read(uc, t3, out_mul_vf, sizeof(out_mul_vf)));
    OK(uc_mem_read(uc, t4, out_add_wv, sizeof(out_add_wv)));
    OK(uc_mem_read(uc, t5, out_sub_wv, sizeof(out_sub_wv)));
    OK(uc_mem_read(uc, t6, out_add_wf, sizeof(out_add_wf)));
    OK(uc_mem_read(uc, s0, out_sub_wf, sizeof(out_sub_wf)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_add_vv[i] == expected_add_vv[i]);
        TEST_CHECK(out_sub_vv[i] == expected_sub_vv[i]);
        TEST_CHECK(out_mul_vv[i] == expected_mul_vv[i]);
        TEST_CHECK(out_add_vf[i] == expected_add_vf[i]);
        TEST_CHECK(out_sub_vf[i] == expected_sub_vf[i]);
        TEST_CHECK(out_mul_vf[i] == expected_mul_vf[i]);
        TEST_CHECK(out_add_wv[i] == expected_add_wv[i]);
        TEST_CHECK(out_sub_wv[i] == expected_sub_wv[i]);
        TEST_CHECK(out_add_wf[i] == expected_add_wf[i]);
        TEST_CHECK(out_sub_wf[i] == expected_sub_wf[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_float_illegal(void)
{
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x00, 1, 1, 2, 1, 3), 0xd0);
    run_riscv64_rvv_fp_illegal_vtype(
        riscv_encode_rvv_op(0x00, 1, 1, 2, 1, 3), 0xc0);
    run_riscv64_rvv_fp_illegal_vtype(
        riscv_encode_rvv_op(0x00, 0, 1, 2, 1, 0), 0xd0);
    run_riscv64_rvv_fp_illegal_vtype(
        riscv_encode_rvv_op(0x30, 1, 1, 2, 1, 4), 0xd8);
    run_riscv64_rvv_fp_illegal_vtype(
        riscv_encode_rvv_op(0x3c, 1, 1, 2, 1, 4), 0xd8);
    run_riscv64_rvv_fp_illegal_vtype(
        riscv_encode_rvv_op(0x3c, 1, 2, 1, 1, 2), 0xd0);
    run_riscv64_rvv_fp_illegal_vtype(
        riscv_encode_rvv_op(0x0e, 1, 3, 1, 5, 3), 0xd0);
    run_riscv64_rvv_fp_illegal_vtype(
        riscv_encode_rvv_op(0x13, 1, 1, 0, 1, 2), 0xc0);
    run_riscv64_rvv_fp_illegal_vtype(
        riscv_encode_rvv_op(0x13, 0, 1, 0, 1, 0), 0xd0);
    run_riscv64_rvv_fp_illegal_vtype(
        riscv_encode_rvv_op(0x12, 1, 1, 0, 1, 2), 0xc0);
    run_riscv64_rvv_fp_illegal_vtype(
        riscv_encode_rvv_op(0x12, 1, 1, 8, 1, 4), 0xd8);
    run_riscv64_rvv_fp_illegal_vtype(
        riscv_encode_rvv_op(0x12, 1, 2, 8, 1, 2), 0xd0);
    run_riscv64_rvv_fp_illegal_vtype(
        riscv_encode_rvv_op(0x12, 1, 1, 20, 1, 2), 0xc0);
}

static void test_riscv32_rvv_carry_borrow(void)
{
    uc_engine *uc;
    uint8_t code[14 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 7, 0xc0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 0, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 0, 1, 12, 2),
        riscv_encode_rvv_op(0x10, 0, 1, 2, 0, 3),
        riscv_encode_rvv_ldst(1, 0, 1, 13, 3),
        riscv_encode_rvv_op(0x10, 0, 1, 5, 4, 4),
        riscv_encode_rvv_ldst(1, 0, 1, 14, 4),
        riscv_encode_rvv_op(0x10, 0, 1, 31, 3, 5),
        riscv_encode_rvv_ldst(1, 0, 1, 15, 5),
        riscv_encode_rvv_op(0x12, 0, 1, 2, 0, 6),
        riscv_encode_rvv_ldst(1, 0, 1, 16, 6),
        riscv_encode_rvv_op(0x12, 0, 1, 6, 4, 7),
        riscv_encode_rvv_ldst(1, 0, 1, 17, 7),
    };
    uint8_t carry_mask[] = { 0xad };
    uint8_t src2[] = { 0xff, 0x10, 0x7f, 0x00, 0x01, 0x80, 0x55, 0x01 };
    uint8_t src1[] = { 0x01, 0x20, 0x01, 0xff, 0xff, 0x80, 0xaa, 0xfe };
    uint8_t expected_vvm[] = {
        0x01, 0x30, 0x81, 0x00, 0x00, 0x01, 0xff, 0x00,
    };
    uint8_t expected_vxm[] = {
        0xfe, 0x0e, 0x7e, 0xff, 0xff, 0x7f, 0x53, 0x00,
    };
    uint8_t expected_vim[] = {
        0xff, 0x0f, 0x7f, 0x00, 0x00, 0x80, 0x54, 0x01,
    };
    uint8_t expected_vsbc_vvm[] = {
        0xfd, 0xf0, 0x7d, 0x00, 0x02, 0xff, 0xab, 0x02,
    };
    uint8_t expected_vsbc_vxm[] = {
        0xfc, 0x0e, 0x7c, 0xfd, 0xff, 0x7d, 0x53, 0xfe,
    };
    uint8_t out_vvm[8] = { 0 };
    uint8_t out_vxm[8] = { 0 };
    uint8_t out_vim[8] = { 0 };
    uint8_t out_vsbc_vvm[8] = { 0 };
    uint8_t out_vsbc_vxm[8] = { 0 };
    uint32_t a0 = code_start + 0x1000;
    uint32_t a1 = code_start + 0x1100;
    uint32_t a2 = code_start + 0x1200;
    uint32_t a3 = code_start + 0x1300;
    uint32_t a4 = code_start + 0x1400;
    uint32_t a5 = code_start + 0x1500;
    uint32_t a6 = code_start + 0x1600;
    uint32_t a7 = code_start + 0x1700;
    uint32_t t0 = 0xfe;
    uint32_t t1 = 2;
    uint32_t t2 = 8;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32,
                    (const char *)code, sizeof(code));
    riscv32_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, carry_mask, sizeof(carry_mask)));
    OK(uc_mem_write(uc, a1, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a2, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_vvm, sizeof(out_vvm)));
    OK(uc_mem_read(uc, a4, out_vxm, sizeof(out_vxm)));
    OK(uc_mem_read(uc, a5, out_vim, sizeof(out_vim)));
    OK(uc_mem_read(uc, a6, out_vsbc_vvm, sizeof(out_vsbc_vvm)));
    OK(uc_mem_read(uc, a7, out_vsbc_vxm, sizeof(out_vsbc_vxm)));
    for (i = 0; i < sizeof(expected_vvm); i++) {
        TEST_CHECK(out_vvm[i] == expected_vvm[i]);
        TEST_CHECK(out_vxm[i] == expected_vxm[i]);
        TEST_CHECK(out_vim[i] == expected_vim[i]);
        TEST_CHECK(out_vsbc_vvm[i] == expected_vsbc_vvm[i]);
        TEST_CHECK(out_vsbc_vxm[i] == expected_vsbc_vxm[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_carry_borrow_masks(void)
{
    uc_engine *uc;
    uint8_t code[14 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 7, 0xc0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 0, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 0, 1, 12, 2),
        riscv_encode_rvv_op(0x11, 0, 1, 2, 0, 3),
        riscv_encode_rvv_mask_ldst(1, 13, 3),
        riscv_encode_rvv_op(0x11, 1, 1, 5, 4, 4),
        riscv_encode_rvv_mask_ldst(1, 14, 4),
        riscv_encode_rvv_op(0x11, 0, 1, 31, 3, 5),
        riscv_encode_rvv_mask_ldst(1, 15, 5),
        riscv_encode_rvv_op(0x13, 0, 1, 2, 0, 6),
        riscv_encode_rvv_mask_ldst(1, 16, 6),
        riscv_encode_rvv_op(0x13, 1, 1, 6, 4, 7),
        riscv_encode_rvv_mask_ldst(1, 17, 7),
    };
    uint8_t carry_mask[] = { 0xad };
    uint8_t src2[] = { 0xff, 0x10, 0x7f, 0x00, 0x01, 0x80, 0x55, 0x01 };
    uint8_t src1[] = { 0x01, 0x20, 0x01, 0xff, 0xff, 0x80, 0xaa, 0xfe };
    uint8_t expected_vmadc_vvm[] = { 0xb9 };
    uint8_t expected_vmadc_vxm[] = { 0x01 };
    uint8_t expected_vmadc_vim[] = { 0xff };
    uint8_t expected_vmsbc_vvm[] = { 0xfa };
    uint8_t expected_vmsbc_vxm[] = { 0x98 };
    uint8_t out_vmadc_vvm[sizeof(expected_vmadc_vvm)] = { 0 };
    uint8_t out_vmadc_vxm[sizeof(expected_vmadc_vxm)] = { 0 };
    uint8_t out_vmadc_vim[sizeof(expected_vmadc_vim)] = { 0 };
    uint8_t out_vmsbc_vvm[sizeof(expected_vmsbc_vvm)] = { 0 };
    uint8_t out_vmsbc_vxm[sizeof(expected_vmsbc_vxm)] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 1;
    uint64_t t1 = 2;
    uint64_t t2 = 8;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, carry_mask, sizeof(carry_mask)));
    OK(uc_mem_write(uc, a1, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a2, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_vmadc_vvm, sizeof(out_vmadc_vvm)));
    OK(uc_mem_read(uc, a4, out_vmadc_vxm, sizeof(out_vmadc_vxm)));
    OK(uc_mem_read(uc, a5, out_vmadc_vim, sizeof(out_vmadc_vim)));
    OK(uc_mem_read(uc, a6, out_vmsbc_vvm, sizeof(out_vmsbc_vvm)));
    OK(uc_mem_read(uc, a7, out_vmsbc_vxm, sizeof(out_vmsbc_vxm)));
    for (i = 0; i < sizeof(expected_vmadc_vvm); i++) {
        TEST_CHECK(out_vmadc_vvm[i] == expected_vmadc_vvm[i]);
        TEST_CHECK(out_vmadc_vxm[i] == expected_vmadc_vxm[i]);
        TEST_CHECK(out_vmadc_vim[i] == expected_vmadc_vim[i]);
        TEST_CHECK(out_vmsbc_vvm[i] == expected_vmsbc_vvm[i]);
        TEST_CHECK(out_vmsbc_vxm[i] == expected_vmsbc_vxm[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_carry_borrow_illegal(void)
{
    run_riscv64_rvv_illegal(riscv_encode_rvv_op(0x10, 1, 1, 2, 0, 3));
    run_riscv64_rvv_illegal(riscv_encode_rvv_op(0x10, 0, 1, 2, 0, 0));
    run_riscv64_rvv_illegal(riscv_encode_rvv_op(0x13, 0, 1, 31, 3, 3));
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x11, 0, 0, 0, 0, 1), 0xc1);
}

static void test_riscv64_rvv_narrow_shift(void)
{
    uc_engine *uc;
    uint8_t code[18 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 7, 0xc8),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 5, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 2),
        riscv_encode_rvv_op(0x2c, 1, 2, 1, 0, 4),
        riscv_encode_rvv_ldst(1, 5, 1, 13, 4),
        riscv_encode_rvv_op(0x2d, 1, 2, 1, 0, 5),
        riscv_encode_rvv_ldst(1, 5, 1, 14, 5),
        riscv_encode_rvv_op(0x2c, 1, 2, 5, 4, 6),
        riscv_encode_rvv_ldst(1, 5, 1, 15, 6),
        riscv_encode_rvv_op(0x2d, 1, 2, 6, 4, 7),
        riscv_encode_rvv_ldst(1, 5, 1, 16, 7),
        riscv_encode_rvv_op(0x2c, 1, 2, 4, 3, 8),
        riscv_encode_rvv_ldst(1, 5, 1, 17, 8),
        riscv_encode_rvv_op(0x2d, 1, 2, 31, 3, 9),
        riscv_encode_rvv_ldst(1, 5, 1, 10, 9),
        riscv_encode_rvv_op(0x2c, 0, 2, 1, 0, 10),
        riscv_encode_rvv_ldst(1, 5, 1, 28, 10),
    };
    uint8_t mask[] = { 0x05 };
    uint16_t shifts[] = { 20, 1, 8, 31 };
    uint32_t src[] = {
        0x8000f000u, 0xffffffffu, 0x0000ff00u, 0x7fffffffu,
    };
    uint16_t expected_vnsrl_wv[] = { 0x0800, 0xffff, 0x00ff, 0x0000 };
    uint16_t expected_vnsra_wv[] = { 0xf800, 0xffff, 0x00ff, 0x0000 };
    uint16_t expected_vnsrl_wx[] = { 0x0f00, 0xffff, 0x0ff0, 0xffff };
    uint16_t expected_vnsra_wx[] = { 0xf800, 0xffff, 0x0000, 0x07ff };
    uint16_t expected_vnsrl_wi[] = { 0x0f00, 0xffff, 0x0ff0, 0xffff };
    uint16_t expected_vnsra_wi[] = { 0xffff, 0xffff, 0x0000, 0x0000 };
    uint16_t expected_masked[] = { 0x0800, 0xffff, 0x00ff, 0xffff };
    uint16_t out_vnsrl_wv[4] = { 0 };
    uint16_t out_vnsra_wv[4] = { 0 };
    uint16_t out_vnsrl_wx[4] = { 0 };
    uint16_t out_vnsra_wx[4] = { 0 };
    uint16_t out_vnsrl_wi[4] = { 0 };
    uint16_t out_vnsra_wi[4] = { 0 };
    uint16_t out_masked[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 36;
    uint64_t t1 = 20;
    uint64_t t2 = 4;
    uint64_t t3 = code_start + 0x1800;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, shifts, sizeof(shifts)));
    OK(uc_mem_write(uc, a2, src, sizeof(src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_vnsrl_wv, sizeof(out_vnsrl_wv)));
    OK(uc_mem_read(uc, a4, out_vnsra_wv, sizeof(out_vnsra_wv)));
    OK(uc_mem_read(uc, a5, out_vnsrl_wx, sizeof(out_vnsrl_wx)));
    OK(uc_mem_read(uc, a6, out_vnsra_wx, sizeof(out_vnsra_wx)));
    OK(uc_mem_read(uc, a7, out_vnsrl_wi, sizeof(out_vnsrl_wi)));
    OK(uc_mem_read(uc, a0, out_vnsra_wi, sizeof(out_vnsra_wi)));
    OK(uc_mem_read(uc, t3, out_masked, sizeof(out_masked)));
    for (i = 0; i < sizeof(expected_vnsrl_wv) /
                    sizeof(expected_vnsrl_wv[0]); i++) {
        TEST_CHECK(out_vnsrl_wv[i] == expected_vnsrl_wv[i]);
        TEST_CHECK(out_vnsra_wv[i] == expected_vnsra_wv[i]);
        TEST_CHECK(out_vnsrl_wx[i] == expected_vnsrl_wx[i]);
        TEST_CHECK(out_vnsra_wx[i] == expected_vnsra_wx[i]);
        TEST_CHECK(out_vnsrl_wi[i] == expected_vnsrl_wi[i]);
        TEST_CHECK(out_vnsra_wi[i] == expected_vnsra_wi[i]);
        TEST_CHECK(out_masked[i] == expected_masked[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_narrow_shift_illegal(void)
{
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x2c, 1, 2, 1, 0, 4), 0xd8);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x2c, 1, 0, 1, 0, 8), 0xcb);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x2c, 0, 2, 1, 0, 0), 0xc8);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x2c, 1, 0, 4, 0, 2), 0xc9);
}

static void test_riscv64_rvv_integer_extension(void)
{
    uc_engine *uc;
    uint8_t code[20 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 0, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 5, 1, 12, 2),
        riscv_encode_rvv_op(0x12, 1, 1, 4, 2, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 3),
        riscv_encode_rvv_op(0x12, 1, 1, 5, 2, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 14, 4),
        riscv_encode_rvv_op(0x12, 1, 2, 6, 2, 5),
        riscv_encode_rvv_ldst(1, 6, 1, 15, 5),
        riscv_encode_rvv_op(0x12, 1, 2, 7, 2, 6),
        riscv_encode_rvv_ldst(1, 6, 1, 16, 6),
        riscv_encode_rvv_op(0x12, 0, 1, 4, 2, 7),
        riscv_encode_rvv_ldst(1, 6, 1, 29, 7),
        riscv_encode_rvv_vsetvli(0, 6, 0xd8),
        riscv_encode_rvv_ldst(0, 0, 1, 11, 1),
        riscv_encode_rvv_op(0x12, 1, 1, 2, 2, 8),
        riscv_encode_rvv_ldst(1, 7, 1, 17, 8),
        riscv_encode_rvv_op(0x12, 1, 1, 3, 2, 9),
        riscv_encode_rvv_ldst(1, 7, 1, 28, 9),
    };
    uint8_t mask[] = { 0x05 };
    uint8_t bytes[] = { 0x01, 0x80, 0xff, 0x7f };
    uint16_t halves[] = { 0x0001, 0x8001, 0xffff, 0x7fff };
    uint32_t expected_zext_vf4[] = { 1, 0x80, 0xff, 0x7f };
    uint32_t expected_sext_vf4[] = {
        1, 0xffffff80u, 0xffffffffu, 0x7f,
    };
    uint32_t expected_zext_vf2[] = { 1, 0x8001, 0xffff, 0x7fff };
    uint32_t expected_sext_vf2[] = {
        1, 0xffff8001u, 0xffffffffu, 0x7fff,
    };
    uint32_t expected_masked[] = { 1, 0xffffffffu, 0xff, 0xffffffffu };
    uint64_t expected_zext_vf8[] = { 1, 0x80 };
    uint64_t expected_sext_vf8[] = { 1, 0xffffffffffffff80ull };
    uint32_t out_zext_vf4[4] = { 0 };
    uint32_t out_sext_vf4[4] = { 0 };
    uint32_t out_zext_vf2[4] = { 0 };
    uint32_t out_sext_vf2[4] = { 0 };
    uint32_t out_masked[4] = { 0 };
    uint64_t out_zext_vf8[2] = { 0 };
    uint64_t out_sext_vf8[2] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 4;
    uint64_t t1 = 2;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, bytes, sizeof(bytes)));
    OK(uc_mem_write(uc, a2, halves, sizeof(halves)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_zext_vf4, sizeof(out_zext_vf4)));
    OK(uc_mem_read(uc, a4, out_sext_vf4, sizeof(out_sext_vf4)));
    OK(uc_mem_read(uc, a5, out_zext_vf2, sizeof(out_zext_vf2)));
    OK(uc_mem_read(uc, a6, out_sext_vf2, sizeof(out_sext_vf2)));
    OK(uc_mem_read(uc, a7, out_zext_vf8, sizeof(out_zext_vf8)));
    OK(uc_mem_read(uc, t3, out_sext_vf8, sizeof(out_sext_vf8)));
    OK(uc_mem_read(uc, t4, out_masked, sizeof(out_masked)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_zext_vf4[i] == expected_zext_vf4[i]);
        TEST_CHECK(out_sext_vf4[i] == expected_sext_vf4[i]);
        TEST_CHECK(out_zext_vf2[i] == expected_zext_vf2[i]);
        TEST_CHECK(out_sext_vf2[i] == expected_sext_vf2[i]);
        TEST_CHECK(out_masked[i] == expected_masked[i]);
    }
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_zext_vf8[i] == expected_zext_vf8[i]);
        TEST_CHECK(out_sext_vf8[i] == expected_sext_vf8[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_integer_extension_illegal(void)
{
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x12, 1, 1, 6, 2, 3), 0xc0);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x12, 1, 1, 4, 2, 3), 0xc8);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x12, 1, 1, 6, 2, 1), 0xd0);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x12, 0, 1, 4, 2, 0), 0xd0);
}

static void test_riscv64_rvv_widening_add_sub_vv_vx(void)
{
    uc_engine *uc;
    uint8_t code[22 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xc8),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 5, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 5, 1, 12, 2),
        riscv_encode_rvv_op(0x30, 1, 1, 2, 2, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 4),
        riscv_encode_rvv_op(0x32, 1, 1, 2, 2, 6),
        riscv_encode_rvv_ldst(1, 6, 1, 14, 6),
        riscv_encode_rvv_op(0x31, 1, 1, 2, 2, 8),
        riscv_encode_rvv_ldst(1, 6, 1, 15, 8),
        riscv_encode_rvv_op(0x33, 1, 1, 2, 2, 10),
        riscv_encode_rvv_ldst(1, 6, 1, 16, 10),
        riscv_encode_rvv_op(0x30, 1, 1, 7, 6, 12),
        riscv_encode_rvv_ldst(1, 6, 1, 17, 12),
        riscv_encode_rvv_op(0x31, 1, 1, 7, 6, 14),
        riscv_encode_rvv_ldst(1, 6, 1, 28, 14),
        riscv_encode_rvv_op(0x32, 1, 1, 7, 6, 16),
        riscv_encode_rvv_ldst(1, 6, 1, 29, 16),
        riscv_encode_rvv_op(0x33, 1, 1, 7, 6, 18),
        riscv_encode_rvv_ldst(1, 6, 1, 30, 18),
        riscv_encode_rvv_op(0x30, 0, 1, 2, 2, 20),
        riscv_encode_rvv_ldst(1, 6, 1, 31, 20),
    };
    uint8_t mask[] = { 0x05 };
    uint16_t src2[] = { 0xffff, 0x8000, 0x0001, 0x7fff };
    uint16_t src1[] = { 0x0001, 0xffff, 0x8000, 0x0002 };
    uint32_t expected_vwaddu_vv[] = {
        0x00010000u, 0x00017fffu, 0x00008001u, 0x00008001u,
    };
    uint32_t expected_vwsubu_vv[] = {
        0x0000fffeu, 0xffff8001u, 0xffff8001u, 0x00007ffdu,
    };
    uint32_t expected_vwadd_vv[] = {
        0, 0xffff7fffu, 0xffff8001u, 0x00008001u,
    };
    uint32_t expected_vwsub_vv[] = {
        0xfffffffeu, 0xffff8001u, 0x00008001u, 0x00007ffdu,
    };
    uint32_t expected_vwaddu_vx[] = {
        0x0001fffdu, 0x00017ffeu, 0x0000ffffu, 0x00017ffdu,
    };
    uint32_t expected_vwadd_vx[] = {
        0xfffffffdu, 0xffff7ffeu, 0xffffffffu, 0x00007ffdu,
    };
    uint32_t expected_vwsubu_vx[] = {
        1, 0xffff8002u, 0xffff0003u, 0xffff8001u,
    };
    uint32_t expected_vwsub_vx[] = {
        1, 0xffff8002u, 3, 0x00008001u,
    };
    uint32_t expected_masked[] = {
        0x00010000u, 0xffffffffu, 0x00008001u, 0xffffffffu,
    };
    uint32_t out_vwaddu_vv[4] = { 0 };
    uint32_t out_vwsubu_vv[4] = { 0 };
    uint32_t out_vwadd_vv[4] = { 0 };
    uint32_t out_vwsub_vv[4] = { 0 };
    uint32_t out_vwaddu_vx[4] = { 0 };
    uint32_t out_vwadd_vx[4] = { 0 };
    uint32_t out_vwsubu_vx[4] = { 0 };
    uint32_t out_vwsub_vx[4] = { 0 };
    uint32_t out_masked[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 4;
    uint64_t t2 = 0xfffe;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    uint64_t t5 = code_start + 0x1a00;
    uint64_t t6 = code_start + 0x1b00;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a2, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T5, &t5));
    OK(uc_reg_write(uc, UC_RISCV_REG_T6, &t6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_vwaddu_vv, sizeof(out_vwaddu_vv)));
    OK(uc_mem_read(uc, a4, out_vwsubu_vv, sizeof(out_vwsubu_vv)));
    OK(uc_mem_read(uc, a5, out_vwadd_vv, sizeof(out_vwadd_vv)));
    OK(uc_mem_read(uc, a6, out_vwsub_vv, sizeof(out_vwsub_vv)));
    OK(uc_mem_read(uc, a7, out_vwaddu_vx, sizeof(out_vwaddu_vx)));
    OK(uc_mem_read(uc, t3, out_vwadd_vx, sizeof(out_vwadd_vx)));
    OK(uc_mem_read(uc, t4, out_vwsubu_vx, sizeof(out_vwsubu_vx)));
    OK(uc_mem_read(uc, t5, out_vwsub_vx, sizeof(out_vwsub_vx)));
    OK(uc_mem_read(uc, t6, out_masked, sizeof(out_masked)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_vwaddu_vv[i] == expected_vwaddu_vv[i]);
        TEST_CHECK(out_vwsubu_vv[i] == expected_vwsubu_vv[i]);
        TEST_CHECK(out_vwadd_vv[i] == expected_vwadd_vv[i]);
        TEST_CHECK(out_vwsub_vv[i] == expected_vwsub_vv[i]);
        TEST_CHECK(out_vwaddu_vx[i] == expected_vwaddu_vx[i]);
        TEST_CHECK(out_vwadd_vx[i] == expected_vwadd_vx[i]);
        TEST_CHECK(out_vwsubu_vx[i] == expected_vwsubu_vx[i]);
        TEST_CHECK(out_vwsub_vx[i] == expected_vwsub_vx[i]);
        TEST_CHECK(out_masked[i] == expected_masked[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_widening_add_sub_wv_wx(void)
{
    uc_engine *uc;
    uint8_t code[21 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xc8),
        riscv_encode_rvv_ldst(0, 5, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 2),
        riscv_encode_rvv_op(0x34, 1, 2, 1, 2, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 4),
        riscv_encode_rvv_op(0x36, 1, 2, 1, 2, 6),
        riscv_encode_rvv_ldst(1, 6, 1, 14, 6),
        riscv_encode_rvv_op(0x35, 1, 2, 1, 2, 8),
        riscv_encode_rvv_ldst(1, 6, 1, 15, 8),
        riscv_encode_rvv_op(0x37, 1, 2, 1, 2, 10),
        riscv_encode_rvv_ldst(1, 6, 1, 16, 10),
        riscv_encode_rvv_op(0x34, 1, 2, 7, 6, 12),
        riscv_encode_rvv_ldst(1, 6, 1, 17, 12),
        riscv_encode_rvv_op(0x35, 1, 2, 7, 6, 14),
        riscv_encode_rvv_ldst(1, 6, 1, 28, 14),
        riscv_encode_rvv_op(0x36, 1, 2, 7, 6, 16),
        riscv_encode_rvv_ldst(1, 6, 1, 29, 16),
        riscv_encode_rvv_op(0x37, 1, 2, 7, 6, 18),
        riscv_encode_rvv_ldst(1, 6, 1, 30, 18),
        riscv_encode_rvv_op(0x34, 1, 2, 1, 2, 2),
        riscv_encode_rvv_ldst(1, 6, 1, 31, 2),
    };
    uint16_t narrow[] = { 0x0001, 0xffff, 0x8000, 0x0002 };
    uint32_t wide[] = {
        0xffffffffu, 0x00008000u, 0xffff8000u, 0x00000001u,
    };
    uint32_t expected_vwaddu_wv[] = {
        0, 0x00017fffu, 0, 3,
    };
    uint32_t expected_vwsubu_wv[] = {
        0xfffffffeu, 0xffff8001u, 0xffff0000u, 0xffffffffu,
    };
    uint32_t expected_vwadd_wv[] = {
        0, 0x00007fffu, 0xffff0000u, 3,
    };
    uint32_t expected_vwsub_wv[] = {
        0xfffffffeu, 0x00008001u, 0, 0xffffffffu,
    };
    uint32_t expected_vwaddu_wx[] = {
        0x0000fffdu, 0x00017ffeu, 0x00007ffeu, 0x0000ffffu,
    };
    uint32_t expected_vwadd_wx[] = {
        0xfffffffdu, 0x00007ffeu, 0xffff7ffeu, 0xffffffffu,
    };
    uint32_t expected_vwsubu_wx[] = {
        0xffff0001u, 0xffff8002u, 0xfffe8002u, 0xffff0003u,
    };
    uint32_t expected_vwsub_wx[] = {
        1, 0x00008002u, 0xffff8002u, 3,
    };
    uint32_t out_vwaddu_wv[4] = { 0 };
    uint32_t out_vwsubu_wv[4] = { 0 };
    uint32_t out_vwadd_wv[4] = { 0 };
    uint32_t out_vwsub_wv[4] = { 0 };
    uint32_t out_vwaddu_wx[4] = { 0 };
    uint32_t out_vwadd_wx[4] = { 0 };
    uint32_t out_vwsubu_wx[4] = { 0 };
    uint32_t out_vwsub_wx[4] = { 0 };
    uint32_t out_inplace[4] = { 0 };
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 4;
    uint64_t t2 = 0xfffe;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    uint64_t t5 = code_start + 0x1a00;
    uint64_t t6 = code_start + 0x1b00;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a1, narrow, sizeof(narrow)));
    OK(uc_mem_write(uc, a2, wide, sizeof(wide)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T5, &t5));
    OK(uc_reg_write(uc, UC_RISCV_REG_T6, &t6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_vwaddu_wv, sizeof(out_vwaddu_wv)));
    OK(uc_mem_read(uc, a4, out_vwsubu_wv, sizeof(out_vwsubu_wv)));
    OK(uc_mem_read(uc, a5, out_vwadd_wv, sizeof(out_vwadd_wv)));
    OK(uc_mem_read(uc, a6, out_vwsub_wv, sizeof(out_vwsub_wv)));
    OK(uc_mem_read(uc, a7, out_vwaddu_wx, sizeof(out_vwaddu_wx)));
    OK(uc_mem_read(uc, t3, out_vwadd_wx, sizeof(out_vwadd_wx)));
    OK(uc_mem_read(uc, t4, out_vwsubu_wx, sizeof(out_vwsubu_wx)));
    OK(uc_mem_read(uc, t5, out_vwsub_wx, sizeof(out_vwsub_wx)));
    OK(uc_mem_read(uc, t6, out_inplace, sizeof(out_inplace)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_vwaddu_wv[i] == expected_vwaddu_wv[i]);
        TEST_CHECK(out_vwsubu_wv[i] == expected_vwsubu_wv[i]);
        TEST_CHECK(out_vwadd_wv[i] == expected_vwadd_wv[i]);
        TEST_CHECK(out_vwsub_wv[i] == expected_vwsub_wv[i]);
        TEST_CHECK(out_vwaddu_wx[i] == expected_vwaddu_wx[i]);
        TEST_CHECK(out_vwadd_wx[i] == expected_vwadd_wx[i]);
        TEST_CHECK(out_vwsubu_wx[i] == expected_vwsubu_wx[i]);
        TEST_CHECK(out_vwsub_wx[i] == expected_vwsub_wx[i]);
        TEST_CHECK(out_inplace[i] == expected_vwaddu_wv[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_widening_add_sub_illegal(void)
{
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x30, 1, 1, 2, 2, 4), 0xd8);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x30, 1, 1, 2, 2, 8), 0xcb);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x30, 0, 1, 2, 2, 0), 0xc8);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x30, 1, 2, 1, 2, 2), 0xc8);
}

static void test_riscv64_rvv_widening_multiply(void)
{
    uc_engine *uc;
    uint8_t code[18 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xc8),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 5, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 5, 1, 12, 2),
        riscv_encode_rvv_op(0x3b, 1, 1, 2, 2, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 4),
        riscv_encode_rvv_op(0x38, 1, 1, 2, 2, 6),
        riscv_encode_rvv_ldst(1, 6, 1, 14, 6),
        riscv_encode_rvv_op(0x3a, 1, 1, 2, 2, 8),
        riscv_encode_rvv_ldst(1, 6, 1, 15, 8),
        riscv_encode_rvv_op(0x3b, 1, 1, 7, 6, 10),
        riscv_encode_rvv_ldst(1, 6, 1, 16, 10),
        riscv_encode_rvv_op(0x38, 1, 1, 7, 6, 12),
        riscv_encode_rvv_ldst(1, 6, 1, 17, 12),
        riscv_encode_rvv_op(0x3a, 1, 1, 7, 6, 14),
        riscv_encode_rvv_ldst(1, 6, 1, 28, 14),
        riscv_encode_rvv_op(0x3b, 0, 1, 2, 2, 16),
        riscv_encode_rvv_ldst(1, 6, 1, 29, 16),
    };
    uint8_t mask[] = { 0x05 };
    uint16_t src2[] = { 0xffff, 0x8000, 0x1234, 0xfffe };
    uint16_t src1[] = { 0x0002, 0xffff, 0x0100, 0x8001 };
    uint32_t expected_vwmul_vv[] = {
        0xfffffffeu, 0x00008000u, 0x00123400u, 0x0000fffeu,
    };
    uint32_t expected_vwmulu_vv[] = {
        0x0001fffeu, 0x7fff8000u, 0x00123400u, 0x7ffffffeu,
    };
    uint32_t expected_vwmulsu_vv[] = {
        0xfffffffeu, 0x80008000u, 0x00123400u, 0xfffefffeu,
    };
    uint32_t expected_vwmul_vx[] = {
        3, 0x00018000u, 0xffffc964u, 6,
    };
    uint32_t expected_vwmulu_vx[] = {
        0xfffc0003u, 0x7ffe8000u, 0x1233c964u, 0xfffb0006u,
    };
    uint32_t expected_vwmulsu_vx[] = {
        0xffff0003u, 0x80018000u, 0x1233c964u, 0xfffe0006u,
    };
    uint32_t expected_masked[] = {
        0xfffffffeu, 0xffffffffu, 0x00123400u, 0xffffffffu,
    };
    uint32_t out_vwmul_vv[4] = { 0 };
    uint32_t out_vwmulu_vv[4] = { 0 };
    uint32_t out_vwmulsu_vv[4] = { 0 };
    uint32_t out_vwmul_vx[4] = { 0 };
    uint32_t out_vwmulu_vx[4] = { 0 };
    uint32_t out_vwmulsu_vx[4] = { 0 };
    uint32_t out_masked[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 4;
    uint64_t t2 = 0xfffd;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a2, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_vwmul_vv, sizeof(out_vwmul_vv)));
    OK(uc_mem_read(uc, a4, out_vwmulu_vv, sizeof(out_vwmulu_vv)));
    OK(uc_mem_read(uc, a5, out_vwmulsu_vv, sizeof(out_vwmulsu_vv)));
    OK(uc_mem_read(uc, a6, out_vwmul_vx, sizeof(out_vwmul_vx)));
    OK(uc_mem_read(uc, a7, out_vwmulu_vx, sizeof(out_vwmulu_vx)));
    OK(uc_mem_read(uc, t3, out_vwmulsu_vx, sizeof(out_vwmulsu_vx)));
    OK(uc_mem_read(uc, t4, out_masked, sizeof(out_masked)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_vwmul_vv[i] == expected_vwmul_vv[i]);
        TEST_CHECK(out_vwmulu_vv[i] == expected_vwmulu_vv[i]);
        TEST_CHECK(out_vwmulsu_vv[i] == expected_vwmulsu_vv[i]);
        TEST_CHECK(out_vwmul_vx[i] == expected_vwmul_vx[i]);
        TEST_CHECK(out_vwmulu_vx[i] == expected_vwmulu_vx[i]);
        TEST_CHECK(out_vwmulsu_vx[i] == expected_vwmulsu_vx[i]);
        TEST_CHECK(out_masked[i] == expected_masked[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_widening_multiply_32(void)
{
    uc_engine *uc;
    uint8_t code[9 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 2),
        riscv_encode_rvv_op(0x3b, 1, 1, 2, 2, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 4),
        riscv_encode_rvv_op(0x38, 1, 1, 2, 2, 6),
        riscv_encode_rvv_ldst(1, 7, 1, 14, 6),
        riscv_encode_rvv_op(0x3a, 1, 1, 7, 6, 8),
        riscv_encode_rvv_ldst(1, 7, 1, 15, 8),
    };
    uint32_t src2[] = { 0xffffffffu, 0x80000000u };
    uint32_t src1[] = { 3, 0xffffffffu };
    uint64_t expected_vwmul_vv[] = {
        0xfffffffffffffffdull, 0x0000000080000000ull,
    };
    uint64_t expected_vwmulu_vv[] = {
        0x00000002fffffffdull, 0x7fffffff80000000ull,
    };
    uint64_t expected_vwmulsu_vx[] = {
        0xffffffff00000003ull, 0x8000000180000000ull,
    };
    uint64_t out_vwmul_vv[2] = { 0 };
    uint64_t out_vwmulu_vv[2] = { 0 };
    uint64_t out_vwmulsu_vx[2] = { 0 };
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t t0 = 2;
    uint64_t t2 = 0xfffffffd;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a1, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a2, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_vwmul_vv, sizeof(out_vwmul_vv)));
    OK(uc_mem_read(uc, a4, out_vwmulu_vv, sizeof(out_vwmulu_vv)));
    OK(uc_mem_read(uc, a5, out_vwmulsu_vx, sizeof(out_vwmulsu_vx)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_vwmul_vv[i] == expected_vwmul_vv[i]);
        TEST_CHECK(out_vwmulu_vv[i] == expected_vwmulu_vv[i]);
        TEST_CHECK(out_vwmulsu_vx[i] == expected_vwmulsu_vx[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_widening_multiply_illegal(void)
{
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x3b, 1, 1, 2, 2, 4), 0xd8);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x3b, 1, 1, 2, 2, 8), 0xcb);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x3b, 0, 1, 2, 2, 0), 0xc8);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x3b, 1, 2, 1, 2, 2), 0xc8);
}

static void test_riscv64_rvv_multiply_add(void)
{
    uc_engine *uc;
    uint8_t code[31 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xc8),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 5, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 5, 1, 12, 2),
        riscv_encode_rvv_ldst(0, 5, 1, 13, 3),
        riscv_encode_rvv_op(0x2d, 1, 1, 2, 2, 3),
        riscv_encode_rvv_ldst(1, 5, 1, 14, 3),
        riscv_encode_rvv_ldst(0, 5, 1, 13, 4),
        riscv_encode_rvv_op(0x2f, 1, 1, 2, 2, 4),
        riscv_encode_rvv_ldst(1, 5, 1, 15, 4),
        riscv_encode_rvv_ldst(0, 5, 1, 13, 5),
        riscv_encode_rvv_op(0x29, 1, 1, 2, 2, 5),
        riscv_encode_rvv_ldst(1, 5, 1, 16, 5),
        riscv_encode_rvv_ldst(0, 5, 1, 13, 6),
        riscv_encode_rvv_op(0x2b, 1, 1, 2, 2, 6),
        riscv_encode_rvv_ldst(1, 5, 1, 17, 6),
        riscv_encode_rvv_ldst(0, 5, 1, 13, 7),
        riscv_encode_rvv_op(0x2d, 1, 1, 7, 6, 7),
        riscv_encode_rvv_ldst(1, 5, 1, 28, 7),
        riscv_encode_rvv_ldst(0, 5, 1, 13, 8),
        riscv_encode_rvv_op(0x2f, 1, 1, 7, 6, 8),
        riscv_encode_rvv_ldst(1, 5, 1, 29, 8),
        riscv_encode_rvv_ldst(0, 5, 1, 13, 9),
        riscv_encode_rvv_op(0x29, 1, 1, 7, 6, 9),
        riscv_encode_rvv_ldst(1, 5, 1, 30, 9),
        riscv_encode_rvv_ldst(0, 5, 1, 13, 10),
        riscv_encode_rvv_op(0x2b, 1, 1, 7, 6, 10),
        riscv_encode_rvv_ldst(1, 5, 1, 31, 10),
        riscv_encode_rvv_ldst(0, 5, 1, 13, 11),
        riscv_encode_rvv_op(0x2d, 0, 1, 2, 2, 11),
        riscv_encode_rvv_ldst(1, 5, 1, 8, 11),
    };
    uint8_t mask[] = { 0x05 };
    uint16_t src2[] = { 0x0002, 0xfffc, 0x8000, 0x0007 };
    uint16_t src1[] = { 0x0003, 0xfffe, 0x0002, 0x8001 };
    uint16_t acc[] = { 0x000a, 0x0014, 0xfffb, 0x8000 };
    uint16_t expected_vmacc_vv[] = { 0x0010, 0x001c, 0xfffb, 0x0007 };
    uint16_t expected_vnmsac_vv[] = { 0x0004, 0x000c, 0xfffb, 0xfff9 };
    uint16_t expected_vmadd_vv[] = { 0x0020, 0xffd4, 0x7ff6, 0x8007 };
    uint16_t expected_vnmsub_vv[] = { 0xffe4, 0x0024, 0x800a, 0x8007 };
    uint16_t expected_vmacc_vx[] = { 0x0004, 0x0020, 0x7ffb, 0x7feb };
    uint16_t expected_vnmsac_vx[] = { 0x0010, 0x0008, 0x7ffb, 0x8015 };
    uint16_t expected_vmadd_vx[] = { 0xffe4, 0xffc0, 0x800f, 0x8007 };
    uint16_t expected_vnmsub_vx[] = { 0x0020, 0x0038, 0x7ff1, 0x8007 };
    uint16_t expected_masked[] = { 0x0010, 0xffff, 0xfffb, 0xffff };
    uint16_t out_vmacc_vv[4] = { 0 };
    uint16_t out_vnmsac_vv[4] = { 0 };
    uint16_t out_vmadd_vv[4] = { 0 };
    uint16_t out_vnmsub_vv[4] = { 0 };
    uint16_t out_vmacc_vx[4] = { 0 };
    uint16_t out_vnmsac_vx[4] = { 0 };
    uint16_t out_vmadd_vx[4] = { 0 };
    uint16_t out_vnmsub_vx[4] = { 0 };
    uint16_t out_masked[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 4;
    uint64_t t2 = 0xfffd;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    uint64_t t5 = code_start + 0x1a00;
    uint64_t t6 = code_start + 0x1b00;
    uint64_t s0 = code_start + 0x1c00;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a2, src1, sizeof(src1)));
    OK(uc_mem_write(uc, a3, acc, sizeof(acc)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T5, &t5));
    OK(uc_reg_write(uc, UC_RISCV_REG_T6, &t6));
    OK(uc_reg_write(uc, UC_RISCV_REG_S0, &s0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a4, out_vmacc_vv, sizeof(out_vmacc_vv)));
    OK(uc_mem_read(uc, a5, out_vnmsac_vv, sizeof(out_vnmsac_vv)));
    OK(uc_mem_read(uc, a6, out_vmadd_vv, sizeof(out_vmadd_vv)));
    OK(uc_mem_read(uc, a7, out_vnmsub_vv, sizeof(out_vnmsub_vv)));
    OK(uc_mem_read(uc, t3, out_vmacc_vx, sizeof(out_vmacc_vx)));
    OK(uc_mem_read(uc, t4, out_vnmsac_vx, sizeof(out_vnmsac_vx)));
    OK(uc_mem_read(uc, t5, out_vmadd_vx, sizeof(out_vmadd_vx)));
    OK(uc_mem_read(uc, t6, out_vnmsub_vx, sizeof(out_vnmsub_vx)));
    OK(uc_mem_read(uc, s0, out_masked, sizeof(out_masked)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_vmacc_vv[i] == expected_vmacc_vv[i]);
        TEST_CHECK(out_vnmsac_vv[i] == expected_vnmsac_vv[i]);
        TEST_CHECK(out_vmadd_vv[i] == expected_vmadd_vv[i]);
        TEST_CHECK(out_vnmsub_vv[i] == expected_vnmsub_vv[i]);
        TEST_CHECK(out_vmacc_vx[i] == expected_vmacc_vx[i]);
        TEST_CHECK(out_vnmsac_vx[i] == expected_vnmsac_vx[i]);
        TEST_CHECK(out_vmadd_vx[i] == expected_vmadd_vx[i]);
        TEST_CHECK(out_vnmsub_vx[i] == expected_vnmsub_vx[i]);
        TEST_CHECK(out_masked[i] == expected_masked[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_widening_multiply_add(void)
{
    uc_engine *uc;
    uint8_t code[28 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xc8),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 5, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 5, 1, 12, 2),
        riscv_encode_rvv_ldst(0, 6, 1, 13, 4),
        riscv_encode_rvv_op(0x3c, 1, 1, 2, 2, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 14, 4),
        riscv_encode_rvv_ldst(0, 6, 1, 13, 6),
        riscv_encode_rvv_op(0x3d, 1, 1, 2, 2, 6),
        riscv_encode_rvv_ldst(1, 6, 1, 15, 6),
        riscv_encode_rvv_ldst(0, 6, 1, 13, 8),
        riscv_encode_rvv_op(0x3f, 1, 1, 2, 2, 8),
        riscv_encode_rvv_ldst(1, 6, 1, 16, 8),
        riscv_encode_rvv_ldst(0, 6, 1, 13, 10),
        riscv_encode_rvv_op(0x3c, 1, 1, 7, 6, 10),
        riscv_encode_rvv_ldst(1, 6, 1, 17, 10),
        riscv_encode_rvv_ldst(0, 6, 1, 13, 12),
        riscv_encode_rvv_op(0x3d, 1, 1, 7, 6, 12),
        riscv_encode_rvv_ldst(1, 6, 1, 28, 12),
        riscv_encode_rvv_ldst(0, 6, 1, 13, 14),
        riscv_encode_rvv_op(0x3f, 1, 1, 7, 6, 14),
        riscv_encode_rvv_ldst(1, 6, 1, 29, 14),
        riscv_encode_rvv_ldst(0, 6, 1, 13, 16),
        riscv_encode_rvv_op(0x3e, 1, 1, 7, 6, 16),
        riscv_encode_rvv_ldst(1, 6, 1, 30, 16),
        riscv_encode_rvv_ldst(0, 6, 1, 13, 18),
        riscv_encode_rvv_op(0x3d, 0, 1, 2, 2, 18),
        riscv_encode_rvv_ldst(1, 6, 1, 31, 18),
    };
    uint8_t mask[] = { 0x05 };
    uint16_t src2[] = { 0xffff, 0x8000, 0x0005, 0xfffe };
    uint16_t src1[] = { 0x0002, 0xffff, 0xfffd, 0x0004 };
    uint32_t acc[] = { 10, 0xfffffff0u, 1000, 0x80000000u };
    uint32_t expected_vwmaccu_vv[] = {
        0x00020008u, 0x7fff7ff0u, 0x000503d9u, 0x8003fff8u,
    };
    uint32_t expected_vwmacc_vv[] = {
        0x00000008u, 0x00007ff0u, 0x000003d9u, 0x7ffffff8u,
    };
    uint32_t expected_vwmaccsu_vv[] = {
        0x00020008u, 0xffff7ff0u, 0x000003d9u, 0x8003fff8u,
    };
    uint32_t expected_vwmaccu_vx[] = {
        0xfffc000du, 0x7ffe7ff0u, 0x000503d9u, 0x7ffb0006u,
    };
    uint32_t expected_vwmacc_vx[] = {
        0x0000000du, 0x00017ff0u, 0x000003d9u, 0x80000006u,
    };
    uint32_t expected_vwmaccsu_vx[] = {
        0xfffd000du, 0xfffe7ff0u, 0x000003d9u, 0x7ffd0006u,
    };
    uint32_t expected_vwmaccus_vx[] = {
        0xffff000du, 0x80017ff0u, 0x000503d9u, 0x7ffe0006u,
    };
    uint32_t expected_masked[] = {
        0x00000008u, 0xffffffffu, 0x000003d9u, 0xffffffffu,
    };
    uint32_t out_vwmaccu_vv[4] = { 0 };
    uint32_t out_vwmacc_vv[4] = { 0 };
    uint32_t out_vwmaccsu_vv[4] = { 0 };
    uint32_t out_vwmaccu_vx[4] = { 0 };
    uint32_t out_vwmacc_vx[4] = { 0 };
    uint32_t out_vwmaccsu_vx[4] = { 0 };
    uint32_t out_vwmaccus_vx[4] = { 0 };
    uint32_t out_masked[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 4;
    uint64_t t2 = 0xfffd;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    uint64_t t5 = code_start + 0x1a00;
    uint64_t t6 = code_start + 0x1b00;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a2, src1, sizeof(src1)));
    OK(uc_mem_write(uc, a3, acc, sizeof(acc)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T5, &t5));
    OK(uc_reg_write(uc, UC_RISCV_REG_T6, &t6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a4, out_vwmaccu_vv, sizeof(out_vwmaccu_vv)));
    OK(uc_mem_read(uc, a5, out_vwmacc_vv, sizeof(out_vwmacc_vv)));
    OK(uc_mem_read(uc, a6, out_vwmaccsu_vv, sizeof(out_vwmaccsu_vv)));
    OK(uc_mem_read(uc, a7, out_vwmaccu_vx, sizeof(out_vwmaccu_vx)));
    OK(uc_mem_read(uc, t3, out_vwmacc_vx, sizeof(out_vwmacc_vx)));
    OK(uc_mem_read(uc, t4, out_vwmaccsu_vx, sizeof(out_vwmaccsu_vx)));
    OK(uc_mem_read(uc, t5, out_vwmaccus_vx, sizeof(out_vwmaccus_vx)));
    OK(uc_mem_read(uc, t6, out_masked, sizeof(out_masked)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_vwmaccu_vv[i] == expected_vwmaccu_vv[i]);
        TEST_CHECK(out_vwmacc_vv[i] == expected_vwmacc_vv[i]);
        TEST_CHECK(out_vwmaccsu_vv[i] == expected_vwmaccsu_vv[i]);
        TEST_CHECK(out_vwmaccu_vx[i] == expected_vwmaccu_vx[i]);
        TEST_CHECK(out_vwmacc_vx[i] == expected_vwmacc_vx[i]);
        TEST_CHECK(out_vwmaccsu_vx[i] == expected_vwmaccsu_vx[i]);
        TEST_CHECK(out_vwmaccus_vx[i] == expected_vwmaccus_vx[i]);
        TEST_CHECK(out_masked[i] == expected_masked[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_widening_multiply_add_32(void)
{
    uc_engine *uc;
    uint8_t code[15 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 12, 2),
        riscv_encode_rvv_ldst(0, 7, 1, 13, 4),
        riscv_encode_rvv_op(0x3d, 1, 1, 2, 2, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 14, 4),
        riscv_encode_rvv_ldst(0, 7, 1, 13, 6),
        riscv_encode_rvv_op(0x3c, 1, 1, 2, 2, 6),
        riscv_encode_rvv_ldst(1, 7, 1, 15, 6),
        riscv_encode_rvv_ldst(0, 7, 1, 13, 8),
        riscv_encode_rvv_op(0x3f, 1, 1, 7, 6, 8),
        riscv_encode_rvv_ldst(1, 7, 1, 16, 8),
        riscv_encode_rvv_ldst(0, 7, 1, 13, 10),
        riscv_encode_rvv_op(0x3e, 1, 1, 7, 6, 10),
        riscv_encode_rvv_ldst(1, 7, 1, 17, 10),
    };
    uint32_t src2[] = { 0xffffffffu, 0x80000000u };
    uint32_t src1[] = { 3, 0xffffffffu };
    uint64_t acc[] = { 10, 0xfffffffffffffff0ull };
    uint64_t expected_vwmacc_vv[] = {
        0x0000000000000007ull, 0x000000007ffffff0ull,
    };
    uint64_t expected_vwmaccu_vv[] = {
        0x0000000300000007ull, 0x7fffffff7ffffff0ull,
    };
    uint64_t expected_vwmaccsu_vx[] = {
        0xfffffffd0000000dull, 0xfffffffe7ffffff0ull,
    };
    uint64_t expected_vwmaccus_vx[] = {
        0xffffffff0000000dull, 0x800000017ffffff0ull,
    };
    uint64_t out_vwmacc_vv[2] = { 0 };
    uint64_t out_vwmaccu_vv[2] = { 0 };
    uint64_t out_vwmaccsu_vx[2] = { 0 };
    uint64_t out_vwmaccus_vx[2] = { 0 };
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 2;
    uint64_t t2 = 0xfffffffd;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a1, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a2, src1, sizeof(src1)));
    OK(uc_mem_write(uc, a3, acc, sizeof(acc)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a4, out_vwmacc_vv, sizeof(out_vwmacc_vv)));
    OK(uc_mem_read(uc, a5, out_vwmaccu_vv, sizeof(out_vwmaccu_vv)));
    OK(uc_mem_read(uc, a6, out_vwmaccsu_vx, sizeof(out_vwmaccsu_vx)));
    OK(uc_mem_read(uc, a7, out_vwmaccus_vx, sizeof(out_vwmaccus_vx)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_vwmacc_vv[i] == expected_vwmacc_vv[i]);
        TEST_CHECK(out_vwmaccu_vv[i] == expected_vwmaccu_vv[i]);
        TEST_CHECK(out_vwmaccsu_vx[i] == expected_vwmaccsu_vx[i]);
        TEST_CHECK(out_vwmaccus_vx[i] == expected_vwmaccus_vx[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_multiply_add_illegal(void)
{
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x2d, 0, 1, 2, 2, 0), 0xc8);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x3d, 1, 1, 2, 2, 4), 0xd8);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x3d, 1, 1, 2, 2, 8), 0xcb);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x3d, 0, 1, 2, 2, 0), 0xc8);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x3d, 1, 2, 1, 2, 2), 0xc8);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x3e, 0, 1, 7, 6, 0), 0xc8);
}

static void test_riscv64_rvv_mask_logical(void)
{
    uc_engine *uc;
    uint8_t code[19 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_rvv_mask_ldst(0, 10, 1),
        riscv_encode_rvv_mask_ldst(0, 11, 2),
        riscv_encode_rvv_op(0x19, 0, 1, 2, 2, 3),
        riscv_encode_rvv_op(0x1d, 0, 1, 2, 2, 4),
        riscv_encode_rvv_op(0x18, 0, 1, 2, 2, 5),
        riscv_encode_rvv_op(0x1b, 0, 1, 2, 2, 6),
        riscv_encode_rvv_op(0x1a, 0, 1, 2, 2, 7),
        riscv_encode_rvv_op(0x1e, 0, 1, 2, 2, 8),
        riscv_encode_rvv_op(0x1c, 0, 1, 2, 2, 9),
        riscv_encode_rvv_op(0x1f, 0, 1, 2, 2, 10),
        riscv_encode_rvv_mask_ldst(1, 12, 3),
        riscv_encode_rvv_mask_ldst(1, 13, 4),
        riscv_encode_rvv_mask_ldst(1, 14, 5),
        riscv_encode_rvv_mask_ldst(1, 15, 6),
        riscv_encode_rvv_mask_ldst(1, 17, 7),
        riscv_encode_rvv_mask_ldst(1, 7, 8),
        riscv_encode_rvv_mask_ldst(1, 28, 9),
        riscv_encode_rvv_mask_ldst(1, 29, 10),
    };
    uint8_t lhs[] = { 0xb3 };
    uint8_t rhs[] = { 0x6d };
    uint8_t expected[] = {
        0x21, 0xde, 0x92, 0xde, 0xff, 0x00, 0xb3, 0x21,
    };
    uint8_t output[sizeof(expected)] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = 8;
    uint64_t a7 = code_start + 0x1600;
    uint64_t t2 = code_start + 0x1700;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, lhs, sizeof(lhs)));
    OK(uc_mem_write(uc, a1, rhs, sizeof(rhs)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, &output[0], 1));
    OK(uc_mem_read(uc, a3, &output[1], 1));
    OK(uc_mem_read(uc, a4, &output[2], 1));
    OK(uc_mem_read(uc, a5, &output[3], 1));
    OK(uc_mem_read(uc, a7, &output[4], 1));
    OK(uc_mem_read(uc, t2, &output[5], 1));
    OK(uc_mem_read(uc, t3, &output[6], 1));
    OK(uc_mem_read(uc, t4, &output[7], 1));
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_mask_scalar(void)
{
    uc_engine *uc;
    uint8_t code[10 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_mask_ldst(0, 11, 1),
        riscv_encode_rvv_op(0x10, 1, 1, 16, 2, 12),
        riscv_encode_rvv_op(0x10, 1, 1, 17, 2, 13),
        riscv_encode_rvv_op(0x10, 0, 1, 16, 2, 14),
        riscv_encode_rvv_op(0x10, 0, 1, 17, 2, 15),
        riscv_encode_rvv_vsetvli(0, 5, 0xc0),
        riscv_encode_rvv_op(0x10, 1, 1, 16, 2, 16),
        riscv_encode_rvv_op(0x10, 1, 1, 17, 2, 17),
    };
    uint8_t mask[] = { 0x6d };
    uint8_t source[] = { 0xb2 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = 0;
    uint64_t a3 = 0;
    uint64_t a4 = 0;
    uint64_t a5 = 0;
    uint64_t a6 = 8;
    uint64_t a7 = 0;
    uint64_t t0 = 0;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, source, sizeof(source)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_read(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_read(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_read(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_read(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_read(uc, UC_RISCV_REG_A7, &a7));

    TEST_CHECK(a2 == 4);
    TEST_CHECK(a3 == 1);
    TEST_CHECK(a4 == 1);
    TEST_CHECK(a5 == 5);
    TEST_CHECK(a6 == 0);
    TEST_CHECK(a7 == 0xffffffffffffffffull);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_mask_set(void)
{
    uc_engine *uc;
    uint8_t code[8 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_rvv_mask_ldst(0, 10, 1),
        riscv_encode_rvv_op(0x14, 1, 1, 1, 2, 2),
        riscv_encode_rvv_op(0x14, 1, 1, 3, 2, 3),
        riscv_encode_rvv_op(0x14, 1, 1, 2, 2, 4),
        riscv_encode_rvv_mask_ldst(1, 11, 2),
        riscv_encode_rvv_mask_ldst(1, 12, 3),
        riscv_encode_rvv_mask_ldst(1, 13, 4),
    };
    uint8_t source[] = { 0x28 };
    uint8_t expected[] = { 0x07, 0x0f, 0x08 };
    uint8_t output[sizeof(expected)] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a6 = 8;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, source, sizeof(source)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a1, &output[0], 1));
    OK(uc_mem_read(uc, a2, &output[1], 1));
    OK(uc_mem_read(uc, a3, &output[2], 1));
    for (i = 0; i < sizeof(expected); i++) {
        TEST_CHECK(output[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_viota_vid(void)
{
    uc_engine *uc;
    uint8_t code[8 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_mask_ldst(0, 11, 1),
        riscv_encode_rvv_op(0x14, 1, 1, 16, 2, 2),
        riscv_encode_rvv_op(0x14, 1, 0, 17, 2, 3),
        riscv_encode_rvv_op(0x14, 0, 0, 17, 2, 4),
        riscv_encode_rvv_ldst(1, 5, 1, 12, 2),
        riscv_encode_rvv_ldst(1, 5, 1, 13, 3),
    };
    uint32_t store_vid_masked = riscv_encode_rvv_ldst(1, 5, 1, 14, 4);
    uint8_t full_code[9 * 4];
    uint8_t mask[] = { 0x5b };
    uint8_t source[] = { 0xb2 };
    uint16_t expected_viota[] = { 0, 0, 1, 1, 1, 2, 3, 3 };
    uint16_t expected_vid[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    uint16_t expected_vid_masked[] = {
        0, 1, 0xffff, 3, 4, 0xffff, 6, 0xffff,
    };
    uint16_t out_viota[8] = { 0 };
    uint16_t out_vid[8] = { 0 };
    uint16_t out_vid_masked[8] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a6 = 8;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&full_code[i * 4], insns[i]);
    }
    riscv_insn_to_code(&full_code[8 * 4], store_vid_masked);

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)full_code, sizeof(full_code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, source, sizeof(source)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(full_code), 0, 0));

    OK(uc_mem_read(uc, a2, out_viota, sizeof(out_viota)));
    OK(uc_mem_read(uc, a3, out_vid, sizeof(out_vid)));
    OK(uc_mem_read(uc, a4, out_vid_masked, sizeof(out_vid_masked)));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(out_viota[i] == expected_viota[i]);
        TEST_CHECK(out_vid[i] == expected_vid[i]);
        TEST_CHECK(out_vid_masked[i] == expected_vid_masked[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_mask_utilities_illegal(void)
{
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_op(0x14, 0, 1, 1, 2, 0));
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_op(0x14, 1, 1, 1, 2, 1));
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_op(0x14, 1, 1, 16, 2, 1));
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_op(0x14, 0, 0, 17, 2, 0));
}

static void test_riscv64_rvv_fixed_point_saturating(void)
{
    uc_engine *uc;
    uint8_t code[16 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_csr(RISCV_CSR_VXSAT, 0, 1, 0),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 0, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 0, 1, 12, 2),
        riscv_encode_rvv_op(0x20, 1, 1, 2, 0, 3),
        riscv_encode_rvv_ldst(1, 0, 1, 13, 3),
        riscv_encode_rvv_op(0x21, 1, 1, 15, 3, 4),
        riscv_encode_rvv_ldst(1, 0, 1, 14, 4),
        riscv_encode_rvv_op(0x22, 1, 1, 7, 4, 5),
        riscv_encode_rvv_ldst(1, 0, 1, 15, 5),
        riscv_encode_rvv_op(0x23, 1, 1, 2, 0, 6),
        riscv_encode_rvv_ldst(1, 0, 1, 29, 6),
        riscv_encode_csr(RISCV_CSR_VXSAT, 0, 2, 17),
        riscv_encode_rvv_op(0x20, 0, 1, 2, 0, 7),
        riscv_encode_rvv_ldst(1, 0, 1, 28, 7),
    };
    uint8_t mask[] = { 0x05 };
    uint8_t src2[] = { 250, 10, 0, 128, 100, 127, 0x80, 5 };
    uint8_t src1[] = { 10, 250, 1, 128, 100, 1, 0xff, 0xfb };
    uint8_t expected_vsaddu[] = {
        0xff, 0xff, 0x01, 0xff, 0xc8, 0x80, 0xff, 0xff,
    };
    uint8_t expected_vsadd_vi[] = {
        0x09, 0x19, 0x0f, 0x8f, 0x73, 0x7f, 0x8f, 0x14,
    };
    uint8_t expected_vssubu_vx[] = {
        0xf3, 0x03, 0x00, 0x79, 0x5d, 0x78, 0x79, 0x00,
    };
    uint8_t expected_vssub[] = {
        0xf0, 0x10, 0xff, 0x00, 0x00, 0x7e, 0x81, 0x0a,
    };
    uint8_t expected_masked[] = {
        0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    uint8_t out_vsaddu[8] = { 0 };
    uint8_t out_vsadd_vi[8] = { 0 };
    uint8_t out_vssubu_vx[8] = { 0 };
    uint8_t out_vssub[8] = { 0 };
    uint8_t out_masked[8] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = 8;
    uint64_t a7 = 0;
    uint64_t t2 = 7;
    uint64_t t3 = code_start + 0x1600;
    uint64_t t4 = code_start + 0x1700;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a2, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_vsaddu, sizeof(out_vsaddu)));
    OK(uc_mem_read(uc, a4, out_vsadd_vi, sizeof(out_vsadd_vi)));
    OK(uc_mem_read(uc, a5, out_vssubu_vx, sizeof(out_vssubu_vx)));
    OK(uc_mem_read(uc, t4, out_vssub, sizeof(out_vssub)));
    OK(uc_mem_read(uc, t3, out_masked, sizeof(out_masked)));
    OK(uc_reg_read(uc, UC_RISCV_REG_A7, &a7));
    TEST_CHECK(a7 == 1);
    for (i = 0; i < 8; i++) {
        TEST_CHECK(out_vsaddu[i] == expected_vsaddu[i]);
        TEST_CHECK(out_vsadd_vi[i] == expected_vsadd_vi[i]);
        TEST_CHECK(out_vssubu_vx[i] == expected_vssubu_vx[i]);
        TEST_CHECK(out_vssub[i] == expected_vssub[i]);
        TEST_CHECK(out_masked[i] == expected_masked[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_fixed_point_rounding(void)
{
    uc_engine *uc;
    uint8_t code[22 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc0),
        riscv_encode_csr(RISCV_CSR_VXRM, 5, 1, 0),
        riscv_encode_csr(RISCV_CSR_VXSAT, 0, 1, 0),
        riscv_encode_rvv_ldst(0, 0, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 0, 1, 11, 2),
        riscv_encode_rvv_op(0x08, 1, 1, 2, 2, 3),
        riscv_encode_rvv_ldst(1, 0, 1, 12, 3),
        riscv_encode_rvv_op(0x09, 1, 1, 2, 2, 4),
        riscv_encode_rvv_ldst(1, 0, 1, 13, 4),
        riscv_encode_rvv_op(0x0b, 1, 1, 2, 2, 5),
        riscv_encode_rvv_ldst(1, 0, 1, 14, 5),
        riscv_encode_rvv_op(0x0a, 1, 1, 7, 6, 6),
        riscv_encode_rvv_ldst(1, 0, 1, 15, 6),
        riscv_encode_rvv_op(0x27, 1, 1, 2, 0, 7),
        riscv_encode_rvv_ldst(1, 0, 1, 17, 7),
        riscv_encode_rvv_op(0x2a, 1, 1, 2, 3, 8),
        riscv_encode_rvv_ldst(1, 0, 1, 28, 8),
        riscv_encode_rvv_op(0x2b, 1, 1, 2, 3, 9),
        riscv_encode_rvv_ldst(1, 0, 1, 29, 9),
        riscv_encode_csr(RISCV_CSR_VXRM, 6, 1, 0),
        riscv_encode_rvv_op(0x2a, 1, 1, 2, 3, 10),
        riscv_encode_rvv_ldst(1, 0, 1, 30, 10),
    };
    uint8_t src2[] = { 10, 11, 5, 250, 0x80, 0x7f, 0x40, 0xc0 };
    uint8_t src1[] = { 3, 4, 5, 10, 0x80, 1, 0x40, 0xc0 };
    uint8_t expected_vaaddu[] = {
        0x07, 0x08, 0x05, 0x82, 0x80, 0x40, 0x40, 0xc0,
    };
    uint8_t expected_vaadd[] = {
        0x07, 0x08, 0x05, 0x02, 0x80, 0x40, 0x40, 0xc0,
    };
    uint8_t expected_vasub[] = {
        0x04, 0x04, 0x00, 0xf8, 0x00, 0x3f, 0x00, 0x00,
    };
    uint8_t expected_vasubu_vx[] = {
        0x04, 0x04, 0x01, 0x7c, 0x3f, 0x3e, 0x1f, 0x5f,
    };
    uint8_t expected_vsmul[] = {
        0x00, 0x00, 0x00, 0x00, 0x7f, 0x01, 0x20, 0x20,
    };
    uint8_t expected_vssrl_rnu[] = {
        0x03, 0x03, 0x01, 0x3f, 0x20, 0x20, 0x10, 0x30,
    };
    uint8_t expected_vssra_rnu[] = {
        0x03, 0x03, 0x01, 0xff, 0xe0, 0x20, 0x10, 0xf0,
    };
    uint8_t expected_vssrl_rne[] = {
        0x02, 0x03, 0x01, 0x3e, 0x20, 0x20, 0x10, 0x30,
    };
    uint8_t out_vaaddu[8] = { 0 };
    uint8_t out_vaadd[8] = { 0 };
    uint8_t out_vasub[8] = { 0 };
    uint8_t out_vasubu_vx[8] = { 0 };
    uint8_t out_vsmul[8] = { 0 };
    uint8_t out_vssrl_rnu[8] = { 0 };
    uint8_t out_vssra_rnu[8] = { 0 };
    uint8_t out_vssrl_rne[8] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = 8;
    uint64_t a7 = code_start + 0x1600;
    uint64_t t2 = 3;
    uint64_t t3 = code_start + 0x1700;
    uint64_t t4 = code_start + 0x1800;
    uint64_t t5 = code_start + 0x1900;
    uint64_t t0 = 0;
    uint64_t t1 = 1;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a1, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T5, &t5));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T1, &t1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_vaaddu, sizeof(out_vaaddu)));
    OK(uc_mem_read(uc, a3, out_vaadd, sizeof(out_vaadd)));
    OK(uc_mem_read(uc, a4, out_vasub, sizeof(out_vasub)));
    OK(uc_mem_read(uc, a5, out_vasubu_vx, sizeof(out_vasubu_vx)));
    OK(uc_mem_read(uc, a7, out_vsmul, sizeof(out_vsmul)));
    OK(uc_mem_read(uc, t3, out_vssrl_rnu, sizeof(out_vssrl_rnu)));
    OK(uc_mem_read(uc, t4, out_vssra_rnu, sizeof(out_vssra_rnu)));
    OK(uc_mem_read(uc, t5, out_vssrl_rne, sizeof(out_vssrl_rne)));
    for (i = 0; i < 8; i++) {
        TEST_CHECK(out_vaaddu[i] == expected_vaaddu[i]);
        TEST_CHECK(out_vaadd[i] == expected_vaadd[i]);
        TEST_CHECK(out_vasub[i] == expected_vasub[i]);
        TEST_CHECK(out_vasubu_vx[i] == expected_vasubu_vx[i]);
        TEST_CHECK(out_vsmul[i] == expected_vsmul[i]);
        TEST_CHECK(out_vssrl_rnu[i] == expected_vssrl_rnu[i]);
        TEST_CHECK(out_vssra_rnu[i] == expected_vssra_rnu[i]);
        TEST_CHECK(out_vssrl_rne[i] == expected_vssrl_rne[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_fixed_point_clip(void)
{
    uc_engine *uc;
    uint8_t code[18 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_csr(RISCV_CSR_VXRM, 5, 1, 0),
        riscv_encode_csr(RISCV_CSR_VXSAT, 0, 1, 0),
        riscv_encode_rvv_ldst(0, 5, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_op(0x2e, 1, 2, 1, 0, 4),
        riscv_encode_rvv_ldst(1, 5, 1, 12, 4),
        riscv_encode_rvv_op(0x2f, 1, 2, 1, 0, 5),
        riscv_encode_rvv_ldst(1, 5, 1, 13, 5),
        riscv_encode_rvv_op(0x2e, 1, 2, 7, 4, 6),
        riscv_encode_rvv_ldst(1, 5, 1, 14, 6),
        riscv_encode_rvv_op(0x2f, 1, 2, 7, 4, 7),
        riscv_encode_rvv_ldst(1, 5, 1, 15, 7),
        riscv_encode_rvv_op(0x2e, 1, 2, 4, 3, 8),
        riscv_encode_rvv_ldst(1, 5, 1, 17, 8),
        riscv_encode_rvv_op(0x2f, 1, 2, 4, 3, 9),
        riscv_encode_rvv_ldst(1, 5, 1, 28, 9),
        riscv_encode_csr(RISCV_CSR_VXSAT, 0, 2, 29),
    };
    uint16_t shifts[] = { 8, 8, 0, 16 };
    uint32_t source[] = {
        0x0001ff00u, 0xffff0000u, 0x00008000u, 0x80000000u,
    };
    uint16_t expected_vnclipu_wv[] = {
        0x01ff, 0xffff, 0x8000, 0x8000,
    };
    uint16_t expected_vnclip_wv[] = {
        0x01ff, 0xff00, 0x7fff, 0x8000,
    };
    uint16_t expected_vnclipu_wx[] = {
        0x01ff, 0xffff, 0x0080, 0xffff,
    };
    uint16_t expected_vnclip_wx[] = {
        0x01ff, 0xff00, 0x0080, 0x8000,
    };
    uint16_t expected_vnclipu_wi[] = {
        0x1ff0, 0xffff, 0x0800, 0xffff,
    };
    uint16_t expected_vnclip_wi[] = {
        0x1ff0, 0xf000, 0x0800, 0x8000,
    };
    uint16_t out_vnclipu_wv[4] = { 0 };
    uint16_t out_vnclip_wv[4] = { 0 };
    uint16_t out_vnclipu_wx[4] = { 0 };
    uint16_t out_vnclip_wx[4] = { 0 };
    uint16_t out_vnclipu_wi[4] = { 0 };
    uint16_t out_vnclip_wi[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = 4;
    uint64_t a7 = code_start + 0x1600;
    uint64_t t0 = 0;
    uint64_t t2 = 8;
    uint64_t t3 = code_start + 0x1700;
    uint64_t t4 = 0;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, shifts, sizeof(shifts)));
    OK(uc_mem_write(uc, a1, source, sizeof(source)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_vnclipu_wv, sizeof(out_vnclipu_wv)));
    OK(uc_mem_read(uc, a3, out_vnclip_wv, sizeof(out_vnclip_wv)));
    OK(uc_mem_read(uc, a4, out_vnclipu_wx, sizeof(out_vnclipu_wx)));
    OK(uc_mem_read(uc, a5, out_vnclip_wx, sizeof(out_vnclip_wx)));
    OK(uc_mem_read(uc, a7, out_vnclipu_wi, sizeof(out_vnclipu_wi)));
    OK(uc_mem_read(uc, t3, out_vnclip_wi, sizeof(out_vnclip_wi)));
    OK(uc_reg_read(uc, UC_RISCV_REG_T4, &t4));
    TEST_CHECK(t4 == 1);
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_vnclipu_wv[i] == expected_vnclipu_wv[i]);
        TEST_CHECK(out_vnclip_wv[i] == expected_vnclip_wv[i]);
        TEST_CHECK(out_vnclipu_wx[i] == expected_vnclipu_wx[i]);
        TEST_CHECK(out_vnclip_wx[i] == expected_vnclip_wx[i]);
        TEST_CHECK(out_vnclipu_wi[i] == expected_vnclipu_wi[i]);
        TEST_CHECK(out_vnclip_wi[i] == expected_vnclip_wi[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_fixed_point_illegal(void)
{
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_op(0x20, 0, 1, 2, 0, 0));
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x2e, 1, 2, 1, 0, 4), 0xd8);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x2e, 0, 2, 1, 0, 0), 0xc8);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x2e, 1, 0, 4, 0, 2), 0xc9);
}

static void test_riscv64_rvv_integer_reduction_sum_logic(void)
{
    uc_engine *uc;
    uint8_t code[11 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_rvv_ldst(0, 5, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 5, 1, 11, 2),
        riscv_encode_rvv_op(0x00, 1, 1, 2, 2, 3),
        riscv_encode_rvv_ldst(1, 5, 1, 12, 3),
        riscv_encode_rvv_op(0x01, 1, 1, 2, 2, 4),
        riscv_encode_rvv_ldst(1, 5, 1, 13, 4),
        riscv_encode_rvv_op(0x02, 1, 1, 2, 2, 5),
        riscv_encode_rvv_ldst(1, 5, 1, 14, 5),
        riscv_encode_rvv_op(0x03, 1, 1, 2, 2, 6),
        riscv_encode_rvv_ldst(1, 5, 1, 15, 6),
    };
    uint16_t source[] = { 0x0003, 0x0005, 0x000c, 0x00f0 };
    uint16_t seed[] = { 0x00ff, 0, 0, 0 };
    uint16_t expected_sum[] = { 0x0203, 0xffff, 0xffff, 0xffff };
    uint16_t expected_and[] = { 0, 0xffff, 0xffff, 0xffff };
    uint16_t expected_or[] = { 0x00ff, 0xffff, 0xffff, 0xffff };
    uint16_t expected_xor[] = { 0x0005, 0xffff, 0xffff, 0xffff };
    uint16_t out_sum[4] = { 0 };
    uint16_t out_and[4] = { 0 };
    uint16_t out_or[4] = { 0 };
    uint16_t out_xor[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = 4;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, source, sizeof(source)));
    OK(uc_mem_write(uc, a1, seed, sizeof(seed)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_sum, sizeof(out_sum)));
    OK(uc_mem_read(uc, a3, out_and, sizeof(out_and)));
    OK(uc_mem_read(uc, a4, out_or, sizeof(out_or)));
    OK(uc_mem_read(uc, a5, out_xor, sizeof(out_xor)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_sum[i] == expected_sum[i]);
        TEST_CHECK(out_and[i] == expected_and[i]);
        TEST_CHECK(out_or[i] == expected_or[i]);
        TEST_CHECK(out_xor[i] == expected_xor[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv32_rvv_integer_reduction_minmax(void)
{
    uc_engine *uc;
    uint8_t code[11 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_op(0x04, 1, 1, 2, 2, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x05, 1, 1, 2, 2, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 4),
        riscv_encode_rvv_op(0x06, 1, 1, 2, 2, 5),
        riscv_encode_rvv_ldst(1, 6, 1, 14, 5),
        riscv_encode_rvv_op(0x07, 1, 1, 2, 2, 6),
        riscv_encode_rvv_ldst(1, 6, 1, 15, 6),
    };
    uint32_t source[] = {
        0x80000000u, 5, 0xfffffffeu, 0x7fffffffu,
    };
    uint32_t seed[] = { 0x10, 0, 0, 0 };
    uint32_t out_minu[4] = { 0 };
    uint32_t out_min[4] = { 0 };
    uint32_t out_maxu[4] = { 0 };
    uint32_t out_max[4] = { 0 };
    uint32_t a0 = code_start + 0x1000;
    uint32_t a1 = code_start + 0x1100;
    uint32_t a2 = code_start + 0x1200;
    uint32_t a3 = code_start + 0x1300;
    uint32_t a4 = code_start + 0x1400;
    uint32_t a5 = code_start + 0x1500;
    uint32_t a6 = 4;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32,
                    (const char *)code, sizeof(code));
    riscv32_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, source, sizeof(source)));
    OK(uc_mem_write(uc, a1, seed, sizeof(seed)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_minu, sizeof(out_minu)));
    OK(uc_mem_read(uc, a3, out_min, sizeof(out_min)));
    OK(uc_mem_read(uc, a4, out_maxu, sizeof(out_maxu)));
    OK(uc_mem_read(uc, a5, out_max, sizeof(out_max)));
    TEST_CHECK(out_minu[0] == 5);
    TEST_CHECK(out_min[0] == 0x80000000u);
    TEST_CHECK(out_maxu[0] == 0xfffffffeu);
    TEST_CHECK(out_max[0] == 0x7fffffffu);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_integer_reduction_masked(void)
{
    uc_engine *uc;
    uint8_t code[6 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 5, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 5, 1, 12, 2),
        riscv_encode_rvv_op(0x00, 0, 1, 2, 2, 0),
        riscv_encode_rvv_ldst(1, 5, 1, 13, 0),
    };
    uint8_t mask[] = { 0x0b };
    uint16_t source[] = { 1, 10, 100, 1000 };
    uint16_t seed[] = { 5, 0, 0, 0 };
    uint16_t expected[] = { 1016, 0xffff, 0xffff, 0xffff };
    uint16_t output[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a6 = 4;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, source, sizeof(source)));
    OK(uc_mem_write(uc, a2, seed, sizeof(seed)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, output, sizeof(output)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(output[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_widening_reduction_sum(void)
{
    uc_engine *uc;
    uint8_t code[7 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_rvv_ldst(0, 5, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_op(0x30, 1, 1, 2, 0, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 12, 4),
        riscv_encode_rvv_op(0x31, 1, 1, 2, 0, 6),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 6),
    };
    uint16_t source[] = { 0xffff, 1, 2, 0xfffe };
    uint32_t seed[] = { 10, 0, 0, 0 };
    uint32_t expected_unsigned[] = {
        0x0002000a, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    };
    uint32_t expected_signed[] = {
        10, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    };
    uint32_t out_unsigned[4] = { 0 };
    uint32_t out_signed[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a6 = 4;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, source, sizeof(source)));
    OK(uc_mem_write(uc, a1, seed, sizeof(seed)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_unsigned, sizeof(out_unsigned)));
    OK(uc_mem_read(uc, a3, out_signed, sizeof(out_signed)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_unsigned[i] == expected_unsigned[i]);
        TEST_CHECK(out_signed[i] == expected_signed[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_widening_reduction_32_to_64(void)
{
    uc_engine *uc;
    uint8_t code[7 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 7, 1, 11, 2),
        riscv_encode_rvv_op(0x30, 1, 1, 2, 0, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 12, 4),
        riscv_encode_rvv_op(0x31, 1, 1, 2, 0, 6),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 6),
    };
    uint32_t source[] = { 0xffffffffu, 1, 0x80000000u };
    uint64_t seed[] = { 5, 0, 0 };
    uint64_t expected_unsigned[] = {
        0x0000000180000005ull,
        0xffffffffffffffffull,
        0xffffffffffffffffull,
    };
    uint64_t expected_signed[] = {
        0xffffffff80000005ull,
        0xffffffffffffffffull,
        0xffffffffffffffffull,
    };
    uint64_t out_unsigned[3] = { 0 };
    uint64_t out_signed[3] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a6 = 3;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, source, sizeof(source)));
    OK(uc_mem_write(uc, a1, seed, sizeof(seed)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_unsigned, sizeof(out_unsigned)));
    OK(uc_mem_read(uc, a3, out_signed, sizeof(out_signed)));
    for (i = 0; i < 3; i++) {
        TEST_CHECK(out_unsigned[i] == expected_unsigned[i]);
        TEST_CHECK(out_signed[i] == expected_signed[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_reduction_illegal(void)
{
    uc_engine *uc;
    uint8_t code[3 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 16, 0xc8),
        riscv_encode_csr(RISCV_CSR_VSTART, 5, 1, 0),
        riscv_encode_rvv_op(0x00, 1, 1, 2, 2, 3),
    };
    uint64_t a6 = 0;
    uint64_t t0 = 1;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_close(uc));

    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x00, 1, 1, 2, 2, 3), 0xc9);
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x31, 1, 2, 6, 0, 4), 0xd8);
}

static void test_riscv64_rvv_float32_reduction(void)
{
    uc_engine *uc;
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 6, 1, 11, 2),
        riscv_encode_rvv_op(0x01, 1, 1, 2, 1, 3),
        riscv_encode_rvv_ldst(1, 6, 1, 12, 3),
        riscv_encode_rvv_op(0x03, 1, 1, 2, 1, 4),
        riscv_encode_rvv_ldst(1, 6, 1, 13, 4),
        riscv_encode_rvv_ldst(0, 6, 1, 14, 5),
        riscv_encode_rvv_op(0x05, 1, 5, 2, 1, 6),
        riscv_encode_rvv_ldst(1, 6, 1, 15, 6),
        riscv_encode_rvv_op(0x07, 1, 5, 2, 1, 7),
        riscv_encode_rvv_ldst(1, 6, 1, 16, 7),
        riscv_encode_csr(RISCV_CSR_FFLAGS, 0, 2, 6),
    };
    uint8_t code[sizeof(insns)];
    uint32_t sum_src[] = {
        0x3f800000u, 0x40000000u, 0x40400000u, 0x40800000u,
    };
    uint32_t minmax_src[] = {
        0x3f800000u, 0x7f800001u, 0xc0000000u, 0x40800000u,
    };
    uint32_t seed[] = { 0x3f000000u, 0, 0, 0 };
    uint32_t expected_sum[] = {
        0x41280000u, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    };
    uint32_t expected_min[] = {
        0xc0000000u, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    };
    uint32_t expected_max[] = {
        0x40800000u, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    };
    uint32_t out_usum[4] = { 0 };
    uint32_t out_osum[4] = { 0 };
    uint32_t out_min[4] = { 0 };
    uint32_t out_max[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t t0 = 4;
    uint64_t t1 = 0;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, sum_src, sizeof(sum_src)));
    OK(uc_mem_write(uc, a1, seed, sizeof(seed)));
    OK(uc_mem_write(uc, a4, minmax_src, sizeof(minmax_src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_usum, sizeof(out_usum)));
    OK(uc_mem_read(uc, a3, out_osum, sizeof(out_osum)));
    OK(uc_mem_read(uc, a5, out_min, sizeof(out_min)));
    OK(uc_mem_read(uc, a6, out_max, sizeof(out_max)));
    OK(uc_reg_read(uc, UC_RISCV_REG_T1, &t1));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_usum[i] == expected_sum[i]);
        TEST_CHECK(out_osum[i] == expected_sum[i]);
        TEST_CHECK(out_min[i] == expected_min[i]);
        TEST_CHECK(out_max[i] == expected_max[i]);
    }
    TEST_CHECK(t1 == 0x10);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_widening_float_reduction(void)
{
    uc_engine *uc;
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_rvv_ldst(0, 6, 1, 10, 1),
        riscv_encode_rvv_ldst(0, 7, 1, 11, 4),
        riscv_encode_rvv_op(0x31, 1, 1, 4, 1, 8),
        riscv_encode_rvv_ldst(1, 7, 1, 12, 8),
        riscv_encode_rvv_op(0x33, 1, 1, 4, 1, 10),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 10),
    };
    uint8_t code[sizeof(insns)];
    uint32_t source[] = {
        0x3f800000u, 0x40000000u, 0x40400000u, 0x40800000u,
    };
    uint64_t seed[] = { 0x3fe0000000000000ull, 0, 0, 0 };
    uint64_t expected[] = {
        0x4025000000000000ull,
        0xffffffffffffffffull,
        0xffffffffffffffffull,
        0xffffffffffffffffull,
    };
    uint64_t out_usum[4] = { 0 };
    uint64_t out_osum[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t t0 = 4;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_mem_write(uc, a0, source, sizeof(source)));
    OK(uc_mem_write(uc, a1, seed, sizeof(seed)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_usum, sizeof(out_usum)));
    OK(uc_mem_read(uc, a3, out_osum, sizeof(out_osum)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_usum[i] == expected[i]);
        TEST_CHECK(out_osum[i] == expected[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_float_reduction_illegal(void)
{
    uc_engine *uc;
    uint8_t code[3 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd0),
        riscv_encode_csr(RISCV_CSR_VSTART, 5, 1, 0),
        riscv_encode_rvv_op(0x01, 1, 1, 2, 1, 3),
    };
    uint64_t t0 = 1;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_fp_state(uc);
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_close(uc));

    run_riscv64_rvv_fp_illegal_vtype(
        riscv_encode_rvv_op(0x01, 1, 1, 2, 1, 3), 0xc0);
    run_riscv64_rvv_fp_illegal_vtype(
        riscv_encode_rvv_op(0x31, 1, 1, 4, 1, 8), 0xd8);
}

static void test_riscv64_rvv_divide_remainder(void)
{
    uc_engine *uc;
    uint8_t code[20 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xc8),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 5, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 5, 1, 12, 2),
        riscv_encode_rvv_op(0x20, 1, 1, 2, 2, 3),
        riscv_encode_rvv_ldst(1, 5, 1, 13, 3),
        riscv_encode_rvv_op(0x21, 1, 1, 2, 2, 4),
        riscv_encode_rvv_ldst(1, 5, 1, 14, 4),
        riscv_encode_rvv_op(0x22, 1, 1, 2, 2, 5),
        riscv_encode_rvv_ldst(1, 5, 1, 15, 5),
        riscv_encode_rvv_op(0x23, 1, 1, 2, 2, 6),
        riscv_encode_rvv_ldst(1, 5, 1, 16, 6),
        riscv_encode_rvv_op(0x20, 1, 1, 7, 6, 7),
        riscv_encode_rvv_ldst(1, 5, 1, 17, 7),
        riscv_encode_rvv_op(0x21, 1, 1, 7, 6, 8),
        riscv_encode_rvv_ldst(1, 5, 1, 28, 8),
        riscv_encode_rvv_op(0x22, 1, 1, 7, 6, 9),
        riscv_encode_rvv_ldst(1, 5, 1, 29, 9),
        riscv_encode_rvv_op(0x23, 1, 1, 7, 6, 10),
        riscv_encode_rvv_ldst(1, 5, 1, 30, 10),
    };
    uint32_t masked_insns[] = {
        riscv_encode_rvv_op(0x20, 0, 1, 2, 2, 11),
        riscv_encode_rvv_ldst(1, 5, 1, 31, 11),
    };
    uint8_t full_code[(20 + 2) * 4];
    uint8_t mask[] = { 0x05 };
    uint16_t src2[] = { 100, 0x8000, 7, 0xfffe };
    uint16_t src1[] = { 3, 0xffff, 0, 0xfffd };
    uint16_t expected_vdivu_vv[] = { 33, 0, 0xffff, 1 };
    uint16_t expected_vdiv_vv[] = { 33, 0x8000, 0xffff, 0 };
    uint16_t expected_vremu_vv[] = { 1, 0x8000, 7, 1 };
    uint16_t expected_vrem_vv[] = { 1, 0, 7, 0xfffe };
    uint16_t expected_vdivu_vx[] = { 0, 0, 0, 1 };
    uint16_t expected_vdiv_vx[] = { 0xffce, 0x4000, 0xfffd, 1 };
    uint16_t expected_vremu_vx[] = { 100, 0x8000, 7, 0 };
    uint16_t expected_vrem_vx[] = { 0, 0, 1, 0 };
    uint16_t expected_masked[] = { 33, 0xffff, 0xffff, 0xffff };
    uint16_t out_vdivu_vv[4] = { 0 };
    uint16_t out_vdiv_vv[4] = { 0 };
    uint16_t out_vremu_vv[4] = { 0 };
    uint16_t out_vrem_vv[4] = { 0 };
    uint16_t out_vdivu_vx[4] = { 0 };
    uint16_t out_vdiv_vx[4] = { 0 };
    uint16_t out_vremu_vx[4] = { 0 };
    uint16_t out_vrem_vx[4] = { 0 };
    uint16_t out_masked[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 4;
    uint64_t t2 = 0xfffe;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    uint64_t t5 = code_start + 0x1a00;
    uint64_t t6 = code_start + 0x1b00;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&full_code[i * 4], insns[i]);
    }
    for (i = 0; i < sizeof(masked_insns) / sizeof(masked_insns[0]); i++) {
        riscv_insn_to_code(&full_code[(20 + i) * 4], masked_insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)full_code, sizeof(full_code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a2, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T5, &t5));
    OK(uc_reg_write(uc, UC_RISCV_REG_T6, &t6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(full_code), 0, 0));

    OK(uc_mem_read(uc, a3, out_vdivu_vv, sizeof(out_vdivu_vv)));
    OK(uc_mem_read(uc, a4, out_vdiv_vv, sizeof(out_vdiv_vv)));
    OK(uc_mem_read(uc, a5, out_vremu_vv, sizeof(out_vremu_vv)));
    OK(uc_mem_read(uc, a6, out_vrem_vv, sizeof(out_vrem_vv)));
    OK(uc_mem_read(uc, a7, out_vdivu_vx, sizeof(out_vdivu_vx)));
    OK(uc_mem_read(uc, t3, out_vdiv_vx, sizeof(out_vdiv_vx)));
    OK(uc_mem_read(uc, t4, out_vremu_vx, sizeof(out_vremu_vx)));
    OK(uc_mem_read(uc, t5, out_vrem_vx, sizeof(out_vrem_vx)));
    OK(uc_mem_read(uc, t6, out_masked, sizeof(out_masked)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_vdivu_vv[i] == expected_vdivu_vv[i]);
        TEST_CHECK(out_vdiv_vv[i] == expected_vdiv_vv[i]);
        TEST_CHECK(out_vremu_vv[i] == expected_vremu_vv[i]);
        TEST_CHECK(out_vrem_vv[i] == expected_vrem_vv[i]);
        TEST_CHECK(out_vdivu_vx[i] == expected_vdivu_vx[i]);
        TEST_CHECK(out_vdiv_vx[i] == expected_vdiv_vx[i]);
        TEST_CHECK(out_vremu_vx[i] == expected_vremu_vx[i]);
        TEST_CHECK(out_vrem_vx[i] == expected_vrem_vx[i]);
        TEST_CHECK(out_masked[i] == expected_masked[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_divide_remainder_zero_vx(void)
{
    uc_engine *uc;
    uint8_t code[10 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xc8),
        riscv_encode_rvv_ldst(0, 5, 1, 11, 1),
        riscv_encode_rvv_op(0x20, 1, 1, 0, 6, 2),
        riscv_encode_rvv_ldst(1, 5, 1, 12, 2),
        riscv_encode_rvv_op(0x21, 1, 1, 0, 6, 3),
        riscv_encode_rvv_ldst(1, 5, 1, 13, 3),
        riscv_encode_rvv_op(0x22, 1, 1, 0, 6, 4),
        riscv_encode_rvv_ldst(1, 5, 1, 14, 4),
        riscv_encode_rvv_op(0x23, 1, 1, 0, 6, 5),
        riscv_encode_rvv_ldst(1, 5, 1, 15, 5),
    };
    uint16_t src[] = { 100, 0x8000, 7, 0xfffe };
    uint16_t expected_div[] = { 0xffff, 0xffff, 0xffff, 0xffff };
    uint16_t expected_rem[] = { 100, 0x8000, 7, 0xfffe };
    uint16_t out_vdivu[4] = { 0 };
    uint16_t out_vdiv[4] = { 0 };
    uint16_t out_vremu[4] = { 0 };
    uint16_t out_vrem[4] = { 0 };
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t t0 = 4;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a1, src, sizeof(src)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a2, out_vdivu, sizeof(out_vdivu)));
    OK(uc_mem_read(uc, a3, out_vdiv, sizeof(out_vdiv)));
    OK(uc_mem_read(uc, a4, out_vremu, sizeof(out_vremu)));
    OK(uc_mem_read(uc, a5, out_vrem, sizeof(out_vrem)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_vdivu[i] == expected_div[i]);
        TEST_CHECK(out_vdiv[i] == expected_div[i]);
        TEST_CHECK(out_vremu[i] == expected_rem[i]);
        TEST_CHECK(out_vrem[i] == expected_rem[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_divide_remainder_64(void)
{
    uc_engine *uc;
    uint8_t code[11 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd8),
        riscv_encode_rvv_ldst(0, 7, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 7, 1, 12, 2),
        riscv_encode_rvv_op(0x21, 1, 1, 2, 2, 3),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 3),
        riscv_encode_rvv_op(0x23, 1, 1, 2, 2, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 14, 4),
        riscv_encode_rvv_op(0x21, 1, 1, 7, 6, 5),
        riscv_encode_rvv_ldst(1, 7, 1, 15, 5),
        riscv_encode_rvv_op(0x23, 1, 1, 7, 6, 6),
        riscv_encode_rvv_ldst(1, 7, 1, 16, 6),
    };
    uint64_t src2[] = { 0x8000000000000000ull, 0xfffffffffffffffbull };
    uint64_t src1[] = { 0xffffffffffffffffull, 2 };
    uint64_t expected_vdiv_vv[] = {
        0x8000000000000000ull, 0xfffffffffffffffeull,
    };
    uint64_t expected_vrem_vv[] = { 0, 0xffffffffffffffffull };
    uint64_t expected_vdiv_vx[] = { 0x8000000000000000ull, 5 };
    uint64_t expected_vrem_vx[] = { 0, 0 };
    uint64_t out_vdiv_vv[2] = { 0 };
    uint64_t out_vrem_vv[2] = { 0 };
    uint64_t out_vdiv_vx[2] = { 0 };
    uint64_t out_vrem_vx[2] = { 0 };
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t t0 = 2;
    uint64_t t2 = 0xffffffffffffffffull;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a1, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a2, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_vdiv_vv, sizeof(out_vdiv_vv)));
    OK(uc_mem_read(uc, a4, out_vrem_vv, sizeof(out_vrem_vv)));
    OK(uc_mem_read(uc, a5, out_vdiv_vx, sizeof(out_vdiv_vx)));
    OK(uc_mem_read(uc, a6, out_vrem_vx, sizeof(out_vrem_vx)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_vdiv_vv[i] == expected_vdiv_vv[i]);
        TEST_CHECK(out_vrem_vv[i] == expected_vrem_vv[i]);
        TEST_CHECK(out_vdiv_vx[i] == expected_vdiv_vx[i]);
        TEST_CHECK(out_vrem_vx[i] == expected_vrem_vx[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_divide_remainder_illegal(void)
{
    run_riscv64_rvv_illegal(
        riscv_encode_rvv_op(0x20, 0, 1, 2, 2, 0));
}

static void test_riscv64_rvv_multiply(void)
{
    uc_engine *uc;
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xc8),
        riscv_encode_rvv_mask_ldst(0, 10, 0),
        riscv_encode_rvv_ldst(0, 5, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 5, 1, 12, 2),
        riscv_encode_rvv_op(0x25, 1, 1, 2, 2, 3),
        riscv_encode_rvv_ldst(1, 5, 1, 13, 3),
        riscv_encode_rvv_op(0x27, 1, 1, 2, 2, 4),
        riscv_encode_rvv_ldst(1, 5, 1, 14, 4),
        riscv_encode_rvv_op(0x24, 1, 1, 2, 2, 5),
        riscv_encode_rvv_ldst(1, 5, 1, 15, 5),
        riscv_encode_rvv_op(0x26, 1, 1, 2, 2, 6),
        riscv_encode_rvv_ldst(1, 5, 1, 16, 6),
        riscv_encode_rvv_op(0x25, 1, 1, 7, 6, 7),
        riscv_encode_rvv_ldst(1, 5, 1, 17, 7),
        riscv_encode_rvv_op(0x27, 1, 1, 7, 6, 8),
        riscv_encode_rvv_ldst(1, 5, 1, 28, 8),
        riscv_encode_rvv_op(0x24, 1, 1, 7, 6, 9),
        riscv_encode_rvv_ldst(1, 5, 1, 29, 9),
    };
    uint32_t tail_insns[] = {
        riscv_encode_rvv_op(0x26, 1, 1, 7, 6, 10),
        riscv_encode_rvv_ldst(1, 5, 1, 30, 10),
        riscv_encode_rvv_op(0x25, 0, 1, 2, 2, 11),
        riscv_encode_rvv_ldst(1, 5, 1, 31, 11),
    };
    uint8_t full_code[(18 + 4) * 4];
    uint8_t mask[] = { 0x05 };
    uint16_t src2[] = { 0xff00, 0x8000, 0x1234, 0xffff };
    uint16_t src1[] = { 0x0002, 0xffff, 0x0100, 0x8001 };
    uint16_t expected_mul[] = { 0xfe00, 0x8000, 0x3400, 0x7fff };
    uint16_t expected_mulh[] = { 0xffff, 0x0000, 0x0012, 0x0000 };
    uint16_t expected_mulhu[] = { 0x0001, 0x7fff, 0x0012, 0x8000 };
    uint16_t expected_mulhsu[] = { 0xffff, 0x8000, 0x0012, 0xffff };
    uint16_t expected_mul_vx[] = { 0x0300, 0x8000, 0xc964, 0x0003 };
    uint16_t expected_mulh_vx[] = { 0x0000, 0x0001, 0xffff, 0x0000 };
    uint16_t expected_mulhu_vx[] = { 0xfefd, 0x7ffe, 0x1233, 0xfffc };
    uint16_t expected_mulhsu_vx[] = { 0xff00, 0x8001, 0x1233, 0xffff };
    uint16_t expected_masked[] = { 0xfe00, 0xffff, 0x3400, 0xffff };
    uint16_t out_mul[4] = { 0 };
    uint16_t out_mulh[4] = { 0 };
    uint16_t out_mulhu[4] = { 0 };
    uint16_t out_mulhsu[4] = { 0 };
    uint16_t out_mul_vx[4] = { 0 };
    uint16_t out_mulh_vx[4] = { 0 };
    uint16_t out_mulhu_vx[4] = { 0 };
    uint16_t out_mulhsu_vx[4] = { 0 };
    uint16_t out_masked[4] = { 0 };
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 4;
    uint64_t t2 = 0xfffd;
    uint64_t t3 = code_start + 0x1800;
    uint64_t t4 = code_start + 0x1900;
    uint64_t t5 = code_start + 0x1a00;
    uint64_t t6 = code_start + 0x1b00;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&full_code[i * 4], insns[i]);
    }
    for (i = 0; i < sizeof(tail_insns) / sizeof(tail_insns[0]); i++) {
        riscv_insn_to_code(&full_code[(18 + i) * 4], tail_insns[i]);
    }

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)full_code, sizeof(full_code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a0, mask, sizeof(mask)));
    OK(uc_mem_write(uc, a1, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a2, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));
    OK(uc_reg_write(uc, UC_RISCV_REG_T3, &t3));
    OK(uc_reg_write(uc, UC_RISCV_REG_T4, &t4));
    OK(uc_reg_write(uc, UC_RISCV_REG_T5, &t5));
    OK(uc_reg_write(uc, UC_RISCV_REG_T6, &t6));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(full_code), 0, 0));

    OK(uc_mem_read(uc, a3, out_mul, sizeof(out_mul)));
    OK(uc_mem_read(uc, a4, out_mulh, sizeof(out_mulh)));
    OK(uc_mem_read(uc, a5, out_mulhu, sizeof(out_mulhu)));
    OK(uc_mem_read(uc, a6, out_mulhsu, sizeof(out_mulhsu)));
    OK(uc_mem_read(uc, a7, out_mul_vx, sizeof(out_mul_vx)));
    OK(uc_mem_read(uc, t3, out_mulh_vx, sizeof(out_mulh_vx)));
    OK(uc_mem_read(uc, t4, out_mulhu_vx, sizeof(out_mulhu_vx)));
    OK(uc_mem_read(uc, t5, out_mulhsu_vx, sizeof(out_mulhsu_vx)));
    OK(uc_mem_read(uc, t6, out_masked, sizeof(out_masked)));
    for (i = 0; i < 4; i++) {
        TEST_CHECK(out_mul[i] == expected_mul[i]);
        TEST_CHECK(out_mulh[i] == expected_mulh[i]);
        TEST_CHECK(out_mulhu[i] == expected_mulhu[i]);
        TEST_CHECK(out_mulhsu[i] == expected_mulhsu[i]);
        TEST_CHECK(out_mul_vx[i] == expected_mul_vx[i]);
        TEST_CHECK(out_mulh_vx[i] == expected_mulh_vx[i]);
        TEST_CHECK(out_mulhu_vx[i] == expected_mulhu_vx[i]);
        TEST_CHECK(out_mulhsu_vx[i] == expected_mulhsu_vx[i]);
        TEST_CHECK(out_masked[i] == expected_masked[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_multiply_64(void)
{
    uc_engine *uc;
    uint8_t code[13 * 4];
    uint32_t insns[] = {
        riscv_encode_rvv_vsetvli(0, 5, 0xd8),
        riscv_encode_rvv_ldst(0, 7, 1, 11, 1),
        riscv_encode_rvv_ldst(0, 7, 1, 12, 2),
        riscv_encode_rvv_op(0x25, 1, 1, 2, 2, 3),
        riscv_encode_rvv_ldst(1, 7, 1, 13, 3),
        riscv_encode_rvv_op(0x27, 1, 1, 2, 2, 4),
        riscv_encode_rvv_ldst(1, 7, 1, 14, 4),
        riscv_encode_rvv_op(0x24, 1, 1, 2, 2, 5),
        riscv_encode_rvv_ldst(1, 7, 1, 15, 5),
        riscv_encode_rvv_op(0x26, 1, 1, 2, 2, 6),
        riscv_encode_rvv_ldst(1, 7, 1, 16, 6),
        riscv_encode_rvv_op(0x24, 1, 1, 7, 6, 7),
    };
    uint32_t store_vmulhu_vx = riscv_encode_rvv_ldst(1, 7, 1, 17, 7);
    uint64_t src2[] = { 0x8000000000000000ull, 0xffffffffffffffffull };
    uint64_t src1[] = { 2, 0x8000000000000001ull };
    uint64_t expected_mul[] = { 0, 0x7fffffffffffffffull };
    uint64_t expected_mulh[] = { 0xffffffffffffffffull, 0 };
    uint64_t expected_mulhu[] = { 1, 0x8000000000000000ull };
    uint64_t expected_mulhsu[] = {
        0xffffffffffffffffull, 0xffffffffffffffffull,
    };
    uint64_t expected_mulhu_vx[] = { 1, 1 };
    uint64_t out_mul[2] = { 0 };
    uint64_t out_mulh[2] = { 0 };
    uint64_t out_mulhu[2] = { 0 };
    uint64_t out_mulhsu[2] = { 0 };
    uint64_t out_mulhu_vx[2] = { 0 };
    uint64_t a1 = code_start + 0x1100;
    uint64_t a2 = code_start + 0x1200;
    uint64_t a3 = code_start + 0x1300;
    uint64_t a4 = code_start + 0x1400;
    uint64_t a5 = code_start + 0x1500;
    uint64_t a6 = code_start + 0x1600;
    uint64_t a7 = code_start + 0x1700;
    uint64_t t0 = 2;
    uint64_t t2 = 2;
    size_t i;

    for (i = 0; i < sizeof(insns) / sizeof(insns[0]); i++) {
        riscv_insn_to_code(&code[i * 4], insns[i]);
    }
    riscv_insn_to_code(&code[12 * 4], store_vmulhu_vx);

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);
    OK(uc_mem_write(uc, a1, src2, sizeof(src2)));
    OK(uc_mem_write(uc, a2, src1, sizeof(src1)));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_reg_write(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_write(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_write(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_write(uc, UC_RISCV_REG_A5, &a5));
    OK(uc_reg_write(uc, UC_RISCV_REG_A6, &a6));
    OK(uc_reg_write(uc, UC_RISCV_REG_A7, &a7));
    OK(uc_reg_write(uc, UC_RISCV_REG_T0, &t0));
    OK(uc_reg_write(uc, UC_RISCV_REG_T2, &t2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a3, out_mul, sizeof(out_mul)));
    OK(uc_mem_read(uc, a4, out_mulh, sizeof(out_mulh)));
    OK(uc_mem_read(uc, a5, out_mulhu, sizeof(out_mulhu)));
    OK(uc_mem_read(uc, a6, out_mulhsu, sizeof(out_mulhsu)));
    OK(uc_mem_read(uc, a7, out_mulhu_vx, sizeof(out_mulhu_vx)));
    for (i = 0; i < 2; i++) {
        TEST_CHECK(out_mul[i] == expected_mul[i]);
        TEST_CHECK(out_mulh[i] == expected_mulh[i]);
        TEST_CHECK(out_mulhu[i] == expected_mulhu[i]);
        TEST_CHECK(out_mulhsu[i] == expected_mulhsu[i]);
        TEST_CHECK(out_mulhu_vx[i] == expected_mulhu_vx[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_multiply_illegal(void)
{
    run_riscv64_rvv_illegal_vtype(
        riscv_encode_rvv_op(0x25, 0, 1, 2, 2, 0), 0xc8);
}

static void test_riscv_fp_rejects_non_fp_models(void)
{
    uint32_t flw = riscv_encode_i(0, 10, 2, 1, 0x07);
    uint32_t flh = 0x00051087;
    uint32_t fadd_h = 0x04208253;

    run_riscv_non_fp_model_insn_illegal(UC_MODE_RISCV32,
                                        UC_CPU_RISCV32_SIFIVE_E31, flw);
    run_riscv_non_fp_model_insn_illegal(UC_MODE_RISCV64,
                                        UC_CPU_RISCV64_SIFIVE_E51, flw);
    run_riscv_non_fp_model_insn_illegal(UC_MODE_RISCV32,
                                        UC_CPU_RISCV32_SIFIVE_E31, flh);
    run_riscv_non_fp_model_insn_illegal(UC_MODE_RISCV64,
                                        UC_CPU_RISCV64_SIFIVE_E51, flh);
    run_riscv_non_fp_model_insn_illegal(UC_MODE_RISCV32,
                                        UC_CPU_RISCV32_SIFIVE_E31, fadd_h);
    run_riscv_non_fp_model_insn_illegal(UC_MODE_RISCV64,
                                        UC_CPU_RISCV64_SIFIVE_E51, fadd_h);
}

static void test_riscv_rvv_rejects_non_vector_models(void)
{
    run_riscv_rvv_non_vector_model_illegal(UC_MODE_RISCV32,
                                           UC_CPU_RISCV32_SIFIVE_E31);
    run_riscv_rvv_non_vector_model_illegal(UC_MODE_RISCV64,
                                           UC_CPU_RISCV64_SIFIVE_E51);
    run_riscv_rvv_non_vector_model_data_illegal(UC_MODE_RISCV32,
                                                UC_CPU_RISCV32_SIFIVE_E31);
    run_riscv_rvv_non_vector_model_data_illegal(UC_MODE_RISCV64,
                                                UC_CPU_RISCV64_SIFIVE_E51);
}

static void test_riscv64_rvv_invalid_vtype(void)
{
    uc_engine *uc;
    char code[] =
        "\x57\xf5\x05\x40"
        "\x73\x26\x00\xc2"
        "\xf3\x26\x10\xc2"
        "\x73\x27\x80\x00";
    uint64_t a0 = 1;
    uint64_t a1 = 5;
    uint64_t a2 = 1;
    uint64_t a3 = 1;
    uint64_t a4 = 1;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    riscv64_enable_vector_state(uc);
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_read(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_read(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_read(uc, UC_RISCV_REG_A4, &a4));

    TEST_CHECK(a0 == 0);
    TEST_CHECK(a2 == 0);
    TEST_CHECK(a3 == RISCV64_VTYPE_VILL);
    TEST_CHECK(a4 == 0);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_vill_blocks_data_path(void)
{
    uc_engine *uc;
    char code[] =
        "\x57\xf0\x05\x40"
        "\x87\x00\x05\x02";
    uint64_t a0 = code_start + 0x1000;
    uint64_t a1 = 5;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    riscv64_enable_vector_state(uc);
    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                               0, 0));

    OK(uc_close(uc));
}

static void test_riscv64_rvv_vector_csrs(void)
{
    uc_engine *uc;
    char code[] =
        "\x13\x03\xf0\x0f"
        "\x73\x10\x83\x00"
        "\x73\x25\x80\x00"
        "\x13\x03\x70\x00"
        "\x73\x10\xf3\x00"
        "\x73\x26\xf0\x00"
        "\xf3\x26\xa0\x00"
        "\x73\x27\x90\x00"
        "\xf3\x27\x00\x30";
    uint64_t a0 = 0;
    uint64_t a2 = 0;
    uint64_t a3 = 0;
    uint64_t a4 = 0;
    uint64_t a5 = 0;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    riscv64_enable_vector_state(uc);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_read(uc, UC_RISCV_REG_A2, &a2));
    OK(uc_reg_read(uc, UC_RISCV_REG_A3, &a3));
    OK(uc_reg_read(uc, UC_RISCV_REG_A4, &a4));
    OK(uc_reg_read(uc, UC_RISCV_REG_A5, &a5));

    TEST_CHECK(a0 == 127);
    TEST_CHECK(a2 == 7);
    TEST_CHECK(a3 == 3);
    TEST_CHECK(a4 == 1);
    TEST_CHECK(a5 == (RISCV64_MSTATUS_SD | RISCV_MSTATUS_VS_DIRTY));

    OK(uc_close(uc));
}

static void test_riscv64_rvv_public_scalar_regs(void)
{
    uc_engine *uc;
    char code[] = "\x13\x00\x00\x00";
    uint64_t value;
    uint64_t out;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    riscv64_enable_vector_state(uc);

    value = 9;
    OK(uc_reg_write(uc, UC_RISCV_REG_VSTART, &value));
    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VSTART, &out));
    TEST_CHECK(out == 9);

    value = 7;
    OK(uc_reg_write(uc, UC_RISCV_REG_VXRM, &value));
    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VXRM, &out));
    TEST_CHECK(out == 3);

    value = 3;
    OK(uc_reg_write(uc, UC_RISCV_REG_VXSAT, &value));
    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VXSAT, &out));
    TEST_CHECK(out == 1);

    value = (2 << 1) | 1;
    OK(uc_reg_write(uc, UC_RISCV_REG_VCSR, &value));
    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VCSR, &out));
    TEST_CHECK(out == 5);

    value = 1000;
    OK(uc_reg_write(uc, UC_RISCV_REG_VL, &value));
    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VL, &out));
    TEST_CHECK(out == 16);

    value = RISCV64_VTYPE_VILL | 7;
    OK(uc_reg_write(uc, UC_RISCV_REG_VTYPE, &value));
    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VTYPE, &out));
    TEST_CHECK(out == RISCV64_VTYPE_VILL);
    OK(uc_reg_read(uc, UC_RISCV_REG_VL, &out));
    TEST_CHECK(out == 0);

    value = 0xc0;
    OK(uc_reg_write(uc, UC_RISCV_REG_VTYPE, &value));
    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VTYPE, &out));
    TEST_CHECK(out == 0xc0);

    value = 5;
    OK(uc_reg_write(uc, UC_RISCV_REG_VL, &value));
    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VL, &out));
    TEST_CHECK(out == 5);

    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VLENB, &out));
    TEST_CHECK(out == 16);
    value = 32;
    uc_assert_err(UC_ERR_ARG,
                  uc_reg_write(uc, UC_RISCV_REG_VLENB, &value));

    OK(uc_close(uc));
}

static void test_riscv32_rvv_public_scalar_regs(void)
{
    uc_engine *uc;
    char code[] = "\x13\x00\x00\x00";
    uint32_t value;
    uint32_t out;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV32, code,
                    sizeof(code) - 1);
    riscv32_enable_vector_state(uc);

    value = 7;
    OK(uc_reg_write(uc, UC_RISCV_REG_VCSR, &value));
    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VXRM, &out));
    TEST_CHECK(out == 3);
    OK(uc_reg_read(uc, UC_RISCV_REG_VXSAT, &out));
    TEST_CHECK(out == 1);

    value = 0xc0;
    OK(uc_reg_write(uc, UC_RISCV_REG_VTYPE, &value));
    value = 20;
    OK(uc_reg_write(uc, UC_RISCV_REG_VL, &value));
    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VL, &out));
    TEST_CHECK(out == 16);

    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VLENB, &out));
    TEST_CHECK(out == 16);

    OK(uc_close(uc));
}

static void test_riscv64_rvv_public_vector_reg(void)
{
    uc_engine *uc;
    uint32_t code[] = {
        riscv_encode_rvv_vsetvli(0, 11, 0xc0),
        riscv_encode_rvv_ldst(1, 0, 1, 10, 1),
    };
    uc_riscv_vreg v1 = { { 0 } };
    uc_riscv_vreg actual = { { 0 } };
    uint8_t output[16] = { 0 };
    uint64_t a0 = code_start + 0x1200;
    uint64_t a1 = sizeof(output);
    size_t i;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64,
                    (const char *)code, sizeof(code));
    riscv64_enable_vector_state(uc);

    for (i = 0; i < sizeof(v1.bytes); i++) {
        v1.bytes[i] = (uint8_t)(0x80 + i);
    }

    OK(uc_reg_write(uc, UC_RISCV_REG_V1, &v1));
    OK(uc_reg_read(uc, UC_RISCV_REG_V1, &actual));
    for (i = 0; i < sizeof(output); i++) {
        TEST_CHECK(actual.bytes[i] == v1.bytes[i]);
    }
    for (i = sizeof(output); i < sizeof(actual.bytes); i++) {
        TEST_CHECK(actual.bytes[i] == 0);
    }

    OK(uc_reg_write(uc, UC_RISCV_REG_A0, &a0));
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, a0, output, sizeof(output)));
    for (i = 0; i < sizeof(output); i++) {
        TEST_CHECK(output[i] == v1.bytes[i]);
    }

    OK(uc_close(uc));
}

static void test_riscv64_rvv_context_save_restore_public_regs(void)
{
    uc_engine *uc;
    uc_context *context;
    char code[] = "\x13\x00\x00\x00";
    uc_riscv_vreg saved_v1 = { { 0 } };
    uc_riscv_vreg zero_v1 = { { 0 } };
    uc_riscv_vreg actual_v1 = { { 0 } };
    uint64_t value;
    uint64_t out;
    size_t i;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    riscv64_enable_vector_state(uc);

    value = 0xc0;
    OK(uc_reg_write(uc, UC_RISCV_REG_VTYPE, &value));
    value = 5;
    OK(uc_reg_write(uc, UC_RISCV_REG_VL, &value));
    value = 5;
    OK(uc_reg_write(uc, UC_RISCV_REG_VCSR, &value));
    for (i = 0; i < 16; i++) {
        saved_v1.bytes[i] = (uint8_t)(0x30 + i);
    }
    OK(uc_reg_write(uc, UC_RISCV_REG_V1, &saved_v1));

    OK(uc_context_alloc(uc, &context));
    OK(uc_context_save(uc, context));

    value = RISCV64_VTYPE_VILL;
    OK(uc_reg_write(uc, UC_RISCV_REG_VTYPE, &value));
    value = 0;
    OK(uc_reg_write(uc, UC_RISCV_REG_VCSR, &value));
    OK(uc_reg_write(uc, UC_RISCV_REG_V1, &zero_v1));

    OK(uc_context_restore(uc, context));

    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VTYPE, &out));
    TEST_CHECK(out == 0xc0);
    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VL, &out));
    TEST_CHECK(out == 5);
    out = 0;
    OK(uc_reg_read(uc, UC_RISCV_REG_VCSR, &out));
    TEST_CHECK(out == 5);
    OK(uc_reg_read(uc, UC_RISCV_REG_V1, &actual_v1));
    for (i = 0; i < 16; i++) {
        TEST_CHECK(actual_v1.bytes[i] == saved_v1.bytes[i]);
    }
    for (i = 16; i < sizeof(actual_v1.bytes); i++) {
        TEST_CHECK(actual_v1.bytes[i] == 0);
    }

    OK(uc_context_free(context));
    OK(uc_close(uc));
}

static void test_riscv64_rvv_requires_vs(void)
{
    uc_engine *uc;
    char code[] = "\x57\xf5\x05\x0c";
    uint64_t a1 = 5;

    uc_common_setup(&uc, UC_ARCH_RISCV, UC_MODE_RISCV64, code,
                    sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_RISCV_REG_A1, &a1));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code) - 1,
                               0, 0));

    OK(uc_close(uc));
}

TEST_LIST = {
    {"test_riscv32_nop", test_riscv32_nop},
    {"test_riscv64_nop", test_riscv64_nop},
    {"test_riscv64_sstc_stimecmp", test_riscv64_sstc_stimecmp},
    {"test_riscv32_zihintpause", test_riscv32_zihintpause},
    {"test_riscv64_zihintpause", test_riscv64_zihintpause},
    {"test_riscv32_3steps_pc_update", test_riscv32_3steps_pc_update},
    {"test_riscv64_3steps_pc_update", test_riscv64_3steps_pc_update},
    {"test_riscv64_until_at_page_end", test_riscv64_until_at_page_end},
    {"test_riscv32_until_pc_update", test_riscv32_until_pc_update},
    {"test_riscv64_until_pc_update", test_riscv64_until_pc_update},
    {"test_riscv32_fp_move", test_riscv32_fp_move},
    {"test_riscv64_fp_move", test_riscv64_fp_move},
    {"test_riscv64_fp_move_from_int", test_riscv64_fp_move_from_int},
    {"test_riscv64_fp_move_from_int_reg_write",
     test_riscv64_fp_move_from_int_reg_write},
    {"test_riscv64_fp_move_to_int", test_riscv64_fp_move_to_int},
    {"test_riscv64_fclass_s_nanboxing", test_riscv64_fclass_s_nanboxing},
    {"test_riscv64_fclass_s_produced_nanbox",
     test_riscv64_fclass_s_produced_nanbox},
    {"test_riscv64_fmv_w_x_nanbox", test_riscv64_fmv_w_x_nanbox},
    {"test_riscv64_fmin_fmax_snan", test_riscv64_fmin_fmax_snan},
    {"test_riscv32_zfh_load_store_move", test_riscv32_zfh_load_store_move},
    {"test_riscv64_zfh_load_store_move", test_riscv64_zfh_load_store_move},
    {"test_riscv64_zfh_arith_compare_class",
     test_riscv64_zfh_arith_compare_class},
    {"test_riscv32_zfh_conversions", test_riscv32_zfh_conversions},
    {"test_riscv64_zfh_conversions", test_riscv64_zfh_conversions},
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
    {"test_riscv_mmu", test_riscv_mmu},
    {"test_riscv_priv", test_riscv_priv},
    {"test_riscv64_pmp_na4_load", test_riscv64_pmp_na4_load},
    {"test_riscv64_pmp_na4_rejects_outside",
     test_riscv64_pmp_na4_rejects_outside},
    {"test_riscv64_pmp_na4_rejects_store",
     test_riscv64_pmp_na4_rejects_store},
    {"test_riscv32_svinval", test_riscv32_svinval},
    {"test_riscv64_svinval", test_riscv64_svinval},
    {"test_riscv_svinval_hinval_requires_rvh",
     test_riscv_svinval_hinval_requires_rvh},
    {"test_riscv_svinval_requires_s", test_riscv_svinval_requires_s},
    {"test_riscv32_rvh_hlv_hsv", test_riscv32_rvh_hlv_hsv},
    {"test_riscv64_rvh_hlv_hsv", test_riscv64_rvh_hlv_hsv},
    {"test_riscv64_rvh_hlvx_vs_stage_xonly_mxr",
     test_riscv64_rvh_hlvx_vs_stage_xonly_mxr},
    {"test_riscv_rvh_requires_h", test_riscv_rvh_requires_h},
    {"test_riscv_rvh_requires_hlsx", test_riscv_rvh_requires_hlsx},
    {"test_riscv_rvh_hstatus_layout", test_riscv_rvh_hstatus_layout},
    {"test_riscv_rvh_hedeleg_mask", test_riscv_rvh_hedeleg_mask},
    {"test_riscv_rvh_hu_allows_u_mode", test_riscv_rvh_hu_allows_u_mode},
    {"test_riscv_rvh_hu_tb_flags", test_riscv_rvh_hu_tb_flags},
    {"test_riscv_rvh_virtual_instruction_fault",
     test_riscv_rvh_virtual_instruction_fault},
    {"test_riscv64_rvh_indirect_g_stage_fault",
     test_riscv64_rvh_indirect_g_stage_fault},
    {"test_riscv_virtual_wfi_fault", test_riscv_virtual_wfi_fault},
    {"test_riscv_rvh_hfence", test_riscv_rvh_hfence},
    {"test_riscv_rvh_hfence_requires_h",
     test_riscv_rvh_hfence_requires_h},
    {"test_riscv64_rv128_opcodes_rejected",
     test_riscv64_rv128_opcodes_rejected},
    {"test_riscv32_xventanacondops", test_riscv32_xventanacondops},
    {"test_riscv64_xventanacondops", test_riscv64_xventanacondops},
    {"test_riscv32_zba", test_riscv32_zba},
    {"test_riscv64_zba", test_riscv64_zba},
    {"test_riscv32_zbc", test_riscv32_zbc},
    {"test_riscv64_zbc", test_riscv64_zbc},
    {"test_riscv32_zbkb", test_riscv32_zbkb},
    {"test_riscv64_zbkb", test_riscv64_zbkb},
    {"test_riscv32_zbkx", test_riscv32_zbkx},
    {"test_riscv64_zbkx", test_riscv64_zbkx},
    {"test_riscv32_zknh_sha256", test_riscv32_zknh_sha256},
    {"test_riscv64_zknh_sha256", test_riscv64_zknh_sha256},
    {"test_riscv32_zknh_sha512", test_riscv32_zknh_sha512},
    {"test_riscv64_zknh_sha512", test_riscv64_zknh_sha512},
    {"test_riscv_zksh_sm3", test_riscv_zksh_sm3},
    {"test_riscv32_zkne_aes", test_riscv32_zkne_aes},
    {"test_riscv32_zknd_aes", test_riscv32_zknd_aes},
    {"test_riscv64_zkne_zknd_aes", test_riscv64_zkne_zknd_aes},
    {"test_riscv_zksed_sm4", test_riscv_zksed_sm4},
    {"test_riscv_zkr_seed", test_riscv_zkr_seed},
    {"test_riscv32_zbb_unary", test_riscv32_zbb_unary},
    {"test_riscv64_zbb_unary", test_riscv64_zbb_unary},
    {"test_riscv32_zbb_binary", test_riscv32_zbb_binary},
    {"test_riscv64_zbb_binary", test_riscv64_zbb_binary},
    {"test_riscv32_zbb_rotate", test_riscv32_zbb_rotate},
    {"test_riscv64_zbb_rotate", test_riscv64_zbb_rotate},
    {"test_riscv64_zbb_word", test_riscv64_zbb_word},
    {"test_riscv_zbb_illegal_encodings", test_riscv_zbb_illegal_encodings},
    {"test_riscv32_zbs_register", test_riscv32_zbs_register},
    {"test_riscv64_zbs_register", test_riscv64_zbs_register},
    {"test_riscv32_zbs_immediate", test_riscv32_zbs_immediate},
    {"test_riscv64_zbs_immediate", test_riscv64_zbs_immediate},
    {"test_riscv32_rvv_vsetvli_csrs", test_riscv32_rvv_vsetvli_csrs},
    {"test_riscv64_rvv_vsetvli_csrs", test_riscv64_rvv_vsetvli_csrs},
    {"test_riscv64_rvv_vsetvl_clamp", test_riscv64_rvv_vsetvl_clamp},
    {"test_riscv32_rvv_vsetivli", test_riscv32_rvv_vsetivli},
    {"test_riscv64_rvv_vle8_vadd_vv_vse8",
     test_riscv64_rvv_vle8_vadd_vv_vse8},
    {"test_riscv32_rvv_vle8_vadd_vv_vse8",
     test_riscv32_rvv_vle8_vadd_vv_vse8},
    {"test_riscv64_rvv_vmv_vi_vadd_vi_vse32",
     test_riscv64_rvv_vmv_vi_vadd_vi_vse32},
    {"test_riscv64_rvv_tail_agnostic_vmv",
     test_riscv64_rvv_tail_agnostic_vmv},
    {"test_riscv32_rvv_vle16_vsub_vse16",
     test_riscv32_rvv_vle16_vsub_vse16},
    {"test_riscv64_rvv_vle64_moves_logic_compare",
     test_riscv64_rvv_vle64_moves_logic_compare},
    {"test_riscv64_rvv_scalar_moves_compare",
     test_riscv64_rvv_scalar_moves_compare},
    {"test_riscv32_rvv_minmax", test_riscv32_rvv_minmax},
    {"test_riscv64_rvv_reverse_subtract",
     test_riscv64_rvv_reverse_subtract},
    {"test_riscv32_rvv_reverse_subtract",
     test_riscv32_rvv_reverse_subtract},
    {"test_riscv64_rvv_slide", test_riscv64_rvv_slide},
    {"test_riscv32_rvv_slide", test_riscv32_rvv_slide},
    {"test_riscv64_rvv_slide_illegal",
     test_riscv64_rvv_slide_illegal},
    {"test_riscv64_rvv_gather_compress",
     test_riscv64_rvv_gather_compress},
    {"test_riscv32_rvv_gather_compress",
     test_riscv32_rvv_gather_compress},
    {"test_riscv64_rvv_whole_register_move",
     test_riscv64_rvv_whole_register_move},
    {"test_riscv64_rvv_gather_compress_move_illegal",
     test_riscv64_rvv_gather_compress_move_illegal},
    {"test_riscv64_rvv_vmerge", test_riscv64_rvv_vmerge},
    {"test_riscv64_rvv_shift_vv", test_riscv64_rvv_shift_vv},
    {"test_riscv32_rvv_shift_vx_vi", test_riscv32_rvv_shift_vx_vi},
    {"test_riscv32_rvv_mask_load_store",
     test_riscv32_rvv_mask_load_store},
    {"test_riscv64_rvv_masked_unit_stride",
     test_riscv64_rvv_masked_unit_stride},
    {"test_riscv64_rvv_unit_stride_fault_vstart",
     test_riscv64_rvv_unit_stride_fault_vstart},
    {"test_riscv64_rvv_strided_fault_vstart",
     test_riscv64_rvv_strided_fault_vstart},
    {"test_riscv64_rvv_indexed_fault_vstart",
     test_riscv64_rvv_indexed_fault_vstart},
    {"test_riscv64_rvv_unit_stride_segment_memory",
     test_riscv64_rvv_unit_stride_segment_memory},
    {"test_riscv64_rvv_masked_unit_stride_segment",
     test_riscv64_rvv_masked_unit_stride_segment},
    {"test_riscv64_rvv_unit_stride_segment_illegal",
     test_riscv64_rvv_unit_stride_segment_illegal},
    {"test_riscv64_rvv_strided_load_store",
     test_riscv64_rvv_strided_load_store},
    {"test_riscv64_rvv_negative_stride_load",
     test_riscv64_rvv_negative_stride_load},
    {"test_riscv64_rvv_masked_strided_memory",
     test_riscv64_rvv_masked_strided_memory},
    {"test_riscv64_rvv_strided_segment_memory",
     test_riscv64_rvv_strided_segment_memory},
    {"test_riscv64_rvv_strided_memory_illegal",
     test_riscv64_rvv_strided_memory_illegal},
    {"test_riscv64_rvv_indexed_load_store",
     test_riscv64_rvv_indexed_load_store},
    {"test_riscv64_rvv_indexed_mixed_widths",
     test_riscv64_rvv_indexed_mixed_widths},
    {"test_riscv64_rvv_masked_indexed_memory",
     test_riscv64_rvv_masked_indexed_memory},
    {"test_riscv64_rvv_indexed_segment_memory",
     test_riscv64_rvv_indexed_segment_memory},
    {"test_riscv64_rvv_indexed_memory_illegal",
     test_riscv64_rvv_indexed_memory_illegal},
    {"test_riscv64_rvv_fault_only_first_segment",
     test_riscv64_rvv_fault_only_first_segment},
    {"test_riscv64_rvv_masked_fault_only_first",
     test_riscv64_rvv_masked_fault_only_first},
    {"test_riscv64_rvv_fault_only_first_partial_fault",
     test_riscv64_rvv_fault_only_first_partial_fault},
    {"test_riscv64_rvv_fault_only_first_first_fault",
     test_riscv64_rvv_fault_only_first_first_fault},
    {"test_riscv64_rvv_fault_only_first_illegal",
     test_riscv64_rvv_fault_only_first_illegal},
    {"test_riscv64_rvv_whole_register_single",
     test_riscv64_rvv_whole_register_single},
    {"test_riscv64_rvv_whole_register_groups",
     test_riscv64_rvv_whole_register_groups},
    {"test_riscv64_rvv_whole_register_ignores_vl_vill",
     test_riscv64_rvv_whole_register_ignores_vl_vill},
    {"test_riscv64_rvv_whole_register_vstart",
     test_riscv64_rvv_whole_register_vstart},
    {"test_riscv64_rvv_whole_register_illegal",
     test_riscv64_rvv_whole_register_illegal},
    {"test_riscv32_rvv_whole_register_smoke",
     test_riscv32_rvv_whole_register_smoke},
    {"test_riscv64_rvv_float32_arith", test_riscv64_rvv_float32_arith},
    {"test_riscv64_rvv_float32_minmax_sign",
     test_riscv64_rvv_float32_minmax_sign},
    {"test_riscv32_rvv_float32_minmax_sign_smoke",
     test_riscv32_rvv_float32_minmax_sign_smoke},
    {"test_riscv64_rvv_float32_compare", test_riscv64_rvv_float32_compare},
    {"test_riscv64_rvv_float32_class_merge",
     test_riscv64_rvv_float32_class_merge},
    {"test_riscv64_rvv_float32_moves", test_riscv64_rvv_float32_moves},
    {"test_riscv64_rvv_float64_arith", test_riscv64_rvv_float64_arith},
    {"test_riscv64_rvv_float32_mask_nanbox",
     test_riscv64_rvv_float32_mask_nanbox},
    {"test_riscv64_rvv_float32_sqrt", test_riscv64_rvv_float32_sqrt},
    {"test_riscv64_rvv_float32_estimate",
     test_riscv64_rvv_float32_estimate},
    {"test_riscv64_rvv_float32_convert",
     test_riscv64_rvv_float32_convert},
    {"test_riscv64_rvv_widening_float_convert",
     test_riscv64_rvv_widening_float_convert},
    {"test_riscv64_rvv_narrowing_float_convert",
     test_riscv64_rvv_narrowing_float_convert},
    {"test_riscv64_rvv_float32_slide", test_riscv64_rvv_float32_slide},
    {"test_riscv64_rvv_float32_fma", test_riscv64_rvv_float32_fma},
    {"test_riscv32_rvv_float32_smoke", test_riscv32_rvv_float32_smoke},
    {"test_riscv64_rvv_widening_float_fma",
     test_riscv64_rvv_widening_float_fma},
    {"test_riscv64_rvv_widening_float_arith",
     test_riscv64_rvv_widening_float_arith},
    {"test_riscv64_rvv_float_illegal", test_riscv64_rvv_float_illegal},
    {"test_riscv32_rvv_carry_borrow", test_riscv32_rvv_carry_borrow},
    {"test_riscv64_rvv_carry_borrow_masks",
     test_riscv64_rvv_carry_borrow_masks},
    {"test_riscv64_rvv_carry_borrow_illegal",
     test_riscv64_rvv_carry_borrow_illegal},
    {"test_riscv64_rvv_narrow_shift", test_riscv64_rvv_narrow_shift},
    {"test_riscv64_rvv_narrow_shift_illegal",
     test_riscv64_rvv_narrow_shift_illegal},
    {"test_riscv64_rvv_integer_extension",
     test_riscv64_rvv_integer_extension},
    {"test_riscv64_rvv_integer_extension_illegal",
     test_riscv64_rvv_integer_extension_illegal},
    {"test_riscv64_rvv_widening_add_sub_vv_vx",
     test_riscv64_rvv_widening_add_sub_vv_vx},
    {"test_riscv64_rvv_widening_add_sub_wv_wx",
     test_riscv64_rvv_widening_add_sub_wv_wx},
    {"test_riscv64_rvv_widening_add_sub_illegal",
     test_riscv64_rvv_widening_add_sub_illegal},
    {"test_riscv64_rvv_widening_multiply",
     test_riscv64_rvv_widening_multiply},
    {"test_riscv64_rvv_widening_multiply_32",
     test_riscv64_rvv_widening_multiply_32},
    {"test_riscv64_rvv_widening_multiply_illegal",
     test_riscv64_rvv_widening_multiply_illegal},
    {"test_riscv64_rvv_multiply_add",
     test_riscv64_rvv_multiply_add},
    {"test_riscv64_rvv_widening_multiply_add",
     test_riscv64_rvv_widening_multiply_add},
    {"test_riscv64_rvv_widening_multiply_add_32",
     test_riscv64_rvv_widening_multiply_add_32},
    {"test_riscv64_rvv_multiply_add_illegal",
     test_riscv64_rvv_multiply_add_illegal},
    {"test_riscv64_rvv_mask_logical",
     test_riscv64_rvv_mask_logical},
    {"test_riscv64_rvv_mask_scalar",
     test_riscv64_rvv_mask_scalar},
    {"test_riscv64_rvv_mask_set",
     test_riscv64_rvv_mask_set},
    {"test_riscv64_rvv_viota_vid",
     test_riscv64_rvv_viota_vid},
    {"test_riscv64_rvv_mask_utilities_illegal",
     test_riscv64_rvv_mask_utilities_illegal},
    {"test_riscv64_rvv_fixed_point_saturating",
     test_riscv64_rvv_fixed_point_saturating},
    {"test_riscv64_rvv_fixed_point_rounding",
     test_riscv64_rvv_fixed_point_rounding},
    {"test_riscv64_rvv_fixed_point_clip",
     test_riscv64_rvv_fixed_point_clip},
    {"test_riscv64_rvv_fixed_point_illegal",
     test_riscv64_rvv_fixed_point_illegal},
    {"test_riscv64_rvv_integer_reduction_sum_logic",
     test_riscv64_rvv_integer_reduction_sum_logic},
    {"test_riscv32_rvv_integer_reduction_minmax",
     test_riscv32_rvv_integer_reduction_minmax},
    {"test_riscv64_rvv_integer_reduction_masked",
     test_riscv64_rvv_integer_reduction_masked},
    {"test_riscv64_rvv_widening_reduction_sum",
     test_riscv64_rvv_widening_reduction_sum},
    {"test_riscv64_rvv_widening_reduction_32_to_64",
     test_riscv64_rvv_widening_reduction_32_to_64},
    {"test_riscv64_rvv_reduction_illegal",
     test_riscv64_rvv_reduction_illegal},
    {"test_riscv64_rvv_float32_reduction",
     test_riscv64_rvv_float32_reduction},
    {"test_riscv64_rvv_widening_float_reduction",
     test_riscv64_rvv_widening_float_reduction},
    {"test_riscv64_rvv_float_reduction_illegal",
     test_riscv64_rvv_float_reduction_illegal},
    {"test_riscv64_rvv_divide_remainder",
     test_riscv64_rvv_divide_remainder},
    {"test_riscv64_rvv_divide_remainder_zero_vx",
     test_riscv64_rvv_divide_remainder_zero_vx},
    {"test_riscv64_rvv_divide_remainder_64",
     test_riscv64_rvv_divide_remainder_64},
    {"test_riscv64_rvv_divide_remainder_illegal",
     test_riscv64_rvv_divide_remainder_illegal},
    {"test_riscv64_rvv_multiply", test_riscv64_rvv_multiply},
    {"test_riscv64_rvv_multiply_64", test_riscv64_rvv_multiply_64},
    {"test_riscv64_rvv_multiply_illegal",
     test_riscv64_rvv_multiply_illegal},
    {"test_riscv_fp_rejects_non_fp_models",
     test_riscv_fp_rejects_non_fp_models},
    {"test_riscv_rvv_rejects_non_vector_models",
     test_riscv_rvv_rejects_non_vector_models},
    {"test_riscv64_rvv_invalid_vtype", test_riscv64_rvv_invalid_vtype},
    {"test_riscv64_rvv_vill_blocks_data_path",
     test_riscv64_rvv_vill_blocks_data_path},
    {"test_riscv64_rvv_vector_csrs", test_riscv64_rvv_vector_csrs},
    {"test_riscv64_rvv_public_scalar_regs",
     test_riscv64_rvv_public_scalar_regs},
    {"test_riscv32_rvv_public_scalar_regs",
     test_riscv32_rvv_public_scalar_regs},
    {"test_riscv64_rvv_public_vector_reg",
     test_riscv64_rvv_public_vector_reg},
    {"test_riscv64_rvv_context_save_restore_public_regs",
     test_riscv64_rvv_context_save_restore_public_regs},
    {"test_riscv64_rvv_requires_vs", test_riscv64_rvv_requires_vs},
    {NULL, NULL}};
