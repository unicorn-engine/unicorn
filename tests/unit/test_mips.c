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

static void test_mips_el_ori(void)
{
    uc_engine *uc;
    char code[] = "\x56\x34\x21\x34"; // ori $at, $at, 0x3456;
    int r_r1 = 0x6789;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_1, &r_r1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_1, &r_r1));

    TEST_CHECK(r_r1 == 0x77df);

    OK(uc_close(uc));
}

static void test_mips_eb_ori(void)
{
    uc_engine *uc;
    char code[] = "\x34\x21\x34\x56"; // ori $at, $at, 0x3456;
    int r_r1 = 0x6789;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_1, &r_r1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_1, &r_r1));

    TEST_CHECK(r_r1 == 0x77df);

    OK(uc_close(uc));
}

static void test_mips_stop_at_branch(void)
{
    uc_engine *uc;
    char code[] =
        "\x02\x00\x00\x08\x21\x10\x62\x00"; // j 0x8; addu $v0, $v1, $v0;
    int r_pc = 0x0;
    uint32_t v1 = 5;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);

    OK(uc_reg_write(uc, UC_MIPS_REG_V1, &v1));
    // Execute one instruction with branch delay slot.
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 1));

    OK(uc_reg_read(uc, UC_MIPS_REG_PC, &r_pc));
    OK(uc_reg_read(uc, UC_MIPS_REG_V0, &v1));

    // Even if we just execute one instruction, the instruction in the
    // delay slot would also be executed.
    TEST_CHECK(r_pc == code_start + 0x8);
    TEST_CHECK(v1 == 0x5);

    OK(uc_close(uc));
}

static void test_mips_stop_at_delay_slot(void)
{
    uc_engine *uc;
    char code[] =
        "\x02\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"; // j 0x8; nop;
    int r_pc = 0x0;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);

    // Stop at the delay slot by design.
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_PC, &r_pc));

    // The branch instruction isn't committed and the PC is not updated.
    // Users is responsible to restart emulation at the branch instruction.
    TEST_CHECK(r_pc == code_start);

    OK(uc_close(uc));
}

static void test_mips_stop_delay_slot_from_qiling(void)
{
    uc_engine *uc;
    // 24 06 00 03          addiu                $a2, $zero, 3
    // 10 a6 00 79          beq                  $a1, $a2, 0x1e8
    // 30 42 00 fc          andi                 $v0, $v0, 0xfc
    // 10 40 00 32          beqz                 $v0, 0x47c8c90
    // 24 ab ff da          addiu                $t3, $a1, -0x26
    // 2d 62 00 02          sltiu                $v0, $t3, 2
    // 10 40 00 32          beqz                 $v0, 0x47c8c9c
    // 00 00 00 00          nop
    char code[] =
        "\x24\x06\x00\x03\x10\xa6\x00\x79\x30\x42\x00\xfc\x10\x40\x00\x32\x24"
        "\xab\xff\xda\x2d\x62\x00\x02\x10\x40\x00\x32\x00\x00\x00\x00";
    uint32_t r_pc = 0x0;
    uint32_t r_v0 = 0xff;
    uint32_t r_a1 = 0x3;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_V0, &r_v0));
    OK(uc_reg_write(uc, UC_MIPS_REG_A1, &r_a1));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) + 16, 0, 2));

    OK(uc_reg_read(uc, UC_MIPS_REG_PC, &r_pc));
    OK(uc_reg_read(uc, UC_MIPS_REG_V0, &r_v0));
    TEST_CHECK(r_pc == code_start + 4 + 0x1e8);
    TEST_CHECK(r_v0 == 0xfc);

    OK(uc_close(uc));
}

static void test_mips_lwx_exception_issue_1314(void)
{
    uc_engine *uc;
    char code[] = "\x0a\xc8\x79\x7e"; // lwx $t9, $t9($s3)
    int reg;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_mem_map(uc, 0x10000, 0x4000, UC_PROT_ALL));

    // Enable DSP
    // https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/MD00090-2B-MIPS32PRA-AFP-06.02.pdf
    OK(uc_reg_read(uc, UC_MIPS_REG_CP0_STATUS, &reg));
    reg |= (1 << 24);
    OK(uc_reg_write(uc, UC_MIPS_REG_CP0_STATUS, &reg));

    reg = 0;
    OK(uc_reg_write(uc, UC_MIPS_REG_1, &reg));
    OK(uc_reg_write(uc, UC_MIPS_REG_T9, &reg));
    reg = LEINT32(0xdeadbeef);
    OK(uc_mem_write(uc, 0x10000, &reg, 4));
    reg = 0x10000;
    OK(uc_reg_write(uc, UC_MIPS_REG_S3, &reg));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_T9, &reg));

    TEST_CHECK(reg == 0xdeadbeef);

    OK(uc_close(uc));
}

static void test_mips_mips16(void)
{
    uc_engine *uc;
    char code[] = "\xC4\x6B\x49\xE3"; // li $v1, 0xC4;  addu $v0, $v1, $v0
    int r_v0 = 0x6789;
    int mips16_lowbit = 1;

    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
                    code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_MIPS_REG_V0, &r_v0));

    OK(uc_emu_start(uc, code_start | mips16_lowbit,
                    code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_V0, &r_v0));

    TEST_CHECK(r_v0 == 0x684D);

    OK(uc_close(uc));
}

static void test_mips_mips_fpr(void)
{
    uc_engine *uc;
    uint64_t r_f1;
    // ks.asm("li $t1, 0x42f6e979;mtc1 $t1, $f1")
    const char code[] = "\xf6\x42\x09\x3c\x79\xe9\x29\x35\x00\x08\x89\x44";
    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32, code, sizeof(code) - 1);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_F1, (void *)&r_f1));

    TEST_CHECK(r_f1 = 0x42f6e979);

    OK(uc_close(uc));
}

static void test_mips_simple_coredump_2134(void)
{
    uc_engine *uc;
    const char code[] = "\x25\xc8\x80\x03\x25\x78\xe0\x03\x09\xf8\x20\x03\x10\x00\x18\x24";
    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32, code, sizeof(code) - 1);

    uc_assert_err(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0), UC_ERR_FETCH_UNMAPPED);

    OK(uc_close(uc));
}

static void test_mips_simple_coredump_2137(void)
{
    uc_engine *uc;
    const char code[] = "\x1c\x00\x40\x54\xe8\x00\xc4\xaf";
    uc_common_setup(&uc, UC_ARCH_MIPS, UC_MODE_MIPS32, code, sizeof(code) - 1);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

// Identity virtual-TLB fill hook: maps every virtual page to the same physical
// address with full permissions.
static bool test_mips_vtlb_identity_cb(uc_engine *uc, uint64_t addr,
                                       uc_mem_type type, uc_tlb_entry *result,
                                       void *user_data)
{
    result->paddr = addr;
    result->perms = UC_PROT_ALL;
    return true;
}

// Under UC_TLB_VIRTUAL, a Load-Linked (ll) from an address above useg (>= 2GB)
// must succeed via the soft-TLB instead of raising a spurious Address Error
// (EXCP_AdEL). The ll helper used to call do_translate_address() to populate
// CP0_LLAddr, which segment-checked the address and rejected anything outside
// useg even though the soft-TLB maps it and the load itself succeeds.
static void test_mips_virtual_tlb_ll_high_address(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\xc2\x03\x00\x00"; // ll $v1, 0($s0)
    const uint64_t lock_addr = 0x120000000; // above useg: requires the vtlb
    uint64_t r_s0 = lock_addr;
    uint64_t r_v1 = 0;
    char lock_val[] = "\x12\x34\xab\xcd"; // value the lock word holds (BE)

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_TLB_FILL, test_mips_vtlb_identity_cb, NULL,
                   1, 0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_map(uc, lock_addr, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, lock_addr, lock_val, sizeof(lock_val) - 1));
    OK(uc_reg_write(uc, UC_MIPS_REG_S0, &r_s0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_MIPS_REG_V1, &r_v1));
    TEST_CHECK(r_v1 == 0x1234abcd);

    OK(uc_close(uc));
}

// Remapping virtual-TLB fill hook: maps one specific virtual page to a
// different physical page, everything else identity. Used to verify that a
// Load-Linked records the hook-mapped *physical* address in CP0_LLAddr, not
// the virtual address.
struct vtlb_remap {
    uint64_t vpage; // page-aligned virtual page that gets remapped
    uint64_t ppage; // page-aligned physical page it maps to
};

static bool test_mips_vtlb_remap_cb(uc_engine *uc, uint64_t addr,
                                    uc_mem_type type, uc_tlb_entry *result,
                                    void *user_data)
{
    struct vtlb_remap *m = (struct vtlb_remap *)user_data;

    // addr is already page-aligned when the hook is invoked.
    result->paddr = (addr == m->vpage) ? m->ppage : addr;
    result->perms = UC_PROT_ALL;
    return true;
}

// Under UC_TLB_VIRTUAL the fill hook may map a virtual page to an arbitrary
// physical page (not just identity). CP0_LLAddr must record the hook-mapped
// *physical* address of the Load-Linked, which a guest can read back via
// `mfc0 LLAddr`. Recording the raw virtual address (as a naive vtlb fix would)
// is wrong whenever the hook remaps the page.
static void test_mips_virtual_tlb_ll_records_mapped_paddr(void)
{
    uc_engine *uc;
    uc_hook hook;
    // ll $v1, 0($s0) ; mfc0 $v0, $17 (LLAddr)
    char code[] = "\xc2\x03\x00\x00\x40\x02\x88\x00";
    const uint64_t lock_vaddr = 0x120000000; // above useg
    const uint64_t lock_paddr = 0x6000;      // remapped, != vaddr
    struct vtlb_remap remap = {lock_vaddr, lock_paddr};
    uint64_t r_s0 = lock_vaddr;
    uint64_t r_v0 = 0;
    uint64_t r_v1 = 0;
    char lock_val[] = "\x12\x34\xab\xcd"; // value at the physical lock word (BE)

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_TLB_FILL, test_mips_vtlb_remap_cb, &remap,
                   1, 0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_map(uc, lock_paddr, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, lock_paddr, lock_val, sizeof(lock_val) - 1));
    OK(uc_reg_write(uc, UC_MIPS_REG_S0, &r_s0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    // ll read the word at the mapped physical address...
    OK(uc_reg_read(uc, UC_MIPS_REG_V1, &r_v1));
    TEST_CHECK(r_v1 == 0x1234abcd);
    // ...and CP0_LLAddr holds that physical address (R4000: shifted right by 4),
    // not the virtual address (which would read back as 0x12000000).
    OK(uc_reg_read(uc, UC_MIPS_REG_V0, &r_v0));
    TEST_CHECK(r_v0 == (lock_paddr >> 4));

    OK(uc_close(uc));
}

// The ll fix must preserve the alignment check: a misaligned ll, even under
// UC_TLB_VIRTUAL, must still raise an Address Error.
static void test_mips_virtual_tlb_ll_unaligned_still_faults(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\xc2\x03\x00\x00";       // ll $v1, 0($s0)
    const uint64_t lock_addr = 0x120000002; // misaligned (low bits set)
    uint64_t r_s0 = lock_addr;

    OK(uc_open(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_TLB_FILL, test_mips_vtlb_identity_cb, NULL,
                   1, 0));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));
    OK(uc_mem_map(uc, lock_addr & ~0xfffULL, 0x1000, UC_PROT_ALL));
    OK(uc_reg_write(uc, UC_MIPS_REG_S0, &r_s0));

    uc_assert_err(
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0),
        UC_ERR_EXCEPTION);

    OK(uc_close(uc));
}

TEST_LIST = {
    {"test_mips_virtual_tlb_ll_high_address",
     test_mips_virtual_tlb_ll_high_address},
    {"test_mips_virtual_tlb_ll_records_mapped_paddr",
     test_mips_virtual_tlb_ll_records_mapped_paddr},
    {"test_mips_virtual_tlb_ll_unaligned_still_faults",
     test_mips_virtual_tlb_ll_unaligned_still_faults},
    {"test_mips_stop_at_branch", test_mips_stop_at_branch},
    {"test_mips_stop_at_delay_slot", test_mips_stop_at_delay_slot},
    {"test_mips_el_ori", test_mips_el_ori},
    {"test_mips_eb_ori", test_mips_eb_ori},
    {"test_mips_lwx_exception_issue_1314", test_mips_lwx_exception_issue_1314},
    {"test_mips_mips16", test_mips_mips16},
    {"test_mips_mips_fpr", test_mips_mips_fpr},
    {"test_mips_stop_delay_slot_from_qiling",
     test_mips_stop_delay_slot_from_qiling},
     {"test_mips_simple_coredump_2134", test_mips_simple_coredump_2134},
     {"test_mips_simple_coredump_2137", test_mips_simple_coredump_2137},
    {NULL, NULL}};