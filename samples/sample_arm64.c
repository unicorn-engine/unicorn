/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate ARM64 code */

#include <unicorn/unicorn.h>
#include <string.h>

// code to be emulated
#define ARM64_CODE                                                             \
    "\xab\x05\x00\xb8\xaf\x05\x40\x38" // str w11, [x13], #0; ldrb w15, [x13],
                                       // #0
// #define ARM64_CODE_EB "\xb8\x00\x05\xab\x38\x40\x05\xaf" // str w11, [x13];
//  ldrb w15, [x13]
#define ARM64_CODE_EB ARM64_CODE

// mrs        x2, tpidrro_el0
#define ARM64_MRS_CODE "\x62\xd0\x3b\xd5"

// memory address where emulation starts
#define ADDRESS 0x10000

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size,
                       void *user_data)
{
    printf(">>> Tracing basic block at 0x%" PRIx64 ", block size = 0x%x\n",
           address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data)
{
    printf(">>> Tracing instruction at 0x%" PRIx64
           ", instruction size = 0x%x\n",
           address, size);
}

static void test_arm64_mem_fetch(void)
{
    uc_engine *uc;
    uc_err err;
    uint64_t x1, sp, x0;
    // msr x0, CurrentEL
    unsigned char shellcode0[4] = {64, 66, 56, 213};
    // .text:00000000004002C0                 LDR             X1, [SP,#arg_0]
    unsigned char shellcode[4] = {0xE1, 0x03, 0x40, 0xF9};
    unsigned shellcode_address = 0x4002C0;
    uint64_t data_address = 0x10000000000000;

    printf(">>> Emulate ARM64 fetching stack data from high address %" PRIx64
           "\n",
           data_address);

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    uc_mem_map(uc, data_address, 0x30000, UC_PROT_ALL);
    uc_mem_map(uc, 0x400000, 0x1000, UC_PROT_ALL);

    sp = data_address;
    uc_reg_write(uc, UC_ARM64_REG_SP, &sp);
    uc_mem_write(uc, data_address, "\xc8\xc8\xc8\xc8\xc8\xc8\xc8\xc8", 8);
    uc_mem_write(uc, shellcode_address, shellcode0, 4);
    uc_mem_write(uc, shellcode_address + 4, shellcode, 4);

    err = uc_emu_start(uc, shellcode_address, shellcode_address + 4, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    x0 = 0;
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
    printf(">>> x0(Exception Level)=%" PRIx64 "\n", x0 >> 2);

    err = uc_emu_start(uc, shellcode_address + 4, shellcode_address + 8, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    uc_reg_read(uc, UC_ARM64_REG_X1, &x1);

    printf(">>> X1 = 0x%" PRIx64 "\n", x1);

    uc_close(uc);
}

static void test_arm64(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int64_t x11 = 0x12345678;    // X11 register
    int64_t x13 = 0x10000 + 0x8; // X13 register
    int64_t x15 = 0x33;          // X15 register

    printf("Emulate ARM64 code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, ARM64_CODE, sizeof(ARM64_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_ARM64_REG_X11, &x11);
    uc_reg_write(uc, UC_ARM64_REG_X13, &x13);
    uc_reg_write(uc, UC_ARM64_REG_X15, &x15);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM64_CODE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");
    printf(">>> As little endian, X15 should be 0x78:\n");

    uc_reg_read(uc, UC_ARM64_REG_X15, &x15);
    printf(">>> X15 = 0x%" PRIx64 "\n", x15);

    uc_close(uc);
}

static void test_arm64eb(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int64_t x11 = 0x12345678;    // X11 register
    int64_t x13 = 0x10000 + 0x8; // X13 register
    int64_t x15 = 0x33;          // X15 register

    printf("Emulate ARM64 Big-Endian code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM + UC_MODE_BIG_ENDIAN, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, ARM64_CODE_EB, sizeof(ARM64_CODE_EB) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_ARM64_REG_X11, &x11);
    uc_reg_write(uc, UC_ARM64_REG_X13, &x13);
    uc_reg_write(uc, UC_ARM64_REG_X15, &x15);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM64_CODE_EB) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");
    printf(">>> As big endian, X15 should be 0x78:\n");

    uc_reg_read(uc, UC_ARM64_REG_X15, &x15);
    printf(">>> X15 = 0x%" PRIx64 "\n", x15);

    uc_close(uc);
}

static void test_arm64_sctlr(void)
{
    uc_engine *uc;
    uc_err err;
    uc_arm64_cp_reg reg;

    printf("Read the SCTLR register.\n");

    err = uc_open(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_open() with error returned: %u\n", err);
    }

    // SCTLR_EL1. See arm reference.
    reg.crn = 1;
    reg.crm = 0;
    reg.op0 = 0b11;
    reg.op1 = 0;
    reg.op2 = 0;

    err = uc_reg_read(uc, UC_ARM64_REG_CP_REG, &reg);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_reg_read() with error returned: %u\n", err);
    }

    printf(">>> SCTLR_EL1 = 0x%" PRIx64 "\n", reg.val);

    reg.op1 = 0b100;
    err = uc_reg_read(uc, UC_ARM64_REG_CP_REG, &reg);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_reg_read() with error returned: %u\n", err);
    }

    printf(">>> SCTLR_EL2 = 0x%" PRIx64 "\n", reg.val);

    uc_close(uc);
}

static uint32_t hook_mrs(uc_engine *uc, uc_arm64_reg reg,
                         const uc_arm64_cp_reg *cp_reg, void *user_data)
{
    uint64_t r_x2 = 0x114514;

    printf(">>> Hook MSR instruction. Write 0x114514 to X2.\n");

    uc_reg_write(uc, reg, &r_x2);

    // Skip
    return 1;
}

static void test_arm64_hook_mrs(void)
{
    uc_engine *uc;
    uc_err err;
    uint64_t r_x2;
    uc_hook hk;

    printf("Hook MRS instruction.\n");

    err = uc_open(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_open() with error returned: %u\n", err);
    }

    err = uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_mem_map() with error returned: %u\n", err);
    }

    err = uc_mem_write(uc, 0x1000, ARM64_MRS_CODE, sizeof(ARM64_MRS_CODE));
    if (err != UC_ERR_OK) {
        printf("Failed on uc_mem_write() with error returned: %u\n", err);
    }

    err = uc_hook_add(uc, &hk, UC_HOOK_INSN, hook_mrs, NULL, 1, 0,
                      UC_ARM64_INS_MRS);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_hook_add() with error returned: %u\n", err);
    }

    err = uc_emu_start(uc, 0x1000, 0x1000 + sizeof(ARM64_MRS_CODE) - 1, 0, 0);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    err = uc_reg_read(uc, UC_ARM64_REG_X2, &r_x2);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_reg_read() with error returned: %u\n", err);
    }

    printf(">>> X2 = 0x%" PRIx64 "\n", r_x2);

    uc_close(uc);
}

#define CHECK(x)                                                               \
    do {                                                                       \
        if ((x) != UC_ERR_OK) {                                                \
            fprintf(stderr, "FAIL at %s:%d: %s\n", __FILE__, __LINE__, #x);    \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

/* Test PAC support in the emulator. Code adapted from
https://github.com/unicorn-engine/unicorn/issues/1789#issuecomment-1536320351 */
static void test_arm64_pac(void)
{
    uc_engine *uc;
    uint64_t x1 = 0x0000aaaabbbbccccULL;

// paciza x1
#define ARM64_PAC_CODE "\xe1\x23\xc1\xda"

    printf("Try ARM64 PAC\n");

    // Initialize emulator in ARM mode
    CHECK(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc));
    CHECK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM64_MAX));
    CHECK(uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL));
    CHECK(
        uc_mem_write(uc, ADDRESS, ARM64_PAC_CODE, sizeof(ARM64_PAC_CODE) - 1));
    CHECK(uc_reg_write(uc, UC_ARM64_REG_X1, &x1));

    /** Initialize PAC support **/
    uc_arm64_cp_reg reg;

    // SCR_EL3
    reg.op0 = 0b11;
    reg.op1 = 0b110;
    reg.crn = 0b0001;
    reg.crm = 0b0001;
    reg.op2 = 0b000;

    CHECK(uc_reg_read(uc, UC_ARM64_REG_CP_REG, &reg));

    // NS && RW && API
    reg.val |= (1 | (1 << 10) | (1 << 17));

    CHECK(uc_reg_write(uc, UC_ARM64_REG_CP_REG, &reg));

    // SCTLR_EL1
    reg.op0 = 0b11;
    reg.op1 = 0b000;
    reg.crn = 0b0001;
    reg.crm = 0b0000;
    reg.op2 = 0b000;

    CHECK(uc_reg_read(uc, UC_ARM64_REG_CP_REG, &reg));

    // EnIA && EnIB
    reg.val |= (1 << 31) | (1 << 30);

    CHECK(uc_reg_write(uc, UC_ARM64_REG_CP_REG, &reg));

    // HCR_EL2
    reg.op0 = 0b11;
    reg.op1 = 0b100;
    reg.crn = 0b0001;
    reg.crm = 0b0001;
    reg.op2 = 0b000;

    // HCR.API
    reg.val |= (1ULL << 41);

    CHECK(uc_reg_write(uc, UC_ARM64_REG_CP_REG, &reg));

    /** Check that PAC worked **/
    CHECK(
        uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM64_PAC_CODE) - 1, 0, 0));
    CHECK(uc_reg_read(uc, UC_ARM64_REG_X1, &x1));

    printf("X1 = 0x%" PRIx64 "\n", x1);
    if (x1 == 0x0000aaaabbbbccccULL) {
        printf("FAIL: No PAC tag added!\n");
    } else {
        // Expect 0x1401aaaabbbbccccULL with the default key
        printf("SUCCESS: PAC tag found.\n");
    }

    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    test_arm64_mem_fetch();

    printf("-------------------------\n");
    test_arm64();

    printf("-------------------------\n");
    test_arm64eb();

    printf("-------------------------\n");
    test_arm64_sctlr();

    printf("-------------------------\n");
    test_arm64_hook_mrs();

    printf("-------------------------\n");
    test_arm64_pac();

    return 0;
}
