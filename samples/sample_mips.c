/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate Mips code (big endian) */

#include <unicorn/unicorn.h>
#include <string.h>

// code to be emulated
#define MIPS_CODE_EB "\x34\x21\x34\x56" // ori $at, $at, 0x3456;
#define MIPS_CODE_EL "\x56\x34\x21\x34" // ori $at, $at, 0x3456;

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

static void test_mips_eb(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int r1 = 0x6789; // R1 register

    printf("Emulate MIPS code (big-endian)\n");

    // Initialize emulator in MIPS mode
    err = uc_open(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, MIPS_CODE_EB, sizeof(MIPS_CODE_EB) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_MIPS_REG_1, &r1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(MIPS_CODE_EB) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n", err,
               uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_MIPS_REG_1, &r1);
    printf(">>> R1 = 0x%x\n", r1);

    uc_close(uc);
}

static void test_mips_el(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int r1 = 0x6789; // R1 register

    printf("===========================\n");
    printf("Emulate MIPS code (little-endian)\n");

    // Initialize emulator in MIPS mode
    err = uc_open(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, MIPS_CODE_EL, sizeof(MIPS_CODE_EL) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_MIPS_REG_1, &r1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(MIPS_CODE_EL) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n", err,
               uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_MIPS_REG_1, &r1);
    printf(">>> R1 = 0x%x\n", r1);

    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    test_mips_eb();
    test_mips_el();

    return 0;
}
