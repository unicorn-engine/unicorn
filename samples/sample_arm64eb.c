/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */
/* modify from arm64 sample zhangwm, 2017 */

/* Sample code to demonstrate how to emulate ARM64EB code */

#include <unicorn/unicorn.h>
#include <string.h>

// code to be emulated
#define ARM_CODE "\xab\x05\x00\xb8\xaf\x05\x40\x38" // str x11, [x13]; ldrb x15, [x13]

// memory address where emulation starts
#define ADDRESS 0x10000

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
}

static void test_arm64(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int64_t x11 = 0x12345678;        // X11 register
    int64_t x13 = 0x10000 + 0x8;     // X13 register
    int64_t x15 = 0x33;              // X15 register

    printf("Emulate ARM64 Big-Endian code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM + UC_MODE_BIG_ENDIAN, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, ARM_CODE, sizeof(ARM_CODE) - 1);

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
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM_CODE) -1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");
    printf(">>> As big endian, X15 should be 0x12:\n");

    uc_reg_read(uc, UC_ARM64_REG_X15, &x15);
    printf(">>> X15 = 0x%" PRIx64 "\n", x15);

    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    // dynamically load shared library
#ifdef DYNLOAD
    if (!uc_dyn_load(NULL, 0)) {
        printf("Error dynamically loading shared library.\n");
        printf("Please check that unicorn.dll/unicorn.so is available as well as\n");
        printf("any other dependent dll/so files.\n");
        printf("The easiest way is to place them in the same directory as this app.\n");
        return 1;
    }
#endif
    
    test_arm64();

    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif
    
    return 0;
}
