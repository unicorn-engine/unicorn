/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate ARM64 code */

#include <inttypes.h>

#include <unicorn/unicorn.h>


// code to be emulated
#define ARM_CODE "\xab\x01\x0f\x8b" // add x11, x13, x15

// memory address where emulation starts
#define ADDRESS 0x10000

static void hook_block(uch handle, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

static void hook_code(uch handle, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
}

static void test_arm64(void)
{
    uch handle;
    uc_err err;
    uch trace1, trace2;

    int64_t x11 = 0x1234;     // X11 register
    int64_t x13 = 0x6789;     // X13 register
    int64_t x15 = 0x3333;     // X15 register

    printf("Emulate ARM64 code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &handle);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(handle, ADDRESS, 2 * 1024 * 1024);

    // write machine code to be emulated to memory
    uc_mem_write(handle, ADDRESS, (uint8_t *)ARM_CODE, sizeof(ARM_CODE) - 1);

    // initialize machine registers
    uc_reg_write(handle, UC_ARM64_REG_X11, &x11);
    uc_reg_write(handle, UC_ARM64_REG_X13, &x13);
    uc_reg_write(handle, UC_ARM64_REG_X15, &x15);

    // tracing all basic blocks with customized callback
    uc_hook_add(handle, &trace1, UC_HOOK_BLOCK, hook_block, NULL, (uint64_t)1, (uint64_t)0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(handle, &trace2, UC_HOOK_CODE, hook_code, NULL, (uint64_t)ADDRESS, (uint64_t)ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(handle, ADDRESS, ADDRESS + sizeof(ARM_CODE) -1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(handle, UC_ARM64_REG_X11, &x11);
    printf(">>> X11 = 0x%" PRIx64 "\n", x11);

    uc_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    test_arm64();

    return 0;
}
