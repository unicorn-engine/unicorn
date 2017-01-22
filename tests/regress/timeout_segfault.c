/*
timeout_segfault.c

This program shows a case where the emulation timer keeps running after
emulation has ended. It triggers an intermittent segfault when _timeout_fn()
tries to call uc_emu_stop() after emulation has already been cleaned up. This
code is the same as samples/sample_arm.c, except that it adds a timeout on each
call to uc_emu_start(). See issue #78 for more details:
https://github.com/unicorn-engine/unicorn/issues/78
*/

#include <unicorn/unicorn.h>


// code to be emulated
#define ARM_CODE "\x37\x00\xa0\xe3\x03\x10\x42\xe0" // mov r0, #0x37; sub r1, r2, r3
#define THUMB_CODE "\x83\xb0" // sub    sp, #0xc

// memory address where emulation starts
#define ADDRESS 0x10000

// number of seconds to wait before timeout
#define TIMEOUT 5

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
}

static void test_arm(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int r0 = 0x1234;     // R0 register
    int r2 = 0x6789;     // R1 register
    int r3 = 0x3333;     // R2 register
    int r1;     // R1 register

    printf("Emulate ARM code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
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
    uc_reg_write(uc, UC_ARM_REG_R0, &r0);
    uc_reg_write(uc, UC_ARM_REG_R2, &r2);
    uc_reg_write(uc, UC_ARM_REG_R3, &r3);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM_CODE) -1, UC_SECOND_SCALE * TIMEOUT, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_ARM_REG_R0, &r0);
    uc_reg_read(uc, UC_ARM_REG_R1, &r1);
    printf(">>> R0 = 0x%x\n", r0);
    printf(">>> R1 = 0x%x\n", r1);

    uc_close(uc);
}

static void test_thumb(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int sp = 0x1234;     // R0 register

    printf("Emulate THUMB code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, THUMB_CODE, sizeof(THUMB_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_ARM_REG_SP, &sp);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(THUMB_CODE) -1, UC_SECOND_SCALE * TIMEOUT, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_ARM_REG_SP, &sp);
    printf(">>> SP = 0x%x\n", sp);

    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    test_arm();
    printf("==========================\n");
    test_thumb();

    return 0;
}
