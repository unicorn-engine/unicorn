/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate ARM code */

// windows specific
#ifdef _MSC_VER
#include <io.h>
#include <windows.h>
#define PRIx64 "llX"
#ifdef DYNLOAD
#include "unicorn_dynload.h"
#else // DYNLOAD
#include <unicorn/unicorn.h>
#ifdef _WIN64
#pragma comment(lib, "unicorn_staload64.lib")
#else // _WIN64
#pragma comment(lib, "unicorn_staload.lib")
#endif // _WIN64
#endif // DYNLOAD

// posix specific
#else // _MSC_VER
#include <unicorn/unicorn.h>
#endif // _MSC_VER


// code to be emulated
#define ARM_CODE "\x37\x00\xa0\xe3\x03\x10\x42\xe0" // mov r0, #0x37; sub r1, r2, r3
#define THUMB_CODE "\x83\xb0" // sub    sp, #0xc

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
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, (uint64_t)1, (uint64_t)0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, (uint64_t)ADDRESS, (uint64_t)ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM_CODE) -1, 0, 0);
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
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, (uint64_t)1, (uint64_t)0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, (uint64_t)ADDRESS, (uint64_t)ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(THUMB_CODE) -1, 0, 0);
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
    
    // test memleak
    while(1) {
        test_arm();
        printf("==========================\n");
        test_thumb();
    }

    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif
    
    return 0;
}
