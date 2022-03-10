/*
   Created for Unicorn Engine by Eric Poole <eric.poole@aptiv.com>, 2022
   Copyright 2022 Aptiv 
*/

/* Sample code to demonstrate how to emulate TriCore code */

#include <unicorn/unicorn.h>
#include <string.h>


// code to be emulated
#define CODE "\x82\x11\xbb\x00\x00\x08" // mov d0, #0x1; mov.u d0, #0x8000

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

static void test_tricore(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int d0 = 0x0;     // d0 register

    printf("Emulate TriCore code\n");

    // Initialize emulator in TriCore mode
    err = uc_open(UC_ARCH_TRICORE, UC_MODE_LITTLE_ENDIAN, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, CODE, sizeof(CODE) - 1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(CODE) -1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_TRICORE_REG_D0, &d0);
    printf(">>> d0 = 0x%x\n", d0);
    uc_reg_read(uc, UC_TRICORE_REG_D2, &d0);
    printf(">>> d2 = 0x%x\n", d0);
    uc_reg_read(uc, UC_TRICORE_REG_D15, &d0);
    printf(">>> d15 = 0x%x\n", d0);

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
    
    test_tricore();
#ifdef DYNLOAD
    uc_dyn_free();
#endif
    
    return 0;
}