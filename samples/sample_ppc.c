/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate PPC code (big endian) */

#include <unicorn/unicorn.h>
#include <string.h>


// code to be emulated
#define PPC_CODE_BE "\x38\x63\x00\x04" 
#define PPC_CODE_LE "\x04\x00\x63\x38" 
// memory address where emulation starts
#define ADDRESS 0x1000

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

static void test_ppc_be(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1;

    int gpr3;

    printf("Emulate PPC code (big-endian)\n");

    // Initialize emulator in PPC mode
    err = uc_open(UC_ARCH_PPC, UC_MODE_PPC32 + UC_MODE_BIG_ENDIAN, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, PPC_CODE_BE, sizeof(PPC_CODE_BE) - 1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(PPC_CODE_BE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n", err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_PPC_REG_GPR_3, &gpr3);
    printf(">>> R3 = 0x%x\n", gpr3);

    uc_close(uc);
}

static void test_ppc_le(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1;

    int gpr3;

    printf("===========================\n");
    printf("Emulate PPC code (little-endian)\n");

    // Initialize emulator in PPC mode
    err = uc_open(UC_ARCH_PPC, UC_MODE_PPC32 + UC_MODE_LITTLE_ENDIAN, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, PPC_CODE_LE, sizeof(PPC_CODE_LE) - 1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(PPC_CODE_LE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n", err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_PPC_REG_GPR_3, &gpr3);
    printf(">>> R3 = 0x%x\n", gpr3);

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
    
    test_ppc_be();
    test_ppc_le();

    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif
    
    return 0;
}
